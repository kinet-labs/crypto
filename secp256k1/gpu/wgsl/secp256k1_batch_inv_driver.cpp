// WGSL host driver for Stage A (Montgomery batch inversion). Mirrors the
// shape of gpu/metal/secp256k1_batch_inv_driver.mm and gpu/cuda/
// secp256k1_batch_inv_driver.cu so the test harness can swap drivers.
//
// Real WebGPU dispatch is built only when CRYPTO_HAS_DAWN is defined
// (CI runner has Dawn / wgpu-native installed). Without it, the entry point
// returns a NOTIMPL sentinel so the umbrella library still links and the
// determinism tests skip the WGSL leg.
//
// Entry: cuda-shaped signature (kind = 0 Fp, 1 Fn).

#include "crypto.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

#ifdef CRYPTO_HAS_DAWN
#include <dawn/webgpu_cpp.h>
#include <dawn/native/DawnNative.h>
#include <fstream>
#include <sstream>
#include <vector>
#endif

// Use the public C-ABI return codes from crypto.h; no local constants
// (Kinet brand-neutral C-ABI per LP-137).
namespace {

#ifdef CRYPTO_HAS_DAWN

// Load WGSL source from disk (CMake places kernel next to the build artifacts).
std::string load_wgsl(const char* path) {
    std::ifstream f(path);
    if (!f) return {};
    std::stringstream ss; ss << f.rdbuf();
    return ss.str();
}

int dispatch(const uint8_t* in_mont, size_t n, uint8_t* out_mont,
             int kind, const char* wgsl_path) {
    if (n == 0) return CRYPTO_OK;
    if (!in_mont || !out_mont || !wgsl_path) return CRYPTO_ERR_INPUT;
    if (kind != 0 && kind != 1) return CRYPTO_ERR_INPUT;

    const std::string src = load_wgsl(wgsl_path);
    if (src.empty()) return -3;

    // ---- Instance + adapter + device ---------------------------------------
    wgpu::InstanceDescriptor idesc{};
    wgpu::Instance instance = wgpu::CreateInstance(&idesc);
    if (!instance) return -4;

    wgpu::RequestAdapterOptions aopts{};
    aopts.powerPreference = wgpu::PowerPreference::HighPerformance;
    wgpu::Adapter adapter = nullptr;
    instance.RequestAdapter(&aopts,
        [](WGPURequestAdapterStatus status, WGPUAdapter ad, const char*, void* ud) {
            if (status == WGPURequestAdapterStatus_Success) {
                *static_cast<wgpu::Adapter*>(ud) = wgpu::Adapter::Acquire(ad);
            }
        }, &adapter);
    if (!adapter) return -5;

    wgpu::Device device = nullptr;
    wgpu::DeviceDescriptor ddesc{};
    adapter.RequestDevice(&ddesc,
        [](WGPURequestDeviceStatus status, WGPUDevice d, const char*, void* ud) {
            if (status == WGPURequestDeviceStatus_Success) {
                *static_cast<wgpu::Device*>(ud) = wgpu::Device::Acquire(d);
            }
        }, &device);
    if (!device) return -6;

    wgpu::Queue queue = device.GetQueue();

    // ---- Shader module ------------------------------------------------------
    wgpu::ShaderSourceWGSL wgsl{};
    wgsl.code = src.c_str();
    wgpu::ShaderModuleDescriptor smd{};
    smd.nextInChain = &wgsl;
    wgpu::ShaderModule shader = device.CreateShaderModule(&smd);
    if (!shader) return -7;

    // ---- Buffers ------------------------------------------------------------
    const size_t bytes = n * 32;

    wgpu::BufferDescriptor in_bd{};
    in_bd.size = bytes;
    in_bd.usage = wgpu::BufferUsage::Storage | wgpu::BufferUsage::CopyDst;
    in_bd.mappedAtCreation = true;
    wgpu::Buffer in_buf = device.CreateBuffer(&in_bd);
    std::memcpy(in_buf.GetMappedRange(), in_mont, bytes);
    in_buf.Unmap();

    wgpu::BufferDescriptor out_bd{};
    out_bd.size = bytes;
    out_bd.usage = wgpu::BufferUsage::Storage | wgpu::BufferUsage::CopySrc;
    wgpu::Buffer out_buf = device.CreateBuffer(&out_bd);

    wgpu::BufferDescriptor cfg_bd{};
    cfg_bd.size = 16;  // vec4<u32>
    cfg_bd.usage = wgpu::BufferUsage::Uniform | wgpu::BufferUsage::CopyDst;
    cfg_bd.mappedAtCreation = true;
    wgpu::Buffer cfg_buf = device.CreateBuffer(&cfg_bd);
    uint32_t cfg[4] = { (uint32_t)n, (uint32_t)kind, 0u, 0u };
    std::memcpy(cfg_buf.GetMappedRange(), cfg, sizeof(cfg));
    cfg_buf.Unmap();

    wgpu::BufferDescriptor read_bd{};
    read_bd.size = bytes;
    read_bd.usage = wgpu::BufferUsage::CopyDst | wgpu::BufferUsage::MapRead;
    wgpu::Buffer read_buf = device.CreateBuffer(&read_bd);

    // ---- Pipeline -----------------------------------------------------------
    wgpu::ComputePipelineDescriptor pd{};
    pd.compute.module = shader;
    pd.compute.entryPoint = (kind == 0) ? "secp256k1_batch_inv_fp"
                                        : "secp256k1_batch_inv_fn";
    wgpu::ComputePipeline pipeline = device.CreateComputePipeline(&pd);
    if (!pipeline) return -8;

    // ---- Bind group ---------------------------------------------------------
    wgpu::BindGroupEntry entries[3] = {};
    entries[0].binding = 0; entries[0].buffer = in_buf;  entries[0].size = bytes;
    entries[1].binding = 1; entries[1].buffer = out_buf; entries[1].size = bytes;
    entries[2].binding = 2; entries[2].buffer = cfg_buf; entries[2].size = 16;

    wgpu::BindGroupDescriptor bgd{};
    bgd.layout = pipeline.GetBindGroupLayout(0);
    bgd.entryCount = 3;
    bgd.entries = entries;
    wgpu::BindGroup bg = device.CreateBindGroup(&bgd);

    // ---- Encode + dispatch (single thread) ----------------------------------
    wgpu::CommandEncoder enc = device.CreateCommandEncoder();
    {
        wgpu::ComputePassEncoder pass = enc.BeginComputePass();
        pass.SetPipeline(pipeline);
        pass.SetBindGroup(0, bg);
        pass.DispatchWorkgroups(1, 1, 1);
        pass.End();
    }
    enc.CopyBufferToBuffer(out_buf, 0, read_buf, 0, bytes);
    wgpu::CommandBuffer cmd = enc.Finish();
    queue.Submit(1, &cmd);

    // ---- Map + read --------------------------------------------------------
    bool done = false;
    bool ok = false;
    read_buf.MapAsync(wgpu::MapMode::Read, 0, bytes,
        [](WGPUBufferMapAsyncStatus s, void* ud) {
            auto* p = static_cast<std::pair<bool*, bool*>*>(ud);
            *p->first = true;
            *p->second = (s == WGPUBufferMapAsyncStatus_Success);
        }, new std::pair<bool*, bool*>(&done, &ok));
    while (!done) { device.Tick(); }
    if (!ok) return -9;

    const void* mapped = read_buf.GetConstMappedRange();
    std::memcpy(out_mont, mapped, bytes);
    read_buf.Unmap();
    return CRYPTO_OK;
}

#endif  // CRYPTO_HAS_DAWN

}  // namespace

extern "C" int wgsl_secp256k1_batch_inv(
    const uint8_t* in_mont,    // n * 32 bytes (Mont-form, limb little-endian)
    size_t         n,
    uint8_t*       out_mont,   // n * 32 bytes
    int            kind,       // 0 = Fp, 1 = Fn
    const char*    wgsl_path)  // path to secp256k1_batch_inv.wgsl
{
#ifdef CRYPTO_HAS_DAWN
    return dispatch(in_mont, n, out_mont, kind, wgsl_path);
#else
    (void)in_mont; (void)n; (void)out_mont; (void)kind; (void)wgsl_path;
    return CRYPTO_ERR_NOTIMPL;
#endif
}
