// WebGPU/WGSL host driver for BLS12-381 Fp-tower kernels (Stage 4 parity port).
//
// Concatenates the WGSL source fragments (Fp ops, Fp2, Fp6, Fp12, kernels) at
// runtime, compiles a single shader module, then dispatches per kernel name.
//
// Build:
//   * BLS_HAS_WEBGPU=1                — Dawn or wgpu-native runtime found
//   * BLS_HAS_WGPU_NATIVE=1           — wgpu-native specifically (gives wgpuDevicePoll)
//
// On Apple host with Homebrew wgpu-native, both flags are set by CMake.

#include "bls_driver_wgpu.h"

#if defined(BLS_HAS_WEBGPU)

#include <webgpu.h>
#if defined(BLS_HAS_WGPU_NATIVE)
#  include <wgpu.h>
#endif

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

// WGSL sources concatenated by CMake into bls_wgsl_sources.h.
#include "bls_wgsl_sources.h"

namespace {

WGPUStringView sv(const char* s) {
    WGPUStringView v{};
    v.data = s;
    v.length = (s == nullptr) ? 0 : std::strlen(s);
    return v;
}
WGPUStringView sv(const std::string& s) {
    WGPUStringView v{};
    v.data = s.data();
    v.length = s.size();
    return v;
}

void drain(WGPUInstance inst, WGPUDevice dev) {
    if (inst) wgpuInstanceProcessEvents(inst);
#if defined(BLS_HAS_WGPU_NATIVE)
    if (dev) wgpuDevicePoll(dev, /*wait=*/WGPU_TRUE, nullptr);
#else
    (void)dev;
#endif
}

bool wait_map(WGPUInstance inst, WGPUDevice dev, WGPUBuffer buf,
              WGPUMapMode mode, size_t off, size_t size) {
    struct State { std::atomic<bool> done{false}; WGPUMapAsyncStatus status{WGPUMapAsyncStatus_Error}; } s;
    WGPUBufferMapCallbackInfo cb{};
    cb.mode = WGPUCallbackMode_AllowProcessEvents;
    cb.callback = [](WGPUMapAsyncStatus st, WGPUStringView, void* u, void*) {
        auto* p = static_cast<State*>(u);
        p->status = st;
        p->done.store(true, std::memory_order_release);
    };
    cb.userdata1 = &s;
    wgpuBufferMapAsync(buf, mode, off, size, cb);
    for (int spin = 0; spin < 4096; spin++) {
        if (s.done.load(std::memory_order_acquire)) break;
        drain(inst, dev);
    }
    return s.done.load() && s.status == WGPUMapAsyncStatus_Success;
}

struct Engine {
    WGPUInstance instance{nullptr};
    WGPUAdapter  adapter{nullptr};
    WGPUDevice   device{nullptr};
    WGPUQueue    queue{nullptr};
    WGPUShaderModule module{nullptr};
    bool initialized{false};
};

Engine& engine() { static Engine e; return e; }

bool init_engine() {
    Engine& e = engine();
    if (e.initialized) return true;

    WGPUInstanceDescriptor idesc{};
    e.instance = wgpuCreateInstance(&idesc);
    if (!e.instance) return false;

    struct AS { std::atomic<bool> done{false}; WGPUAdapter ad{nullptr}; } as;
    WGPURequestAdapterOptions ropt{};
    ropt.powerPreference = WGPUPowerPreference_HighPerformance;
    WGPURequestAdapterCallbackInfo rcb{};
    rcb.mode = WGPUCallbackMode_AllowProcessEvents;
    rcb.callback = [](WGPURequestAdapterStatus st, WGPUAdapter ad,
                       WGPUStringView, void* u, void*) {
        auto* p = static_cast<AS*>(u);
        if (st == WGPURequestAdapterStatus_Success) p->ad = ad;
        p->done.store(true, std::memory_order_release);
    };
    rcb.userdata1 = &as;
    wgpuInstanceRequestAdapter(e.instance, &ropt, rcb);
    for (int spin = 0; spin < 4096; spin++) {
        if (as.done.load(std::memory_order_acquire)) break;
        wgpuInstanceProcessEvents(e.instance);
    }
    if (!as.ad) { fprintf(stderr, "wgpu: no adapter\n"); return false; }
    e.adapter = as.ad;

    struct DS { std::atomic<bool> done{false}; WGPUDevice dev{nullptr}; } ds;
    WGPUDeviceDescriptor ddesc{};
    WGPURequestDeviceCallbackInfo dcb{};
    dcb.mode = WGPUCallbackMode_AllowProcessEvents;
    dcb.callback = [](WGPURequestDeviceStatus st, WGPUDevice dev,
                       WGPUStringView, void* u, void*) {
        auto* p = static_cast<DS*>(u);
        if (st == WGPURequestDeviceStatus_Success) p->dev = dev;
        p->done.store(true, std::memory_order_release);
    };
    dcb.userdata1 = &ds;
    wgpuAdapterRequestDevice(e.adapter, &ddesc, dcb);
    for (int spin = 0; spin < 4096; spin++) {
        if (ds.done.load(std::memory_order_acquire)) break;
        wgpuInstanceProcessEvents(e.instance);
    }
    if (!ds.dev) { fprintf(stderr, "wgpu: no device\n"); return false; }
    e.device = ds.dev;
    e.queue  = wgpuDeviceGetQueue(e.device);
    if (!e.queue) return false;

    // Concatenate WGSL sources and compile a single module.
    std::string src;
    src.append(kBLS_WGSL_FpOps);
    src.append(kBLS_WGSL_Fp2);
    src.append(kBLS_WGSL_Fp6);
    src.append(kBLS_WGSL_Fp12);
    src.append(kBLS_WGSL_Kernels);

    WGPUShaderSourceWGSL wgsl{};
    wgsl.chain.sType = WGPUSType_ShaderSourceWGSL;
    wgsl.code = sv(src);

    WGPUShaderModuleDescriptor smd{};
    smd.nextInChain = &wgsl.chain;
    smd.label = sv("bls_fp_tower");
    e.module = wgpuDeviceCreateShaderModule(e.device, &smd);
    if (!e.module) { fprintf(stderr, "wgpu: shader compile failed\n"); return false; }

    e.initialized = true;
    return true;
}

WGPUBuffer make_buf(Engine& e, size_t size, WGPUBufferUsage usage) {
    WGPUBufferDescriptor bd{};
    bd.size = (size + 3) & ~size_t(3);
    bd.usage = usage;
    return wgpuDeviceCreateBuffer(e.device, &bd);
}

bool dispatch(const char* entry, const void* a_data, const void* b_data,
              void* out_data, size_t a_bytes, size_t b_bytes, size_t out_bytes,
              uint32_t count) {
    Engine& e = engine();
    if (!init_engine()) return false;

    // Buffers
    WGPUBuffer bufA = make_buf(e, a_bytes ? a_bytes : 4, WGPUBufferUsage_Storage | WGPUBufferUsage_CopyDst);
    WGPUBuffer bufB = make_buf(e, b_bytes ? b_bytes : 4, WGPUBufferUsage_Storage | WGPUBufferUsage_CopyDst);
    WGPUBuffer bufO = make_buf(e, out_bytes, WGPUBufferUsage_Storage | WGPUBufferUsage_CopySrc);
    WGPUBuffer bufU = make_buf(e, 16, WGPUBufferUsage_Uniform | WGPUBufferUsage_CopyDst);
    WGPUBuffer bufR = make_buf(e, out_bytes, WGPUBufferUsage_MapRead | WGPUBufferUsage_CopyDst);
    if (!bufA || !bufB || !bufO || !bufU || !bufR) return false;

    if (a_bytes) wgpuQueueWriteBuffer(e.queue, bufA, 0, a_data, a_bytes);
    if (b_bytes) wgpuQueueWriteBuffer(e.queue, bufB, 0, b_data, b_bytes);
    uint32_t params[4] = { count, 0, 0, 0 };
    wgpuQueueWriteBuffer(e.queue, bufU, 0, params, 16);

    // Pipeline
    WGPUComputePipelineDescriptor cpd{};
    cpd.compute.module = e.module;
    cpd.compute.entryPoint = sv(entry);
    cpd.label = sv(entry);
    WGPUComputePipeline pso = wgpuDeviceCreateComputePipeline(e.device, &cpd);
    if (!pso) { fprintf(stderr, "wgpu: pipeline %s failed\n", entry); return false; }

    // Bind group (auto-derive layout)
    WGPUBindGroupLayout bgl = wgpuComputePipelineGetBindGroupLayout(pso, 0);
    WGPUBindGroupEntry bge[4] = {};
    bge[0].binding = 0; bge[0].buffer = bufA; bge[0].size = a_bytes ? a_bytes : 4;
    bge[1].binding = 1; bge[1].buffer = bufB; bge[1].size = b_bytes ? b_bytes : 4;
    bge[2].binding = 2; bge[2].buffer = bufO; bge[2].size = out_bytes;
    bge[3].binding = 3; bge[3].buffer = bufU; bge[3].size = 16;
    WGPUBindGroupDescriptor bgd{};
    bgd.layout = bgl;
    bgd.entryCount = 4;
    bgd.entries = bge;
    WGPUBindGroup bg = wgpuDeviceCreateBindGroup(e.device, &bgd);
    if (!bg) return false;

    // Encode + dispatch
    WGPUCommandEncoderDescriptor ced{};
    WGPUCommandEncoder ce = wgpuDeviceCreateCommandEncoder(e.device, &ced);
    WGPUComputePassDescriptor cpd2{};
    WGPUComputePassEncoder cpe = wgpuCommandEncoderBeginComputePass(ce, &cpd2);
    wgpuComputePassEncoderSetPipeline(cpe, pso);
    wgpuComputePassEncoderSetBindGroup(cpe, 0, bg, 0, nullptr);
    wgpuComputePassEncoderDispatchWorkgroups(cpe, count, 1, 1);
    wgpuComputePassEncoderEnd(cpe);

    wgpuCommandEncoderCopyBufferToBuffer(ce, bufO, 0, bufR, 0, out_bytes);
    WGPUCommandBufferDescriptor cbd{};
    WGPUCommandBuffer cmd = wgpuCommandEncoderFinish(ce, &cbd);
    wgpuQueueSubmit(e.queue, 1, &cmd);

    if (!wait_map(e.instance, e.device, bufR, WGPUMapMode_Read, 0, out_bytes)) {
        fprintf(stderr, "wgpu: map readback failed\n");
        return false;
    }
    const void* mapped = wgpuBufferGetConstMappedRange(bufR, 0, out_bytes);
    std::memcpy(out_data, mapped, out_bytes);
    wgpuBufferUnmap(bufR);

    wgpuComputePassEncoderRelease(cpe);
    wgpuCommandEncoderRelease(ce);
    wgpuCommandBufferRelease(cmd);
    wgpuBindGroupRelease(bg);
    wgpuBindGroupLayoutRelease(bgl);
    wgpuComputePipelineRelease(pso);
    wgpuBufferRelease(bufA);
    wgpuBufferRelease(bufB);
    wgpuBufferRelease(bufO);
    wgpuBufferRelease(bufU);
    wgpuBufferRelease(bufR);
    return true;
}

} // namespace

extern "C" {

int bls_wgpu_available(void) {
    return init_engine() ? 1 : 0;
}

int bls_wgpu_run_binary(const char* entry, const void* a, const void* b,
                             void* out, unsigned elem_bytes, unsigned count) {
    size_t bytes = size_t(elem_bytes) * count;
    return dispatch(entry, a, b, out, bytes, bytes, bytes, count) ? 0 : -1;
}

int bls_wgpu_run_unary(const char* entry, const void* a, void* out,
                            unsigned elem_bytes, unsigned count) {
    size_t bytes = size_t(elem_bytes) * count;
    return dispatch(entry, a, nullptr, out, bytes, 0, bytes, count) ? 0 : -1;
}

} // extern "C"

#else // BLS_HAS_WEBGPU not defined: stub mode

extern "C" {
int bls_wgpu_available(void) { return 0; }
int bls_wgpu_run_binary(const char*, const void*, const void*, void*, unsigned, unsigned) { return -1; }
int bls_wgpu_run_unary(const char*, const void*, void*, unsigned, unsigned) { return -1; }
}

#endif
