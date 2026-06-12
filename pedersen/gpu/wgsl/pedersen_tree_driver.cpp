// WebGPU/WGSL host driver for the tree-reduce Pedersen vector commitment.
//
// Single-stage dispatch: M workgroups of 256 invocations each. Workgroup
// memory holds the 256 partial points; an in-shader workgroupBarrier()
// loop collapses them to one before thread 0 emits the result.
//
// Build modes:
//   * KINET_PEDERSEN_HAS_WEBGPU=1     -- Dawn / wgpu-native runtime
//   * KINET_PEDERSEN_HAS_WGPU_NATIVE=1 -- enables wgpuDevicePoll
// Stub mode otherwise (returns -1).

#include "pedersen_tree_driver.h"

#if defined(KINET_PEDERSEN_HAS_WEBGPU)

#include <webgpu.h>
#if defined(KINET_PEDERSEN_HAS_WGPU_NATIVE)
#  include <wgpu.h>
#endif

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

// Embedded WGSL source (concatenated by CMake into pedersen_tree_wgsl_source.h).
#include "pedersen_tree_wgsl_source.h"

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
#if defined(KINET_PEDERSEN_HAS_WGPU_NATIVE)
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
    for (int spin = 0; spin < 8192; spin++) {
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
    for (int spin = 0; spin < 8192; spin++) {
        if (as.done.load(std::memory_order_acquire)) break;
        wgpuInstanceProcessEvents(e.instance);
    }
    if (!as.ad) return false;
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
    for (int spin = 0; spin < 8192; spin++) {
        if (ds.done.load(std::memory_order_acquire)) break;
        wgpuInstanceProcessEvents(e.instance);
    }
    if (!ds.dev) return false;
    e.device = ds.dev;
    e.queue  = wgpuDeviceGetQueue(e.device);
    if (!e.queue) return false;

    std::string src(kPedersenTreeWGSL);
    WGPUShaderSourceWGSL wgsl{};
    wgsl.chain.sType = WGPUSType_ShaderSourceWGSL;
    wgsl.code = sv(src);
    WGPUShaderModuleDescriptor smd{};
    smd.nextInChain = &wgsl.chain;
    smd.label = sv("pedersen_tree");
    e.module = wgpuDeviceCreateShaderModule(e.device, &smd);
    if (!e.module) return false;

    e.initialized = true;
    return true;
}

WGPUBuffer make_buf(Engine& e, size_t size, WGPUBufferUsage usage) {
    WGPUBufferDescriptor bd{};
    bd.size = (size + 3) & ~size_t(3);
    bd.usage = usage;
    return wgpuDeviceCreateBuffer(e.device, &bd);
}

}  // namespace

extern "C" int kinet_pedersen_tree_wgpu_available(void) {
    return init_engine() ? 1 : 0;
}

extern "C" int pedersen_tree_wgpu(
    const uint8_t* gens_be,
    const uint8_t* scalars_be,
    const uint8_t* blindings_be,
    uint32_t       M,
    uint8_t*       out_be) {
    if (M == 0) return 0;
    if (!gens_be || !scalars_be || !blindings_be || !out_be) return -1;
    if (!init_engine()) return -1;

    Engine& e = engine();
    const uint32_t N = PEDERSEN_TREE_WIDTH;

    size_t gens_len    = (size_t)(N + 1) * 64;
    size_t scalars_len = (size_t)M * N * 32;
    size_t blind_len   = (size_t)M * 32;
    size_t out_len     = (size_t)M * 64;

    WGPUBuffer bufGens = make_buf(e, gens_len,
        (WGPUBufferUsage)(WGPUBufferUsage_Storage | WGPUBufferUsage_CopyDst));
    WGPUBuffer bufScalars = make_buf(e, scalars_len,
        (WGPUBufferUsage)(WGPUBufferUsage_Storage | WGPUBufferUsage_CopyDst));
    WGPUBuffer bufBlind = make_buf(e, blind_len,
        (WGPUBufferUsage)(WGPUBufferUsage_Storage | WGPUBufferUsage_CopyDst));
    WGPUBuffer bufOut = make_buf(e, out_len,
        (WGPUBufferUsage)(WGPUBufferUsage_Storage | WGPUBufferUsage_CopySrc));
    WGPUBuffer bufDims = make_buf(e, 16,
        (WGPUBufferUsage)(WGPUBufferUsage_Uniform | WGPUBufferUsage_CopyDst));
    WGPUBuffer bufRead = make_buf(e, out_len,
        (WGPUBufferUsage)(WGPUBufferUsage_MapRead | WGPUBufferUsage_CopyDst));
    if (!bufGens || !bufScalars || !bufBlind ||
        !bufOut  || !bufDims    || !bufRead) {
        return -2;
    }

    wgpuQueueWriteBuffer(e.queue, bufGens,    0, gens_be,      gens_len);
    wgpuQueueWriteBuffer(e.queue, bufScalars, 0, scalars_be,   scalars_len);
    wgpuQueueWriteBuffer(e.queue, bufBlind,   0, blindings_be, blind_len);
    uint32_t dimVals[4] = { M, N, 0, 0 };
    wgpuQueueWriteBuffer(e.queue, bufDims, 0, dimVals, 16);

    // Single pipeline; bind group 0.
    WGPUComputePipelineDescriptor cpd{};
    cpd.compute.module = e.module;
    cpd.compute.entryPoint = sv("pedersen_tree_commit");
    cpd.label = sv("pedersen_tree_commit");
    WGPUComputePipeline pso = wgpuDeviceCreateComputePipeline(e.device, &cpd);
    if (!pso) return -3;

    WGPUBindGroupLayout bgl = wgpuComputePipelineGetBindGroupLayout(pso, 0);
    WGPUBindGroupEntry bge[5] = {};
    bge[0].binding = 0; bge[0].buffer = bufGens;    bge[0].size = gens_len;
    bge[1].binding = 1; bge[1].buffer = bufScalars; bge[1].size = scalars_len;
    bge[2].binding = 2; bge[2].buffer = bufBlind;   bge[2].size = blind_len;
    bge[3].binding = 3; bge[3].buffer = bufOut;     bge[3].size = out_len;
    bge[4].binding = 4; bge[4].buffer = bufDims;    bge[4].size = 16;
    WGPUBindGroupDescriptor bgd{};
    bgd.layout = bgl; bgd.entryCount = 5; bgd.entries = bge;
    WGPUBindGroup bg = wgpuDeviceCreateBindGroup(e.device, &bgd);
    if (!bg) return -4;

    WGPUCommandEncoderDescriptor ced{};
    WGPUCommandEncoder ce = wgpuDeviceCreateCommandEncoder(e.device, &ced);

    {
        WGPUComputePassDescriptor cpdesc{};
        WGPUComputePassEncoder cpe = wgpuCommandEncoderBeginComputePass(ce, &cpdesc);
        wgpuComputePassEncoderSetPipeline(cpe, pso);
        wgpuComputePassEncoderSetBindGroup(cpe, 0, bg, 0, nullptr);
        // M workgroups; the kernel fixes the workgroup size at 256.
        wgpuComputePassEncoderDispatchWorkgroups(cpe, M, 1, 1);
        wgpuComputePassEncoderEnd(cpe);
        wgpuComputePassEncoderRelease(cpe);
    }

    wgpuCommandEncoderCopyBufferToBuffer(ce, bufOut, 0, bufRead, 0, out_len);
    WGPUCommandBufferDescriptor cbd{};
    WGPUCommandBuffer cmd = wgpuCommandEncoderFinish(ce, &cbd);
    wgpuQueueSubmit(e.queue, 1, &cmd);

    int rc = 0;
    if (!wait_map(e.instance, e.device, bufRead, WGPUMapMode_Read, 0, out_len)) {
        rc = -5;
    } else {
        const void* mapped = wgpuBufferGetConstMappedRange(bufRead, 0, out_len);
        std::memcpy(out_be, mapped, out_len);
        wgpuBufferUnmap(bufRead);
    }

    wgpuCommandEncoderRelease(ce);
    wgpuCommandBufferRelease(cmd);
    wgpuBindGroupRelease(bg);
    wgpuBindGroupLayoutRelease(bgl);
    wgpuComputePipelineRelease(pso);
    wgpuBufferRelease(bufGens);    wgpuBufferRelease(bufScalars);
    wgpuBufferRelease(bufBlind);
    wgpuBufferRelease(bufOut);     wgpuBufferRelease(bufDims);
    wgpuBufferRelease(bufRead);
    return rc;
}

#else // KINET_PEDERSEN_HAS_WEBGPU not defined: stub mode

extern "C" int kinet_pedersen_tree_wgpu_available(void) { return 0; }
extern "C" int pedersen_tree_wgpu(
    const uint8_t*, const uint8_t*, const uint8_t*,
    uint32_t, uint8_t*) { return -1; }

#endif
