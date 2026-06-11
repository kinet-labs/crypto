// WebGPU/WGSL host driver for the batched Pedersen vector commitment.
//
// Two-stage dispatch into a single shader module:
//   stage 1 (group 0): pedersen_pointmul    -- M*(N+1) threads
//   stage 2 (group 1): pedersen_reduce_add  -- M       threads
//
// Build modes:
//   * KINET_PEDERSEN_HAS_WEBGPU=1  -- Dawn or wgpu-native runtime
//   * KINET_PEDERSEN_HAS_WGPU_NATIVE=1 -- enables wgpuDevicePoll
// Stub mode otherwise (returns -1).

#include "pedersen_driver_wgpu.h"

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

// Embedded WGSL source (concatenated by CMake into pedersen_wgsl_source.h).
#include "pedersen_wgsl_source.h"

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

    std::string src(kPedersenWGSL);
    WGPUShaderSourceWGSL wgsl{};
    wgsl.chain.sType = WGPUSType_ShaderSourceWGSL;
    wgsl.code = sv(src);
    WGPUShaderModuleDescriptor smd{};
    smd.nextInChain = &wgsl.chain;
    smd.label = sv("pedersen");
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

extern "C" int kinet_pedersen_wgpu_available(void) {
    return init_engine() ? 1 : 0;
}

extern "C" int pedersen_batch_wgpu(
    const uint8_t* gens_be,
    const uint8_t* scalars_be,
    const uint8_t* blindings_be,
    uint32_t       M,
    uint32_t       N,
    uint8_t*       out_be) {
    if (M == 0 || N == 0) return 0;
    if (!gens_be || !scalars_be || !blindings_be || !out_be) return -1;
    if (!init_engine()) return -1;

    Engine& e = engine();

    size_t gens_len    = (size_t)(N + 1) * 64;
    size_t scalars_len = (size_t)M * N * 32;
    size_t blind_len   = (size_t)M * 32;
    size_t scratch_len = (size_t)M * (N + 1) * 24 * sizeof(uint32_t);
    size_t out_len     = (size_t)M * 64;

    WGPUBuffer bufGens = make_buf(e, gens_len,
        (WGPUBufferUsage)(WGPUBufferUsage_Storage | WGPUBufferUsage_CopyDst));
    WGPUBuffer bufScalars = make_buf(e, scalars_len,
        (WGPUBufferUsage)(WGPUBufferUsage_Storage | WGPUBufferUsage_CopyDst));
    WGPUBuffer bufBlind = make_buf(e, blind_len,
        (WGPUBufferUsage)(WGPUBufferUsage_Storage | WGPUBufferUsage_CopyDst));
    WGPUBuffer bufScratch = make_buf(e, scratch_len,
        (WGPUBufferUsage)(WGPUBufferUsage_Storage));
    WGPUBuffer bufOut = make_buf(e, out_len,
        (WGPUBufferUsage)(WGPUBufferUsage_Storage | WGPUBufferUsage_CopySrc));
    WGPUBuffer bufDims = make_buf(e, 16,
        (WGPUBufferUsage)(WGPUBufferUsage_Uniform | WGPUBufferUsage_CopyDst));
    WGPUBuffer bufRead = make_buf(e, out_len,
        (WGPUBufferUsage)(WGPUBufferUsage_MapRead | WGPUBufferUsage_CopyDst));
    if (!bufGens || !bufScalars || !bufBlind || !bufScratch ||
        !bufOut  || !bufDims    || !bufRead) {
        return -2;
    }

    wgpuQueueWriteBuffer(e.queue, bufGens,    0, gens_be,      gens_len);
    wgpuQueueWriteBuffer(e.queue, bufScalars, 0, scalars_be,   scalars_len);
    wgpuQueueWriteBuffer(e.queue, bufBlind,   0, blindings_be, blind_len);
    uint32_t dimVals[4] = { M, N, 0, 0 };
    wgpuQueueWriteBuffer(e.queue, bufDims, 0, dimVals, 16);

    // Stage 1: pipeline + bind group 0 ------------------------------------
    WGPUComputePipelineDescriptor cpd1{};
    cpd1.compute.module = e.module;
    cpd1.compute.entryPoint = sv("pedersen_pointmul");
    cpd1.label = sv("pedersen_pointmul");
    WGPUComputePipeline pso1 = wgpuDeviceCreateComputePipeline(e.device, &cpd1);
    if (!pso1) return -3;

    WGPUBindGroupLayout bgl1 = wgpuComputePipelineGetBindGroupLayout(pso1, 0);
    WGPUBindGroupEntry bge1[5] = {};
    bge1[0].binding = 0; bge1[0].buffer = bufGens;    bge1[0].size = gens_len;
    bge1[1].binding = 1; bge1[1].buffer = bufScalars; bge1[1].size = scalars_len;
    bge1[2].binding = 2; bge1[2].buffer = bufBlind;   bge1[2].size = blind_len;
    bge1[3].binding = 3; bge1[3].buffer = bufScratch; bge1[3].size = scratch_len;
    bge1[4].binding = 4; bge1[4].buffer = bufDims;    bge1[4].size = 16;
    WGPUBindGroupDescriptor bgd1{};
    bgd1.layout = bgl1; bgd1.entryCount = 5; bgd1.entries = bge1;
    WGPUBindGroup bg1 = wgpuDeviceCreateBindGroup(e.device, &bgd1);
    if (!bg1) return -4;

    // Stage 2: pipeline + bind group 1 ------------------------------------
    WGPUComputePipelineDescriptor cpd2{};
    cpd2.compute.module = e.module;
    cpd2.compute.entryPoint = sv("pedersen_reduce_add");
    cpd2.label = sv("pedersen_reduce_add");
    WGPUComputePipeline pso2 = wgpuDeviceCreateComputePipeline(e.device, &cpd2);
    if (!pso2) return -5;

    WGPUBindGroupLayout bgl2 = wgpuComputePipelineGetBindGroupLayout(pso2, 1);
    WGPUBindGroupEntry bge2[3] = {};
    bge2[0].binding = 0; bge2[0].buffer = bufScratch; bge2[0].size = scratch_len;
    bge2[1].binding = 1; bge2[1].buffer = bufOut;     bge2[1].size = out_len;
    bge2[2].binding = 2; bge2[2].buffer = bufDims;    bge2[2].size = 16;
    WGPUBindGroupDescriptor bgd2{};
    bgd2.layout = bgl2; bgd2.entryCount = 3; bgd2.entries = bge2;
    WGPUBindGroup bg2 = wgpuDeviceCreateBindGroup(e.device, &bgd2);
    if (!bg2) return -6;

    // Encode + dispatch both stages in one command buffer.
    WGPUCommandEncoderDescriptor ced{};
    WGPUCommandEncoder ce = wgpuDeviceCreateCommandEncoder(e.device, &ced);

    {
        WGPUComputePassDescriptor cpd{};
        WGPUComputePassEncoder cpe = wgpuCommandEncoderBeginComputePass(ce, &cpd);
        wgpuComputePassEncoderSetPipeline(cpe, pso1);
        wgpuComputePassEncoderSetBindGroup(cpe, 0, bg1, 0, nullptr);
        uint32_t total1 = M * (N + 1);
        uint32_t wg1 = (total1 + 63) / 64;
        wgpuComputePassEncoderDispatchWorkgroups(cpe, wg1, 1, 1);
        wgpuComputePassEncoderEnd(cpe);
        wgpuComputePassEncoderRelease(cpe);
    }
    {
        WGPUComputePassDescriptor cpd{};
        WGPUComputePassEncoder cpe = wgpuCommandEncoderBeginComputePass(ce, &cpd);
        wgpuComputePassEncoderSetPipeline(cpe, pso2);
        wgpuComputePassEncoderSetBindGroup(cpe, 1, bg2, 0, nullptr);
        uint32_t wg2 = (M + 31) / 32;
        wgpuComputePassEncoderDispatchWorkgroups(cpe, wg2, 1, 1);
        wgpuComputePassEncoderEnd(cpe);
        wgpuComputePassEncoderRelease(cpe);
    }

    wgpuCommandEncoderCopyBufferToBuffer(ce, bufOut, 0, bufRead, 0, out_len);
    WGPUCommandBufferDescriptor cbd{};
    WGPUCommandBuffer cmd = wgpuCommandEncoderFinish(ce, &cbd);
    wgpuQueueSubmit(e.queue, 1, &cmd);

    int rc = 0;
    if (!wait_map(e.instance, e.device, bufRead, WGPUMapMode_Read, 0, out_len)) {
        rc = -7;
    } else {
        const void* mapped = wgpuBufferGetConstMappedRange(bufRead, 0, out_len);
        std::memcpy(out_be, mapped, out_len);
        wgpuBufferUnmap(bufRead);
    }

    wgpuCommandEncoderRelease(ce);
    wgpuCommandBufferRelease(cmd);
    wgpuBindGroupRelease(bg1);     wgpuBindGroupRelease(bg2);
    wgpuBindGroupLayoutRelease(bgl1); wgpuBindGroupLayoutRelease(bgl2);
    wgpuComputePipelineRelease(pso1); wgpuComputePipelineRelease(pso2);
    wgpuBufferRelease(bufGens);    wgpuBufferRelease(bufScalars);
    wgpuBufferRelease(bufBlind);   wgpuBufferRelease(bufScratch);
    wgpuBufferRelease(bufOut);     wgpuBufferRelease(bufDims);
    wgpuBufferRelease(bufRead);
    return rc;
}

#else // KINET_PEDERSEN_HAS_WEBGPU not defined: stub mode

extern "C" int kinet_pedersen_wgpu_available(void) { return 0; }
extern "C" int pedersen_batch_wgpu(
    const uint8_t*, const uint8_t*, const uint8_t*,
    uint32_t, uint32_t, uint8_t*) { return -1; }

#endif
