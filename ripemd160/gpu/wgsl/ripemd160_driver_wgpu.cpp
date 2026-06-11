// WebGPU/WGSL host driver for batched RIPEMD-160 (Dobbertin et al. 1996).
//
// Mirrors the Metal/CUDA layout: caller supplies a packed input arena, an
// (offset, length) descriptor per input, and a contiguous 20-byte stride
// output buffer.
//
// Build flags:
//   * KINET_RIPEMD160_HAS_WEBGPU=1      - Dawn or wgpu-native runtime found
//   * KINET_RIPEMD160_HAS_WGPU_NATIVE=1 - wgpu-native specifically (gives
//                                       wgpuDevicePoll for synchronous waits)

#include "ripemd160_driver_wgpu.h"

#if defined(KINET_RIPEMD160_HAS_WEBGPU)

#include <webgpu.h>
#if defined(KINET_RIPEMD160_HAS_WGPU_NATIVE)
#  include <wgpu.h>
#endif

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// WGSL source concatenated into a string literal by CMake.
#include "ripemd160_wgsl_sources.h"

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
#if defined(KINET_RIPEMD160_HAS_WGPU_NATIVE)
    if (dev) wgpuDevicePoll(dev, /*wait=*/WGPU_TRUE, nullptr);
#else
    (void)dev;
#endif
}

bool wait_map(WGPUInstance inst, WGPUDevice dev, WGPUBuffer buf,
              WGPUMapMode mode, size_t off, size_t size) {
    struct State {
        std::atomic<bool> done{false};
        WGPUMapAsyncStatus status{WGPUMapAsyncStatus_Error};
    } s;
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
    WGPUInstance        instance{nullptr};
    WGPUAdapter         adapter{nullptr};
    WGPUDevice          device{nullptr};
    WGPUQueue           queue{nullptr};
    WGPUShaderModule    module{nullptr};
    WGPUComputePipeline pipeline{nullptr};
    bool                initialized{false};
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
    if (!as.ad) { std::fprintf(stderr, "wgpu: no adapter\n"); return false; }
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
    if (!ds.dev) { std::fprintf(stderr, "wgpu: no device\n"); return false; }
    e.device = ds.dev;
    e.queue  = wgpuDeviceGetQueue(e.device);
    if (!e.queue) return false;

    WGPUShaderSourceWGSL wgsl{};
    wgsl.chain.sType = WGPUSType_ShaderSourceWGSL;
    wgsl.code = sv(kRIPEMD160_WGSL_Source);

    WGPUShaderModuleDescriptor smd{};
    smd.nextInChain = &wgsl.chain;
    smd.label = sv("ripemd160");
    e.module = wgpuDeviceCreateShaderModule(e.device, &smd);
    if (!e.module) {
        std::fprintf(stderr, "wgpu: ripemd160 shader compile failed\n");
        return false;
    }

    WGPUComputePipelineDescriptor cpd{};
    cpd.compute.module = e.module;
    cpd.compute.entryPoint = sv("ripemd160_batch");
    cpd.label = sv("ripemd160_batch");
    e.pipeline = wgpuDeviceCreateComputePipeline(e.device, &cpd);
    if (!e.pipeline) {
        std::fprintf(stderr, "wgpu: ripemd160 pipeline failed\n");
        return false;
    }

    e.initialized = true;
    return true;
}

WGPUBuffer make_buf(Engine& e, size_t size, WGPUBufferUsage usage) {
    WGPUBufferDescriptor bd{};
    bd.size = (size + 3) & ~size_t(3);
    if (bd.size == 0) bd.size = 4;
    bd.usage = usage;
    return wgpuDeviceCreateBuffer(e.device, &bd);
}

} // namespace

extern "C" int kinet_ripemd160_wgpu_available(void) {
    return init_engine() ? 1 : 0;
}

extern "C" int ripemd160_batch_wgpu(
    const uint8_t*  inputs_arena,
    size_t          inputs_arena_len,
    const uint32_t* input_offsets,
    const uint32_t* input_lens,
    size_t          n,
    uint8_t*        outputs_arena) {

    if (n == 0) return 0;
    if (!input_offsets || !input_lens || !outputs_arena) return -1;
    if (!init_engine()) return -2;
    Engine& e = engine();

    // Pack the inputs descriptor (offset, length) into a u32 array of
    // length 2*n. Pad inputs_arena up to a 4-byte boundary for the data
    // buffer because WGSL reads it as array<u32>.
    std::vector<uint32_t> desc(n * 2);
    for (size_t i = 0; i < n; ++i) {
        desc[i * 2 + 0] = input_offsets[i];
        desc[i * 2 + 1] = input_lens[i];
    }

    size_t data_bytes = (inputs_arena_len + 3) & ~size_t(3);
    if (data_bytes == 0) data_bytes = 4;
    std::vector<uint8_t> data_padded(data_bytes, 0);
    if (inputs_arena_len) std::memcpy(data_padded.data(), inputs_arena,
                                       inputs_arena_len);

    size_t out_words = n * 5;             // 20 bytes per hash = 5 u32 words
    size_t out_bytes = out_words * 4;

    WGPUBuffer buf_desc = make_buf(e, desc.size() * sizeof(uint32_t),
                                   WGPUBufferUsage_Storage | WGPUBufferUsage_CopyDst);
    WGPUBuffer buf_data = make_buf(e, data_bytes,
                                   WGPUBufferUsage_Storage | WGPUBufferUsage_CopyDst);
    WGPUBuffer buf_out  = make_buf(e, out_bytes,
                                   WGPUBufferUsage_Storage | WGPUBufferUsage_CopySrc);
    WGPUBuffer buf_read = make_buf(e, out_bytes,
                                   WGPUBufferUsage_MapRead | WGPUBufferUsage_CopyDst);
    if (!buf_desc || !buf_data || !buf_out || !buf_read) return -3;

    wgpuQueueWriteBuffer(e.queue, buf_desc, 0, desc.data(),
                         desc.size() * sizeof(uint32_t));
    wgpuQueueWriteBuffer(e.queue, buf_data, 0, data_padded.data(), data_bytes);

    WGPUBindGroupLayout bgl = wgpuComputePipelineGetBindGroupLayout(e.pipeline, 0);
    WGPUBindGroupEntry bge[3] = {};
    bge[0].binding = 0; bge[0].buffer = buf_desc; bge[0].size = desc.size() * sizeof(uint32_t);
    bge[1].binding = 1; bge[1].buffer = buf_data; bge[1].size = data_bytes;
    bge[2].binding = 2; bge[2].buffer = buf_out;  bge[2].size = out_bytes;
    WGPUBindGroupDescriptor bgd{};
    bgd.layout = bgl;
    bgd.entryCount = 3;
    bgd.entries = bge;
    WGPUBindGroup bg = wgpuDeviceCreateBindGroup(e.device, &bgd);
    if (!bg) return -4;

    WGPUCommandEncoderDescriptor ced{};
    WGPUCommandEncoder ce = wgpuDeviceCreateCommandEncoder(e.device, &ced);
    WGPUComputePassDescriptor cpd2{};
    WGPUComputePassEncoder cpe = wgpuCommandEncoderBeginComputePass(ce, &cpd2);
    wgpuComputePassEncoderSetPipeline(cpe, e.pipeline);
    wgpuComputePassEncoderSetBindGroup(cpe, 0, bg, 0, nullptr);
    uint32_t wg = uint32_t((n + 63) / 64);
    wgpuComputePassEncoderDispatchWorkgroups(cpe, wg, 1, 1);
    wgpuComputePassEncoderEnd(cpe);

    wgpuCommandEncoderCopyBufferToBuffer(ce, buf_out, 0, buf_read, 0, out_bytes);
    WGPUCommandBufferDescriptor cbd{};
    WGPUCommandBuffer cmd = wgpuCommandEncoderFinish(ce, &cbd);
    wgpuQueueSubmit(e.queue, 1, &cmd);

    if (!wait_map(e.instance, e.device, buf_read, WGPUMapMode_Read, 0, out_bytes)) {
        std::fprintf(stderr, "wgpu: ripemd160 readback map failed\n");
        return -5;
    }
    const void* mapped = wgpuBufferGetConstMappedRange(buf_read, 0, out_bytes);
    std::memcpy(outputs_arena, mapped, n * 20);
    wgpuBufferUnmap(buf_read);

    wgpuComputePassEncoderRelease(cpe);
    wgpuCommandEncoderRelease(ce);
    wgpuCommandBufferRelease(cmd);
    wgpuBindGroupRelease(bg);
    wgpuBindGroupLayoutRelease(bgl);
    wgpuBufferRelease(buf_desc);
    wgpuBufferRelease(buf_data);
    wgpuBufferRelease(buf_out);
    wgpuBufferRelease(buf_read);
    return 0;
}

#else // KINET_RIPEMD160_HAS_WEBGPU not defined: stub mode

extern "C" int kinet_ripemd160_wgpu_available(void) { return 0; }
extern "C" int ripemd160_batch_wgpu(
    const uint8_t*, size_t,
    const uint32_t*, const uint32_t*,
    size_t, uint8_t*) {
    return -1;
}

#endif
