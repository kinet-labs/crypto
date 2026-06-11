// WebGPU/WGSL host driver for batched AEAD ciphers (ChaCha20-Poly1305 +
// AES-256-GCM). Builds against wgpu-native (or Dawn). Output is byte-equal
// to the CPU body in cpp/aead.cpp.

#include "aead_driver_wgpu.h"

#if defined(KINET_AEAD_HAS_WEBGPU)

#include <webgpu.h>
#if defined(KINET_AEAD_HAS_WGPU_NATIVE)
#  include <wgpu.h>
#endif

#include "aead_wgsl_sources.h"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

WGPUStringView sv(const char* s) {
    WGPUStringView v{};
    v.data = s;
    v.length = (s == nullptr) ? 0 : std::strlen(s);
    return v;
}

void drain(WGPUInstance inst, WGPUDevice dev) {
    if (inst) wgpuInstanceProcessEvents(inst);
#if defined(KINET_AEAD_HAS_WGPU_NATIVE)
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
    for (int spin = 0; spin < 8192; ++spin) {
        if (s.done.load(std::memory_order_acquire)) break;
        drain(inst, dev);
    }
    return s.done.load() && s.status == WGPUMapAsyncStatus_Success;
}

struct Engine {
    WGPUInstance       instance{nullptr};
    WGPUAdapter        adapter{nullptr};
    WGPUDevice         device{nullptr};
    WGPUQueue          queue{nullptr};
    WGPUShaderModule   chacha_module{nullptr};
    WGPUShaderModule   aes_module{nullptr};
    WGPUComputePipeline chacha_pipe{nullptr};
    WGPUComputePipeline aes_pipe{nullptr};
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
    for (int spin = 0; spin < 8192; ++spin) {
        if (as.done.load(std::memory_order_acquire)) break;
        wgpuInstanceProcessEvents(e.instance);
    }
    if (!as.ad) {
        std::fprintf(stderr, "aead/wgpu: no adapter\n");
        return false;
    }
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
    for (int spin = 0; spin < 8192; ++spin) {
        if (ds.done.load(std::memory_order_acquire)) break;
        wgpuInstanceProcessEvents(e.instance);
    }
    if (!ds.dev) {
        std::fprintf(stderr, "aead/wgpu: no device\n");
        return false;
    }
    e.device = ds.dev;
    e.queue  = wgpuDeviceGetQueue(e.device);
    if (!e.queue) return false;

    auto compile = [&](const char* src, const char* label) -> WGPUShaderModule {
        WGPUShaderSourceWGSL wgsl{};
        wgsl.chain.sType = WGPUSType_ShaderSourceWGSL;
        wgsl.code = sv(src);
        WGPUShaderModuleDescriptor smd{};
        smd.nextInChain = &wgsl.chain;
        smd.label = sv(label);
        return wgpuDeviceCreateShaderModule(e.device, &smd);
    };

    e.chacha_module = compile(kAEAD_WGSL_ChaCha20Poly1305, "aead_chacha20_poly1305");
    if (!e.chacha_module) {
        std::fprintf(stderr, "aead/wgpu: chacha20_poly1305 compile failed\n");
        return false;
    }
    e.aes_module = compile(kAEAD_WGSL_AesGcm, "aead_aes_256_gcm");
    if (!e.aes_module) {
        std::fprintf(stderr, "aead/wgpu: aes_gcm compile failed\n");
        return false;
    }

    auto make_pipe = [&](WGPUShaderModule mod, const char* entry) -> WGPUComputePipeline {
        WGPUComputePipelineDescriptor cpd{};
        cpd.compute.module = mod;
        cpd.compute.entryPoint = sv(entry);
        cpd.label = sv(entry);
        return wgpuDeviceCreateComputePipeline(e.device, &cpd);
    };
    e.chacha_pipe = make_pipe(e.chacha_module, "chacha20_poly1305_jobs");
    if (!e.chacha_pipe) {
        std::fprintf(stderr, "aead/wgpu: chacha pipeline failed\n");
        return false;
    }
    e.aes_pipe = make_pipe(e.aes_module, "aes_gcm_jobs");
    if (!e.aes_pipe) {
        std::fprintf(stderr, "aead/wgpu: aes pipeline failed\n");
        return false;
    }

    e.initialized = true;
    return true;
}

WGPUBuffer make_buf(Engine& e, size_t bytes, WGPUBufferUsage usage) {
    WGPUBufferDescriptor bd{};
    // Round up to 4 (WGSL storage alignment).
    bd.size = (bytes + 3) & ~size_t(3);
    if (bd.size == 0) bd.size = 4;
    bd.usage = usage;
    return wgpuDeviceCreateBuffer(e.device, &bd);
}

// One unified dispatch path. The caller picks the pipeline and supplies the
// job-record stride (same for both AEAD ciphers: 8 * uint32_t = 32 bytes).
int dispatch_aead(WGPUComputePipeline pipeline,
                  const uint8_t* keys,         size_t keys_bytes,
                  const uint8_t* nonces,       size_t nonces_bytes,
                  const uint8_t* inputs_arena, size_t inputs_bytes,
                  const void*    jobs,         size_t jobs_bytes,
                  uint8_t*       outputs,      size_t outputs_bytes,
                  uint32_t       n) {
    Engine& e = engine();

    WGPUBuffer buf_jobs   = make_buf(e, jobs_bytes,   WGPUBufferUsage_Storage | WGPUBufferUsage_CopyDst);
    WGPUBuffer buf_keys   = make_buf(e, keys_bytes,   WGPUBufferUsage_Storage | WGPUBufferUsage_CopyDst);
    WGPUBuffer buf_nonces = make_buf(e, nonces_bytes, WGPUBufferUsage_Storage | WGPUBufferUsage_CopyDst);
    WGPUBuffer buf_in     = make_buf(e, inputs_bytes ? inputs_bytes : 4, WGPUBufferUsage_Storage | WGPUBufferUsage_CopyDst);
    WGPUBuffer buf_out    = make_buf(e, outputs_bytes, WGPUBufferUsage_Storage | WGPUBufferUsage_CopySrc | WGPUBufferUsage_CopyDst);
    WGPUBuffer buf_params = make_buf(e, 16, WGPUBufferUsage_Uniform | WGPUBufferUsage_CopyDst);
    WGPUBuffer buf_read   = make_buf(e, outputs_bytes, WGPUBufferUsage_MapRead | WGPUBufferUsage_CopyDst);
    if (!buf_jobs || !buf_keys || !buf_nonces || !buf_in || !buf_out ||
        !buf_params || !buf_read) {
        return -3;
    }

    // wgpuQueueWriteBuffer requires copy size multiple of 4. Round each
    // payload up by copying into a 4-aligned staging vector.
    auto padded = [](const uint8_t* src, size_t n) {
        size_t up = (n + 3) & ~size_t(3);
        std::vector<uint8_t> v(up, 0);
        if (n > 0 && src != nullptr) std::memcpy(v.data(), src, n);
        return v;
    };
    {
        auto j = padded(static_cast<const uint8_t*>(jobs), jobs_bytes);
        wgpuQueueWriteBuffer(e.queue, buf_jobs, 0, j.data(), j.size());
    }
    {
        auto k = padded(keys, keys_bytes);
        wgpuQueueWriteBuffer(e.queue, buf_keys, 0, k.data(), k.size());
    }
    {
        auto n_pad = padded(nonces, nonces_bytes);
        wgpuQueueWriteBuffer(e.queue, buf_nonces, 0, n_pad.data(), n_pad.size());
    }
    if (inputs_bytes > 0) {
        auto in_pad = padded(inputs_arena, inputs_bytes);
        wgpuQueueWriteBuffer(e.queue, buf_in, 0, in_pad.data(), in_pad.size());
    } else {
        uint32_t z = 0;
        wgpuQueueWriteBuffer(e.queue, buf_in, 0, &z, 4);
    }
    // Zero outputs (matches Metal driver: deterministic unused regions).
    {
        size_t up = (outputs_bytes + 3) & ~size_t(3);
        std::vector<uint8_t> zeros(up, 0);
        wgpuQueueWriteBuffer(e.queue, buf_out, 0, zeros.data(), up);
    }
    uint32_t params[4] = { n, 0, 0, 0 };
    wgpuQueueWriteBuffer(e.queue, buf_params, 0, params, 16);

    auto align4 = [](size_t n) { return (n + 3) & ~size_t(3); };
    WGPUBindGroupLayout bgl = wgpuComputePipelineGetBindGroupLayout(pipeline, 0);
    WGPUBindGroupEntry bge[6] = {};
    bge[0].binding = 0; bge[0].buffer = buf_jobs;   bge[0].size = align4(jobs_bytes);
    bge[1].binding = 1; bge[1].buffer = buf_keys;   bge[1].size = align4(keys_bytes);
    bge[2].binding = 2; bge[2].buffer = buf_nonces; bge[2].size = align4(nonces_bytes);
    bge[3].binding = 3; bge[3].buffer = buf_in;     bge[3].size = align4(inputs_bytes ? inputs_bytes : 4);
    bge[4].binding = 4; bge[4].buffer = buf_out;    bge[4].size = align4(outputs_bytes);
    bge[5].binding = 5; bge[5].buffer = buf_params; bge[5].size = 16;
    WGPUBindGroupDescriptor bgd{};
    bgd.layout = bgl;
    bgd.entryCount = 6;
    bgd.entries = bge;
    WGPUBindGroup bg = wgpuDeviceCreateBindGroup(e.device, &bgd);
    if (!bg) return -4;

    WGPUCommandEncoderDescriptor ced{};
    WGPUCommandEncoder ce = wgpuDeviceCreateCommandEncoder(e.device, &ced);
    WGPUComputePassDescriptor cpd{};
    WGPUComputePassEncoder cpe = wgpuCommandEncoderBeginComputePass(ce, &cpd);
    wgpuComputePassEncoderSetPipeline(cpe, pipeline);
    wgpuComputePassEncoderSetBindGroup(cpe, 0, bg, 0, nullptr);
    // Workgroup size = 64; dispatch ceil(n / 64) groups.
    const uint32_t groups = (n + 63u) / 64u;
    wgpuComputePassEncoderDispatchWorkgroups(cpe, groups, 1, 1);
    wgpuComputePassEncoderEnd(cpe);
    const size_t out_pad = (outputs_bytes + 3) & ~size_t(3);
    wgpuCommandEncoderCopyBufferToBuffer(ce, buf_out, 0, buf_read, 0, out_pad);
    WGPUCommandBufferDescriptor cbd{};
    WGPUCommandBuffer cmd = wgpuCommandEncoderFinish(ce, &cbd);
    wgpuQueueSubmit(e.queue, 1, &cmd);

    if (!wait_map(e.instance, e.device, buf_read, WGPUMapMode_Read, 0, out_pad)) {
        return -5;
    }
    const void* mapped = wgpuBufferGetConstMappedRange(buf_read, 0, out_pad);
    std::memcpy(outputs, mapped, outputs_bytes);
    wgpuBufferUnmap(buf_read);

    wgpuComputePassEncoderRelease(cpe);
    wgpuCommandEncoderRelease(ce);
    wgpuCommandBufferRelease(cmd);
    wgpuBindGroupRelease(bg);
    wgpuBindGroupLayoutRelease(bgl);
    wgpuBufferRelease(buf_jobs);
    wgpuBufferRelease(buf_keys);
    wgpuBufferRelease(buf_nonces);
    wgpuBufferRelease(buf_in);
    wgpuBufferRelease(buf_out);
    wgpuBufferRelease(buf_params);
    wgpuBufferRelease(buf_read);

    return 0;
}

}  // namespace

extern "C" int kinet_aead_wgpu_available(void) {
    return init_engine() ? 1 : 0;
}

extern "C" int aead_chacha20poly1305_batch_wgpu(
    const uint8_t* keys, const uint8_t* nonces,
    const uint8_t* inputs_arena, size_t inputs_arena_len,
    const void* jobs, size_t n,
    uint8_t* outputs_arena, size_t outputs_arena_len) {
    if (n == 0) return 0;
    if (!keys || !nonces || !jobs || !outputs_arena) return -1;
    if (!init_engine()) return -2;
    return dispatch_aead(engine().chacha_pipe,
                         keys,   n * 32,
                         nonces, n * 12,
                         inputs_arena, inputs_arena_len,
                         jobs,   n * 32,
                         outputs_arena, outputs_arena_len,
                         (uint32_t)n);
}

extern "C" int aead_aes_256_gcm_batch_wgpu(
    const uint8_t* keys, const uint8_t* ivs,
    const uint8_t* inputs_arena, size_t inputs_arena_len,
    const void* jobs, size_t n,
    uint8_t* outputs_arena, size_t outputs_arena_len) {
    if (n == 0) return 0;
    if (!keys || !ivs || !jobs || !outputs_arena) return -1;
    if (!init_engine()) return -2;
    return dispatch_aead(engine().aes_pipe,
                         keys,   n * 32,
                         ivs,    n * 12,
                         inputs_arena, inputs_arena_len,
                         jobs,   n * 32,
                         outputs_arena, outputs_arena_len,
                         (uint32_t)n);
}

#else  // KINET_AEAD_HAS_WEBGPU not defined

extern "C" int kinet_aead_wgpu_available(void) { return 0; }
extern "C" int aead_chacha20poly1305_batch_wgpu(
    const uint8_t*, const uint8_t*, const uint8_t*, size_t,
    const void*, size_t, uint8_t*, size_t) { return -1; }
extern "C" int aead_aes_256_gcm_batch_wgpu(
    const uint8_t*, const uint8_t*, const uint8_t*, size_t,
    const void*, size_t, uint8_t*, size_t) { return -1; }

#endif
