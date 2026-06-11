// CUDA Miller-loop kernels — same kernel split as Metal (host orchestrates).

#include "bls_miller.cuh"

extern "C" {

__global__ void k_miller_init(const MillerIn* __restrict__ in,
                               P2* __restrict__ T_buf,
                               Fp12* __restrict__ ret_buf,
                               Fp2* __restrict__ px2_buf,
                               unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;

    P2Aff Q = in[tid].Q;
    P1Aff P = in[tid].P;

    uint384 two_px = fp_add(P.X, P.X);
    Fp2 Px2;
    Px2.c0 = fp_neg(two_px);
    Px2.c1 = fp_add(P.Y, P.Y);
    px2_buf[tid] = Px2;

    P2 T;
    T.X = Q.X; T.Y = Q.Y; T.Z = fp2_one();

    Line L0 = line_dbl_dev(T, T);
    L0      = line_by_Px2_dev(L0, Px2.c0, Px2.c1);
    Fp12 ret = unpack_initial_line_dev(L0);

    T_buf[tid]   = T;
    ret_buf[tid] = ret;
}

__global__ void k_miller_add_T_and_line(const MillerIn* __restrict__ in,
                                         P2* __restrict__ T_buf,
                                         LineBuf* __restrict__ line_buf,
                                         const Fp2* __restrict__ px2_buf,
                                         unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    P2 T    = T_buf[tid];
    Fp2 Px2 = px2_buf[tid];

    Line L = line_add_dev(T, T, in[tid].Q);
    L      = line_by_Px2_dev(L, Px2.c0, Px2.c1);

    T_buf[tid]    = T;
    LineBuf lb;   lb.x = L.x;   lb.y = L.y;   lb.z = L.z;
    line_buf[tid] = lb;
}

__global__ void k_miller_dbl_T_and_line(P2* __restrict__ T_buf,
                                         LineBuf* __restrict__ line_buf,
                                         const Fp2* __restrict__ px2_buf,
                                         unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    P2 T   = T_buf[tid];
    Fp2 Px2 = px2_buf[tid];

    Line Ld = line_dbl_dev(T, T);
    Ld      = line_by_Px2_dev(Ld, Px2.c0, Px2.c1);

    T_buf[tid]      = T;
    LineBuf lb;  lb.x = Ld.x;  lb.y = Ld.y;  lb.z = Ld.z;
    line_buf[tid]   = lb;
}

__global__ void k_miller_sqr_ret(Fp12* __restrict__ ret_buf, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    ret_buf[tid] = fp12_sqr(ret_buf[tid]);
}

__global__ void k_miller_fold_line(Fp12* __restrict__ ret_buf,
                                    const LineBuf* __restrict__ line_buf,
                                    unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    LineBuf lb = line_buf[tid];
    Line L; L.x = lb.x; L.y = lb.y; L.z = lb.z;
    ret_buf[tid] = fp12_mul_by_xy00z0_dev(ret_buf[tid], L);
}

__global__ void k_miller_finalize(Fp12* __restrict__ ret_buf,
                                   Fp12* __restrict__ out, unsigned n) {
    unsigned tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    out[tid] = fp12_conj(ret_buf[tid]);
}

} // extern "C"
