//go:build darwin && cgo
// +build darwin,cgo

package cgo

/*
#cgo CFLAGS: -I../metal
#cgo LDFLAGS: -framework Metal -framework MetalKit -framework Foundation -L${SRCDIR}/../metal -lmetal_zk

#include "metal_zk.h"
*/
import "C"
import (
	"errors"
	"sync"
	"unsafe"
)

var (
	zkContext   *C.MetalZKContext
	initOnce    sync.Once
	initErr     error

	ErrNotInitialized  = errors.New("ZK Metal context not initialized")
	ErrGPUNotAvailable = errors.New("Metal GPU not available")
	ErrOperationFailed = errors.New("ZK operation failed")
)

// InitZKMetal initializes the Metal ZK context
func InitZKMetal() error {
	initOnce.Do(func() {
		zkContext = C.metal_zk_create()
		if zkContext == nil {
			initErr = ErrGPUNotAvailable
		}
	})
	return initErr
}

// DestroyZKMetal destroys the Metal ZK context
func DestroyZKMetal() {
	if zkContext != nil {
		C.metal_zk_destroy(zkContext)
		zkContext = nil
	}
}

// Blake3Hash computes Blake3 hash using GPU
func Blake3Hash(data []byte) ([32]byte, error) {
	if zkContext == nil {
		if err := InitZKMetal(); err != nil {
			return [32]byte{}, err
		}
	}

	var result [32]byte
	ret := C.metal_blake3_hash(
		zkContext,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		(*C.uint8_t)(unsafe.Pointer(&result[0])),
	)

	if ret != 0 {
		return [32]byte{}, ErrOperationFailed
	}

	return result, nil
}

// Blake3HashXOF computes Blake3 extensible output
func Blake3HashXOF(data []byte, outputLen int) ([]byte, error) {
	if zkContext == nil {
		if err := InitZKMetal(); err != nil {
			return nil, err
		}
	}

	result := make([]byte, outputLen)
	ret := C.metal_blake3_xof(
		zkContext,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		(*C.uint8_t)(unsafe.Pointer(&result[0])),
		C.size_t(outputLen),
	)

	if ret != 0 {
		return nil, ErrOperationFailed
	}

	return result, nil
}

// Blake3MerkleRoot computes Merkle root using Blake3
func Blake3MerkleRoot(leaves [][]byte) ([32]byte, error) {
	if zkContext == nil {
		if err := InitZKMetal(); err != nil {
			return [32]byte{}, err
		}
	}

	if len(leaves) == 0 {
		return [32]byte{}, errors.New("empty leaves")
	}

	// Flatten leaves into contiguous memory
	leafData := make([]byte, len(leaves)*32)
	for i, leaf := range leaves {
		if len(leaf) != 32 {
			return [32]byte{}, errors.New("invalid leaf size")
		}
		copy(leafData[i*32:], leaf)
	}

	var result [32]byte
	ret := C.metal_blake3_merkle_root(
		zkContext,
		(*C.uint8_t)(unsafe.Pointer(&leafData[0])),
		C.size_t(len(leaves)),
		(*C.uint8_t)(unsafe.Pointer(&result[0])),
	)

	if ret != 0 {
		return [32]byte{}, ErrOperationFailed
	}

	return result, nil
}

// PedersenCommit creates a Pedersen commitment using GPU
func PedersenCommit(value, blindingFactor [32]byte) ([32]byte, error) {
	if zkContext == nil {
		if err := InitZKMetal(); err != nil {
			return [32]byte{}, err
		}
	}

	var result [32]byte
	ret := C.metal_pedersen_commit(
		zkContext,
		(*C.uint8_t)(unsafe.Pointer(&value[0])),
		(*C.uint8_t)(unsafe.Pointer(&blindingFactor[0])),
		(*C.uint8_t)(unsafe.Pointer(&result[0])),
	)

	if ret != 0 {
		return [32]byte{}, ErrOperationFailed
	}

	return result, nil
}

// PedersenVerify verifies a Pedersen commitment opening
func PedersenVerify(commitment, value, blindingFactor [32]byte) (bool, error) {
	if zkContext == nil {
		if err := InitZKMetal(); err != nil {
			return false, err
		}
	}

	ret := C.metal_pedersen_verify(
		zkContext,
		(*C.uint8_t)(unsafe.Pointer(&commitment[0])),
		(*C.uint8_t)(unsafe.Pointer(&value[0])),
		(*C.uint8_t)(unsafe.Pointer(&blindingFactor[0])),
	)

	return ret != 0, nil
}

// BN254G1Add performs G1 point addition
func BN254G1Add(a, b [64]byte) ([64]byte, error) {
	if zkContext == nil {
		if err := InitZKMetal(); err != nil {
			return [64]byte{}, err
		}
	}

	var result [64]byte
	ret := C.metal_bn254_g1_add(
		zkContext,
		(*C.uint8_t)(unsafe.Pointer(&a[0])),
		(*C.uint8_t)(unsafe.Pointer(&b[0])),
		(*C.uint8_t)(unsafe.Pointer(&result[0])),
	)

	if ret != 0 {
		return [64]byte{}, ErrOperationFailed
	}

	return result, nil
}

// BN254G1ScalarMul performs G1 scalar multiplication
func BN254G1ScalarMul(point [64]byte, scalar [32]byte) ([64]byte, error) {
	if zkContext == nil {
		if err := InitZKMetal(); err != nil {
			return [64]byte{}, err
		}
	}

	var result [64]byte
	ret := C.metal_bn254_g1_scalar_mul(
		zkContext,
		(*C.uint8_t)(unsafe.Pointer(&point[0])),
		(*C.uint8_t)(unsafe.Pointer(&scalar[0])),
		(*C.uint8_t)(unsafe.Pointer(&result[0])),
	)

	if ret != 0 {
		return [64]byte{}, ErrOperationFailed
	}

	return result, nil
}

// BN254MSM performs Multi-Scalar Multiplication
func BN254MSM(points [][64]byte, scalars [][32]byte) ([64]byte, error) {
	if zkContext == nil {
		if err := InitZKMetal(); err != nil {
			return [64]byte{}, err
		}
	}

	if len(points) != len(scalars) || len(points) == 0 {
		return [64]byte{}, errors.New("invalid input lengths")
	}

	// Flatten points and scalars
	pointData := make([]byte, len(points)*64)
	scalarData := make([]byte, len(scalars)*32)

	for i := range points {
		copy(pointData[i*64:], points[i][:])
		copy(scalarData[i*32:], scalars[i][:])
	}

	var result [64]byte
	ret := C.metal_bn254_msm(
		zkContext,
		(*C.uint8_t)(unsafe.Pointer(&pointData[0])),
		(*C.uint8_t)(unsafe.Pointer(&scalarData[0])),
		C.size_t(len(points)),
		(*C.uint8_t)(unsafe.Pointer(&result[0])),
	)

	if ret != 0 {
		return [64]byte{}, ErrOperationFailed
	}

	return result, nil
}

// KZGVerify verifies a KZG point evaluation proof
func KZGVerify(commitment, proof [48]byte, z, y [32]byte) (bool, error) {
	if zkContext == nil {
		if err := InitZKMetal(); err != nil {
			return false, err
		}
	}

	ret := C.metal_kzg_verify(
		zkContext,
		(*C.uint8_t)(unsafe.Pointer(&commitment[0])),
		(*C.uint8_t)(unsafe.Pointer(&z[0])),
		(*C.uint8_t)(unsafe.Pointer(&y[0])),
		(*C.uint8_t)(unsafe.Pointer(&proof[0])),
	)

	return ret != 0, nil
}

// KZGFFT performs FFT for polynomial operations
func KZGFFT(coefficients [][32]byte, inverse bool) ([][32]byte, error) {
	if zkContext == nil {
		if err := InitZKMetal(); err != nil {
			return nil, err
		}
	}

	n := len(coefficients)
	if n == 0 || (n&(n-1)) != 0 {
		return nil, errors.New("length must be power of 2")
	}

	// Flatten coefficients
	data := make([]byte, n*32)
	for i := range coefficients {
		copy(data[i*32:], coefficients[i][:])
	}

	inverseInt := C.int(0)
	if inverse {
		inverseInt = 1
	}

	ret := C.metal_kzg_fft(
		zkContext,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(n),
		inverseInt,
	)

	if ret != 0 {
		return nil, ErrOperationFailed
	}

	// Convert back to array
	result := make([][32]byte, n)
	for i := range result {
		copy(result[i][:], data[i*32:(i+1)*32])
	}

	return result, nil
}

// IsGPUAvailable checks if Metal GPU is available
func IsGPUAvailable() bool {
	return C.metal_zk_gpu_available() != 0
}

// GetGPUInfo returns GPU device information
func GetGPUInfo() (name string, memory uint64) {
	var nameBuf [256]C.char
	var mem C.uint64_t

	C.metal_zk_gpu_info(zkContext, &nameBuf[0], 256, &mem)

	return C.GoString(&nameBuf[0]), uint64(mem)
}
