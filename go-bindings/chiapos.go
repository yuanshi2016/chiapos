package go_bindings

/********************************************************
 * Description : chiapos wrapper
 * Author      : Gwkang
 * Email       : 975500206@qq.com
 * Version     : 1.0
 * History     :
 * Copyright(C): 2021
 ********************************************************/

/*
#cgo CFLAGS: -I.
#cgo CXXFLAGS: -I. -std=c++17
#cgo linux LDFLAGS: -L${SRCDIR} -lchiapos -lfse -luint128 -lm -lstdc++ -lstdc++fs
#include <stdlib.h>
#include "chiapos.h"
*/
import "C"
import (
	"runtime"
	"unsafe"
)

const kIdLen = 32

func CreatePlotDisk(tmp_dirname, tmp2_dirname, final_dirname, filename string,
	k uint8, memo []byte, id []byte, buf_megabytes, num_buckets uint32,
	stripe_size uint64, num_threads uint8, nobitfield bool) bool {

	ctmp_dirname := C.CString(tmp_dirname)
	defer C.free(unsafe.Pointer(ctmp_dirname))

	ctmp2_dirname := C.CString(tmp2_dirname)
	defer C.free(unsafe.Pointer(ctmp2_dirname))

	cfinal_dirname := C.CString(final_dirname)
	defer C.free(unsafe.Pointer(cfinal_dirname))

	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))

	ret := C.CreatePlotDisk(ctmp_dirname, ctmp2_dirname, cfinal_dirname, cfilename,
		C.uint8_t(k), (*C.uint8_t)(unsafe.Pointer(&memo[0])), C.uint32_t(len(memo)),
		(*C.uint8_t)(unsafe.Pointer(&id[0])), C.uint32_t(len(id)),
		C.uint32_t(buf_megabytes), C.uint32_t(num_buckets),
		C.uint64_t(stripe_size), C.uint8_t(num_threads), C.bool(nobitfield),
	)
	return bool(ret)
}

type DiskProver struct {
	ptr C.PDiskProver
}

func CreateDiskProver(filename string) *DiskProver {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	pdp := C.CreateDiskProver(cfilename)
	if pdp == C.PDiskProver(unsafe.Pointer(uintptr(0))) {
		return nil
	}
	dp := &DiskProver{ptr: pdp}
	runtime.SetFinalizer(dp, func(dp *DiskProver) {
		C.FreeDiskProver(dp.ptr)
	})
	return dp
}

func (dp *DiskProver) GetMemo() []byte {
	memsize := uint32(C.DiskProverGetMemoSize(dp.ptr))
	ret := make([]byte, memsize)
	C.DiskProverGetMemo(dp.ptr, (*C.uchar)(unsafe.Pointer(&ret[0])))
	return ret
}

func (dp *DiskProver) GetId() []byte {
	id := make([]byte, kIdLen)
	C.DiskProverGetId(dp.ptr, (*C.uchar)(unsafe.Pointer(&id[0])))
	return id
}

func (dp *DiskProver) GetSize() uint32  {
	return uint32(C.DiskProverGetSize(dp.ptr))
}

func (dp *DiskProver) GetFilename() string {
	return C.GoString(C.DiskProverGetFilename(dp.ptr))
}

func (dp *DiskProver) GetQualitiesForChallenge(challenge []byte) [][]byte {
	if (len(challenge) != kIdLen) {
		return nil
	}

	var qualities **C.uint8_t
	var qualities_num C.uint32_t
	C.DiskProverGetQualitiesForChallenge(dp.ptr, (*C.uchar)(unsafe.Pointer(&challenge[0])), &qualities, &qualities_num)

	if qualities_num == 0 {
		return nil
	}

	ret := make([][]byte, int(qualities_num))
	for i:=0; i < int(qualities_num); i++ {
		qualities_pos := (**C.uint8_t)(unsafe.Pointer(uintptr(unsafe.Pointer(qualities)) + uintptr(i * int(unsafe.Sizeof(*qualities)))))
		ret[i] = C.GoBytes(unsafe.Pointer(*qualities_pos), C.int(kIdLen))
		C.free(unsafe.Pointer(*qualities_pos))
	}
	C.free(unsafe.Pointer(qualities))
	return ret
}

func (dp *DiskProver) GetFullProof(challenge []byte, index uint32) []byte {
	var proof_buf *C.uint8_t
	var proof_size C.uint32_t

	C.DiskProverGetFullProof(dp.ptr, (*C.uchar)(unsafe.Pointer(&challenge[0])), C.uint32_t(index), &proof_buf, &proof_size)
	if uint32(proof_size) == 0 {
		return nil
	}
	ret := C.GoBytes(unsafe.Pointer(proof_buf), C.int(proof_size))
	C.free(unsafe.Pointer(proof_buf))
	return ret
}

func ValidateProof(id []byte, k uint8, challenge []byte, proof []byte) []byte {
	quality := C.ValidateProof((*C.uchar)(unsafe.Pointer(&id[0])), C.uchar(k), (*C.uchar)(unsafe.Pointer(&challenge[0])),
		(*C.uchar)(unsafe.Pointer(&proof[0])), C.uint16_t(len(proof)))
	defer C.free(unsafe.Pointer(quality))
	return C.GoBytes(unsafe.Pointer(quality), C.int(32))
}
