package chiapos

/*
#cgo CFLAGS: -I.
#cgo CXXFLAGS: -I. -Iuint128_t -Ilib -Isrc -std=c++17
//#cgo LDFLAGS: -L${SRCDIR} -lchiapos -lfse -luint128 -lm -lstdc++
#cgo windows LDFLAGS: -L${SRCDIR}/include/windows -lchiapos -lfse -luint128 -lm -lstdc++
#cgo darwin LDFLAGS: -L${SRCDIR}/include/darwin -lchiapos -lfse -luint128 -lm -lc++
#cgo liunx LDFLAGS: -L${SRCDIR}/include/liunx -lchiapos -lfse -luint128 -lm -lc++
#include <stdio.h>
#include <stdlib.h>
#include "chiapos.h"
*/
import "C"
import (
	"ChiaYYPure/Util"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"unsafe"
)

const kIdLen = 32

type PlotInfo struct {
	FarmerPK      string `json:"farmerPK"`
	FileSize      int64  `json:"fileSize"`
	KSize         uint32 `json:"kSize"`
	LocalMasterSK string `json:"localMasterSK"`
	PlotID        string `json:"plotId"`
	PoolPK        string `json:"poolPK"`
	TablePointers string `json:"tablePointers"`
}

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
	ptr      C.PDiskProver
	filename string
}

func CreateDiskProver(filename string) *DiskProver {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	pdp := C.CreateDiskProver(cfilename)
	if pdp == C.PDiskProver(unsafe.Pointer(uintptr(0))) {
		return nil
	}
	dp := &DiskProver{ptr: pdp, filename: filename}
	runtime.SetFinalizer(dp, func(dp *DiskProver) {
		C.FreeDiskProver(dp.ptr)
	})
	return dp
}
func (dp *DiskProver) GetPlotInfo() *PlotInfo {
	return &PlotInfo{
		FarmerPK:      hex.EncodeToString(dp.GetFarmerPK()),
		FileSize:      Util.FileGetSize(dp.filename),
		KSize:         dp.GetSize(),
		LocalMasterSK: hex.EncodeToString(dp.GetLocalMasterSK()),
		PlotID:        hex.EncodeToString(dp.GetId()),
		PoolPK:        hex.EncodeToString(dp.GetPoolPK()),
		TablePointers: hex.EncodeToString(TableBase(dp.GetTable(), true)),
	}
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
func (dp *DiskProver) GetFarmerPK() []byte {
	fpk := make([]byte, 48)
	C.DiskProverFarmerPK(dp.ptr, (*C.uchar)(unsafe.Pointer(&fpk[0])))
	return fpk
}
func (dp *DiskProver) GetPoolPK() []byte {
	ppk := make([]byte, 48)
	C.DiskProverpoolPK(dp.ptr, (*C.uchar)(unsafe.Pointer(&ppk[0])))
	return ppk
}
func (dp *DiskProver) GetLocalMasterSK() []byte {
	localSK := make([]byte, 32)
	C.DiskProverLocalMasterSK(dp.ptr, (*C.uchar)(unsafe.Pointer(&localSK[0])))
	return localSK
}
func (dp *DiskProver) GetTable() []byte {
	table := make([]byte, 80)
	C.DiskProverTable(dp.ptr, (*C.uchar)(unsafe.Pointer(&table[0])))
	return table
}
func (dp *DiskProver) GetSize() uint32 {
	return uint32(C.DiskProverGetSize(dp.ptr))
}
func (dp *DiskProver) GetPlotSize() int {
	return int(C.DiskProverGetPlotSize(dp.ptr))
}
func (dp *DiskProver) GetFilename() string {
	return C.GoString(C.DiskProverGetFilename(dp.ptr))
}
func (dp *DiskProver) GetIndexChallenge(index int) []byte {
	var hash_input = Util.IntToBytes(index)
	hash_input = append(hash_input, dp.GetId()...)
	h := sha256.New()
	h.Write(hash_input)
	sum := h.Sum(nil)
	return sum
}

func (dp *DiskProver) GetQualitiesForChallenge(challenge []byte) [][]byte {
	if len(challenge) != kIdLen {
		return nil
	}
	var qualities **C.uint8_t
	var qualities_num C.uint32_t
	var num uint32 = uint32(C.DiskProverGetQualitiesForChallenge(dp.ptr, (*C.uchar)(unsafe.Pointer(&challenge[0])), &qualities, &qualities_num))
	ret := make([][]byte, int(num))
	for i := 0; i < int(num); i++ {
		var qualities_pos = (**C.uint8_t)(unsafe.Pointer(uintptr(unsafe.Pointer(qualities)) + uintptr(i*int(unsafe.Sizeof(*qualities)))))
		ret[i] = C.GoBytes(unsafe.Pointer(*qualities_pos), C.int(kIdLen))
		//C.free(unsafe.Pointer(qualities_pos))
	}
	//defer C.free(unsafe.Pointer(qualities))
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
	//defer C.free(unsafe.Pointer(proof_buf))
	return ret
}

func ValidateProof(id []byte, k uint8, challenge []byte, proof []byte) []byte {
	quality := C.ValidateProof((*C.uchar)(unsafe.Pointer(&id[0])), C.uchar(k), (*C.uchar)(unsafe.Pointer(&challenge[0])),
		(*C.uchar)(unsafe.Pointer(&proof[0])), C.uint16_t(len(proof)))
	//defer C.free(unsafe.Pointer(quality))
	return C.GoBytes(unsafe.Pointer(quality), C.int(32))
}
func CreateHeader(string fpk, string ppk) []byte {
	CreateHeader := C.CreateHeader((*C.uchar)(unsafe.Pointer(&id[0])), C.uchar(k), (*C.uchar)(unsafe.Pointer(&challenge[0])),
		(*C.uchar)(unsafe.Pointer(&proof[0])), C.uint16_t(len(proof)))
	//defer C.free(unsafe.Pointer(quality))
	return C.GoBytes(unsafe.Pointer(quality), C.int(32))
}
//TODO Table 加密 false解密 true加密
func TableBase(str []byte, tp bool) []byte {
	/**
	加密字段：00000000000000000c01000000000000e2b872740300000065eecfb506000000e68d73fd090000009e4b2a550d00000027ca6ed810000000a4111ee814000000a4ca2907190000007cfb4307190000002cfc430719000000
	原字段：000000000000010c000000037472b8e200000006b5cfee6500000009fd738de60000000d552a4b9e00000010d86eca2700000014e81e11a4000000190729caa4000000190743fb7c000000190743fc2c
	解密思路：
	4字节反序存入切片
	偶数取下一组4字节 ，奇数取上一组字节
	去除头部8字节
	*/
	var tableSize = 4
	var index = 0
	var t []byte
	if tp {
		t = make([]byte, 8)
	}
	t = append(t, str...)
	fmt.Println(t)
	var newtable = make([][]byte, len(t)/tableSize)
	for i := 0; i < (len(t)); i += tableSize {
		if index%2 == 0 { //如果是偶数 就取下一组
			var buf = t[i+tableSize : i+tableSize*2]
			newtable[index] = Util.ByteReverse(buf)
		} else {
			var buf []byte
			if i > tableSize {
				buf = t[i-tableSize : i]
			} else {
				buf = t[i : i+tableSize]
			}
			newtable[index] = Util.ByteReverse(buf)
		}

		index++
	}
	if !tp {
		newtable = newtable[2:len(newtable)]
	}
	return bytes.Join(newtable, nil)
}
