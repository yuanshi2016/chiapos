#pragma once
#include <stdint.h>
#include <stdbool.h>
#if defined(_MSC_VER)
    //  Microsoft
    #define EXPORT __declspec(dllexport)
    #define IMPORT __declspec(dllimport)
#elif defined(__GNUC__)
    //  GCC
    #define EXPORT __attribute__((visibility("default")))
    #define IMPORT
#else
    //  do nothing and hope for the best?
    #define EXPORT extern
    #define IMPORT extern
    #pragma warning Unknown dynamic link import/export semantics.
#endif
#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
__declspec(dllexport) bool CreatePlotDisk(const char * tmp_dirname,const char * tmp2_dirname,const char * final_dirname,const char * filename,uint8_t k,const uint8_t* memo,uint32_t memo_len,const uint8_t* id,uint32_t id_len,uint32_t buf_megabytes,uint32_t num_buckets,uint64_t stripe_size,uint8_t num_threads,bool nobitfield);
#else
extern bool CreatePlotDisk(const char * tmp_dirname,const char * tmp2_dirname,const char * final_dirname,const char * filename,uint8_t k,const uint8_t* memo,uint32_t memo_len,const uint8_t* id,uint32_t id_len,uint32_t buf_megabytes,uint32_t num_buckets,uint64_t stripe_size,uint8_t num_threads,bool nobitfield);
#endif


typedef void * PDiskProver;
#ifdef _WIN32
__declspec(dllexport) PDiskProver CreateDiskProver(const char *filename);
#else
extern PDiskProver CreateDiskProver(const char *filename);
#endif

#ifdef _WIN32
__declspec(dllexport) void FreeDiskProver(PDiskProver);
#else
extern void FreeDiskProver(PDiskProver);
#endif

#ifdef _WIN32
__declspec(dllexport) void DiskProverGetMemo(PDiskProver, uint8_t * buffer);
#else
extern void DiskProverGetMemo(PDiskProver, uint8_t * buffer);
#endif

#ifdef _WIN32
__declspec(dllexport) uint32_t DiskProverGetMemoSize(PDiskProver);
#else
extern uint32_t DiskProverGetMemoSize(PDiskProver);
#endif

#ifdef _WIN32
__declspec(dllexport) long DiskProverGetPlotSize(PDiskProver);
#else
extern long DiskProverGetPlotSize(PDiskProver);
#endif

#ifdef _WIN32
__declspec(dllexport) void DiskProverGetId(PDiskProver, uint8_t *);
#else
extern void DiskProverGetId(PDiskProver, uint8_t *);
#endif

#ifdef _WIN32
__declspec(dllexport) uint8_t DiskProverGetSize(PDiskProver);
#else
extern uint8_t DiskProverGetSize(PDiskProver);
#endif

#ifdef _WIN32
__declspec(dllexport) void DiskProverFarmerPK(PDiskProver, uint8_t *);
#else
extern void DiskProverFarmerPK(PDiskProver, uint8_t *);
#endif

#ifdef _WIN32
__declspec(dllexport) void DiskProverLocalMasterSK(PDiskProver, uint8_t *);
#else
extern void DiskProverLocalMasterSK(PDiskProver, uint8_t *);
#endif

#ifdef _WIN32
__declspec(dllexport) void DiskProverpoolPK(PDiskProver, uint8_t *);
#else
extern void DiskProverpoolPK(PDiskProver, uint8_t *);
#endif

#ifdef _WIN32
__declspec(dllexport) void DiskProverTable(PDiskProver, uint8_t *);
#else
extern void DiskProverTable(PDiskProver, uint8_t *);
#endif

#ifdef _WIN32
__declspec(dllexport) const char *DiskProverGetFilename(PDiskProver);
#else
extern const char *DiskProverGetFilename(PDiskProver);
#endif

#ifdef _WIN32
__declspec(dllexport) uint32_t DiskProverGetQualitiesForChallenge(PDiskProver, const uint8_t *challenge, uint8_t ** *qualities, uint32_t *qualities_num);
#else
extern uint32_t DiskProverGetQualitiesForChallenge(PDiskProver, const uint8_t *challenge, uint8_t ** *qualities, uint32_t *qualities_num);
#endif

#ifdef _WIN32
__declspec(dllexport) void DiskProverGetFullProof(PDiskProver, const uint8_t* challenge, uint32_t index, uint8_t ** proof_buf, uint32_t *proof_size);
#else
extern void DiskProverGetFullProof(PDiskProver, const uint8_t* challenge, uint32_t index, uint8_t ** proof_buf, uint32_t *proof_size);
#endif

#ifdef _WIN32
__declspec(dllexport) uint8_t * ValidateProof(const uint8_t* id,uint8_t k,const uint8_t* challenge,const uint8_t* proof_bytes,uint16_t proof_size);
#else
extern uint8_t * ValidateProof(const uint8_t* id,uint8_t k,const uint8_t* challenge,const uint8_t* proof_bytes,uint16_t proof_size);
#endif


#ifdef __cplusplus
}
#endif