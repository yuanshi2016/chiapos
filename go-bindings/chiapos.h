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

EXPORT bool CreatePlotDisk(const char * tmp_dirname,const char * tmp2_dirname,const char * final_dirname,const char * filename,uint8_t k,const uint8_t* memo,uint32_t memo_len,const uint8_t* id,uint32_t id_len,uint32_t buf_megabytes,uint32_t num_buckets,uint64_t stripe_size,uint8_t num_threads,bool nobitfield);



typedef void * PDiskProver;
EXPORT PDiskProver CreateDiskProver(const char *filename);

EXPORT void DiskProofs(PDiskProver, uint32_t, char *proof);


EXPORT void FreeDiskProver(PDiskProver);


EXPORT void DiskProverGetMemo(PDiskProver, uint8_t * buffer);

EXPORT uint32_t DiskProverGetMemoSize(PDiskProver);

EXPORT long DiskProverGetPlotSize(PDiskProver);

EXPORT void DiskProverGetId(PDiskProver, uint8_t *);


EXPORT uint8_t DiskProverGetSize(PDiskProver);

EXPORT void DiskProverFarmerPK(PDiskProver, uint8_t *);


EXPORT void DiskProverLocalMasterSK(PDiskProver, uint8_t *);


EXPORT void DiskProverpoolPK(PDiskProver, uint8_t *);


EXPORT void DiskProverTable(PDiskProver, uint8_t *);

EXPORT const char *DiskProverGetFilename(PDiskProver);

EXPORT uint32_t DiskProverGetQualitiesForChallenge(PDiskProver, const uint8_t *challenge, uint8_t ** *qualities, uint32_t *qualities_num);


EXPORT void DiskProverGetFullProof(PDiskProver, const uint8_t* challenge, uint32_t index, uint8_t ** proof_buf, uint32_t *proof_size);


EXPORT uint8_t * ValidateProof(const uint8_t* id,uint8_t k,const uint8_t* challenge,const uint8_t* proof_bytes,uint16_t proof_size);


#ifdef __cplusplus
}
#endif