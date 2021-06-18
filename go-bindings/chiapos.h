#pragma once
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool CreatePlotDisk(
    const char * tmp_dirname,
    const char * tmp2_dirname,
    const char * final_dirname,
    const char * filename,
    uint8_t k,
    const uint8_t* memo,
    uint32_t memo_len,
    const uint8_t* id,
    uint32_t id_len,
    uint32_t buf_megabytes,
    uint32_t num_buckets,
    uint64_t stripe_size,
    uint8_t num_threads,
    bool nobitfield);

typedef void * PDiskProver;

PDiskProver CreateDiskProver(const char *filename);
void FreeDiskProver(PDiskProver);

void DiskProverGetMemo(PDiskProver, uint8_t * buffer);
uint32_t DiskProverGetMemoSize(PDiskProver);

// id len == 32
void DiskProverGetId(PDiskProver, uint8_t *);

uint8_t DiskProverGetSize(PDiskProver);

const char *DiskProverGetFilename(PDiskProver);

// qualities data size == 32
void DiskProverGetQualitiesForChallenge(PDiskProver, const uint8_t *challenge, uint8_t ** *qualities, uint32_t *qualities_num);

void DiskProverGetFullProof(PDiskProver, const uint8_t* challenge, uint32_t index, uint8_t ** proof_buf, uint32_t *proof_size);

uint8_t * ValidateProof(
        const uint8_t* id,
        uint8_t k,
        const uint8_t* challenge,
        const uint8_t* proof_bytes,
        uint16_t proof_size);

#ifdef __cplusplus
}
#endif