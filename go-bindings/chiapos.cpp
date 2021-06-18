extern "C" {
#include "chiapos.h"
}
#include <iostream>
#include <vector>
#include "../src/plotter_disk.hpp"
#include "../src/prover_disk.hpp"
#include "../src/verifier.hpp"

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
    bool nobitfield)
{
    try
    {
        DiskPlotter().CreatePlotDisk(tmp_dirname,
                        tmp2_dirname,
                        final_dirname,
                        filename,
                        k, memo, memo_len,
                        id, id_len,
                        buf_megabytes, num_buckets,
                        stripe_size, num_threads,
                        nobitfield ? 0 : ENABLE_BITFIELD);
        return true;
    }
    catch (const std::exception & e)
    {
        std::cout << "Caught plotting error: " << e.what() << std::endl;
        return false;
    }
}

PDiskProver CreateDiskProver(const char *filename)
{
    try
    {
        std::unique_ptr<DiskProver> dp = std::make_unique<DiskProver>(filename);
        return dp.release();
    }
    catch (const std::exception & e)
    {
       std::cout << e.what() << std::endl;
    }
    return NULL;
}

void FreeDiskProver(PDiskProver dp)
{
    delete (DiskProver*)dp;
}

void DiskProverGetMemo(PDiskProver dp, uint8_t * buffer)
{
    ((DiskProver*)dp)->GetMemo(buffer);
}
uint32_t DiskProverGetMemoSize(PDiskProver dp)
{
    return ((DiskProver*)dp)->GetMemoSize();
}

// id len == 32
void DiskProverGetId(PDiskProver dp, uint8_t *id)
{
    ((DiskProver*)dp)->GetId(id);
}

uint8_t DiskProverGetSize(PDiskProver dp)
{
    return ((DiskProver*)dp)->GetSize();
}

const char *DiskProverGetFilename(PDiskProver dp)
{
    return ((DiskProver*)dp)->GetFilename().c_str();
}

// qualities data size == 32
void DiskProverGetQualitiesForChallenge(PDiskProver dp, const uint8_t *challenge, uint8_t ** *qualities, uint32_t *qualities_num)
{
    std::vector<LargeBits> qualities_vec = ((DiskProver*)dp)->GetQualitiesForChallenge(challenge);
    if (qualities_vec.empty()) return;

    *qualities = (uint8_t **)malloc(sizeof(uint8_t **) * qualities_vec.size());

    for (int i=0; i < qualities_vec.size(); ++i)
    {
        uint8_t *quality_buf = (uint8_t *)malloc(sizeof(uint8_t) * 32);
        qualities_vec[i].ToBytes(quality_buf);
        (*qualities)[i] = quality_buf;
    }

}

void DiskProverGetFullProof(PDiskProver dp, const uint8_t* challenge, uint32_t index, uint8_t ** proof_buf, uint32_t *proof_size)
{
    LargeBits proof = ((DiskProver*)dp)->GetFullProof(challenge, index);
    *proof_size = Util::ByteAlign(64 * ((DiskProver*)dp)->GetSize()) / 8;
    *proof_buf = (uint8_t *)malloc(*proof_size);
    proof.ToBytes(*proof_buf);
}

uint8_t * ValidateProof(
        const uint8_t* id,
        uint8_t k,
        const uint8_t* challenge,
        const uint8_t* proof_bytes,
        uint16_t proof_size)
{
    LargeBits quality = Verifier().ValidateProof(id, k, challenge, proof_bytes, proof_size);
    if (quality.GetSize() == 0) return nullptr;
    uint8_t *quality_buf = (uint8_t *)malloc(32);
    quality.ToBytes(quality_buf);
    return quality_buf;
}
