extern "C" {
#include "chiapos.h"
}
#include <sodium.h>
#include <bls.hpp>
#include <iostream>
#include <vector>
#include <phase1.hpp>
#include <util.hpp>
#include "../src/plotter_disk.hpp"
#include "../src/prover_disk.hpp"
#include "../src/verifier.hpp"
struct input_t {
    std::array<uint8_t, 32> id = {};
    std::vector<uint8_t> memo;
    std::string plot_name;
};
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
long DiskProverGetPlotSize(PDiskProver dp)
{
    cout << ((DiskProver*)dp)->GetPlotSize() << endl;
    return ((DiskProver*)dp)->GetPlotSize();
}
// id len == 32
void DiskProverGetId(PDiskProver dp, uint8_t *id)
{
    ((DiskProver*)dp)->GetId(id);
}
void DiskProverFarmerPK(PDiskProver dp, uint8_t *fpk)
{
    ((DiskProver*)dp)->GetfarmerPK(fpk);
}
void DiskProverLocalMasterSK(PDiskProver dp, uint8_t *localSK)
{
    ((DiskProver*)dp)->GetlocalMasterSK(localSK);
}
void DiskProverpoolPK(PDiskProver dp, uint8_t *ppk)
{
    ((DiskProver*)dp)->GetpoolPK(ppk);
}
void DiskProverTable(PDiskProver dp, uint8_t *table)
{
    ((DiskProver*)dp)->GetTableBegin(table);
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
uint32_t DiskProverGetQualitiesForChallenge(PDiskProver dp, const uint8_t *challenge, uint8_t ** *qualities, uint32_t *qualities_num)
{
    std::vector<LargeBits> qualities_vec = ((DiskProver*)dp)->GetQualitiesForChallenge(challenge);
    if (qualities_vec.empty()) return 0;

    *qualities = (uint8_t **)malloc(sizeof(uint8_t **) * qualities_vec.size());
    for (int i=0; i < qualities_vec.size(); ++i)
    {
        uint8_t *quality_buf = (uint8_t *)malloc(sizeof(uint8_t) * 32);
        qualities_vec[i].ToBytes(quality_buf);
        (*qualities)[i] = quality_buf;
    }
    return qualities_vec.size();
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
uint8_t *  CreateHeader(string fpk, string ppk){
    vector<uint8_t> seed(32);
    randombytes_buf(seed.data(), seed.size());
    bls::AugSchemeMPL MPL;

    std::vector<uint8_t> poolPubKey(48 * 2);
    std::vector<uint8_t> farmerPubKey(48 * 2);
    Util::HexToBytes(Util::Strip0x(ppk), poolPubKey.data());
    Util::HexToBytes(Util::Strip0x(fpk), farmerPubKey.data());
    bls::G1Element pool_key = bls::G1Element::FromByteVector(poolPubKey);
    bls::G1Element farmer_key = bls::G1Element::FromByteVector(farmerPubKey);

    const bls::PrivateKey master_sk = MPL.KeyGen(seed);
    bls::PrivateKey local_sk = master_sk;
    for(uint32_t i : {12381, 8444, 3, 0}) {
        local_sk = MPL.DeriveChildSk(local_sk, i);
    }
    const bls::G1Element local_key = local_sk.GetG1Element();
    const bls::G1Element plot_key = local_key + farmer_key;
    input_t params;
    {
        //--- plot-id 基于pool_key追加plot_key 计算hash256
        vector<uint8_t> bytes = pool_key.Serialize();
        {
            const auto plot_bytes = plot_key.Serialize();
            bytes.insert(bytes.end(), plot_bytes.begin(), plot_bytes.end());
        }
        bls::Util::Hash256(params.id.data(), bytes.data(), bytes.size());
    }
    const std::string plot_name = "plot-k32-" + Util::get_date_string_ex("%Y-%m-%d-%H-%M") + "-" + bls::Util::HexStr(params.id.data(), params.id.size());

    params.memo.insert(params.memo.end(), poolPubKey.begin(), poolPubKey.end());
    params.memo.insert(params.memo.end(), farmerPubKey.begin(), farmerPubKey.end());
    {
        const auto bytes = master_sk.Serialize();
        params.memo.insert(params.memo.end(), bytes.begin(), bytes.end());
    }
    params.plot_name = plot_name;
    vector<uint8_t> header(188);
    std::string Str{"50726F6F66206F6620537061636520506C6F74"};
    std::string Str1{"20000476312E300080"};
    seed.assign(Str.begin(), Str.end());
    seed.assign(params.id.begin(), params.id.end());
    seed.assign(Str1.begin(), Str1.end());
    seed.assign(params.memo.begin(), params.memo.end());
    return header.data();
}
