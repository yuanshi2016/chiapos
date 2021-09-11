extern "C" {
#include "chiapos.h"
}
#include <iostream>
#include <vector>
#include <util.hpp>
#include "../src/plotter_disk.hpp"
#include "../src/prover_disk.hpp"
#include "../src/verifier.hpp"
#include "../lib/xpack-src/json.h"

vector<unsigned char> intToBytes(uint32_t paramInt, uint32_t numBytes)
{
    vector<unsigned char> arrayOfByte(numBytes, 0);
    for (uint32_t i = 0; paramInt > 0; i++) {
        arrayOfByte[numBytes - i - 1] = paramInt & 0xff;
        paramInt >>= 8;
    }
    return arrayOfByte;
}

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
struct proofs {
    string challenge;
    vector<string> proof;
    XPACK(O(challenge, proof));
};
struct plotInfo{
    string plot_id;
    string pool_public_key;
    string plot_public_key;
    string farmer_public_key;
    string local_master_sk;
    uint32_t plot_size;
    uint32_t proof_len;
    vector<proofs> ProofArr;
    XPACK(O(plot_id, pool_public_key, plot_public_key, farmer_public_key, local_master_sk, plot_size, proof_len,ProofArr));
};
void DiskProofs(PDiskProver dp, uint32_t total, char *proof)
{
    DiskProver *prover = ((DiskProver *)dp);
    uint8_t id_bytes[32];
    uint8_t farmer_public_key[48];
    uint8_t pool_public_key[48];
    uint8_t local_master_sk[32];
    prover->GetId(id_bytes);
    prover->GetfarmerPK(farmer_public_key);
    prover->GetpoolPK(pool_public_key);
    prover->GetlocalMasterSK(local_master_sk);
    int Numi = 0;
    plotInfo Proofs;
    Proofs.ProofArr.resize(total);
    Proofs.plot_id = Util::HexStr(id_bytes, 32);
    Proofs.pool_public_key = Util::HexStr(pool_public_key, 48);
    Proofs.farmer_public_key = Util::HexStr(farmer_public_key, 48);
    Proofs.local_master_sk = Util::HexStr(local_master_sk, 32);
    Proofs.plot_size = prover->GetSize();
    bool ProofDataSuccess = false;
    for (uint32_t num = 0; num < 10000; num++){
        vector<unsigned char> hash_input = intToBytes(num, 4);
        hash_input.insert(hash_input.end(), &id_bytes[0], &id_bytes[32]);
        vector<unsigned char> hash(picosha2::k_digest_size);
        picosha2::hash256(hash_input.begin(), hash_input.end(), hash.begin(), hash.end());
        if (ProofDataSuccess) {
            break;
        }
        try {
            vector<LargeBits> qualities = prover->GetQualitiesForChallenge(hash.data());
            //std::cout << "challenge:" << Proofs[Numi].challenge << endl;
            if (qualities.size() <= 0){
                continue;
            }
            Proofs.ProofArr[Numi].challenge = Util::HexStr(hash.data(), 32);
            Proofs.ProofArr[Numi].proof.resize(qualities.size());
            for (size_t i = 0; i < qualities.size(); i++) {
                LargeBits proof = prover->GetFullProof(hash.data(), i);
                uint8_t *proof_data = new uint8_t[proof.GetSize() / 8];
                Proofs.proof_len = proof.GetSize() / 8;
                proof.ToBytes(proof_data);
                Proofs.ProofArr[Numi].proof[i] = Util::HexStr(proof_data, 256);
            }
            Numi++;
            if (Numi >= total || num >= 30) {
                ProofDataSuccess = true;
            }
        } catch (...) {
            std::cout << "失败" << endl;
            continue;
        }
    }
    string json = xpack::json::encode(Proofs);  // 结构体转json
    const char *p = json.c_str();
    std::cout << "json:" << json.c_str() << "	Size:" << sizeof(p) << endl;
    strcpy(proof, p);
    cout << proof << endl;
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
    try{
        LargeBits proof = ((DiskProver*)dp)->GetFullProof(challenge, index);
        *proof_size = Util::ByteAlign(64 * ((DiskProver*)dp)->GetSize()) / 8;
        *proof_buf = (uint8_t *)malloc(*proof_size);
        proof.ToBytes(*proof_buf);
    } catch (...) {

    }

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

