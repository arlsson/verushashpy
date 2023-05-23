
// Copyright (c) 2020 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/utilstrencodings.h"
#include "solutiondata.h"

uint160 ASSETCHAINS_CHAINID = uint160(ParseHex("1af5b8015c64d39ab44c60ead8317f9f5a9b6c4c"));
uint32_t ASSETCHAINS_MAGIC = 2387029918;

[[noreturn]] void new_handler_terminate()
{
    // Rather than throwing std::bad-alloc if allocation fails, terminate
    // immediately to (try to) avoid chain corruption.
    // Since LogPrintf may itself allocate memory, set the handler directly
    // to terminate first.
    std::set_new_handler(std::terminate);
    fputs("Error: Out of memory. Terminating.\n", stderr);

    // The log was successful, terminate now.
    std::terminate();
};

// checks that the solution stored data for this header matches what is expected, ensuring that the
// values in the header match the hash of the pre-header.
bool CBlockHeader::CheckNonCanonicalData(const uint160 &cID) const
{
    CPBaaSPreHeader pbph(*this);
    CPBaaSBlockHeader pbbh1 = CPBaaSBlockHeader(cID, pbph);
    CPBaaSBlockHeader pbbh2;
    int32_t idx = GetPBaaSHeader(pbbh2, cID);
    if (idx != -1)
    {
        if (pbbh1.hashPreHeader == pbbh2.hashPreHeader)
        {
            return true;
        }
    }
    return false;
}

// checks that the solution stored data for this header matches what is expected, ensuring that the
// values in the header match the hash of the pre-header.
bool CBlockHeader::CheckNonCanonicalData() const
{
    // true this chain first for speed
    if (CheckNonCanonicalData(ASSETCHAINS_CHAINID))
    {
        return true;
    }
    else
    {
        CPBaaSSolutionDescriptor d = CVerusSolutionVector::solutionTools.GetDescriptor(nSolution);
        if (CVerusSolutionVector::solutionTools.HasPBaaSHeader(nSolution) != 0)
        {
            int32_t len = CVerusSolutionVector::solutionTools.ExtraDataLen(nSolution, true);
            int32_t numHeaders = d.numPBaaSHeaders;
            if (numHeaders * sizeof(CPBaaSBlockHeader) > len)
            {
                numHeaders = len / sizeof(CPBaaSBlockHeader);
            }
            const CPBaaSBlockHeader *ppbbh = CVerusSolutionVector::solutionTools.GetFirstPBaaSHeader(nSolution);
            for (int32_t i = 0; i < numHeaders; i++)
            {
                if ((ppbbh + i)->chainID == ASSETCHAINS_CHAINID)
                {
                    continue;
                }
                if (CheckNonCanonicalData((ppbbh + i)->chainID))
                {
                    return true;
                }
            }
        }
    }
    return false;
}


// returns -1 on failure, upon failure, pbbh is undefined and likely corrupted
int32_t CBlockHeader::GetPBaaSHeader(CPBaaSBlockHeader &pbh, const uint160 &cID) const
{
    // find the specified PBaaS header in the solution and return its index if present
    // if not present, return -1
    if (nVersion == VERUS_V2)
    {
        // search in the solution for this header index and return it if found
        CPBaaSSolutionDescriptor d = CVerusSolutionVector::solutionTools.GetDescriptor(nSolution);
        if (CVerusSolutionVector::solutionTools.HasPBaaSHeader(nSolution) != 0)
        {
            int32_t len = CVerusSolutionVector::solutionTools.ExtraDataLen(nSolution, true);
            int32_t numHeaders = d.numPBaaSHeaders;
            if (numHeaders * sizeof(CPBaaSBlockHeader) > len)
            {
                numHeaders = len / sizeof(CPBaaSBlockHeader);
            }
            const CPBaaSBlockHeader *ppbbh = CVerusSolutionVector::solutionTools.GetFirstPBaaSHeader(nSolution);
            for (int32_t i = 0; i < numHeaders; i++)
            {
                if ((ppbbh + i)->chainID == cID)
                {
                    pbh = *(ppbbh + i);
                    return i;
                }
            }
        }
    }
    return -1;
}

// returns the index of the new header if added, otherwise, -1
int32_t CBlockHeader::AddPBaaSHeader(const CPBaaSBlockHeader &pbh)
{
    CVerusSolutionVector sv(nSolution);
    CPBaaSSolutionDescriptor d = sv.Descriptor();
    int32_t retVal = d.numPBaaSHeaders;

    // make sure we have space. do not adjust capacity
    // if there is anything in the extradata, we have no more room
    if (!d.extraDataSize && (uint32_t)(sv.ExtraDataLen() / sizeof(CPBaaSBlockHeader)) > 0)
    {
        d.numPBaaSHeaders++;
        sv.SetDescriptor(d);                            // update descriptor to make sure it will accept the set
        sv.SetPBaaSHeader(pbh, d.numPBaaSHeaders - 1);
        return retVal;
    }

    return -1;
}

// add or update the PBaaS header for this block from the current block header & this prevMMR. This is required to make a valid PoS or PoW block.
bool CBlockHeader::AddUpdatePBaaSHeader(const CPBaaSBlockHeader &pbh)
{
    CPBaaSBlockHeader pbbh;
    if (nVersion == VERUS_V2 && CConstVerusSolutionVector::Version(nSolution) >= CActivationHeight::ACTIVATE_PBAAS_HEADER)
    {
        if (int32_t idx = GetPBaaSHeader(pbbh, pbh.chainID) != -1)
        {
            return UpdatePBaaSHeader(pbh);
        }
        else
        {
            return (AddPBaaSHeader(pbh) != -1);
        }
    }
    return false;
}

// add or update the current PBaaS header for this block from the current block header & this prevMMR.
// This is required to make a valid PoS or PoW block.
bool CBlockHeader::AddUpdatePBaaSHeader()
{
    if (nVersion == VERUS_V2 && CConstVerusSolutionVector::Version(nSolution) >= CActivationHeight::ACTIVATE_PBAAS_HEADER)
    {
        CPBaaSBlockHeader pbh(ASSETCHAINS_CHAINID, CPBaaSPreHeader(*this));

        CPBaaSBlockHeader pbbh;
        int32_t idx = GetPBaaSHeader(pbbh, ASSETCHAINS_CHAINID);

        if (idx != -1)
        {
            return UpdatePBaaSHeader(pbh);
        }
        else
        {
            return (AddPBaaSHeader(pbh) != -1);
        }
    }
    return false;
}

uint256 CBlockHeader::GetSHA256DHash() const
{
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetVerusHash() const
{
    if (hashPrevBlock.IsNull())
        // always use SHA256D for genesis block
        return SerializeHash(*this);
    else
        return SerializeVerusHash(*this);
}

uint256 CBlockHeader::GetVerusV2Hash() const
{
    if (hashPrevBlock.IsNull())
    {
        // always use SHA256D for genesis block
        return SerializeHash(*this);
    }
    else
    {
        if (nVersion == VERUS_V2)
        {
            int solutionVersion = CConstVerusSolutionVector::Version(nSolution);

            // in order for this to work, the PBaaS hash of the pre-header must match the header data
            // otherwise, it cannot clear the canonical data and hash in a chain-independent manner
            int pbaasType = CConstVerusSolutionVector::HasPBaaSHeader(nSolution);
            //bool debugPrint = false;
            //if (pbaasType != 0 && solutionVersion == CActivationHeight::SOLUTION_VERUSV5_1)
            //{
            //    debugPrint = true;
            //    printf("%s: version V5_1 header, pbaasType: %d, CheckNonCanonicalData: %d\n", __func__, pbaasType, CheckNonCanonicalData());
            //}
            if (pbaasType != 0 && CheckNonCanonicalData())
            {
                CBlockHeader bh = CBlockHeader(*this);
                bh.ClearNonCanonicalData();
                //if (debugPrint)
                //{
                //    printf("%s\n", SerializeVerusHashV2b(bh, solutionVersion).GetHex().c_str());
                //    printf("%s\n", SerializeVerusHashV2b(*this, solutionVersion).GetHex().c_str());
                //}
                return SerializeVerusHashV2b(bh, solutionVersion);
            }
            else
            {
                //if (debugPrint)
                //{
                //    printf("%s\n", SerializeVerusHashV2b(*this, solutionVersion).GetHex().c_str());
                //}
                return SerializeVerusHashV2b(*this, solutionVersion);
            }
        }
        else
        {
            return SerializeVerusHash(*this);
        }
    }
}

