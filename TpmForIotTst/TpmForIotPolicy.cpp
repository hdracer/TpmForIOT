#include "stdafx.h"

#include "TpmForIotPolicy.h"

using namespace std;
using namespace TpmCpp;

#define TPM_FOR_IOT_HASH_ALG TPM_ALG_ID::SHA1

PolicyTree GeneratePolicy(
    TSS_KEY& authorityKey,
    vector<TPM2B_DIGEST>& pcrValues,
    vector<TPMS_PCR_SELECTION>& pcrs)
{
    PolicyCommandCode p_cc(TPM_CC::Sign);

    PolicyPcr p_pcr(pcrValues, pcrs);

    PolicyTree p(p_cc, p_pcr);

    ByteVec NullVec;

    auto preDigest = p.GetPolicyDigest(TPM_FOR_IOT_HASH_ALG);

    auto aHash = TPMT_HA::FromHashOfData(TPM_FOR_IOT_HASH_ALG, Helpers::Concatenate(preDigest.digest, NullVec));

    SignResponse signature = authorityKey.Sign(aHash.digest, TPMS_NULL_SIG_SCHEME());

    return PolicyTree(PolicyAuthorize(preDigest.digest, NullVec, authorityKey.publicPart, *signature.signature), p_cc, p_pcr);
}

ByteVec GeneratePolicyAuthorizeDigest(
    TPMT_PUBLIC& publicKey)
{
    TPMT_SIGNATURE signature;
    PolicyTree p(PolicyAuthorize(ByteVec(12, 0), ByteVec(), publicKey, signature));

    return p.GetPolicyDigest(TPM_FOR_IOT_HASH_ALG).digest;
}