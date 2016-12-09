#include "stdafx.h"

#include "TpmForIotPolicy.h"

using namespace std;
using namespace TpmCpp;

#define TPM_FOR_IOT_HASH_ALG TPM_ALG_ID::SHA1

PolicyTree RawPolicyToTree(
    RawPolicy   &rawPolicy)
{
    TPM_CC cc = (TPM_CC)rawPolicy.ulCommandCode;

    auto pcrValues = vector<TPM2B_DIGEST>(rawPolicy.vecBufPcrValues.size());
    auto pcrs = vector<TPMS_PCR_SELECTION>(rawPolicy.vecBufPcrs.size());

    TPMT_PUBLIC authPubKey;

    //TPMU_SIGNATURE signature;
    SignResponse signature;

    size_t i = 0;

    for (auto it = rawPolicy.vecBufPcrValues.begin(); it != rawPolicy.vecBufPcrValues.end(); it++) {
        TPM2B_DIGEST digest;
        digest.FromBuf(*it);
        pcrValues[i++] = digest;
    }

    i = 0;

    for (auto it = rawPolicy.vecBufPcrs.begin(); it != rawPolicy.vecBufPcrs.end(); it++) {
        TPMS_PCR_SELECTION pcr;
        pcr.FromBuf(*it);
        pcrs[i++] = pcr;
    }

    authPubKey.FromBuf(rawPolicy.bufAuthPubKey);

    signature.FromBuf(rawPolicy.bufSignature);

    PolicyCommandCode p_cc(cc);

    PolicyPcr p_pcr(pcrValues, pcrs);

    return PolicyTree(PolicyAuthorize(rawPolicy.bufIntermediateDigest, ByteVec(), authPubKey, *signature.signature), p_cc, p_pcr);
}

RawPolicy GenerateRawPolicy(
    TSS_KEY& authorityKey,
    vector<TPM2B_DIGEST>& pcrValues,
    vector<TPMS_PCR_SELECTION>& pcrs)
{
    ByteVec NullVec;

    RawPolicy rawPolicy = { 0 };

    TPM_CC cc = TPM_CC::Sign;

    PolicyCommandCode p_cc(cc);

    PolicyPcr p_pcr(pcrValues, pcrs);

    PolicyTree p(p_cc, p_pcr);

    auto preDigest = p.GetPolicyDigest(TPM_FOR_IOT_HASH_ALG);

    auto aHash = TPMT_HA::FromHashOfData(TPM_FOR_IOT_HASH_ALG, Helpers::Concatenate(preDigest.digest, NullVec));

    SignResponse signature = authorityKey.Sign(aHash.digest, TPMS_NULL_SIG_SCHEME());

    rawPolicy.ulCommandCode = (uint32_t)cc;
    rawPolicy.vecBufPcrValues = vector<ByteVec>(pcrValues.size());

    for (size_t i = 0; i < pcrValues.size(); i++) {
        rawPolicy.vecBufPcrValues[i] = pcrValues[i].ToBuf();
    }

    rawPolicy.vecBufPcrs = vector<ByteVec>(pcrs.size());

    for (size_t i = 0; i < pcrs.size(); i++) {
        rawPolicy.vecBufPcrs[i] = pcrs[i].ToBuf();
    }

    rawPolicy.bufIntermediateDigest = preDigest.digest;

    rawPolicy.bufAuthPubKey = authorityKey.publicPart.ToBuf();

    rawPolicy.bufSignature = signature.ToBuf();
    //rawPolicy.bufSignature = signature.signature->ToBuf();

    return rawPolicy;
}

PolicyTree GeneratePolicy(
    TSS_KEY& authorityKey,
    vector<TPM2B_DIGEST>& pcrValues,
    vector<TPMS_PCR_SELECTION>& pcrs)
{
    RawPolicy rawPolicy = GenerateRawPolicy(authorityKey,
                                            pcrValues,
                                            pcrs);

    return RawPolicyToTree(rawPolicy);
}

ByteVec GeneratePolicyAuthorizeDigest(
    TPMT_PUBLIC& publicKey)
{
    TPMT_SIGNATURE signature;
    PolicyTree p(PolicyAuthorize(ByteVec(12, 0), ByteVec(), publicKey, signature));

    return p.GetPolicyDigest(TPM_FOR_IOT_HASH_ALG).digest;
}