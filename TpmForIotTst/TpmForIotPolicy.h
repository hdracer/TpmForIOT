#include "stdafx.h"

typedef struct _RawPolicy {
    uint32_t ulCommandCode;
    vector<TpmCpp::ByteVec> vecBufPcrValues;
    vector<TpmCpp::ByteVec> vecBufPcrs;
    TpmCpp::ByteVec bufIntermediateDigest;
    TpmCpp::ByteVec bufAuthPubKey;
    TpmCpp::ByteVec bufSignature;
} RawPolicy;

TpmCpp::PolicyTree GeneratePolicy(
    TpmCpp::TSS_KEY& authorityKey,
    vector<TpmCpp::TPM2B_DIGEST>& pcrValues,
    vector<TpmCpp::TPMS_PCR_SELECTION>& pcrs);

TpmCpp::ByteVec GeneratePolicyAuthorizeDigest(
    TpmCpp::TPMT_PUBLIC& publicKey);