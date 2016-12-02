#include "stdafx.h"

TpmCpp::PolicyTree GeneratePolicy(
    TpmCpp::TSS_KEY& authorityKey,
    vector<TpmCpp::TPM2B_DIGEST>& pcrValues,
    vector<TpmCpp::TPMS_PCR_SELECTION>& pcrs);

TpmCpp::ByteVec GeneratePolicyAuthorizeDigest(
    TpmCpp::TPMT_PUBLIC& publicKey);