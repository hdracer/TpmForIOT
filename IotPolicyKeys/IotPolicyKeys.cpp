#include "IotPolicyKeys.h"

using namespace TpmCpp;

bool IOTPolicyKeyAttestationPackage::generate(Tpm2 tpm)
{
    auto pcrsToQuote = TPMS_PCR_SELECTION::GetSelectionArray(TPM_FOR_IOT_HASH_ALG, 7);
    PCR_ReadResponse pcrVals = tpm.PCR_Read(pcrsToQuote);
    
    return true;
}