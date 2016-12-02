#include "stdafx.h"

#ifndef TPM_FOR_IOT_HASH_ALG
  #define TPM_FOR_IOT_HASH_ALG TPM_ALG_ID::SHA1
#endif

class IOTPolicyPolicy{


};

class IOTPolicyKeyAttestationPackage {
private:

    TpmCpp::TPM_HANDLE quoteKey;

    TpmCpp::ByteVec quoteData;

public:

    IOTPolicyKeyAttestationPackage()
        : quoteKey(NULL),
        quoteData()
    {};

    IOTPolicyKeyAttestationPackage(
        const TpmCpp::TPM_HANDLE& quoteKey,
        const TpmCpp::ByteVec& quoteData)
    : quoteKey(quoteKey),
        quoteData(quoteData)
    {};

    ~IOTPolicyKeyAttestationPackage() {};

    bool generate(TpmCpp::Tpm2 tpm);

    TpmCpp::ByteVec ToBuf();

};

class IOTPolicyKey {
private:
    bool created;

    TpmCpp::PolicyTree p;

    TpmCpp::TSS_KEY authorityPublicKey;

public:

    IOTPolicyKey()
        : p(),
        authorityPublicKey()
    {};

    IOTPolicyKey(
        const TpmCpp::TSS_KEY& authorityPublicKey)
        : p(),
        authorityPublicKey(authorityPublicKey)
    {};

    ~IOTPolicyKey()
        {};

    bool generate_key();

    bool attest_key(const IOTPolicyKeyAttestationPackage& attestation);

    bool set_policy(const TpmCpp::PolicyTree& policy)
    {
        this->p = policy;
    }

};