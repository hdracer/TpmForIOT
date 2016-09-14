#include "stdafx.h"

using namespace TpmCpp;

//
// Non-WIN32 initialization for TSS.CPP.
//
extern void DllInit();

//
// Open the Storage Root Key
//
TPM_HANDLE MakeStoragePrimary(_TPMCPP Tpm2 &tpm)
{
    vector<BYTE> NullVec;
    TPMT_PUBLIC storagePrimaryTemplate(
        TPM_ALG_ID::SHA1,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted |
        TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM |
        TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        NullVec,           // No policy
        TPMS_RSA_PARMS(    // How child keys should be protected
            TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA(NullVec));

    // Create the key
    CreatePrimaryResponse storagePrimary = tpm.CreatePrimary(
        tpm._AdminOwner,
        TPMS_SENSITIVE_CREATE(NullVec, NullVec), 
        storagePrimaryTemplate,
        NullVec, 
        vector<TPMS_PCR_SELECTION>());

    return storagePrimary.objectHandle;
}

//
// Create an RSA signing key, optionally restricted (i.e., an AIK)
//
TPM_HANDLE MakeChildSigningKey(
    _TPMCPP Tpm2 &tpm, 
    TPM_HANDLE parentHandle, 
    bool restricted)
{
    vector<BYTE> NullVec;
    TPMA_OBJECT restrictedAttribute;

    if (restricted) {
        restrictedAttribute = TPMA_OBJECT::restricted;
    }

    TPMT_PUBLIC templ(
        TPM_ALG_ID::SHA1,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent |
        TPMA_OBJECT::fixedTPM | TPMA_OBJECT::sensitiveDataOrigin |
        TPMA_OBJECT::userWithAuth | restrictedAttribute,
        NullVec,  // No policy
        TPMS_RSA_PARMS(
            TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::_NULL, 0, TPM_ALG_ID::_NULL),
            TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA1), 2048, 65537), // PKCS1.5
        TPM2B_PUBLIC_KEY_RSA(NullVec));

    CreateResponse newSigningKey = tpm.Create(
        parentHandle,
        TPMS_SENSITIVE_CREATE(),
        templ,
        NullVec,
        vector<TPMS_PCR_SELECTION>());

    auto signKey = tpm.Load(parentHandle, newSigningKey.outPrivate, newSigningKey.outPublic);
    return signKey;
}

//
// Assume that TPM ownership has been taken and that auth values are
// non-null.
//
void SetPlatformAuthenticationValues(_TPMCPP Tpm2 &tpm)
{
#ifndef __linux__
    WCHAR wszAuthReg[1024] = { 0 };
    UINT32 cbAuthReg = sizeof(wszAuthReg);
    BYTE rgbAuthValue[1024] = { 0 };
    UINT32 cbAuthValue = sizeof(rgbAuthValue);

    //
    // Endorsement
    //

    if (RegGetValueW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement",
        L"EndorsementAuth",
        RRF_RT_REG_SZ,
        NULL,
        wszAuthReg,
        (DWORD*)&cbAuthReg) == ERROR_SUCCESS)
    {
        if (TRUE == CryptStringToBinaryW(
            wszAuthReg,
            0,
            CRYPT_STRING_BASE64,
            rgbAuthValue,
            (DWORD*)&cbAuthValue,
            NULL,
            NULL))
        {
            vector<BYTE> newAuth(rgbAuthValue, rgbAuthValue + cbAuthValue);
            tpm._AdminEndorsement.SetAuth(newAuth);
        }
    }

    //
    // Storage
    //

    cbAuthReg = sizeof(wszAuthReg);
    cbAuthValue = sizeof(rgbAuthValue);
    if (RegGetValueW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Admin",
        L"StorageOwnerAuth",
        RRF_RT_REG_SZ,
        NULL,
        wszAuthReg,
        (DWORD*)&cbAuthReg) == ERROR_SUCCESS)
    {
        if (TRUE == CryptStringToBinaryW(
            wszAuthReg,
            0,
            CRYPT_STRING_BASE64,
            rgbAuthValue,
            (DWORD*)&cbAuthValue,
            NULL,
            NULL))
        {
            vector<BYTE> newAuth(rgbAuthValue, rgbAuthValue + cbAuthValue);
            tpm._AdminOwner.SetAuth(newAuth);
        }
    }
    
#else
    //
    // Linux
    //

    vector<BYTE> newAuth{ '1', '2', '3', '4' };
    tpm._AdminOwner.SetAuth(newAuth);
    tpm._AdminEndorsement.SetAuth(newAuth);
#endif
}

//
// PCR attestation and AIK activation
//
void AttestationForIot()
{
    Tpm2 tpm;

    // 
    // Tell the TPM2 object where to send commands 
    //

#ifdef __linux__
    //
    // Connect to the Intel TSS resource manager
    //

    TpmTcpDevice tcpDevice;
    if (!tcpDevice.Connect("127.0.0.1", 2323)) {
        cerr << "Could not connect to the resource manager";
        return;
    }
    tpm._SetDevice(tcpDevice);
#else
    //
    // Connect to the TBS
    //

    TpmTbsDevice tbsDevice;
    tbsDevice.Connect();
    tpm._SetDevice(tbsDevice);
#endif

    //
    // Set platform auth values
    //

    SetPlatformAuthenticationValues(tpm);

    //
    // Create a restricted key in the storage hierarchy
    //

    TPM_HANDLE primaryKey = MakeStoragePrimary(tpm);
    TPM_HANDLE signingKey = MakeChildSigningKey(tpm, primaryKey, true);

    // First PCR-signing (quoting). We will sign PCR-7.
    cout << ">> PCR Quoting" << endl;
    auto pcrsToQuote = TPMS_PCR_SELECTION::GetSelectionArray(TPM_ALG_ID::SHA1, 7);

    // Then read the value so that we can validate the signature later
    PCR_ReadResponse pcrVals = tpm.PCR_Read(pcrsToQuote);

    // Do the quote.  Note that we provide a nonce.
    ByteVec Nonce = CryptoServices::GetRand(16);
    QuoteResponse quote = tpm.Quote(signingKey, Nonce, TPMS_NULL_SIG_SCHEME(), pcrsToQuote);

    // Need to cast to the proper attestion type to validate
    TPMS_ATTEST qAttest = quote.quoted;
    TPMS_QUOTE_INFO *qInfo = dynamic_cast<TPMS_QUOTE_INFO *> (qAttest.attested);
    cout << "Quoted PCR: " << qInfo->pcrSelect[0].ToString() << endl;
    cout << "PCR-value digest: " << qInfo->pcrDigest << endl;

    // We can use the TSS.C++ library to verify the quote. First read the public key.
    // Nomrmally the verifier will have other ways of determinig the veractity
    // of the public key
    ReadPublicResponse pubKey = tpm.ReadPublic(signingKey);
    bool sigOk = pubKey.outPublic.ValidateQuote(pcrVals, Nonce, quote);

    if (sigOk) {
        cout << "The quote was verified correctly" << endl;
    }

    //
    // Activate the restricted key
    //

    // TODO

    //
    // Create a user key
    //

    // TODO

    //
    // Either activate or attest to the user key
    //

    // TODO

    //
    // Sign some data with the user key
    //
    
    // TODO
}

//
// Console entry point
//
int main()
{
#ifdef __linux__
DllInit();
try {
#endif
    
    AttestationForIot();

#ifdef __linux__
}
catch (const runtime_error& exc) {
    cerr << "TpmForIotTst: " << exc.what() << "\nExiting...\n";
}
#endif

    return 0;
}

