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
    vector<BYTE> NullVec;

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

    //
    // Optionally, save the AIK, since it can be reused across reboots
    //

    // TODO

    //
    // Read PCR data
    //

    cout << ">> PCR Quoting" << endl;
    auto pcrsToQuote = TPMS_PCR_SELECTION::GetSelectionArray(TPM_ALG_ID::SHA1, 7);
    PCR_ReadResponse pcrVals = tpm.PCR_Read(pcrsToQuote);

    //
    // Simulate retrieving a Nonce from the server
    //

    ByteVec Nonce = CryptoServices::GetRand(16);

    //
    // Sign the PCR has with the AIK
    //

    QuoteResponse quote = tpm.Quote(
        signingKey, Nonce, TPMS_NULL_SIG_SCHEME(), pcrsToQuote);

    //
    // Simulate verifying the quote at the server
    //

    TPMS_ATTEST qAttest = quote.quoted;
    TPMS_QUOTE_INFO *qInfo = dynamic_cast<TPMS_QUOTE_INFO *> (qAttest.attested);
    cout << "Quoted PCR: " << qInfo->pcrSelect[0].ToString() << endl;
    cout << "PCR-value digest: " << qInfo->pcrDigest << endl;

    ReadPublicResponse pubKey = tpm.ReadPublic(signingKey);
    bool sigOk = pubKey.outPublic.ValidateQuote(pcrVals, Nonce, quote);

    if (sigOk) {
        cout << "The quote was verified correctly" << endl;
    }

    //
    // Create a user signing-only key in the storage hierarchy. 
    //

    TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::sign |           // Key attributes
        TPMA_OBJECT::fixedParent |
        TPMA_OBJECT::fixedTPM |
        TPMA_OBJECT::sensitiveDataOrigin |
        TPMA_OBJECT::userWithAuth,
        NullVec,                      // No policy
        TPMS_RSA_PARMS(
            TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::_NULL, 0, TPM_ALG_ID::_NULL),
            TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA1), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA(NullVec));

    //
    // Include the same PCR selection as above
    //

    CreateResponse newSigningKey = tpm.Create(
        primaryKey,
        TPMS_SENSITIVE_CREATE(NullVec, NullVec),
        templ,
        NullVec,
        pcrsToQuote);

    //
    // Load the new key
    //

    TPM_HANDLE keyToCertify = tpm.Load(
        primaryKey,
        newSigningKey.outPrivate,
        newSigningKey.outPublic);

    //
    // Certify the creation of the user key using the AIK
    //

    CertifyCreationResponse createQuote = tpm.CertifyCreation(
        signingKey,
        keyToCertify,
        Nonce,
        newSigningKey.creationHash,
        TPMS_NULL_SIG_SCHEME(),
        newSigningKey.creationTicket);

    //
    // Simulate checking the key creation quote signature at the server
    //

    sigOk = pubKey.outPublic.ValidateCertifyCreation(
        Nonce,
        newSigningKey.creationHash,
        createQuote);
    if (sigOk) {
        cout << "Key creation certification validated" << endl;
    }

    //
    // Sign a message with the user key
    //

    ByteVec messageHash = TPMT_HA::FromHashOfString(
        TPM_ALG_ID::SHA1, "some message or telemetry data").digest;
    auto signature = tpm.Sign(
        keyToCertify,
        messageHash,
        TPMS_NULL_SIG_SCHEME(),
        TPMT_TK_HASHCHECK::NullTicket());

    cout << "Signature with imported key: " << signature.ToString(false) << endl;

    //
    // Simulate checking the message signature at the server
    //

    ReadPublicResponse userPublic = tpm.ReadPublic(keyToCertify);
    sigOk = userPublic.outPublic.ValidateSignature(
        messageHash, *signature.signature);
    if (sigOk) {
        cout << "Message signature validated" << endl;
    }
    
    //
    // Dump handles we're done with
    //

    tpm.FlushContext(keyToCertify);
    tpm.FlushContext(primaryKey);
    tpm.FlushContext(signingKey);
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

