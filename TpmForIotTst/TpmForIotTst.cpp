#include "stdafx.h"

using namespace TpmCpp;

//
// Non-WIN32 initialization for TSS.CPP.
//
extern void DllInit();

//
// Open the Endorsement Key
//
TPM_HANDLE MakeEndorsementKey(_TPMCPP Tpm2 &tpm)
{
    vector<BYTE> NullVec;
    TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted |
        TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM |
        TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        NullVec,           // No policy
        TPMS_RSA_PARMS(    // How child keys should be protected
            TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA(NullVec));

    // Create the key
    CreatePrimaryResponse ek = tpm.CreatePrimary(
        tpm._AdminEndorsement,
        TPMS_SENSITIVE_CREATE(NullVec, NullVec), 
        storagePrimaryTemplate,
        NullVec, 
        vector<TPMS_PCR_SELECTION>());

    return ek.objectHandle;
}


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
// Simulated server call that returns a Nonce
//
ByteVec ServerGetNonce()
{
    ByteVec nonce = CryptoServices::GetRand(16);
    cout << "Server: Nonce is " << nonce << endl;
    return nonce;
}

//
// Simulate server call that challenges the linkage between an Endorsement Key
// and another key stored on the same TPM.
//
ActivationData ServerGetActivation(
    TPMT_PUBLIC &clientEkPub, 
    ByteVec &nameOfKeyToActivate)
{
    //
    // Lookup the client EK public in a whitelist (or, similarly, find its 
    // certificate and build trust off that). Either way, this is a critical
    // step, since the EK is the root of trust for the whole protocol, and is 
    // used to prove that child keys are truly TPM-protected.
    //
    // For an example of pulling EK manufacturer certificates from the 
    // internet, see:
    // https://github.com/01org/tpm2.0-tools/blob/master/src/tpm2_getmanufec.cpp

    // TODO
    cout << "Server: EK public is trusted: " << clientEkPub.Serialize(SerializationType::Text) << endl;

    //
    // Create a random secret and encrypt it back to the client. If the client
    // can decrypt it, the server can trust that the "activated" key is on the
    // same TPM as the EK.
    //
    // A production server should ideally store each secret, associated with 
    // the EK pub to which it was encrypted. That way, if the secret is used 
    // for some downstream purpose (such as a public cloud API key), and gets 
    // stolen (the secret is exportable; the EK is not), that situation can 
    // be detected.
    //

    ByteVec secret = CryptoServices::GetRand(16);
    cout << "Server: Secret is " << secret << endl;
    return clientEkPub.CreateActivation(
        secret,
        TPM_ALG_ID::SHA1,
        nameOfKeyToActivate);
}

void ServerRegisterKey(
    ByteVec &serverSecret, 
    TPMT_PUBLIC &clientRestrictedPub,
    PCR_ReadResponse &clientPcrVals,
    QuoteResponse &clientPcrQuote, 
    TPMS_CREATION_DATA &clientKeyCreation,
    CertifyCreationResponse &clientKeyQuote)
{
    //
    // Confirm that the provided PCR hash is as expected for this particular 
    // client device. On Windows, an attested boot log can be used instead. On 
    // Linux, this procedure requires whitelisting.
    //

    // TODO
    TPMS_ATTEST qAttest = clientPcrQuote.quoted;
    TPMS_QUOTE_INFO *qInfo = dynamic_cast<TPMS_QUOTE_INFO *> (qAttest.attested);
    cout << "Server: quoted PCR is trusted: " << qInfo->pcrSelect[0].ToString() << endl;

    //
    // Confirm that the client restricted public is the same key that the 
    // server activated in the previous call
    //

    // TODO
    cout << "Server: restricted key is trusted: " << clientRestrictedPub.Serialize(SerializationType::Text) << endl;

    //
    // Check the PCR quote signature
    //

    bool sigOk = clientRestrictedPub.ValidateQuote(
        clientPcrVals, serverSecret, clientPcrQuote);
    if (sigOk) {
        cout << "Server: PCR quote is valid" << endl;
    }

    //
    // For the new child key, hash the creation data
    //

    ByteVec creationHash = TPMT_HA::FromHashOfData(
        TPM_ALG_ID::SHA1, clientKeyCreation.ToBuf()).digest;

    //
    // Check the parent key identity
    //

    // TODO

    //
    // Check the PCR binding
    //

    // TODO

    // 
    // Check the key quote signature
    //

    sigOk = clientRestrictedPub.ValidateCertifyCreation(
        serverSecret,
        creationHash,
        clientKeyQuote);
    if (sigOk) {
        cout << "Server: key quote is valid" << endl;
    }
}

void ServerReceiveMessage(
    TPMT_PUBLIC &clientSigningPub,
    const std::string &clientMessage,
    TPMU_SIGNATURE &messageSig)
{
    //
    // Confirm that the client signing key is the one registered in the 
    // previous server call
    //

    // TODO
    cout << "Server: client signing key is trusted " << clientSigningPub.Serialize(SerializationType::Text) << endl;

    //
    // Hash the message
    //

    ByteVec messageHash = TPMT_HA::FromHashOfString(
        TPM_ALG_ID::SHA1, clientMessage).digest;

    //
    // Check the signature
    //

    bool sigOk = clientSigningPub.ValidateSignature(
        messageHash, messageSig);
    if (sigOk) {
        cout << "Server: message received and verified" << endl;
    }

    //
    // Process the message, as appropriate, based on whether the signature
    // is valid and from a trusted device
    //

    // TODO
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
    // Read out the manufacturer Endorsement Key (EK)
    //

    TPM_HANDLE ekHandle = MakeEndorsementKey(tpm);
    auto ekPubX = tpm.ReadPublic(ekHandle);
    TPMT_PUBLIC& ekPub = ekPubX.outPublic;

    //
    // Create a restricted key in the storage hierarchy
    //

    TPM_HANDLE primaryKey = MakeStoragePrimary(tpm);
    TPM_HANDLE restrictedKey = MakeChildSigningKey(tpm, primaryKey, true);
    auto restrictedPubX = tpm.ReadPublic(restrictedKey);
    TPMT_PUBLIC& restrictedPub = restrictedPubX.outPublic;

    //
    // Request activation to prove linkage between restricted key and EK 
    //

    ByteVec nameOfKeyToActivate = restrictedKey.GetName();
    ActivationData encryptedSecret = ServerGetActivation(
        ekPub, nameOfKeyToActivate);

    //
    // Activation data can only be decrypted on this TPM
    //

    ByteVec decryptedSecret = tpm.ActivateCredential(
        restrictedKey, 
        ekHandle, 
        encryptedSecret.CredentialBlob, 
        encryptedSecret.Secret);
    cout << "Client: decrypted secret is " << decryptedSecret << endl;

    //
    // Optionally, save the AIK, since it can be reused across reboots
    //

    // TODO

    //
    // Read PCR data
    //

    auto pcrsToQuote = TPMS_PCR_SELECTION::GetSelectionArray(TPM_ALG_ID::SHA1, 7);
    PCR_ReadResponse pcrVals = tpm.PCR_Read(pcrsToQuote);

    //
    // Sign the PCR hash with the AIK
    //

    QuoteResponse quote = tpm.Quote(
        restrictedKey, decryptedSecret, TPMS_NULL_SIG_SCHEME(), pcrsToQuote);

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
    auto userSigningPubX = tpm.ReadPublic(keyToCertify);
    TPMT_PUBLIC &userSigningPub = userSigningPubX.outPublic;

    //
    // Certify the creation of the user key using the AIK
    //

    CertifyCreationResponse createQuote = tpm.CertifyCreation(
        restrictedKey,
        keyToCertify,
        decryptedSecret,
        newSigningKey.creationHash,
        TPMS_NULL_SIG_SCHEME(),
        newSigningKey.creationTicket);

    //
    // Send the PCR quote and key certification to the server
    //

    ServerRegisterKey(
        decryptedSecret,
        restrictedPub,
        pcrVals,
        quote,
        newSigningKey.creationData,
        createQuote);

    //
    // Sign a message with the user key
    //

    std::string clientMessage("some message or telemetry data");
    ByteVec messageHash = TPMT_HA::FromHashOfString(
        TPM_ALG_ID::SHA1, clientMessage).digest;
    auto signature = tpm.Sign(
        keyToCertify,
        messageHash,
        TPMS_NULL_SIG_SCHEME(),
        TPMT_TK_HASHCHECK::NullTicket());

    cout << "Client: message signature: " << signature.ToString(false) << endl;

    //
    // Send the signed message to the server
    //

    ServerReceiveMessage(
        userSigningPub,
        clientMessage,
        *signature.signature);

    //
    // Save the message signing key to be reused until the PCR(s) change(s)
    //

    // TODO
    
    //
    // Close handles 
    //

    tpm.FlushContext(keyToCertify);
    tpm.FlushContext(primaryKey);
    tpm.FlushContext(restrictedKey);
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

