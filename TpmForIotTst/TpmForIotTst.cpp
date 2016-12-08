#include "stdafx.h"

#include "TpmForIotPolicy.h"

using namespace TpmCpp;

#define TPM_FOR_IOT_HASH_ALG TPM_ALG_ID::SHA1

#define TRY_FAILING_PCR true

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
    TPMT_PUBLIC storagePrimaryTemplate(TPM_FOR_IOT_HASH_ALG,
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
        TPM_FOR_IOT_HASH_ALG,
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
        TPM_FOR_IOT_HASH_ALG,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent |
        TPMA_OBJECT::fixedTPM | TPMA_OBJECT::sensitiveDataOrigin |
        TPMA_OBJECT::userWithAuth | restrictedAttribute,
        NullVec,  // No policy
        TPMS_RSA_PARMS(
            TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::_NULL, 0, TPM_ALG_ID::_NULL),
            TPMS_SCHEME_RSASSA(TPM_FOR_IOT_HASH_ALG), 2048, 65537), // PKCS1.5
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

void ShowTpmCapabilities(_TPMCPP Tpm2 &tpm)
{
    UINT32 startVal = 0;
 
    //
    // Manufacturer information
    // See also https://github.com/ms-iot/security/blob/master/Urchin/T2T/T2T.cpp
    //

    do {
        GetCapabilityResponse caps = tpm.GetCapability(TPM_CAP::TPM_PROPERTIES, startVal, 8);
        TPML_TAGGED_TPM_PROPERTY *props = dynamic_cast<TPML_TAGGED_TPM_PROPERTY *> (caps.capabilityData);

        // Print name and value
        for (auto p = props->tpmProperty.begin(); p != props->tpmProperty.end(); p++) {
            char *pCharValue = (char *)&p->value;
            cout << Tpm2::GetEnumString(p->property) << ": ";
            switch (p->property)
            {
            case TPM_PT::FAMILY_INDICATOR:
            case TPM_PT::MANUFACTURER:
            case TPM_PT::VENDOR_STRING_1:
            case TPM_PT::VENDOR_STRING_2:
            case TPM_PT::VENDOR_STRING_3:
            case TPM_PT::VENDOR_STRING_4:
                cout << pCharValue[3] << pCharValue[2] << pCharValue[1] << pCharValue[0];
                break;
            default:
                cout << p->value;
                break;
            }
            cout << endl;
        }

        if (!caps.moreData) {
            break;
        }

        startVal = ((UINT32)props->tpmProperty[props->tpmProperty.size() - 1].property) + 1;
    } while (true);
    cout << endl;

    //
    // Cryptographic capabilities
    //

    cout << "Algorithms:" << endl;
    startVal = 0;
    do {
        GetCapabilityResponse caps = tpm.GetCapability(TPM_CAP::ALGS, startVal, 8);
        TPML_ALG_PROPERTY *props = dynamic_cast<TPML_ALG_PROPERTY *> (caps.capabilityData);

        // Print alg name and properties
        for (auto p = props->algProperties.begin(); p != props->algProperties.end(); p++) {
            cout << setw(16) << Tpm2::GetEnumString(p->alg) <<
                ": " << Tpm2::GetEnumString(p->algProperties) << endl;
        }

        if (!caps.moreData) {
            break;
        }

        startVal = ((UINT32)props->algProperties[props->algProperties.size() - 1].alg) + 1;
    } while (true);
    cout << endl;
}

TSS_KEY* g_pAuthorityKey;

void ServerStart()
{
    ByteVec NullVec(0);

    TPMT_PUBLIC authorityTempl = TPMT_PUBLIC(TPM_FOR_IOT_HASH_ALG,
        TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth,
        NullVec,
        TPMS_RSA_PARMS(
            TPMT_SYM_DEF_OBJECT::NullObject(),
            TPMS_SCHEME_RSASSA(TPM_FOR_IOT_HASH_ALG), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA(NullVec));
    
    g_pAuthorityKey = new TSS_KEY();

    g_pAuthorityKey->publicPart = authorityTempl;
    g_pAuthorityKey->CreateKey();
}

void ServerStop()
{
    delete g_pAuthorityKey;
}

bool ServerGetAuthorityPublicKey(TPMT_PUBLIC& authorityPubKey)
{
    if (NULL == g_pAuthorityKey)
    {
        return false;
    }

    authorityPubKey = g_pAuthorityKey->publicPart;

    return true;
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
    //

    cout << "Server: assume Endorsement Key is trusted: " << clientEkPub.GetName() << endl;

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
    cout << "Server: secret is: " << secret << endl;
    cout << "Server: creating activation challenge for this key: " << nameOfKeyToActivate << endl;
    return clientEkPub.CreateActivation(
        secret,
        TPM_FOR_IOT_HASH_ALG,
        nameOfKeyToActivate);
}

void ServerRegisterKey(
    ByteVec &serverSecret, 
    TPMT_PUBLIC &clientRestrictedPub,
    PCR_ReadResponse &clientPcrVals,
    TPMS_CREATION_DATA &clientKeyCreation,
    CertifyCreationResponse &clientKeyQuote)
{

    //
    // Confirm that the client restricted public is the same key that the 
    // server activated in the previous call
    //

    cout << "Server: assume restricted key matches previous activation: " << clientRestrictedPub.GetName() << endl;

    if (clientPcrVals.pcrSelectionOut != clientKeyCreation.pcrSelect)
    {
        cout << "Server: PCR Selection did not match." << endl;
        exit(1);
    }

    //
    // For the new child key, hash the creation data
    //

    ByteVec creationHash = TPMT_HA::FromHashOfData(
        TPM_FOR_IOT_HASH_ALG, clientKeyCreation.ToBuf()).digest;

    // 
    // Check the key quote signature
    //

    bool sigOk = clientRestrictedPub.ValidateCertifyCreation(serverSecret,
                                                             creationHash,
                                                             clientKeyQuote);

    TPMS_ATTEST cAttest = clientKeyQuote.certifyInfo;
    TPMS_CREATION_INFO *cInfo = dynamic_cast<TPMS_CREATION_INFO *> (cAttest.attested);
    if (sigOk) {
        cout << "Server: quote is valid for this key: " << cInfo->objectName << endl;
    }
    else {
        cout << "Server: key creation certification/quote is invalid" << endl;
        exit(1);
    }



}

PolicyTree ServerIssueLicense(
    ByteVec &serverSecret,
    TPMT_PUBLIC &clientRestrictedPub,
    PCR_ReadResponse &clientPcrVals,
    QuoteResponse &clientPcrQuote)
{
    //
    // Confirm that the provided PCR hash is as expected for this particular 
    // client device. On Windows, an attested boot log can be used instead. On 
    // Linux, this procedure requires whitelisting.
    //

    TPMS_ATTEST qAttest = clientPcrQuote.quoted;
    TPMS_QUOTE_INFO *qInfo = dynamic_cast<TPMS_QUOTE_INFO *> (qAttest.attested);
    cout << "Server: assume quoted PCR is correct: " << qInfo->pcrDigest << endl;

    //
    // Confirm that the client restricted public is the same key that the 
    // server activated in the previous call
    //

    cout << "Server: assume restricted key matches previous activation: " << clientRestrictedPub.GetName() << endl;

    //
    // Check the PCR quote signature
    //

    bool sigOk = clientRestrictedPub.ValidateQuote(
        clientPcrVals, serverSecret, clientPcrQuote);
    if (sigOk) {
        cout << "Server: PCR quote is valid" << endl;
    }
    else {
        cout << "Server: PCR quote is invalid" << endl;
        exit(1);
    }

    return GeneratePolicy(*g_pAuthorityKey, clientPcrVals.pcrValues, qInfo->pcrSelect);
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

    cout << "Server: assume previous registration of this key: " << clientSigningPub.GetName() << endl;

    //
    // Hash the message
    //

    ByteVec messageHash = TPMT_HA::FromHashOfString(
        TPM_FOR_IOT_HASH_ALG, clientMessage).digest;

    //
    // Check the signature
    //

    bool sigOk = clientSigningPub.ValidateSignature(
        messageHash, messageSig);
    if (sigOk) {
        cout << "Server: message received and verified" << endl;
    }
    else {
        cout << "Server: message signature verification failed" << endl;
        exit(1);
    }

    //
    // Process the message, as appropriate for the host app, based on whether 
    // the signature is valid and from a trusted device
    //

    // TODO
}

void
ClientSignMessage(
    Tpm2 &tpm,
    TPM_HANDLE &contentKey,
    PolicyTree &p,
    const std::string &clientMessage,
    ByteVec &messageHash,
    SignResponse &sign
)
{
    //
    // Sign a message with the user key
    //

    cout << "Executing policy tree... ";

    AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_FOR_IOT_HASH_ALG);

    s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_FOR_IOT_HASH_ALG);

    p.Execute(tpm, s);

    cout << "done." << endl;

    cout << "Policy digest from auth Session " << tpm.PolicyGetDigest(s) << endl;

    messageHash = TPMT_HA::FromHashOfString(TPM_FOR_IOT_HASH_ALG, clientMessage).digest;
    sign = tpm._Sessions(s).Sign(   contentKey,
                                    messageHash,
                                    TPMS_NULL_SIG_SCHEME(),
                                    TPMT_TK_HASHCHECK::NullTicket());

    tpm.FlushContext(s);

    cout << "done." << endl;

    cout << "Client: message hash: " << messageHash << endl;

}

ActivationData ServerGetActivationWire(
    ByteVec &bufClientEkPub,
    ByteVec &nameOfKeyToActivate)
{
    TPMT_PUBLIC clientEkPub;
    
    clientEkPub.FromBuf(bufClientEkPub);

    return ServerGetActivation(clientEkPub, nameOfKeyToActivate);
}

void ServerRegisterKeyWire(
    ByteVec &bufServerSecret,
    ByteVec &bufClientRestrictedPub,
    ByteVec &bufClientPcrVals,
    ByteVec &bufClientKeyCreation,
    ByteVec &bufClientKeyQuote)
{
    TPMT_PUBLIC clientRestrictedPub;
    PCR_ReadResponse clientPcrVals;
    TPMS_CREATION_DATA clientKeyCreation;
    CertifyCreationResponse clientKeyQuote;

    clientRestrictedPub.FromBuf(bufClientRestrictedPub);
    clientPcrVals.FromBuf(bufClientPcrVals);
    clientKeyCreation.FromBuf(bufClientKeyCreation);
    clientKeyQuote.FromBuf(bufClientKeyQuote);

    ServerRegisterKey(bufServerSecret,
                      clientRestrictedPub,
                      clientPcrVals,
                      clientKeyCreation,
                      clientKeyQuote);
}

/*
ByteVec ServerIssueLicenseWire(
    ByteVec bufServerSecret,
    ByteVec bufClientRestrictedPub,
    ByteVec bufClientPcrVals,
    ByteVec bufClientPcrQuote)
{
    TPMT_PUBLIC clientRestrictedPub;
    PCR_ReadResponse clientPcrVals;
    QuoteResponse clientPcrQuote;

    clientRestrictedPub.FromBuf(bufClientPcrQuote);
    clientPcrVals.FromBuf(bufClientPcrVals);
    clientPcrQuote.FromBuf(bufClientPcrQuote);

    PolicyTree p = ServerIssueLicense(bufServerSecret,
                                      clientRestrictedPub,
                                      clientPcrVals,
                                      clientPcrQuote);
    
}
*/

LPCWSTR l_pwszServerCertHash = L"5a9c2c4f3639185eacc306096dfc87e5a97ac799";

PCCERT_CONTEXT LoadServerCertificate()
{
    BYTE rgbHash[64] = { 0 };
    DATA_BLOB dbServerCert = { sizeof(rgbHash), rgbHash};

    HCERTSTORE hStore = NULL;

    PCCERT_CONTEXT pCert = NULL;

    DWORD rc = 0;

    //
    // Find the server certificate in a local store
    //

    if (FALSE == CryptStringToBinary(l_pwszServerCertHash,
                                     0,
                                     CRYPT_STRING_HEX,
                                     dbServerCert.pbData,
                                     &dbServerCert.cbData,
                                     NULL,
                                     NULL))
    {
        rc = GetLastError();
        cerr << "CryptStringToBinary returend error " << rc << endl;
        goto Cleanup;
    }

    if (NULL == (hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                        0,
                                        NULL,
                                        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
                                        L"MY")))
    {
        rc = GetLastError();
        cerr << "CertOpenStore returend error " << rc << endl;
        goto Cleanup;
    }

    if (NULL == (pCert = CertFindCertificateInStore(hStore,
                                                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                    0,
                                                    CERT_FIND_SHA1_HASH,
                                                    &dbServerCert,
                                                    NULL)))
    {
        rc = GetLastError();
        cerr << "CertFindCertificateInStore returend error " << rc << endl;
        goto Cleanup;
    }

Cleanup:

    if (hStore)
    {
        CertCloseStore(hStore, 0);
    }

    return pCert;
}

TPMT_PUBLIC ConvertCertificateToTPMTPub(PCCERT_CONTEXT pCert)
{
    BCRYPT_KEY_HANDLE hKey = NULL;

    TPMT_PUBLIC pubKey;

    BCRYPT_RSAKEY_BLOB *pBlobHdr = NULL;

    PBYTE pbBlob = NULL;
    DWORD cbBlob = 0;

    PBYTE pbRSAKeyStart = NULL;
    PBYTE pbRSAKeyEnd = NULL;

    UINT32 result;

    vector<BYTE> NullVec;

    if (!CryptImportPublicKeyInfoEx2(pCert->dwCertEncodingType, &(pCert->pCertInfo->SubjectPublicKeyInfo), 0, NULL, &hKey))
    {
        cerr << "CryptImportPublicKeyInfoEx2 returned 0x" << hex << GetLastError() << endl;
        goto Exit;
    }

    result = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &cbBlob, 0);
    if (FAILED(result))
    {
        cerr << "" << endl;
        goto Exit;
    }

    pbBlob = (PBYTE)malloc(cbBlob);
    if (NULL == pbBlob)
    {
        cerr << "Allocating public key buffer failed." << endl;
        goto Exit;
    }

    result = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, pbBlob, cbBlob, &cbBlob, 0);
    if (FAILED(result))
    {
        cerr << "" << endl;
        goto Exit;
    }

    pBlobHdr = (BCRYPT_RSAKEY_BLOB*)pbBlob;

    pbRSAKeyStart = &pbBlob[sizeof(BCRYPT_RSAKEY_BLOB) + pBlobHdr->cbPublicExp];
    pbRSAKeyEnd = pbRSAKeyStart + pBlobHdr->cbModulus;

    pubKey = TPMT_PUBLIC(TPM_FOR_IOT_HASH_ALG,
                         TPMA_OBJECT::decrypt | TPMA_OBJECT::sign,
                         NullVec,
                         TPMS_RSA_PARMS(TPMT_SYM_DEF_OBJECT::NullObject(),
                                        TPMS_SCHEME_RSASSA(TPM_FOR_IOT_HASH_ALG), 2048, 65537),
                         TPM2B_PUBLIC_KEY_RSA(vector<BYTE>(pbRSAKeyStart, pbRSAKeyEnd)));

Exit:

    if (pbBlob)
    {
        free(pbBlob);
    }

    return pubKey;
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
    // List certain TPM capabilities for lab testing
    //

    ShowTpmCapabilities(tpm);

    //
    // Read out the manufacturer Endorsement Key (EK)
    //

    cout << "Client: open a handle to the TPM Endorsement Key (EK)..." << endl;
    TPM_HANDLE ekHandle = MakeEndorsementKey(tpm);
    auto ekPubX = tpm.ReadPublic(ekHandle);
    TPMT_PUBLIC& ekPub = ekPubX.outPublic;

    //
    // Create a restricted key in the storage hierarchy
    //

    cout << "Client: open a handle to the TPM Storage Root Key (SRK)..." << endl;
    TPM_HANDLE primaryKey = MakeStoragePrimary(tpm);
    cout << "Client: create a restricted key: ";
    TPM_HANDLE restrictedKey = MakeChildSigningKey(tpm, primaryKey, true);
    auto restrictedPubX = tpm.ReadPublic(restrictedKey);
    TPMT_PUBLIC& restrictedPub = restrictedPubX.outPublic;
    cout << restrictedPub.GetName() << endl;

    ServerStart();

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
    cout << "Client: decrypted secret: " << decryptedSecret << endl;

    //
    // Optionally, save the AIK, since it can be reused across reboots
    //

    // TODO

    //
    // Read PCR data
    //

    //auto pcrsToQuote_Create = TPMS_PCR_SELECTION::GetSelectionArray(TPM_FOR_IOT_HASH_ALG, 7);
    auto pcrsToQuote_Create = vector<TPMS_PCR_SELECTION>();
    PCR_ReadResponse pcrVals_Create = tpm.PCR_Read(pcrsToQuote_Create);

    //
    // Sign the PCR hash with the AIK
    //

    QuoteResponse quote_Create = tpm.Quote(
        restrictedKey, decryptedSecret, TPMS_NULL_SIG_SCHEME(), pcrsToQuote_Create);
    
    TPMT_PUBLIC authorityPubKey;

    if (!ServerGetAuthorityPublicKey(authorityPubKey))
    {
        cout << "Getting Authority Pub Key failed" << endl;
    }

    ByteVec policyAuthDigest = GeneratePolicyAuthorizeDigest(authorityPubKey);

    //
    // Create a user signing-only key in the storage hierarchy. 
    //

    TPMT_PUBLIC templ(TPM_FOR_IOT_HASH_ALG,
        TPMA_OBJECT::sign |           // Key attributes
        TPMA_OBJECT::fixedParent |
        TPMA_OBJECT::fixedTPM |
        TPMA_OBJECT::sensitiveDataOrigin |
        TPMA_OBJECT::adminWithPolicy,
        policyAuthDigest,
        TPMS_RSA_PARMS(
            TPMT_SYM_DEF_OBJECT::NullObject(),
            TPMS_SCHEME_RSASSA(TPM_FOR_IOT_HASH_ALG), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA(NullVec));

    //
    // Include the same PCR selection as above
    //

    cout << "Client: create a general purpose signing key on the TPM..." << endl;

    CreateResponse newSigningKey = tpm.Create(
        primaryKey,
        TPMS_SENSITIVE_CREATE(NullVec, NullVec),
        templ,
        NullVec,
        pcrsToQuote_Create);

    //
    // Load the new key
    //

    cout << "Client: loading the new key..." << endl;

    TPM_HANDLE keyToCertify = tpm.Load(
        primaryKey,
        newSigningKey.outPrivate,
        newSigningKey.outPublic);
    auto userSigningPubX = tpm.ReadPublic(keyToCertify);
    TPMT_PUBLIC &userSigningPub = userSigningPubX.outPublic;

    //
    // Certify the creation of the user key using the AIK
    //

    cout << "Client: certifying the new key..." << endl;

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
        pcrVals_Create,
        newSigningKey.creationData,
        createQuote);

    UINT32 resettablePcr = 16;

    tpm.PCR_Reset(TPM_HANDLE::PcrHandle(resettablePcr));

    auto pcrsToQuote = TPMS_PCR_SELECTION::GetSelectionArray(TPM_FOR_IOT_HASH_ALG, 7);
    pcrsToQuote.push_back(TPMS_PCR_SELECTION(TPM_FOR_IOT_HASH_ALG, resettablePcr));
    PCR_ReadResponse pcrVals = tpm.PCR_Read(pcrsToQuote);

    //
    // Sign the PCR hash with the AIK
    //

    QuoteResponse quote = tpm.Quote(
        restrictedKey, decryptedSecret, TPMS_NULL_SIG_SCHEME(), pcrsToQuote);

    PolicyTree p = ServerIssueLicense(
        decryptedSecret,
        restrictedPub,
        pcrVals,
        quote);

    std::string clientMessage("some message or telemetry data");

    ByteVec messageHash;

    SignResponse sign;

    ClientSignMessage(tpm,
        keyToCertify,
        p,
        clientMessage,
        messageHash,
        sign);

    //
    // Send the signed message to the server
    //

    ServerReceiveMessage(
        userSigningPub,
        clientMessage,
        *sign.signature);

    if (TRY_FAILING_PCR)
    {
        cout << "Changing resettable PCR and trying to use the policy and key." << endl;

        tpm.PCR_Event(TPM_HANDLE::PcrHandle(resettablePcr), ByteVec{ 1, 2, 3 });

        bool expected_error_seen = false;

        try {
            ClientSignMessage(tpm,
                keyToCertify,
                p,
                clientMessage,
                messageHash,
                sign);
        } catch (const system_error& e) {
            cout << "Unknown system error." << endl;
            cout << "\tsystem error message: " << e.what();
            cout << "\tsystem error code: " << e.code() << endl;
            expected_error_seen = true;
        } catch (const exception& e) {
            cout << "Unknown exception caught." << endl;
            cout << "\tException message: " << e.what() << endl;
        }

        if (expected_error_seen)
        {
            cout << "ClientSignMessage threw exception as expected." << endl;
        }
        else {
            cout << "ClientSignMessage did not throw exception as expected." << endl;
            exit(1);
        }

        cout << "Resetting PCR and trying again." << endl;
        tpm.PCR_Reset(TPM_HANDLE::PcrHandle(resettablePcr));

        ClientSignMessage(tpm,
            keyToCertify,
            p,
            clientMessage,
            messageHash,
            sign);

        cout << "Signing message after PCR Reset succeeded." << endl;
    }

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

    ServerStop();
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

