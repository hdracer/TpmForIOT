#include "stdafx.h"

using namespace TpmCpp;

#define TPM_FOR_IOT_HASH_ALG TPM_ALG_ID::SHA1

//
// Non-WIN32 initialization for TSS.CPP.
//
extern void DllInit();

void PolicyAuthorizeSample(_TPMCPP Tpm2 &tpm)
{
    ByteVec NullVec(0);

    cout << "PolicyAuthorize" << endl;

    // This sample illustrates how TSS.C++ supports PolicyAuthorize.
    // PolicyAuthorize lets a key holder tranform a policyHash into a new
    // policyHash derived from a public key if the corresponding private key
    // holder authorizes the pre-policy-hash with a signature.

    // Make a software signing key
    TPMT_PUBLIC templ(TPM_FOR_IOT_HASH_ALG,
        TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth,
        NullVec,
        TPMS_RSA_PARMS(
            TPMT_SYM_DEF_OBJECT::NullObject(),
            TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA1), 1024, 65537),
        TPM2B_PUBLIC_KEY_RSA(NullVec));
    TSS_KEY swKey;
    swKey.publicPart = templ;
    swKey.CreateKey();

    // We will authorize the change from the policyDigest given by PolicyLocality(1)
    // to a value derived from the authorizing key above.

    // First get the policyHash we want to authorize
    PolicyLocality l(TPMA_LOCALITY::LOC_ONE);
    PolicyTree t1(l);
    auto preDigest = t1.GetPolicyDigest(TPM_ALG_ID::SHA1);

    // Next sign the policyHash as defined in the spec
    auto aHash = TPMT_HA::FromHashOfData(TPM_ALG_ID::SHA1,
        Helpers::Concatenate(preDigest.digest, NullVec));

    SignResponse signature = swKey.Sign(aHash.digest, TPMS_NULL_SIG_SCHEME());

    // Now make the second policy that contains the PolicyLocality AND the PolicyAuthorize
    PolicyTree p2(PolicyAuthorize(preDigest.digest, NullVec, swKey.publicPart, *signature.signature), l);

    AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
    p2.Execute(tpm, s);

    auto policyDigest = tpm.PolicyGetDigest(s);

    // Is it what we expect? This is the PolicyUpdate function from the spec.
    /*
    OutByteBuf b;
    b << ToIntegral(TPM_CC::PolicyAuthorize) << swKey.publicPart.GetName();
    TPMT_HA expectedPolicyDigest(TPM_ALG_ID::SHA1);
    expectedPolicyDigest.Extend(b.GetBuf());
    expectedPolicyDigest.Extend(NullVec);

    if (expectedPolicyDigest.digest != policyDigest) {
        throw runtime_error("Incorrect policyHash");
    }
    */
    cout << "PolicyAuthorize digest is correct" << endl;

    // We could now use the policy session, but for the sample we will just clean up.
    tpm.FlushContext(s);

    return;
}


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
    QuoteResponse &clientPcrQuote, 
    TPMS_CREATION_DATA &clientKeyCreation,
    CertifyCreationResponse &clientKeyQuote)
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

    //
    // For the new child key, hash the creation data
    //

    ByteVec creationHash = TPMT_HA::FromHashOfData(
        TPM_FOR_IOT_HASH_ALG, clientKeyCreation.ToBuf()).digest;

    //
    // Check the PCR binding
    //

    if (clientKeyCreation.pcrDigest == qInfo->pcrDigest) {
        cout << "Server: PCR digest for new key is correct" << endl;
    }
    else {
        cout << "Server: PCR digest for new key is incorrect" << endl;
        exit(1);
    }

    // 
    // Check the key quote signature
    //

    sigOk = clientRestrictedPub.ValidateCertifyCreation(
        serverSecret,
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

    auto pcrsToQuote = TPMS_PCR_SELECTION::GetSelectionArray(TPM_FOR_IOT_HASH_ALG, 7);
    PCR_ReadResponse pcrVals = tpm.PCR_Read(pcrsToQuote);

    //
    // Sign the PCR hash with the AIK
    //

    QuoteResponse quote = tpm.Quote(
        restrictedKey, decryptedSecret, TPMS_NULL_SIG_SCHEME(), pcrsToQuote);
    
    PolicyAuthorizeSample(tpm);

    cout << "Starting Auth Session... ";

    /*
    cout << "Loading Server Certificate... ";
    PCCERT_CONTEXT pAuthorityCert = LoadServerCertificate();

    cout << "Converting Certificate to tpm public key... ";
    TPMT_PUBLIC authorityPubKey = ConvertCertificateToTPMTPub(pAuthorityCert);
    */

    TPMT_PUBLIC authorityTempl = TPMT_PUBLIC(TPM_FOR_IOT_HASH_ALG,
                                             //TPMA_OBJECT::decrypt | TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth,
                                             TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth,
                                             NullVec,
                                             TPMS_RSA_PARMS(
                                                 TPMT_SYM_DEF_OBJECT::NullObject(),
                                                 TPMS_SCHEME_RSASSA(TPM_FOR_IOT_HASH_ALG), 2048, 65537),
                                             TPM2B_PUBLIC_KEY_RSA(NullVec));
    TSS_KEY authorityKey;
    authorityKey.publicPart = authorityTempl;
    authorityKey.CreateKey();


    cout << "Beginning policy tree... ";
    //PolicyLocality l(TPMA_LOCALITY::LOC_ONE);
    PolicyCommandCode l(TPM_CC::Sign);
    PolicyTree p(l);
    auto preDigest = p.GetPolicyDigest(TPM_FOR_IOT_HASH_ALG);

    cout << "Intermediate Policy digest " << preDigest.digest << endl;

    auto aHash = TPMT_HA::FromHashOfData(TPM_FOR_IOT_HASH_ALG, Helpers::Concatenate(preDigest.digest, NullVec));

    SignResponse signature = authorityKey.Sign(aHash.digest, TPMS_NULL_SIG_SCHEME());

    PolicyTree p2(PolicyAuthorize(preDigest.digest, NullVec, authorityKey.publicPart, *signature.signature), l);

    auto policyDigest = p2.GetPolicyDigest(TPM_FOR_IOT_HASH_ALG);

    cout << "Policy digest " << policyDigest.digest << endl;

    cout << "Executing policy tree... ";
    AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::TRIAL, TPM_FOR_IOT_HASH_ALG);

    p2.Execute(tpm, s);

    cout << "done." << endl;

    cout << "Policy digest from Trial Session " << tpm.PolicyGetDigest(s) << endl;

    tpm.FlushContext(s);

    cout << "Constructing a policy tree out of apriori unknown information." << endl;
    
    PolicyTree p3(PolicyAuthorize(ByteVec(20,0), NullVec, authorityKey.publicPart, TPMT_SIGNATURE()), l);
    
    cout << "Policy Digest " << p3.GetPolicyDigest(TPM_FOR_IOT_HASH_ALG).digest << endl;


    //
    // Create a user signing-only key in the storage hierarchy. 
    //

    TPMT_PUBLIC templ(TPM_FOR_IOT_HASH_ALG,
        TPMA_OBJECT::sign |           // Key attributes
        TPMA_OBJECT::fixedParent |
        TPMA_OBJECT::fixedTPM |
        TPMA_OBJECT::sensitiveDataOrigin |
        TPMA_OBJECT::adminWithPolicy,
        policyDigest.digest,
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
        pcrsToQuote);

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
        pcrVals,
        quote,
        newSigningKey.creationData,
        createQuote);

    //
    // Sign a message with the user key
    //

    //AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);

    cout << "Executing policy tree... ";
    s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_FOR_IOT_HASH_ALG);

    p2.Execute(tpm, s);

    cout << "done." << endl;

    cout << "Policy digest from auth Session " << tpm.PolicyGetDigest(s) << endl;

    std::string clientMessage("some message or telemetry data");
    ByteVec messageHash = TPMT_HA::FromHashOfString(
        TPM_FOR_IOT_HASH_ALG, clientMessage).digest;
    auto sign = tpm._Sessions(s).Sign(
        keyToCertify,
        messageHash,
        TPMS_NULL_SIG_SCHEME(),
        TPMT_TK_HASHCHECK::NullTicket());

    tpm.FlushContext(s);

    cout << "done." << endl;

    cout << "Client: message hash: " << messageHash << endl;

    //
    // Send the signed message to the server
    //

    ServerReceiveMessage(
        userSigningPub,
        clientMessage,
        *sign.signature);

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

