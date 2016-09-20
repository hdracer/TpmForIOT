# TpmForIoT
This project uses the TPM (Trusted Platform Module) for strong IoT (Internet of Things) device identity, firmware anti-tampering, and secure messaging. 

Written in C++, TpmForIoT compiles and runs on both Linux and Windows. Please see below for sample output from the command-line program. Although the demonstration is single-threaded, it is structured to show how an IoT device can interact with a trusted server. The device-to-server interaction is a cryptographic challenge-response protocol that accomplishes several useful things: device identity based on a manufacturer whitelist, firmware thumbprinting, distribution of a per-device secret (for example, a cloud API key), and creation of a non-exportable general purpose assymetric key usable for message signing (or any PKI-based application).

```
>TpmForIotTst.exe
Client: open a handle to the TPM Endorsement Key (EK)...
Client: open a handle to the TPM Storage Root Key (SRK)...
Client: create a restricted key: 000403ff 81bd4e76 dfd32d1e 6432e41a fc1a6b67 a1ad
Server: assume Endorsement Key is trusted: 00040dda 694b64b9 3a49286d ef6be3f6 04ffdc9b 52ed
Server: secret is: 85dc1f20 2dce70dc 8fa32d60 59ebdad2
Server: creating activation challenge for this key: 000403ff 81bd4e76 dfd32d1e 6432e41a fc1a6b67 a1ad
Client: decrypted secret: 85dc1f20 2dce70dc 8fa32d60 59ebdad2
Client: create a general purpose signing key on the TPM...
Server: assume quoted PCR is correct: 0b34fb38 e564ae46 d2dd635f 40cca6ba a6cf00dc
Server: assume restricted key matches previous activation: 000403ff 81bd4e76 dfd32d1e 6432e41a fc1a6b67 a1ad
Server: PCR quote is valid
Server: PCR digest for new key is correct
Server: quote is valid for this key: 00046e5b d94732b6 26ba345d 0991ba6c a23cdcfc 97f0
Client: message hash: c93ee7a5 2c78653c c5836f5b 5db1fe53 b9f3219e
Server: assume previous registration of this key: 00046e5b d94732b6 26ba345d 0991ba6c a23cdcfc 97f0
Server: message received and verified
```
