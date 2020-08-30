//
// Created by iacopo on 14/08/20.
//

#ifndef PROGETTO_SIGNATUREMANAGER_H
#define PROGETTO_SIGNATUREMANAGER_H
#include<iostream>
#include<string>
#include<cstdio>
#include<cstring>
#include<openssl/pem.h>
#include<openssl/evp.h>
#include<openssl/rand.h>
#include<openssl/err.h>

class SignatureManager {
private:
    const EVP_MD* hashMD = EVP_sha256();
    EVP_PKEY* prvKey; // contains the prvKey of the entity(server or client) who owns the instance of this class
    EVP_PKEY* pubKey; // contains the server pubKey in order to verify his signature (server ha this field NULL)
public:
    SignatureManager(std::string*,std::string*);
    SignatureManager(std::string*);
    explicit SignatureManager(EVP_PKEY*,EVP_PKEY*);

    SignatureManager();
    ~SignatureManager();
    unsigned char* signTHisMessage(unsigned char*, size_t&);
    bool verifyThisSignature(unsigned char* signature, size_t signatureLen,
                             unsigned char* messageToVerify, size_t messageToVerifyLength);
    void setPubkey(EVP_PKEY*);
    void setPrvkey(EVP_PKEY*);
    unsigned char* getPubkey(size_t&);
    void setPrvkey(std::string*);

};


#endif //PROGETTO_SIGNATUREMANAGER_H
