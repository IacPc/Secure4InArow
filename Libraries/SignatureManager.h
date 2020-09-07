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
    EVP_PKEY* pubKey; // contains the server/peer pubKey in order to verify his signature (server has this field NULL)
public:

    SignatureManager(std::string*);


     SignatureManager();
    ~SignatureManager();
    unsigned char* signTHisMessage(unsigned char*, size_t&);
    unsigned char* getPubkey(size_t&);
    bool verifyThisSignature(unsigned char* signature, size_t signatureLen,
                             unsigned char* messageToVerify, size_t messageToVerifyLength);
    void setPubkey(EVP_PKEY*);

    EVP_PKEY* getPrvkey();


};


#endif //PROGETTO_SIGNATUREMANAGER_H
