//
// Created by iacopo on 29/08/20.
//

#ifndef ALL_DIFFIEHELLMANNMANAGER_H
#define ALL_DIFFIEHELLMANNMANAGER_H

#include<iostream>
#include<string>
#include<cstdio>
#include<cstring>
#include<openssl/pem.h>
#include<openssl/evp.h>
#include<openssl/rand.h>
#include<openssl/err.h>

class DiffieHellmannManager {
private:
    EVP_PKEY* peerPubKey;
    EVP_PKEY* myPubKey;
    size_t secret_len;
    unsigned char* sharedSecret;
    void computeSharedSecret();
public:
    DiffieHellmannManager();
    ~DiffieHellmannManager();
    void setPeerPubKey(unsigned char*,size_t);
    unsigned char* getMyPubKey(size_t & );
    unsigned char* getSharedSecret(size_t&);
};


#endif //ALL_DIFFIEHELLMANNMANAGER_H
