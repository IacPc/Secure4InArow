//
// Created by iacopo on 14/08/20.
//

#ifndef PROGETTO_SYMMETRICENCRYPTIONMANAGER_H
#define PROGETTO_SYMMETRICENCRYPTIONMANAGER_H
#include<iostream>
#include<string>
#include<cstdio>
#include<cstring>
#include<openssl/pem.h>
#include<openssl/evp.h>
#include<openssl/rand.h>
#include<openssl/err.h>
#include "Constant.h"

class SymmetricEncryptionManager {
private:
    const EVP_CIPHER* cipher = EVP_aes_128_gcm();
    unsigned char* aesKey;
    size_t aesKeyLen;
public:
    SymmetricEncryptionManager(unsigned char*, size_t);
    ~SymmetricEncryptionManager();
    unsigned char* encryptThisMessage(unsigned char *, size_t& ,unsigned char *, size_t ,
                                      unsigned char* ,size_t& ,unsigned char*& );
    unsigned char* decryptThisMessage(unsigned char *ciphertext, size_t &ciphertext_len,
                                      unsigned char *aad, size_t aad_len,
                                      unsigned char *tag, unsigned char *iv);


};


#endif //PROGETTO_SYMMETRICENCRYPTIONMANAGER_H
