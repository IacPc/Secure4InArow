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

class SymmetricEncryptionManager {
private:
    HMACManager* hmacManager;
    AESManager* aesManager;
public:
    SymmetricEncryptionManager(unsigned char*, unsigned char*, unsigned char*);
    SymmetricEncryptionManager();
    unsigned char* computeMac(unsigned char*, size_t &);
    bool verifyMac(unsigned char*,unsigned char*, size_t &);
    unsigned char* decryptNVerifyMACThisMessage(unsigned char*, size_t &);
    unsigned char* encryptNMACThisMessage(unsigned char*, size_t&);
    unsigned char* getAESKey();
    unsigned char* getHMacKey();
    unsigned char* getIV();
    void setAESKey(unsigned char *k);
    void setAESIV(unsigned char *k);
    void sethmacKey(unsigned char*);

};


#endif //PROGETTO_SYMMETRICENCRYPTIONMANAGER_H
