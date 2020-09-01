//
// Created by iacopo on 14/08/20.
//

#include "SymmetricEncryptionManager.h"

SymmetricEncryptionManager::SymmetricEncryptionManager(unsigned char* key, size_t keylen) {

    this->aesKey = new unsigned char[keylen];
    this->aesKeyLen = keylen;
    memcpy(this->aesKey,key,this->aesKeyLen);

    RAND_poll();
}


unsigned char *
SymmetricEncryptionManager::encryptThisMessage(unsigned char *plaintext, size_t& plaintext_len, unsigned char *aad,
                                               size_t aad_len, unsigned char* iv, size_t& iv_len, unsigned char*& tag) {

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char* ciphertext = new unsigned char[plaintext_len + EVP_CIPHER_block_size(this->cipher)];
    iv_len = AESGCMIVLENGTH ;
    tag = new unsigned char[AESGCMTAGLENGTH];

    std::cout<<"encryptThisMessage"<<std::endl;
    BIO_dump_fp(stdout,(const char*) this->aesKey, AESKEYLENGTH);

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        std::cout<<" Error in creating the context for encryption"<<std::endl;
        goto ENCRYPTIONERROR;
    }
    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), this->aesKey, iv)) {
        std::cout<<"Error in Initialising the encryption operation"<<std::endl;
        goto ENCRYPTIONERROR;
    }
    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)){
        std::cout<<" Error in providing AAD"<<std::endl;
        goto ENCRYPTIONERROR;
    }



    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
        std::cout<<"Error in performing encryption"<<std::endl;
        goto ENCRYPTIONERROR;
    }
    ciphertext_len = len;
    //Finalize Encryption
    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len)){
        std::cout<<"Error in finalizing encryption"<<std::endl;
        goto ENCRYPTIONERROR;
    }
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AESGCMTAGLENGTH, tag)){
        std::cout<<"Error in retrieving the tag "<<std::endl;
        goto ENCRYPTIONERROR;
    }
    /* Clean up */

    EVP_CIPHER_CTX_free(ctx);
    plaintext_len = ciphertext_len;
    return ciphertext;

    ENCRYPTIONERROR:
    delete [] ciphertext;
    delete [] tag;
    aad_len = plaintext_len = iv_len = 0;
    EVP_CIPHER_CTX_cleanup(ctx);
    return nullptr;
}

unsigned char *
SymmetricEncryptionManager::decryptThisMessage(unsigned char *ciphertext, size_t &ciphertext_len, unsigned char *aad,
                                               size_t aad_len, unsigned char *tag, unsigned char *iv) {
    unsigned char * plaintext = new unsigned char[ciphertext_len];
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;
    std::cout<<"decryptThisMessage"<<std::endl;
    BIO_dump_fp(stdout,(const char*) this->aesKey, AESKEYLENGTH);

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
        std::cout<<" Error in creating the context for decryption"<<std::endl;
        goto DECRYPTIONERROR;
    }

    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), this->aesKey, iv)){
        std::cout<<"Error in Initialising the decryption operation"<<std::endl;
        goto DECRYPTIONERROR;
    }
    //Provide any AAD data.
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
        std::cout<<" Error in providing AAD"<<std::endl;
        goto DECRYPTIONERROR;
    }
    //Provide the message to be decrypted, and obtain the plaintext output.
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
        std::cout<<" Error in providing AAD"<<std::endl;
        goto DECRYPTIONERROR;
    }
    plaintext_len = len;
    /* Set expected tag value.*/
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AESGCMTAGLENGTH, tag)){
        std::cout<<" Error in providing AAD"<<std::endl;
        goto DECRYPTIONERROR;
    }
    /*
      Finalise the decryption. A positive return value indicates success,
      anything else is a failure,namely the plaintext is not trustworthy.
     */
    if((EVP_DecryptFinal(ctx, plaintext + len, &len)) <=0){
        std::cout<<" Error Plaintext not valid"<<std::endl;
        goto DECRYPTIONERROR;
    }

    plaintext_len += len;
    ciphertext_len = plaintext_len;
    EVP_CIPHER_CTX_cleanup(ctx);
    return plaintext;

    DECRYPTIONERROR:
        EVP_CIPHER_CTX_cleanup(ctx);
        delete [] plaintext;
        return nullptr;
}

SymmetricEncryptionManager::~SymmetricEncryptionManager() {
    memset(this->aesKey,0X00,this->aesKeyLen);
    delete [] this->aesKey;
}
