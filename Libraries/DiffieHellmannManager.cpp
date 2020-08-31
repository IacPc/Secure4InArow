//
// Created by iacopo on 29/08/20.
//

#include "DiffieHellmannManager.h"

DiffieHellmannManager::DiffieHellmannManager() {
    EVP_PKEY_CTX *pctx, *kctx;
    EVP_PKEY* params= NULL;


    /* Create the context for parameter generation */
    if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
        std::cout<<"EVP_PKEY_CTX_new_id returned NULL"<<std::endl;
        return;
    }

    /* Initialise the parameter generation */
    if(1 != EVP_PKEY_paramgen_init(pctx)) {
        std::cout<<"EVP_PKEY_paramgen_init returned NULL"<<std::endl;
        return;
    }

    /* We're going to use the ANSI X9.62 Prime 256v1 curve */
    if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)){
        std::cout<<"error in generating parameters"<<std::endl;
        return;
    }

    /* Create the parameter object params */
    if (!EVP_PKEY_paramgen(pctx, &params)){
        std::cout<<"error in creating parameters"<<std::endl;
        return;
    }

    /* Create the context for the key generation */
    if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))){
        std::cout<<"error in the context for the key generation"<<std::endl;
        return;
    }

    /* Generate the key */
    if(1 != EVP_PKEY_keygen_init(kctx)) {
        std::cout<<"error in key generation init"<<std::endl;
        return;
    }

    this->myPubKey = NULL;
    if (1 != EVP_PKEY_keygen(kctx, &this->myPubKey)) {
        std::cout<<"error in key generation"<<std::endl;
        return;
    }

    std::cout<<"DH keys generated correctly"<<std::endl;
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);
    this->peerPubKey = nullptr;
}

void DiffieHellmannManager::computeSharedSecret() {
    EVP_PKEY_CTX* ctx = NULL;

    /* Create the context for the shared secret derivation */
    if(NULL == (ctx = EVP_PKEY_CTX_new(this->myPubKey, NULL))) {
        std::cout<<"EVP_PKEY_CTX_new returned NULL"<<std::endl;
        return ;
    }

    /* Initialise */
    if(1 != EVP_PKEY_derive_init(ctx)){
        std::cout<<"Error in initialization"<<std::endl;
        EVP_PKEY_CTX_free(ctx);
        return ;
    }
    std::cout<<"1"<<std::endl;
    /* Provide the peer public key */
    if(1 != EVP_PKEY_derive_set_peer(ctx, this->peerPubKey)){
        std::cout<<"Error in Providing the peer public key"<<std::endl;
        EVP_PKEY_CTX_free(ctx);
        return ;
    }
    std::cout<<"2"<<std::endl;
    /* Determine buffer length for shared secret */
    if(1 != EVP_PKEY_derive(ctx, NULL, &this->secret_len)) {
        std::cout<<"Error in Determining buffer length for shared secret"<<std::endl;
        EVP_PKEY_CTX_free(ctx);
        return ;
    }
    std::cout<<"3"<<std::endl;
    this->sharedSecret = new unsigned char[this->secret_len];
    std::cout<<"4"<<std::endl;
    /* Derive the shared secret */
    if(1 != (EVP_PKEY_derive(ctx, this->sharedSecret, &this->secret_len))){
        std::cout<<"Error in Determining buffer length for shared secret"<<std::endl;
        EVP_PKEY_CTX_free(ctx);
        delete [] this->sharedSecret;
        return ;
    }
    std::cout<<"shared secret computed succesfully"<<std::endl;
    std::cout<<"5"<<std::endl;
    EVP_PKEY_CTX_free(ctx);
}

unsigned char *DiffieHellmannManager::getMyPubKey(size_t & pklen) {

    BIO *mbio = BIO_new(BIO_s_mem());
    if(!mbio){
        std::cout<<"mbio is NULL"<<std::endl;
        return nullptr;
    }
    PEM_write_bio_PUBKEY(mbio, this->myPubKey);
    unsigned char* pubkey_buf;
    long pubkey_size = BIO_get_mem_data(mbio, &pubkey_buf);
    BIO_free(mbio);
    pklen = pubkey_size;
    return pubkey_buf;

}

unsigned char *DiffieHellmannManager::getSharedSecret(size_t & len) {
    len = this->secret_len;
    return this->sharedSecret;
}

void DiffieHellmannManager::setPeerPubKey(unsigned char* pubkey_buf, size_t pubkey_size) {
    BIO *mbio = BIO_new(BIO_s_mem());
    if(!mbio){
        std::cout<<"mbio is NULL"<<std::endl;
        return;
    }
    int ret = BIO_write(mbio, pubkey_buf, pubkey_size);
    std::cout<<"BIO_write returned "<<ret<<std::endl;
    this->peerPubKey = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);

    std::cout<<pubkey_size<<std::endl;
    if (!this->peerPubKey)
        std::cout<<"PEM_read_bio_PUBKEY returned NULL"<<std::endl;
    BIO_free(mbio);
    this->computeSharedSecret();
}

DiffieHellmannManager::~DiffieHellmannManager() {
    memset(this->sharedSecret,0X00,this->secret_len);
    delete [] this->sharedSecret;
    EVP_PKEY_free(this->peerPubKey);
    EVP_PKEY_free(this->myPubKey);
}

EVP_PKEY *DiffieHellmannManager::getMyPubKey_EVP() {
    return this->myPubKey;
}
