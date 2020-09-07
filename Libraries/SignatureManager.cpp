#include "SignatureManager.h"


SignatureManager::SignatureManager(std::string *prvkey_file_name) {
    if (prvkey_file_name) {

        FILE* prvkey_file = fopen(prvkey_file_name->c_str(), "r");

        if (prvkey_file == nullptr) {
            std::cout << "Error: cannot open file '" << prvkey_file_name->c_str() << "' (missing?)\n";
            return;
        }

        EVP_PKEY* pv = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
        fclose(prvkey_file);
        while(!pv){
            std::cout << "Error: PEM_read_PrivateKey returned NULL. Try again"<<std::endl;
            prvkey_file = fopen(prvkey_file_name->c_str(), "r");
            pv = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
            fclose(prvkey_file);
        }

        std::cout << "private key set correctly" << std::endl;
        this->prvKey = pv;
    }else
        std::cout << "private key left empty" << std::endl;

}

SignatureManager::SignatureManager() {
    this->prvKey = nullptr;
    this->pubKey = nullptr;
}

unsigned char *SignatureManager::signTHisMessage(unsigned char *messageToBeSigned, size_t &messageToBeSignedLength) {

    EVP_MD_CTX *signatureCTX = EVP_MD_CTX_new();
    if (!signatureCTX) {
        std::cerr << "Error: EVP_MD_CTX_new returned NULL\n";
        messageToBeSignedLength = 0;
        return nullptr;
    }
    if(!this->prvKey){
        std::cerr << "private key is NULL in Signature Manager\n";
        return nullptr;
    }
    auto *sgnt_buf = new unsigned char[EVP_PKEY_size(this->prvKey)];
    unsigned int sgnt_size;
    int ret;

    ret = EVP_SignInit(signatureCTX, this->hashMD);
    if (ret == 0) {
        std::cerr << "Error: EVP_SignInit returned " << ret << "\n";
        goto SIGNINGERROR;
    }
    ret = EVP_SignUpdate(signatureCTX, messageToBeSigned, messageToBeSignedLength);
    if (ret == 0) {
        std::cerr << "Error: EVP_SignUpdate returned " << ret << "\n";
        goto SIGNINGERROR;
    }

    ret = EVP_SignFinal(signatureCTX, sgnt_buf, &sgnt_size, this->prvKey);
    if (ret == 0) {
        std::cerr << "Error: EVP_SignFinal returned " << ret << "\n";
        ERR_print_errors_fp(stdout);
        goto SIGNINGERROR;
    }

    messageToBeSignedLength = sgnt_size;
    return sgnt_buf;

    SIGNINGERROR:
    EVP_MD_CTX_free(signatureCTX);
    delete [] sgnt_buf;
    messageToBeSignedLength = 0;
    return nullptr;
}

bool SignatureManager::verifyThisSignature(unsigned char* signature, size_t signatureLen,
                                           unsigned char* messageToVerify, size_t messageToVerifyLength) {

    int ret; // used for return values
    EVP_MD_CTX* md_ctx;
    md_ctx= EVP_MD_CTX_new();
    if(!md_ctx)
        return false;

    ret = EVP_VerifyInit(md_ctx, this->hashMD);

    if(ret == 0){ std::cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; }
    ret = EVP_VerifyUpdate(md_ctx, messageToVerify, messageToVerifyLength);

    if (ret == 0) {
        std::cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n";
    }

    if(!this->pubKey)
        std::cerr << "no pubkey " << ret << "\n";

    ret = EVP_VerifyFinal(md_ctx, signature, signatureLen, this->pubKey);

    return (ret == 1);
}


void SignatureManager::setPubkey(EVP_PKEY* pb) {
    this->pubKey = pb;
}

SignatureManager::~SignatureManager() {
    EVP_PKEY_free(this->pubKey);
    EVP_PKEY_free(this->prvKey);

}

unsigned char *SignatureManager::getPubkey(size_t& pblen) {
    unsigned char* i2dbuff = NULL;
    int size = i2d_PUBKEY(this->pubKey, &i2dbuff);

    if(size <= 0 ){
        std::cout<<"i2d_PUBKEY failed"<<std::endl;
        return nullptr;
    }
    pblen = size;
    std::cout<<"Serialized key length is:"<< size<<std::endl;
    return i2dbuff;
}

EVP_PKEY* SignatureManager::getPrvkey() {
    return this->prvKey;
}
