//
// Created by iacopo on 14/08/20.
//

#include "SignatureManager.h"

SignatureManager::SignatureManager(std::string* prvkey_file_name, std::string* pubkey_file_name) {

    EVP_PKEY* prvkey= nullptr;
    if (prvkey_file_name) {
        FILE *prvkey_file = fopen(prvkey_file_name->c_str(), "r");
        if (!prvkey_file) {
            std::cout << "Error: cannot open file '" << prvkey_file_name->c_str() << "' (missing?)\n";
        }

        std::string pwd;
        std::cout << "Enter your prvkey file password" << std::endl;
        getline(std::cin, pwd);
        prvkey = PEM_read_PrivateKey(prvkey_file, nullptr, NULL, (char *) pwd.c_str());
        while (!prvkey) {
            pwd.clear();
            std::cout << "Error:Enter your prvkey file password" << std::endl;
            getline(std::cin, pwd);
            prvkey = PEM_read_PrivateKey(prvkey_file, nullptr, NULL, (char *) pwd.c_str());
        }

    }
    this->prvKey = prvkey;
    std::cout << "private key set correctly" << std::endl;

    if (pubkey_file_name) {
        std::string prv = *pubkey_file_name;
        // load the peer's public key:
        FILE *pubkey_file = fopen(pubkey_file_name->c_str(), "r");
        if (!pubkey_file) {
            std::cout << "Error: cannot open file '" << prv.c_str() << "' (missing?)\n";
        }
        this->pubKey = PEM_read_PUBKEY(pubkey_file, nullptr, nullptr, nullptr);
        fclose(pubkey_file);
        if (!this->pubKey) {
            std::cout << "Error: PEM_read_PUBKEY returned NULL\n";
        }
    }else
        this->pubKey = nullptr;
    std::cout<<"signatureManager constructor ended succesfully "<<std::endl;
}

SignatureManager::SignatureManager(EVP_PKEY* pb , EVP_PKEY* pv) {
    if(pb){
        BIO *mbio = BIO_new(BIO_s_mem());
        if (!mbio) {
            std::cout << "Error in creating RSAManager" << std::endl;
            return;
        }
        if(PEM_write_bio_PUBKEY(mbio, pb)!=1){
            std::cout << "Error in creating RSAManager->pubkey" << std::endl;
            return;
        }
        if(!(this->pubKey = PEM_read_bio_PUBKEY(mbio, nullptr, nullptr, nullptr))){
            std::cout << "Error in creating RSAManager->pubkey" << std::endl;
            BIO_free(mbio);
            return;
        }
        BIO_free(mbio);
    }

    if(pv){
        BIO *mbio = BIO_new(BIO_s_mem());
        if (!mbio) {
            std::cout << "Error in creating RSAManager" << std::endl;
            return;
        }
        if(PEM_write_bio_PrivateKey(mbio, pv,NULL,NULL, 0, 0,NULL) != 1){
            std::cout << "Error in creating RSAManager->prvkey" << std::endl;
            return;
        }
        if(!(this->pubKey = PEM_read_bio_PrivateKey(mbio, nullptr, nullptr, nullptr))){
            std::cout << "Error in creating RSAManager->pubkey" << std::endl;
            BIO_free(mbio);
            return;
        }
        BIO_free(mbio);
    }
    std::cout << "Signature Manager keys created succesfully" << std::endl;
}

SignatureManager::SignatureManager(std::string *prvkey_file_name) {
    if (prvkey_file_name) {
        FILE *prvkey_file = fopen(prvkey_file_name->c_str(), "r");
        if (!prvkey_file) {
            std::cout << "Error: cannot open file '" << prvkey_file_name->c_str() << "' (missing?)\n";
        }

        this->prvKey = PEM_read_PrivateKey(prvkey_file, nullptr, NULL, NULL);

        fclose(prvkey_file);
        if (!this->prvKey) {
            std::cout << "Error: PEM_read_PrivateKey returned NULL\n";
        }else
            std::cout<<"private key set correctly"<<std::endl;
    }else
        this->prvKey = nullptr;
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
        delete[] sgnt_buf;
        messageToBeSignedLength = 0;
        return nullptr;
}

bool SignatureManager::verifyThisSignature(unsigned char* signature, size_t signatureLen,
                                           unsigned char* messageToVerify, size_t messageToVerifyLength) {

    int ret; // used for return values
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
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

    if(!signature || signatureLen != 256)
        std::cerr << "no roba " << ret << "\n";

    ret = EVP_VerifyFinal(md_ctx, signature, signatureLen, this->pubKey);

    return (ret == 1);
}

void SignatureManager::setPrvkey(std::string* prvkey_file_name) {
    if (prvkey_file_name) {
        FILE *prvkey_file = fopen(prvkey_file_name->c_str(), "r");
        if (!prvkey_file) {
            std::cerr << "Error: cannot open file '" << prvkey_file_name->c_str() << "' (missing?)\n";
        }

        this->prvKey = PEM_read_PrivateKey(prvkey_file, nullptr, NULL, NULL);

        fclose(prvkey_file);
        if (!this->prvKey) {
            std::cerr << "Error: PEM_read_PrivateKey returned NULL\n";
        }
    }
}


void SignatureManager::setPubkey(EVP_PKEY* pb) {
    this->pubKey = pb;
}

void SignatureManager::setPrvkey(EVP_PKEY * pv) {
    this->prvKey = pv;
}

SignatureManager::~SignatureManager() {
    EVP_PKEY_free(this->pubKey);
    EVP_PKEY_free(this->prvKey);

}

unsigned char *SignatureManager::getPubkey(size_t& pblen) {
    BIO *mbio = BIO_new(BIO_s_mem());
    if(!mbio) return nullptr;
    PEM_write_bio_PUBKEY(mbio, this->pubKey);
    unsigned char* pubkey_buf;
    long pubkey_size = BIO_get_mem_data(mbio, &pubkey_buf);
    BIO_free(mbio);
    pblen = pubkey_size;
    return pubkey_buf;
}



