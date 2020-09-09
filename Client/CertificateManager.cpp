//
// Created by iacopo on 14/08/20.
//

#include "CertificateManager.h"

CertificateManager::CertificateManager() {
    int ret;
    FILE *cacert_file = fopen(this->caCertificatePath.c_str(), "r");
    if (!cacert_file) {
        cerr << "Error: cannot open file '" << this->caCertificatePath.c_str() << "' (missing?)\n";
    }
    X509 *cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
    fclose(cacert_file);
    if (!cacert) {
        cerr << "Error: PEM_read_X509 returned NULL\n";
    }

    FILE *crl_file = fopen(this->caCRLPath.c_str(), "r");
    if (!crl_file) {
        cerr << "Error: cannot open file '" << this->caCRLPath.c_str() << "' (missing?)\n";
    }
    X509_CRL *crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if (!crl) {
        cerr << "Error: PEM_read_X509_CRL returned NULL\n";
    }

    // build a store with the CA's certificate and the CRL:
    this->store = X509_STORE_new();
    if (!store) {
        cerr << "Error: X509_STORE_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
    }
    ret = X509_STORE_add_cert(store, cacert);
    if (ret != 1) {
        cerr << "Error: X509_STORE_add_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL)
             << "\n";
    }
    ret = X509_STORE_add_crl(store, crl);
    if (ret != 1) {
        cerr << "Error: X509_STORE_add_crl returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
    }
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if (ret != 1) {
        cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL)
             << "\n";
    }


}

CertificateManager::~CertificateManager() {
    X509_STORE_free(store);
}

bool CertificateManager::verifyCertificate(unsigned char* uchar_cert, size_t certSize) {
    int ret;
    X509* cert = d2i_X509(NULL,(const unsigned char**)&uchar_cert, certSize);
    if(!cert) {
        cout<<"Certificate not deserialized"<<endl;
        return false;
    }

    X509_STORE_CTX *certvfy_ctx = X509_STORE_CTX_new();

    if (!certvfy_ctx) {
        cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
        return false;
    }

    ret = X509_STORE_CTX_init(certvfy_ctx, this->store, cert, NULL);

    if (ret != 1) {
        cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL)
             << "\n";
        return false;
    }
    ret = X509_verify_cert(certvfy_ctx);

    if (ret != 1) {
        cerr << "Error: X509_verify_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
        X509_free(cert);
        return false;
    }
    X509_free(cert);
    X509_STORE_CTX_free(certvfy_ctx);
    std::cout<<"Server certificate verified correctly"<<endl;

    return true;
}


EVP_PKEY *CertificateManager::extractPubKey(unsigned char* cert, size_t certSize) {
    X509* certificate = d2i_X509(NULL,(const unsigned char**)&cert, certSize);
    if(!certificate)
        return nullptr;
    else
        return X509_get_pubkey(certificate);
}
