//
// Created by iacopo on 14/08/20.
//

#ifndef PROGETTO_CERTIFICATEMANAGER_H
#define PROGETTO_CERTIFICATEMANAGER_H
#include<iostream>
#include<string>
#include<stdio.h>
#include<string.h>
#include<openssl/pem.h>
#include<openssl/evp.h>
#include<openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/conf.h>
using namespace std;

class CertificateManager {
private:
    X509_STORE * store;
    const string caCertificatePath = "../Client/Certificate/Lemmi_Pacini_CA_cert.pem";
    const string caCRLPath = "../Client/Certificate/Lemmi_Pacini_CA_crl.pem";
    const EVP_MD* md = EVP_sha256();
public:
    CertificateManager();//CACert and CRL
    ~CertificateManager();

    bool verifyCertificate(unsigned char*, size_t);
    EVP_PKEY* extractPubKey(unsigned char*, size_t);

};


#endif //PROGETTO_CERTIFICATEMANAGER_H
