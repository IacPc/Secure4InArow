//
// Created by iacopo on 14/08/20.
//
#include "../Libraries/SymmetricEncryptionManager.h"
#include "CertificateManager.h"
#include <string>
#include <vector>
#include <thread>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h> // for error descriptions
#include <stdexcept>
#include <cstdio>
/*
#ifndef PROGETTO_SERVERCONNECTIONMANAGER_H
#define PROGETTO_SERVERCONNECTIONMANAGER_H
*/
using namespace std;
class Client;
class P2PConnectionManager;

class ServerConnectionManager {

private:
    string* userName;
    string* pwd;
    int serverSocket;
    struct sockaddr_in serverAddr;
    int P2Pport;

    bool sendHelloMessage(unsigned char*, size_t&);
    bool verifyCertificate(unsigned char*, int);
    bool sendReadiness(unsigned char*, size_t);
    bool waitForKeys();
    bool sendClientNonce(unsigned char*, size_t);
    bool sendServerNonce(unsigned char*, size_t);
    bool tryParse(std::string*, unsigned int&);
    bool sendSelection(string*);
    bool sendResponse(string*);

    EVP_PKEY *waitForOpponentKey(struct in_addr & ipOpponent, size_t& port);

    string* waitForPlayers(bool&);
    string* selectPlayer(vector<string>);
    string* waitForChallenge();

    unsigned char* createReadiness(size_t&);
    unsigned char* waitForServerNonce(size_t&);
    unsigned char* createHelloMessage(size_t&);
    unsigned char* waitForCertificate(int&);
    unsigned char *obtainAES(unsigned char*);
    unsigned char *obtainIV(unsigned char*);
    unsigned char *obtainHMAC(unsigned char*);

public:

    SymmetricEncryptionManager* symmetricEncryptionManager;
    CertificateManager* certificateManager;

    ServerConnectionManager(unsigned char *, int, string*);
    bool sendServerNonce(const char*, size_t);
    bool establishConnectionToServer();
    bool secureTheConnection();
    bool clientReadyForChallenge();
    const char* getUserName();
    EVP_PKEY* createNewChallenge(bool&, struct in_addr &);
    EVP_PKEY* getPrvKey();
    EVP_PKEY* getPubKey();
    void setPwd(string*);
    int getPort();
    void sendEndOfGame();
    ~ServerConnectionManager();
    bool createConnectionWithServer();

};


//#endif PROGETTO_SERVERCONNECTIONMANAGER_H
