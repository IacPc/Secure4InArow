//
// Created by iacopo on 14/08/20.
//

#ifndef PROGETTO_USERCONNECTIONMANAGER_H
#define PROGETTO_USERCONNECTIONMANAGER_H
#include "Server.h"
#include <vector>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <thread>
#include <string.h>
#include "../Libraries/SymmetricEncryptionManager.h"
#include "../Libraries/RSAManager.h"
#include "../Libraries/Constant.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h> // for error descriptions

using namespace std;
class Server;

class UserConnectionManager{

private:
    Server* server;
    struct sockaddr_in clAdd;
    string *userName;
    SymmetricEncryptionManager *symmetricEncryptionManager;
    RSAManager *rsaManager;
    int userSocket;

    bool waitForHelloMessage();
    bool sendCertificate(unsigned char*, size_t);
    bool waitForClientBeReady();
    bool sendSymmetricKeys(unsigned char*, size_t);
    bool sendServerNonce(unsigned char*, size_t&, unsigned char*, size_t&);
    bool verifyNonce(unsigned char*, unsigned char*);
    bool establishSecureConnection();
    bool sendChallengeMessage(string*);
    bool sendOpponentKey(string*);
    bool sendMyKeyToChallenger(string*, int);
    bool waitForOpponentReady(unsigned int&);

    unsigned char* createPlayerListMsg(vector<string>, size_t&);
    unsigned char* createKeyMessage(size_t&);
    unsigned char* waitForClientNonce(size_t&);
    unsigned char* createCertificateMessage(size_t&);
    unsigned char* createServerNonceMessage(unsigned char*, size_t&, unsigned char*, size_t&, size_t&);
    unsigned char* waitForMyNonce();
    unsigned char* getKeyPlainMgs(size_t&);

    EVP_PKEY* getUserPubKey(string*);

    string *waitForChoice(bool&);
    string* waitForResponse();

    void waitForEndOfGame();

public:
    UserConnectionManager(Server*, sockaddr_in, int);
    void openNewconnectionwithClient();
    bool sendPlayerList(size_t&);
    ~UserConnectionManager();
};


#endif //PROGETTO_USERCONNECTIONMANAGER_H
