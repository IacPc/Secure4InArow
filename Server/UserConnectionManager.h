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
#include "../Libraries/DiffieHellmannManager.h"
#include "../Libraries/Constant.h"
#include "../Libraries/SignatureManager.h"
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
    int userSocket;
    uint32_t counter;
    bool busy;

    SymmetricEncryptionManager *symmetricEncryptionManager;
    SignatureManager *signatureManager;
    DiffieHellmannManager *diffieHellmannManager;

    uint32_t clientNonce;
    uint32_t myNonce;

    std::mutex ucmMutex;

    bool establishSecureConnection();
    bool waitForHelloMessage();
    bool sendCertificate(unsigned char*, size_t);
    bool waitForClientPubKey();
    bool sendMyPubKey();

    bool sharePlayersList();
    bool waitForPlayersRequest(unsigned char*, size_t);
    bool sendPlayerList();
    bool sendChallengerRequest(string*);
    bool sendOpponentKeyToChallenged(string *opponent, uint32_t opponentPort);
    bool waitForChallengedReady(unsigned char*, size_t, uint32_t&, string*);
    bool sendMyKeyToChallenger(string*, uint32_t);
    bool endGame(unsigned char*, size_t);

    void createSessionKey();
    void logout(unsigned char*, size_t);


    unsigned char* createCertificateMessage(size_t&);
    unsigned char* createPlayerListMsg(vector<string>, size_t&);
    unsigned char *getUserPubKey(string*, size_t&);
    string* waitForClientChoice(unsigned char*, size_t);
    string* waitForChallengedResponse(unsigned char*, size_t, bool&);


public:
    UserConnectionManager(Server*, sockaddr_in, int);
    void openNewconnectionwithClient();


    ~UserConnectionManager();
};


#endif //PROGETTO_USERCONNECTIONMANAGER_H
