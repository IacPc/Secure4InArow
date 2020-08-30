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

    SymmetricEncryptionManager *symmetricEncryptionManager;
    SignatureManaegr *signatureManager;
    DiffieHellmannManager *diffieHellmannManager;

    unsigned char* clientNonce;
    unsigned char* myNonce;


    bool establishSecureConnection();
    bool waitForHelloMessage();
    bool sendCertificate(unsigned char*, size_t);
    bool waitForClientPubKey();
    bool verifyNonce(unsigned char*, unsigned char*);
    bool sendMyPubKey();

    bool sharePlayersList();
    bool waitForPlayersRequest();
    bool sendPlayerList();

    void createSessionKey();



    bool sendChallengerRequest(string*);
/*    bool sendOpponentKey(string*);
    bool sendMyKeyToChallenger(string*, int);
    bool waitForOpponentReady(unsigned int&);
*/
    unsigned char* createCertificateMessage(size_t&);
    unsigned char* createPlayerListMsg(vector<string>, size_t&);
    string* waitForClientChoice(bool&);


public:
    UserConnectionManager(Server*, sockaddr_in, int);
    void openNewconnectionwithClient();


    ~UserConnectionManager();
};


#endif //PROGETTO_USERCONNECTIONMANAGER_H
