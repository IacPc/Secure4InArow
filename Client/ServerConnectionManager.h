//
// Created by iacopo on 14/08/20.
//
#include "../Libraries/SymmetricEncryptionManager.h"
#include "../Libraries/DiffieHellmannManager.h"
#include "CertificateManager.h"
#include "../Libraries/SignatureManager.h"
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

class ServerConnectionManager {

private:
    string* userName;
    int serverSocket;
    int serverNonce;
    int myNonce;
    int P2Pport;
    unsigned int counter;
    struct sockaddr_in serverAddr;
    SymmetricEncryptionManager* symmetricEncryptionManager;
    SignatureManager* signatureManager;
    CertificateManager* certificateManager;
    DiffieHellmannManager* diffieHellmannManager;

    bool sendHelloMessage(unsigned char*, size_t&);
    bool sendMyPubKey();
    bool waitForPeerPubkey();
    bool sendPlayersListRequest();
    bool sendSelectedPlayer(std::string*);
    bool waitForChallengedResponseMessage();
    bool sendLogOutMessage();
    bool sendEndGameMessage();
    bool waitForPlayers(std::vector<std::string*>*&);
    bool sendCHallengedReadyMessage();
    //PARSER
    bool tryParsePlayerChoice(std::string* input, unsigned int& output,size_t limit);

    std::string* waitForChallengeRequest();

    unsigned char* createHelloMessage(size_t& helloMessageBufferLen);
    unsigned char* createPubKeyMessage(size_t&);
    unsigned char* waitForCertificate(int&);
    unsigned char* createPlayersListRequestMessage(size_t&);
    unsigned char* createSelectedPlayerMessage(std::string*,size_t&);
    unsigned char* createLogOutMessage(size_t&);
    unsigned char* createEndGameMessage(size_t&);
    unsigned char* createCHallengedReadyMessage(size_t&);

public:

    bool waitForOpponentCredentials(EVP_PKEY*&,struct in_addr&);
    ServerConnectionManager(const char* server_addr, int port, string* user);
    bool connectToServer();
    bool secureTheConnection();
    void enterThegame();
    ~ServerConnectionManager();
    void createConnectionWithServer();
    string *getUsername();
    int getP2PPort();

};


//#endif PROGETTO_SERVERCONNECTIONMANAGER_H
