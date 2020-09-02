//
// Created by Laura Lemmi on 02/09/2020.
//

#ifndef ALL_P2PCONNECTIONMANAGER_H
#define ALL_P2PCONNECTIONMANAGER_H
#include "../Libraries/Constant.h"
#include "../Libraries/SignatureManager.h"
#include "../Libraries/SymmetricEncryptionManager.h"
#include "ServerConnectionManager.h"
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
#include <stdexcept>
#include <cstdio>


class P2PConnectionManager {
private:
    ServerConnectionManager* serverConnectionManager;
    struct sockaddr_in opponentAddr;
    struct sockaddr_in myAddr;
    int opponentSocket;
    int mySocket;
    string *myUsername;
    string *opponentUsername;
    SignatureManager* signatureManager;
    SymmetricEncryptionManager* symmetricEncryptionManager;
    DiffieHellmannManager *diffieHellmannManager;

    uint32_t challengerNonce;
    uint32_t challengedNonce;
    uint32_t counter;

    bool waitForChallengeRConnection();
    bool connectToChallengeD();
    bool establishSecureConnectionWithChallengeR();
    bool establishSecureConnectionWithChallengeD();

    bool waitForChallengeRHelloMessage();
    bool sendChallengeDHelloMessage();
    bool waitForChallengeRPubKey();
    bool sendChallengeDPubKey();

    void createSessionKey();

public:
    P2PConnectionManager(EVP_PKEY*,ServerConnectionManager*);

    void startTheGameAsChallengeR();
    void startTheGameAsChallengeD();
    void setOpponentIp(struct in_addr);

    ~P2PConnectionManager();

};


#endif //ALL_P2PCONNECTIONMANAGER_H
