//
// Created by iacopo on 02/09/20.
//

#ifndef ALL_P2PCONNECTIONMANAGER_H
#define ALL_P2PCONNECTIONMANAGER_H
#include "../Libraries/Constant.h"
#include "../Libraries/SignatureManager.h"
#include "../Libraries/SymmetricEncryptionManager.h"
#include "../Libraries/DiffieHellmannManager.h"
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

class ServerConnectionManager;

class P2PConnectionManager {
private:
    ServerConnectionManager* serverConnectionManager;
    struct sockaddr_in myAddr;
    struct sockaddr_in opponentAddr;
    int opponentSocket;
    int mySocket;
    SignatureManager* signatureManager;
    SymmetricEncryptionManager* symmetricEncryptionManager;

    bool establishSecureConnectionWithChallengeR();
    bool establishSecureConnectionWithChallengeD();
public:
    P2PConnectionManager(EVP_PKEY*,ServerConnectionManager*);

    void startTheGameAsChallengeR();
    void startTheGameAsChallengeD();
    void setChallengedIp(struct in_addr);

};


#endif //ALL_P2PCONNECTIONMANAGER_H
