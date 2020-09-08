//
// Created by Laura Lemmi on 02/09/2020.
//

#ifndef ALL_P2PCONNECTIONMANAGER_H
#define ALL_P2PCONNECTIONMANAGER_H
#include "../Libraries/Constant.h"
#include "../Libraries/SignatureManager.h"
#include "../Libraries/SymmetricEncryptionManager.h"
#include "../Libraries/DiffieHellmannManager.h"
#include "GameBoard.h"
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
using namespace std;
class ServerConnectionManager;

class P2PConnectionManager {
private:
    ServerConnectionManager* serverConnectionManager;
    struct sockaddr_in opponentAddr;
    struct sockaddr_in myAddr;
    int opponentSocket;
    int mySocket;
    string myUsername;
    string *opponentUsername;
    SignatureManager* signatureManager;
    SymmetricEncryptionManager* symmetricEncryptionManager;
    DiffieHellmannManager *diffieHellmannManager;
    GameBoard * gameBoard;

    uint32_t opponentNonce;
    uint32_t myNonce;
    uint32_t counter;

    bool waitForChallengeRConnection();
    bool establishSecureConnectionWithChallengeR();
    bool establishSecureConnectionWithChallengeD();
    bool sendCoordinateMessage(uint8_t, uint8_t);
    bool waitForHelloMessage();         //valido per entrambi
    bool sendHelloMessage();            //valido per entrambi
    bool waitForChallengeRPubKey();
    bool sendChallengeDPubKey();
    bool waitForCoordinateMessage(uint8_t&,uint8_t&,bool);
    bool tryParseX(std::string* , uint8_t& );
    bool tryParseY(std::string* , uint8_t& );
    bool challengeDGame();
    void createSessionKey();
    bool connectToChallengedUser();
    bool sendMyPubKey();
    bool waitForPeerPubkey();

    unsigned char* createCoordinateMessage(uint8_t,uint8_t);
    unsigned char* createPubKeyMessage(size_t&);

public:
    P2PConnectionManager(EVP_PKEY*,ServerConnectionManager*);

    void startTheGameAsChallengeR();
    void startTheGameAsChallengeD();
    void setOpponentIp(struct in_addr);

    ~P2PConnectionManager();

};


#endif //ALL_P2PCONNECTIONMANAGER_H
