//
// Created by Laura Lemmi on 13/08/2020.
//

#ifndef PROGETTO_SERVER_H
#define PROGETTO_SERVER_H

#include "UserConnectionManager.h"
#include <string>
#include <unordered_map>
#include <iostream>
#include <vector>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <thread>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h> // for error descriptions
#include <mutex>


class UserConnectionManager;
using namespace std;

class Server {

private:
    int portNo;
    int listenFd;
    int nThreads;
    unordered_map<string, UserConnectionManager*> usersConnectedMap;
    struct sockaddr_in srvAddr;
    string certificatePath;
    std::mutex mapMutex;
    bool checkUserPresence(string);

public:
    string usersKeysPath;

    Server(int);
    UserConnectionManager* getUserConnection(string);
    bool removeUser(string*);
    bool insertUserConnectionInMap(string, UserConnectionManager*);
    void waitForNewConnections();
    unsigned char* geti2dCertificate(int&);
    std::vector<string> getUserList(string*);
    ~Server();
};


#endif //PROGETTO_SERVER_H
