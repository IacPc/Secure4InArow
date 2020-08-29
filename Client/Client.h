//
// Created by Laura Lemmi on 13/08/2020.
//
#include "ServerConnectionManager.h"
#include <string>
#include <climits>
#include <cstring>
#include <iostream>

#ifndef PROGETTO_CLIENT_H
#define PROGETTO_CLIENT_H


class Client {
private:

    string *userName;
    ServerConnectionManager* serverConnectionManager;
    //OpponentConnectionManager *opponentConnectionManager;

public:
    Client(string* server_addr, int port, string* user);
    bool establishConnection();
    bool establishP2PCommunication();
    string* getUsername();
    ~Client();

};


#endif //PROGETTO_CLIENT_H
