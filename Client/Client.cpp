//
// Created by Laura Lemmi on 13/08/2020.
//

#include "Client.h"

Client::Client(string* server_addr, int port, string* user){
    char* server_addr_cstr = new char[strlen(server_addr->c_str()) + 1];
    strcpy(server_addr_cstr,server_addr->c_str());
    std::cout<<"creating serverConnMan"<<endl;
    serverConnectionManager =  new ServerConnectionManager((const char*)server_addr_cstr, port, user);
    userName = new std::string(user->c_str());

    cout<<"Client created successfully\n";

}

bool Client::establishConnection(){

    if(serverConnectionManager->establishConnectionToServer()) {
        if(serverConnectionManager->secureTheConnection())
            return true;
        else
            return false;
    }
    else
        return false;
}

string* Client::getUsername() {
    return this->userName;
}

Client::~Client() {

    delete userName;
    delete []serverConnectionManager;
}

bool Client::establishP2PCommunication() {

    bool challenger;
    EVP_PKEY *opponentKey;
    struct in_addr opponentAddr;
    opponentKey = serverConnectionManager->createNewChallenge(challenger, opponentAddr);


    char *IPbuffer = inet_ntoa(opponentAddr);
    printf("Host IP: %s", IPbuffer);
    cout<<endl;

    if(opponentKey == nullptr)
        return false;


    P2PConnectionManager *p2p = new P2PConnectionManager(opponentKey, this->serverConnectionManager);

    if(!challenger) {
        std::thread t(&P2PConnectionManager::startPlayingWithChallengerPeer, p2p);
        t.join();
    }else{
        p2p->setChallengedIp(opponentAddr);
        std::thread t(&P2PConnectionManager::startPlayingWithChallengedPeer, p2p);
        t.join();
    }

    return true;

}


