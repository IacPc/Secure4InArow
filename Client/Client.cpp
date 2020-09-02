//
// Created by Laura Lemmi on 13/08/2020.
//

#include "Client.h"

Client::Client(string* server_addr, int port, string* user){
    unsigned char* server_addr_cstr = new unsigned char[strlen(server_addr->c_str()) + 1];
    memcpy(server_addr_cstr, server_addr->c_str(), server_addr->length()+1);
    std::cout<<"Creating ServerConnectionManager"<<endl;
    serverConnectionManager =  new ServerConnectionManager((const char*)server_addr_cstr, port, user);
    userName = new std::string(user->c_str());

    cout<<"Client created successfully\n";

}

bool Client::establishConnection() {

    std::thread t(&ServerConnectionManager::enterThegame, serverConnectionManager);
    t.join();
    return true;
}

string* Client::getUsername() {
    return this->userName;
}

Client::~Client() {

    delete userName;
    delete [] serverConnectionManager;
}
