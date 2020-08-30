//
// Created by iacopo on 19/08/20.
//
#include "Client.h"


int main(int argc, char*argv[]){
    //Client need server addr, server port and client username

    //control the parameters and inizialize the Client
    string* server_addr;
    string* username;
    int port;

    if(argc != 4)
        return -1;
    else{
        server_addr = new std::string(argv[1]);
        port = atoi(argv[2]);
        if((port > 65535) || (port < 2000))
            return -1;
        username = new std::string((argv[3]));
    }

    auto* client = new Client(server_addr, port, username);

    if(!client->establishConnection()){
        cerr<<"Connection with Server failed\n";
        return -1;
    }

/*    if(!client->establishP2PCommunication()){
        cerr<<"The players information exchange failed\n";
        return -1;
    }
*/
    return 0;

}
