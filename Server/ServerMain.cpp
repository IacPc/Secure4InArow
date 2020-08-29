#include "Server.h"

int main(int argc, char* argv[]){
    //Client need server addr, server port and client username

    //control the parameters and inizialize the Client
    if(argc != 2){
        cerr<<"Incorrent input data\n";
        return -1;
    }

    Server *server = new Server(atoi(argv[1]));
    server->waitForNewConnections();

}