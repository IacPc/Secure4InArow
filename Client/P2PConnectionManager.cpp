//
// Created by Laura Lemmi on 02/09/2020.
//

#include "P2PConnectionManager.h"

P2PConnectionManager::P2PConnectionManager(EVP_PKEY *opponentKey, ServerConnectionManager *srvcnm) {

    this->serverConnectionManager = srvcnm;

    std::string* prvkPath = new std::string();
    prvkPath->append("../Client/Client_Key/");
    prvkPath->append(this->serverConnectionManager->getUsername()->c_str());
    prvkPath->append("_prvkey.pem");

    signatureManager = new SignatureManager(prvkPath);
    delete prvkPath;
    signatureManager->setPubkey(opponentKey);


    memset(&this->opponentAddr,0X00,sizeof(struct sockaddr_in));

    RAND_poll();

    std::cout<<"P2PConnectionManager created successfully"<<std::endl;
}



P2PConnectionManager::~P2PConnectionManager() {

    delete serverConnectionManager;
    delete signatureManager;
    delete symmetricEncryptionManager;

}


void P2PConnectionManager::startTheGameAsChallengeD() {

    mySocket = socket(AF_INET, SOCK_STREAM, 0);
    myAddr.sin_family = AF_INET;
    myAddr.sin_port = htons(this->serverConnectionManager->getP2PPort());
    myAddr.sin_addr.s_addr = INADDR_ANY;

    if(::bind(mySocket, (struct sockaddr*)&myAddr, sizeof(myAddr)) == -1){
        cerr<<"Error during bind"<<endl;
        delete this;
        return;
    }

    if(!waitForChallengeRConnection()){
        cerr<<"Error during connection with challenger"<<endl;
        delete this;
        return;
    }

    if(!establishSecureConnectionWithChallengeR()){
        cerr<<"Secure Connection not established"<<endl;
        delete this;
        return;
    }

    cout<<"Secure connection has been established. The game can start. "<<endl;
    cout<<"Wait for the challenger's first move"<<endl;
}

bool P2PConnectionManager::waitForChallengeRConnection() {

    listen(this->mySocket, 10);

    int len;
    len = sizeof(this->opponentAddr);

    cout<<"Server is listening\n";

    opponentSocket = accept(mySocket, (struct sockaddr*)&this->opponentAddr, reinterpret_cast<socklen_t *>(&len));
    if(opponentSocket < 0){
        cerr<<"The connection cannot be accepted\n";
        return false;
    }else
        cout<<"Connection successful\n";

    return true;
}
