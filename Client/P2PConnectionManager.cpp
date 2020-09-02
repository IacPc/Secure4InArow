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
