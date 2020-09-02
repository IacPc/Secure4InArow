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

    myUsername = new string(this->serverConnectionManager->getUsername()->c_str());

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

bool P2PConnectionManager::establishSecureConnectionWithChallengeR() {

    if(!waitForHelloMessage()){
        cerr<<"Error in receiving the peer Hello Message"<<endl;
        delete this;
        return false;
    }

    if(!sendHelloMessage()){
        cerr<<"Error in sending my Hello Message"<<endl;
        delete this;
        return false;
    }

    if(!waitForChallengeRPubKey()){
        cerr<<"Error in receiving challenger pubkey"<<endl;
        delete this;
        return false;
    }else{
        cout<<"Challenger public key received successfully"<<endl;
    }


    if(!sendChallengeDPubKey()){
        cerr<<"Error in sending my pubkey"<<endl;
        delete this;
        return false;
    }else{
        cout<<"PubKey sent successfully"<<endl;
    }

    createSessionKey();

    return true;
}

bool P2PConnectionManager::waitForHelloMessage() {
    cout<<"Waiting for challenger hello message"<<endl;
    auto *buffer = new unsigned char[HELLOMESSAGELENGTH];
    size_t ret;

    ret = recv(this->opponentSocket, buffer, HELLOMESSAGELENGTH, 0);
    if(ret <= 0){
        cout<<"Error in receiving Challenger HelloMessage\n";
        return false;
    }

    cout<<"Dimensione HelloMessage: "<<ret<<endl;
    if(buffer[0] == HELLOMSGCODE) {
        cout << "HelloMessage opcode verified\n";
    }
    else{
        cerr<<"Wrong message!\n";
        delete []buffer;
        return false;
    }


    memcpy((unsigned char*)&this->opponentNonce, &buffer[1], NONCELENGTH);

    buffer[ret-1] = '\0';
    this->opponentUsername = new string((const char*)&buffer[1 + NONCELENGTH]);

    cout<<"THE RECEIVED USERNAME IS: "<<this->opponentUsername->c_str()<<endl;
    delete []buffer;
    return true;
}

bool P2PConnectionManager::sendHelloMessage() {

    size_t msg_len = 1 + NONCELENGTH + strlen(this->myUsername->c_str())+1;
    auto* buffer = new unsigned char[msg_len];

    buffer[0] = HELLOMSGCODE;
    RAND_bytes((unsigned char*)&this->myNonce, sizeof(this->myNonce));
    memcpy(&buffer[1], (unsigned char*)&this->myNonce, NONCELENGTH);
    strcpy((char*)&buffer[1 + NONCELENGTH], this->myUsername->c_str());

    size_t ret = send(this->opponentSocket, buffer, msg_len, 0);
    if(ret != msg_len){
        cout<<"Error in sending my nonce"<<endl;
        return false;
    }

    return true;
}
