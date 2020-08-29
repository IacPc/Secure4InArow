//
// Created by iacopo on 14/08/20.
//

#include "ServerConnectionManager.h"

ServerConnectionManager::ServerConnectionManager(const char *server_addr, int port, string* user) {

    userName = new std::string(user->c_str());
    std::cout<<"username created successfully"<<endl;
    //create new socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    //clean server address
    memset(&serverAddr, 0, sizeof(serverAddr));
    //inizialize the server address structure
    serverAddr.sin_family =  AF_INET;
    serverAddr.sin_port = htons(port);

    inet_pton(AF_INET, (const char*)&server_addr, &serverAddr.sin_addr);

    string* pwd = new string;
    cout<<"insert your pwd for your private key file"<<endl;
    getline(cin,*pwd);
    if(pwd->length()>0){
        this->setPwd(pwd);
    }else{
        this->setPwd(nullptr);
        delete pwd;
    }
    RAND_poll();

    cout<<"ServerConnectionManager created successfully"<<endl;

}

bool ServerConnectionManager::establishConnectionToServer(){

    int ret;
    ret = connect(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if(ret < 0){
        cerr<<"Error during TCP connection with server\n";
        return false;
    }
    return true;

}

bool ServerConnectionManager::secureTheConnection(){

    cout<<"Start creating a secure connection\n";
    //create hello msg


    unsigned char *helloMsg;
    size_t hello_len;
    helloMsg= createHelloMessage(hello_len);
    if(helloMsg == NULL){
        cerr<<"Error during Hello Message creation\n";
        delete this;
        return false;
    }

    cout<<"HelloMessage created successfully\n"<<endl;

    //send hello msg
    if(!sendHelloMessage(helloMsg, hello_len)){
        cerr<<"Error during Hello Message sending\n";
        return false;
    }


    int certLen = MAXCERTIFICATELENGTH;
    //wait for server certificate
    unsigned char *serializedCertificate = waitForCertificate(certLen);
    if(serializedCertificate == NULL){
        cerr<<"Error receiving certificate\n";
        return false;
    }

    certificateManager = new CertificateManager();
    cout<<"The certificate has been received\n";

    //Inizializzo RSA
    string* path = new string("../Client/Client_Key/");
    path->append(userName->c_str());
    path->append("_prvkey.pem");
    this->signatureManager = new SignatureManager(path);

    std::cout<<"veryfing the certificate"<<endl;

    //verify the server certificate
    if(!verifyCertificate(serializedCertificate,certLen)){
        cerr<<"The certificate has not been verified\n";
        return false;
    }

    cout<<"The certificate has been verified\n";

    this->diffieHellmannManager = new DiffieHellmannManager();

    //send the readiness msg
    if(!sendMyPubKey()){
        cerr<<"Error during Readiness Message sending\n";
        return false;
    }
    std::cout<<"Readiness message sent correctly!"<<std::endl;

    //wait for keys message
    if(!waitForPeerPubkey()){
        cerr<<"Error in receiving peer key\n";
        return false;
    }


    return true;
}

unsigned char *ServerConnectionManager::createHelloMessage(size_t &) {
    return nullptr;
}

bool ServerConnectionManager::sendHelloMessage(unsigned char *, size_t &) {
    return false;
}

unsigned char *ServerConnectionManager::waitForCertificate(int &) {
    return nullptr;
}

bool ServerConnectionManager::verifyCertificate(unsigned char *, int) {
    return false;
}

unsigned char *ServerConnectionManager::createPubKeyMessage() {
    return nullptr;
}

bool ServerConnectionManager::sendMyPubKey() {

    unsigned char* pKeyMsg = createPubKeyMessage();
    if(!pKeyMsg){
        cerr<<"Error during public key Message creation\n";
        return false;
    }
    return false;
}

bool ServerConnectionManager::waitForPeerPubkey() {
    return false;
}

unsigned char *ServerConnectionManager::createPlayersListRequestMessage() {
    return nullptr;
}

bool ServerConnectionManager::sendPlayersListRequest() {
    return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////                                         SECURE CHANNEL CREATED                                           ////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool ServerConnectionManager::waitForPlayers(std::string*& pChosen) {
    return false;
}

unsigned char* ServerConnectionManager::createSelectedPlayerMessage() {
    return nullptr;
}

bool ServerConnectionManager::sendSelectedPlayer() {
    return false;
}

unsigned char *ServerConnectionManager::waitForOpponentKey(in_addr &ipOpponent, size_t &port) {
    return nullptr;
}

bool ServerConnectionManager::waitForSomething() {
    return false;
}



