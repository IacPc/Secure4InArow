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
    memset(&serverAddr, 0X00, sizeof(serverAddr));
    //inizialize the server address structure
    serverAddr.sin_family =  AF_INET;
    serverAddr.sin_port = htons(port);

    inet_pton(AF_INET, (const char*)&server_addr, &serverAddr.sin_addr);

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
    EVP_PKEY* serverPubkey;
    if(certificateManager->verifyCertificate(serializedCertificate,certLen)){
        cout<<"The certificate has been verified correcly\n";
        serverPubkey = certificateManager->extractPubKey(serializedCertificate,certLen);
    }else
        return false;

    delete certificateManager;

    string* path = new string("../Client/Client_Key/");
    path->append(userName->c_str());
    path->append("_prvkey.pem");
    this->signatureManager = new SignatureManager(path);
    this->signatureManager->setPubkey(serverPubkey);

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
    auto* HashedSecret = new unsigned char[EVP_MD_size(EVP_sha256())];
    size_t dhSecretLen = 0;
    unsigned char* dhSecret = this->diffieHellmannManager->getSharedSecret(dhSecretLen);

    SHA256(dhSecret,dhSecretLen,HashedSecret);

    delete diffieHellmannManager;

    auto* simmetricKeyBuffer = new unsigned char[EVP_CIPHER_key_length(EVP_aes_128_gcm())];
    memcpy(simmetricKeyBuffer,HashedSecret,EVP_CIPHER_key_length(EVP_aes_128_gcm()));

    memset(HashedSecret,0X00,EVP_CIPHER_key_length(EVP_aes_128_gcm()));
    delete [] HashedSecret;

    this->symmetricEncryptionManager = new SymmetricEncryptionManager(simmetricKeyBuffer,EVP_CIPHER_key_length(EVP_aes_128_gcm()));

    return true;
}

unsigned char *ServerConnectionManager::createHelloMessage(size_t& helloMessageBufferLen) {

    helloMessageBufferLen = 1 + sizeof(this->myNonce) + strlen(this->userName->c_str()) + 1;
    auto* helloMessageBuffer = new unsigned  char[helloMessageBufferLen];
    helloMessageBuffer[0] = HELLOMSGCODE;
    RAND_bytes((unsigned char*)&this->myNonce,sizeof(this->myNonce));
    strcpy((char*)&helloMessageBuffer[1 + sizeof(this->myNonce)], this->userName->c_str());

    return helloMessageBuffer;
}

bool ServerConnectionManager::sendHelloMessage(unsigned char* helloMessageBuffer, size_t& helloMessageBufferLen) {
    int ret = send(this->serverSocket,helloMessageBuffer, helloMessageBufferLen,0) ;
    delete [] helloMessageBuffer;

    if(ret != helloMessageBufferLen)
        return false;
    else
        return true;
}

unsigned char *ServerConnectionManager::waitForCertificate(int & len) {

    size_t ret;
    unsigned char* buffer = new unsigned char[MAXCERTIFICATELENGTH];

    ret = recv(serverSocket, (void*)buffer, MAXCERTIFICATELENGTH, 0);

    if(ret <= 0){
        cout<<"Error in receiving certificate message\n";
        return NULL;
    }

    if(buffer[0] != CERTIFICATEMSGCODE){
        cout<<"Wrong message\n";
        return NULL;
    }else{
        memcpy(&this->serverNonce,&buffer[1 + sizeof(this->serverNonce)],sizeof(this->serverNonce));
        size_t certLen = ret-1 - sizeof(this->serverNonce);
        auto* cert = new unsigned char[certLen];
        memcpy(cert, buffer+1, certLen);

        delete [] buffer;
        len = certLen;
        cout<<"Certificate has been received\n";
        return cert;
    }

}

unsigned char *ServerConnectionManager::createPubKeyMessage(size_t& len) {
    size_t pubKeyLength = 0;
    unsigned char* pubKeyBuf = this->diffieHellmannManager->getMyPubKey(pubKeyLength);

    size_t pubKeyMessageToSignLength = 1 + 2*sizeof(this->serverNonce) + (1 + strlen(this->userName->c_str()))
                                       + pubKeyLength;

    auto* pubKeyMessageToSignBuffer = new unsigned char[pubKeyMessageToSignLength];
    pubKeyMessageToSignBuffer[0] = PUBKEYMESSAGECODE;

    size_t step = 1;
    memcpy(&pubKeyMessageToSignBuffer[step],&this->myNonce,sizeof(this->myNonce));
    step += sizeof(this->myNonce);
    memcpy(&pubKeyMessageToSignBuffer[step],&this->serverNonce,sizeof(this->serverNonce));
    step += sizeof(this->serverNonce);
    strcpy((char*)&pubKeyMessageToSignBuffer[step],this->userName->c_str());
    step += strlen(this->userName->c_str()) + 1;
    memcpy(&pubKeyMessageToSignBuffer[step],pubKeyBuf,pubKeyLength);
    step += pubKeyLength;

    delete [] pubKeyBuf;

    unsigned char* signature = this->signatureManager->signTHisMessage(pubKeyMessageToSignBuffer,pubKeyMessageToSignLength);
    if(!signature) {
        delete [] pubKeyMessageToSignBuffer;
        return nullptr;
    }

    size_t pubKeyMessageLength = pubKeyMessageToSignLength + step;
    auto* pubKeyMessageBuffer = new unsigned char[pubKeyMessageLength];

    memcpy(pubKeyMessageBuffer,pubKeyMessageToSignBuffer,step);
    memcpy(&pubKeyMessageBuffer[step],signature,pubKeyMessageToSignLength);

    delete [] signature;
    delete [] pubKeyMessageToSignBuffer;

    len = pubKeyMessageLength;
    return pubKeyMessageBuffer;
}

bool ServerConnectionManager::sendMyPubKey() {
    size_t len;
    unsigned char* pKeyMsg = createPubKeyMessage(len);
    if(!pKeyMsg){
        cerr<<"Error during public key Message creation\n";
        return false;
    }
    int ret = send(this->serverNonce,pKeyMsg,len,0);
    delete [] pKeyMsg;
    if(ret!= len)
        return false;

    return true;
}

bool ServerConnectionManager::waitForPeerPubkey() {

    size_t PeerPubKeyMessageLen = 1 + 2 * sizeof(this->serverNonce) + this->userName->length() + 1 +
                                  EVP_PKEY_size(this->diffieHellmannManager->getMyPubKey_EVP()) +
                                  EVP_PKEY_size(this->signatureManager->getPrvkey());
    auto* peerPubKeyMessageBuffer = new unsigned char[PeerPubKeyMessageLen];
    int ret = recv(this->serverSocket, peerPubKeyMessageBuffer, PeerPubKeyMessageLen, 0);

    if(ret != PeerPubKeyMessageLen){
        delete [] peerPubKeyMessageBuffer;
        return false;
    }

    if(peerPubKeyMessageBuffer[0] != PUBKEYMESSAGECODE){
        delete [] peerPubKeyMessageBuffer;
        return false;
    }
    uint32_t nonceRecv = 0;
    memcpy(&nonceRecv,&peerPubKeyMessageBuffer[1],sizeof(nonceRecv));

    if(nonceRecv != this->myNonce){
        delete [] peerPubKeyMessageBuffer;
        return false;
    }

    memcpy(&nonceRecv,&peerPubKeyMessageBuffer[1 + sizeof(nonceRecv)],sizeof(nonceRecv));

    if(nonceRecv != this->serverNonce){
        delete [] peerPubKeyMessageBuffer;
        return false;
    }

    size_t dhPKeyLen = EVP_PKEY_size(this->diffieHellmannManager->getMyPubKey_EVP());
    this->diffieHellmannManager->setPeerPubKey(&peerPubKeyMessageBuffer[5 + this->userName->length()],dhPKeyLen);
    return true;
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



