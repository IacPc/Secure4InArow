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

bool ServerConnectionManager::connectToServer(){

    int ret;
    ret = connect(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if(ret < 0){
        cerr<<"Error during TCP connection with server\n";
        return false;
    }
    return true;

}

void ServerConnectionManager::createConnectionWithServer() {
   bool ok = this->connectToServer();
   if(!ok)
       return;
   ok = secureTheConnection();

   if(!ok)
       return;
   ok= this->sendPlayersListRequest();
   if(!ok) {
       cout<<"error in sending Player list request"<<endl;
       return;
   }
   std::vector<std::string*>* playerList = nullptr;
   bool choiceWentWell = this->waitForPlayers(playerList);
   if(!choiceWentWell) return;

   if(playerList){
       bool sendingWentWell = this->sendSelectedPlayer(playerList);
       for (auto &i : *playerList) {
           delete i;
       }
       delete playerList;

       if(!sendingWentWell)
           return;

       bool challengedSaidYes = this->waitForChallengedResponseMessage();
       if(challengedSaidYes){
           // create P2PCommunication, for now just return
           return;
       }
   }

   while(true){
      if(!this->waitForSomething())
          return;
   }

}

bool ServerConnectionManager::secureTheConnection(){

    cout<<"Start creating a secure connection\n";
    //create hello msg


    unsigned char *helloMsg;
    size_t hello_len;
    helloMsg= createHelloMessage(hello_len);
    if(helloMsg == NULL){
        cerr<<"Error during Hello Message creation\n";
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
        serverPubkey = certificateManager->extractPubKey(serializedCertificate, certLen);
    }else
        return false;

    delete certificateManager;

    string* path = new string("../Client/Client_Key/");
    path->append(userName->c_str());
    path->append("_prvkey.pem");
    this->signatureManager = new SignatureManager(path);
    cout<<"private key set correctly"<<endl;
    this->signatureManager->setPubkey(serverPubkey);
    cout<<"server public key set correctly"<<endl;
    this->diffieHellmannManager = new DiffieHellmannManager();
    cout<<"DH created correctly"<<endl;

    //send the readiness msg
    if(!sendMyPubKey()){
        cerr<<"Error during sending my pubkey\n";
        return false;
    }
    std::cout<<"Pubkey message sent correctly!"<<std::endl;

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
    memcpy(&simmetricKeyBuffer[0],&HashedSecret[0],EVP_CIPHER_key_length(EVP_aes_128_gcm()));

    memset(HashedSecret,0X00,EVP_CIPHER_key_length(EVP_aes_128_gcm()));
    delete [] HashedSecret;

    this->symmetricEncryptionManager = new SymmetricEncryptionManager(simmetricKeyBuffer,
                                                                      EVP_CIPHER_key_length(EVP_aes_128_gcm()));
    delete [] simmetricKeyBuffer;

    cout<<"Secure connection established"<<endl;

    return true;
}

unsigned char *ServerConnectionManager::createHelloMessage(size_t& helloMessageBufferLen) {

    helloMessageBufferLen = 1 + sizeof(this->myNonce) + strlen(this->userName->c_str()) + 1;
    auto* helloMessageBuffer = new unsigned char[helloMessageBufferLen];
    helloMessageBuffer[0] = HELLOMSGCODE;
    RAND_bytes((unsigned char*)&this->myNonce,sizeof(this->myNonce));
    memcpy(&helloMessageBuffer[1],(unsigned char*)&this->myNonce,sizeof(this->myNonce));
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
        cout<<"Wrong message,expected CERTIFICATEMSGCODE = 0X02,received "<<(uint8_t)buffer[0]<<endl;
        return NULL;
    }else{
        memcpy(&this->serverNonce,&buffer[1],sizeof(this->serverNonce));
        size_t certLen = ret-1 - sizeof(this->serverNonce);
        auto* cert = new unsigned char[certLen];
        memcpy(cert, buffer + sizeof(this->serverNonce)+1, certLen);

        delete [] buffer;
        len = certLen;
        cout<<"Certificate has been received\n";
        return cert;
    }

}

unsigned char *ServerConnectionManager::createPubKeyMessage(size_t& len) {
    size_t pubKeyLength = 0;
    unsigned char* pubKeyBuf = this->diffieHellmannManager->getMyPubKey(pubKeyLength);
    cout<<"PUBKEY LENGTH "<<pubKeyLength<<endl;

    size_t pubKeyMessageToSignLength = 1 + 2*sizeof(this->serverNonce) + sizeof(uint16_t) + pubKeyLength;

    auto* pubKeyMessageToSignBuffer = new unsigned char[pubKeyMessageToSignLength];
    pubKeyMessageToSignBuffer[0] = PUBKEYMESSAGECODE;

    size_t step = 1;
    memcpy(&pubKeyMessageToSignBuffer[step],&this->myNonce,sizeof(this->myNonce));
    step += sizeof(this->myNonce);
    memcpy(&pubKeyMessageToSignBuffer[step],&this->serverNonce,sizeof(this->serverNonce));
    step += sizeof(this->serverNonce);
    uint16_t len_16t = pubKeyLength;
    std::cout<<"len_16t ="<<len_16t<<std::endl;
    memcpy(&pubKeyMessageToSignBuffer[step], &len_16t, sizeof(len_16t));
    step += sizeof(len_16t);
    memcpy(&pubKeyMessageToSignBuffer[step],pubKeyBuf,len_16t);
    step += len_16t;

    //delete [] pubKeyBuf;
    size_t signatureLength = step;
    unsigned char* signature = this->signatureManager->signTHisMessage(pubKeyMessageToSignBuffer,signatureLength);
    if(!signature) {
        delete [] pubKeyMessageToSignBuffer;
        return nullptr;
    }
    cout<<"SIGNATURE LEN "<<signatureLength<<endl;
    size_t pubKeyMessageLength = step + sizeof(len_16t) + signatureLength;
    auto* pubKeyMessageBuffer = new unsigned char[pubKeyMessageLength];
    memcpy(pubKeyMessageBuffer,pubKeyMessageToSignBuffer,step);

    len_16t = signatureLength;
    memcpy(&pubKeyMessageBuffer[step],&len_16t,sizeof(len_16t));

    step += sizeof(len_16t);
    memcpy(&pubKeyMessageBuffer[step],signature,signatureLength);

    delete [] signature;
    delete [] pubKeyMessageToSignBuffer;
    std::cout<<"PubKeyLen="<<pubKeyLength<<endl;
    std::cout<<"SignatureLen="<<signatureLength<<endl;
    len = pubKeyMessageLength;
    cout<<"Creation of PubKeyMessage of size "<<len<<" finished correctly "<<endl;

    return pubKeyMessageBuffer;
}

bool ServerConnectionManager::sendMyPubKey() {
    size_t len;
    unsigned char* pKeyMsg = createPubKeyMessage(len);
    if(!pKeyMsg){
        cerr<<"Error during public key Message creation\n";
        return false;
    }
    int ret = send(this->serverSocket,pKeyMsg,len,0);
    delete [] pKeyMsg;
    if(ret!= len)
        return false;

    return true;
}

bool ServerConnectionManager::waitForPeerPubkey() {
/*
    size_t PeerPubKeyMessageLen =
            1 + 2 * sizeof(this->serverNonce) + 2 * sizeof(uint16_t) + this->userName->length() + 1 +
            EVP_PKEY_size(this->diffieHellmannManager->getMyPubKey_EVP()) +
            EVP_PKEY_size(this->signatureManager->getPrvkey());
*/
    auto *peerPubKeyMessageBuffer = new unsigned char[2048];
    int ret = recv(this->serverSocket, peerPubKeyMessageBuffer, 2048, 0);

    if (ret <= 0) {
        cout<<"received "<<ret << " bytes"<<endl;
        delete [] peerPubKeyMessageBuffer;
        return false;
    }

    if(peerPubKeyMessageBuffer[0] != PUBKEYMESSAGECODE){
        cout<<"wrong opcode "<<endl;
        delete [] peerPubKeyMessageBuffer;
        return false;
    }
    uint32_t nonceRecv = 0;
    memcpy(&nonceRecv,&peerPubKeyMessageBuffer[1],sizeof(nonceRecv));

    if(nonceRecv != this->myNonce){
        cout<<"wrong client nonce "<<endl;
        delete [] peerPubKeyMessageBuffer;
        return false;
    }

    memcpy(&nonceRecv,&peerPubKeyMessageBuffer[1 + sizeof(nonceRecv)],sizeof(nonceRecv));

    if(nonceRecv != this->serverNonce){
        cout<<"wrong server nonce "<<endl;
        delete [] peerPubKeyMessageBuffer;
        return false;
    }

    uint16_t recvSignatureLen = 0;
    uint16_t recvPubKeyLen = 0;
    memcpy(&recvPubKeyLen,&peerPubKeyMessageBuffer[1 + 2*sizeof(nonceRecv)],sizeof(recvPubKeyLen));
    size_t signaturePosition = 1 +2*sizeof(nonceRecv) +2*sizeof(recvPubKeyLen) + recvPubKeyLen;
    memcpy(&recvSignatureLen,&peerPubKeyMessageBuffer[signaturePosition-2],sizeof(recvSignatureLen));

    auto* recvSignatureBuffer = new unsigned char[recvSignatureLen];
    memcpy(recvSignatureBuffer,&peerPubKeyMessageBuffer[signaturePosition],recvSignatureLen);
    size_t messageToBeVErifiedLength = signaturePosition-2;
    bool signCheck = signatureManager->verifyThisSignature(recvSignatureBuffer, recvSignatureLen,
                                                           peerPubKeyMessageBuffer, messageToBeVErifiedLength);
    delete [] recvSignatureBuffer;
    if(!signCheck){
        cout<<"Uncorrect signature"<<endl;
        delete [] peerPubKeyMessageBuffer;
        return false;
    }
    size_t pubKeyPosition = 1 +2*sizeof(this->serverNonce)+ sizeof(recvPubKeyLen);

    this->diffieHellmannManager->setPeerPubKey(&peerPubKeyMessageBuffer[pubKeyPosition],recvPubKeyLen);
    delete [] peerPubKeyMessageBuffer;

    return true;
}

unsigned char *ServerConnectionManager::createPlayersListRequestMessage(size_t & len) {
    size_t playersListMessageLength = 1 + AESGCMIVLENGTH + sizeof(this->counter) + 2 * AESBLOCKLENGTH + AESGCMTAGLENGTH;
    auto* playersListMessageBuffer = new unsigned char[playersListMessageLength];

    playersListMessageBuffer[0] = LISTREQUESTMESSAGE;
    size_t step = 1;
    auto* ivBuf = new unsigned char[AESGCMIVLENGTH];
    RAND_bytes(ivBuf,AESGCMIVLENGTH);
    memcpy(&playersListMessageBuffer[step],ivBuf,AESGCMIVLENGTH);
    step += AESGCMIVLENGTH;
    RAND_bytes((unsigned char*)&this->counter,sizeof(this->counter));
    memcpy(&playersListMessageBuffer[step],&this->counter,sizeof(this->counter));
    step += sizeof(this->counter);

    size_t ptLen = this->userName->length()+1;
    auto* usrBuf = new unsigned char[ptLen];
    strcpy((char*)usrBuf,this->userName->c_str());

    size_t ivLen = AESGCMIVLENGTH;
    unsigned char* tag;
    unsigned char* cipherText;
    cipherText = this->symmetricEncryptionManager->encryptThisMessage(usrBuf,ptLen,playersListMessageBuffer,step,ivBuf,ivLen,tag);

    delete [] ivBuf;
    delete [] usrBuf;

    memcpy(&playersListMessageBuffer[step],cipherText,ptLen);
    step += ptLen;
    delete [] cipherText;
    memcpy(&playersListMessageBuffer[step],tag,AESGCMTAGLENGTH);
    delete [] tag;
    step += AESGCMTAGLENGTH;
    len = step;
    std::cout<<"playersListMessageBuffer created correctly"<<endl;
    return playersListMessageBuffer;
}

bool ServerConnectionManager::sendPlayersListRequest() {
    size_t playersListMessageLength;
    unsigned char* playersListMessageBuffer = createPlayersListRequestMessage(playersListMessageLength);
    int ret = send(this->serverSocket,playersListMessageBuffer,playersListMessageLength,0);
    delete [] playersListMessageBuffer;
    if(ret != playersListMessageLength){
        return false;
    }
    this->counter++;

    cout<<"PlayersListRequest Message sent correctly"<<endl;
    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////                                         SECURE CHANNEL CREATED                                           ////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool ServerConnectionManager::waitForPlayers(std::vector<std::string*>*& pc) {
    size_t playersListMessageLen = 1 + AESGCMIVLENGTH + sizeof(this->counter) + 2 + MAXUSERNAMELENGTH*MAXPLAYERSONLINE + AESGCMTAGLENGTH;
    const size_t aadLen = 1 + AESGCMIVLENGTH + sizeof(uint32_t);
    unsigned char aadBuf[aadLen];
    unsigned char ivBuf[AESGCMIVLENGTH];
    unsigned char tagBuf[AESGCMTAGLENGTH];
    unsigned int counterRecv;

    auto* playerListBuffer = new unsigned char[playersListMessageLen];
    cout<<"waiting for Players list message"<<endl;
    int ret = recv(this->serverSocket,playerListBuffer,playersListMessageLen,0);
    if(ret<=0) return false;

    if(playerListBuffer[0]!= PLAYERSLISTMESSAGECODE) {
        delete [] playerListBuffer;
        return false;
    }

    memcpy(&counterRecv,&playerListBuffer[1 + AESGCMIVLENGTH],sizeof(counterRecv));
    if(counterRecv!= this->counter){
        delete [] playerListBuffer;
        return false;
    }
    this->counter++;

    memcpy(ivBuf,&playerListBuffer[1],AESGCMIVLENGTH);
    memcpy(tagBuf,&playerListBuffer[ret -AESGCMTAGLENGTH],AESGCMTAGLENGTH);
    memcpy(aadBuf,playerListBuffer,aadLen);
    size_t cipherTextLen = ret - (1 + AESGCMIVLENGTH + sizeof(this->counter) + AESGCMTAGLENGTH);
    unsigned char* cipherText = new unsigned char[cipherTextLen];
    memcpy(cipherText,&playerListBuffer[1 + AESGCMIVLENGTH + sizeof(this->counter)],cipherTextLen);


    unsigned char* decryptedPlayersList = this->symmetricEncryptionManager->decryptThisMessage(cipherText,cipherTextLen,
                                                                                               aadBuf,aadLen,tagBuf,ivBuf);
    delete [] playerListBuffer;
    delete [] cipherText;

    if(!decryptedPlayersList){
        return false;
    }

    uint16_t playersNumb;
    memcpy(&playersNumb,decryptedPlayersList,sizeof(uint16_t));
    if (playersNumb==0){
        delete [] decryptedPlayersList;
        pc = nullptr;
        return true;
    }
    std::vector<std::string*>* playerList = new std::vector<std::string*>;

    size_t step = 0;
    char* players = (char*)&decryptedPlayersList[sizeof(playersNumb)];
    for(std::size_t i = 0; i < playersNumb || step<cipherTextLen;i++){
        string* toInsert = new std::string(players);
        playerList->push_back(toInsert);
        step += toInsert->length() + 1;
        players += step;
    }
    pc= playerList;
    delete [] decryptedPlayersList;
    return true;
}

bool ServerConnectionManager::waitForSomething() {
    return false;
}

ServerConnectionManager::~ServerConnectionManager() {
    delete userName;
    delete symmetricEncryptionManager;
    delete signatureManager;
    delete certificateManager;
    delete diffieHellmannManager;
}

unsigned char *ServerConnectionManager::createSelectedPlayerMessage(std::string * pl,size_t& len) {
    const size_t aadLen = 1 + AESGCMIVLENGTH + sizeof(this->counter);
    unsigned char aadBuf[aadLen];
    size_t ivLen = AESGCMIVLENGTH;

    unsigned char ivBuf[ivLen];
    unsigned char counterBuf[sizeof(this->counter)];
    unsigned char* tagBuf;

    size_t challengedNameLen = pl->length()+1;
    auto* challengedNameBuf = new unsigned char[challengedNameLen];
    strcpy((char*)challengedNameBuf,pl->c_str());
    aadBuf[0] = PLAYERCHOSENMESSAGECODE;
    RAND_bytes(ivBuf,AESGCMIVLENGTH);
    size_t step = 1 ;
    memcpy(&aadBuf[step],ivBuf,AESGCMIVLENGTH);
    step += AESGCMIVLENGTH;
    memcpy(&aadBuf[step],&this->counter,sizeof(this->counter));
    step += sizeof(this->counter);


    unsigned char* encPayload = this->symmetricEncryptionManager->encryptThisMessage(challengedNameBuf,challengedNameLen,
                                                                                     aadBuf,aadLen,ivBuf,ivLen,tagBuf);

    delete [] challengedNameBuf;

    size_t selectedPlayerMessageLen = 1 + AESGCMIVLENGTH + sizeof(this->counter) + challengedNameLen + AESGCMTAGLENGTH;
    auto* selectedPlayerMessageBuf = new unsigned char[selectedPlayerMessageLen];

    memcpy(selectedPlayerMessageBuf,aadBuf,step);
    memcpy(&selectedPlayerMessageBuf[step],encPayload,challengedNameLen);
    delete [] encPayload;

    step += challengedNameLen;
    memcpy(&selectedPlayerMessageBuf[step],tagBuf,AESGCMTAGLENGTH);

    len = selectedPlayerMessageLen;
    return selectedPlayerMessageBuf;

}

bool ServerConnectionManager::sendSelectedPlayer(std::vector<std::string *> * pl) {
    cout<<"The following players are available"<<endl;
    unsigned int i =0;
    unsigned int out =0;
    for (auto &p : *pl) {
        std::cout << i << ")"<<p<<endl;
        i++;
    }
    string choice;
    do{
        choice.clear();
        cout<<"Please choose one player between 1 and "<<i-1<<endl;
        getline(cin, choice);
    }while(!tryParsePlayerChoice(&choice, out, i - 1));

    out--;
    string* selectedPlayer = pl->at(out);
    std::size_t playerChosenMessageLength=0;
    unsigned char* playerChosenMessageBuffer = this->createSelectedPlayerMessage(selectedPlayer,playerChosenMessageLength);
    if(!playerChosenMessageBuffer){
        cout<<"ERROR in creating playerChosenMessageBuffer"<<endl;
        return false;
    }

    int ret = send(this->serverSocket, playerChosenMessageBuffer,playerChosenMessageLength,0);
    this->counter++;
    delete [] playerChosenMessageBuffer;
    if(ret!=playerChosenMessageLength)
        return false;
    else
        return true;

}

bool ServerConnectionManager::tryParsePlayerChoice(std::string* input, unsigned int& output,size_t limit) {
    unsigned int temp;
    try{
        temp = std::stoi(input->c_str());
    } catch (std::invalid_argument) {
        return false;
    }
    if(temp<1 || temp > limit)
        return false;
    output = temp;
    return true;
}

bool ServerConnectionManager::waitForChallengedResponseMessage() {
    size_t challengedResponseMessageLength = 1 + AESGCMIVLENGTH + sizeof(this->counter) + 2* AESBLOCKLENGTH + AESGCMTAGLENGTH;
    auto* challengedResponseMessageBuf = new unsigned char[challengedResponseMessageLength];
    const size_t aadLen = 1 + AESGCMIVLENGTH + sizeof(uint32_t);
    unsigned char aadBuf[aadLen];
    unsigned char ivBuf[AESGCMIVLENGTH];
    unsigned char tagBuf[AESGCMTAGLENGTH];

    int ret = recv(this->serverSocket,challengedResponseMessageBuf,challengedResponseMessageLength,0);
    if(ret <=0){
        cout<<"ERROR in receiving challenged response message"<<endl;
        return false;
    }
    uint32_t countRec;
    memcpy(&countRec, &challengedResponseMessageBuf[1 + AESGCMIVLENGTH],sizeof(countRec));
    if(challengedResponseMessageBuf[0]!= CHALLENGEDRESPONSEMESSAGECODE || (countRec != this->counter)){
        cout<<"ERROR in receiving challenged response message:message corrupted!"<<endl;
        delete [] challengedResponseMessageBuf;
        return false;
    }
    this->counter++;
    memcpy(ivBuf,&challengedResponseMessageBuf[1],AESGCMIVLENGTH);

    size_t cipherTextLen = ret - ( 1 + AESGCMIVLENGTH + sizeof(countRec) + AESGCMTAGLENGTH);
    size_t tagPosition = 1 + AESGCMIVLENGTH + sizeof(countRec) + cipherTextLen;

    memcpy(aadBuf,challengedResponseMessageBuf,aadLen);
    memcpy(tagBuf,&challengedResponseMessageBuf[tagPosition],AESGCMTAGLENGTH);

    auto* cipherText = new unsigned char[cipherTextLen];
    memcpy(cipherText,&challengedResponseMessageBuf[aadLen],cipherTextLen);

    unsigned char* answer = this->symmetricEncryptionManager->decryptThisMessage(cipherText,cipherTextLen,aadBuf,aadLen,tagBuf,ivBuf);
    if(!answer)
        return false;
    else{
        if ((const char)answer[0] == 'Y')
            return true;
        else
            return false;
    }

}


