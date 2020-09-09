//
// Created by iacopo on 14/08/20.
//

#include "P2PConnectionManager.h"
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

void ServerConnectionManager::enterThegame() {

    if(!createConnectionWithServer())
        return;

    while(true){
        std::vector<std::string*>* playerList = nullptr;

        bool iReceivedTheList = this->waitForPlayers(playerList);
        if (!iReceivedTheList) return;

        unsigned int i = 0;
        unsigned int out = 0;

        string choice;

        if (playerList != nullptr) {
            cout << "The following players are available" << endl;
            for (auto &p : *playerList) {
                std::cout << i+1 << ")" << p->c_str() << endl;
                i++;
            }

            do {
                choice.clear();
                cout << "choose one player between 1 and " << i
                     << ",press enter to wait for a challenge request either 0 to exit the game" << endl;
                getline(cin, choice);
                if (choice.length() == 0) {
                    break;
                }
            } while (!tryParsePlayerChoice(&choice, out, playerList->size()));

        }
        out--;
        if (choice.length() == 0) {

            string *challenger = NULL;
            string yn;
            cout << "Waiting for Challenge" << endl;
            if (!(challenger = this->waitForChallengeRequest()))
                return;
            cout << challenger->c_str() << " wants to play with you, do you accept?" << endl;

            char response;
            cin>>response;
            while(response != 'Y' && response != 'N'){
                cout<<"wrong input\n";
                cin>>response;
            }

            if(!sendChallengedResponse(challenger, response)) {
                delete challenger;
                return;
            }
            if(response == 'Y') {
                EVP_PKEY* pb;
                in_addr ip;
                if(!this->waitForOpponentCredentials(&pb,ip)) {
                    cout<<"error in receiving challenger pubkey. The game cannot start"<<endl;
                }else
                    cout<<"challenger pubkey received correctly"<<endl;

                auto *p2pConnMan = new P2PConnectionManager(pb, this);
                p2pConnMan->setOpponentIp(ip);
                std::thread t(&P2PConnectionManager::startTheGameAsChallengeD, p2pConnMan);
                t.join();

            }else{
                this->sendLogOutMessage();
                delete challenger;
                return;

            }

        }

        if (out != -1) {
            string *selectedPlayer = playerList->at(out);
            playerList->erase(playerList->begin() + out );
            cout<<"The selected player is "<<selectedPlayer->c_str()<<endl;
            bool sendingWentWell = this->sendSelectedPlayer(selectedPlayer);

            if (!sendingWentWell)
                return;
            bool challengedSaidYes = this->waitForChallengedResponseMessage();
            if (challengedSaidYes) {
                cout << selectedPlayer->c_str() << " has accepted" << endl;

                auto *p2pConnMan = new P2PConnectionManager(nullptr, this);

                std::thread t(&P2PConnectionManager::startTheGameAsChallengeR, p2pConnMan);

                t.join();
            } else {
                cout << selectedPlayer->c_str() << " refused" << endl;
                delete selectedPlayer;
            }
        }

        if(out==-1 && playerList != nullptr){
            this->sendLogOutMessage();
            for (auto &i : *playerList)
                delete i;
            delete playerList;
            return;
        }

        if (playerList != nullptr) {
            for (auto &i : *playerList)
                delete i;
            delete playerList;
        }

        this->sendEndGameMessage();
    }

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

bool ServerConnectionManager::createConnectionWithServer() {
   bool ok = this->connectToServer();
   if(!ok)
       return ok;
   ok = secureTheConnection();

   if(!ok)
       return ok;
   cout<<"created secure channel with server, players list request ongoing"<<endl;
   ok= this->sendPlayersListRequest();
   if(!ok) {
       cout<<"error in sending Player list request"<<endl;
       return ok;
   }
   return ok;
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
    if(serializedCertificate == nullptr){
        cerr<<"Error receiving certificate\n";
        return false;
    }

    certificateManager = new CertificateManager();
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
    this->signatureManager->setPubkey(serverPubkey);
    this->diffieHellmannManager = new DiffieHellmannManager();
    cout<<"SCM DH OK"<<endl;
    //send the readiness msg
    if(!sendMyPubKey()){
        cerr<<"Error during sending my pubkey\n";
        return false;
    }
    std::cout<<"Pubkey message sent correctly!"<<std::endl;

    //wait for keys message
    if(!waitForPeerPubkey()){
        cerr<<"Error in receiving peer key\n";
        delete [] helloMsg;
        return false;
    }
    cout<<"Peer pubkey obtained succesfully"<<endl;

    auto* HashedSecret = new unsigned char[EVP_MD_size(EVP_sha256())];
    size_t dhSecretLen = 0;
    unsigned char* dhSecret = this->diffieHellmannManager->getSharedSecret(dhSecretLen);

    SHA256(dhSecret,dhSecretLen,HashedSecret);

    delete diffieHellmannManager;
    diffieHellmannManager = nullptr;

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
        return cert;
    }

}

unsigned char *ServerConnectionManager::createPubKeyMessage(size_t& len) {
    size_t pubKeyLength = 0;

    unsigned char* pubKeyBuf = this->diffieHellmannManager->getMyPubKey(pubKeyLength);

    size_t pubKeyMessageToSignLength = 1 + 2*sizeof(this->serverNonce) + sizeof(uint16_t) + pubKeyLength;

    auto* pubKeyMessageToSignBuffer = new unsigned char[pubKeyMessageToSignLength];
    pubKeyMessageToSignBuffer[0] = PUBKEYMESSAGECODE;

    size_t step = 1;
    memcpy(&pubKeyMessageToSignBuffer[step],&this->myNonce,sizeof(this->myNonce));
    step += sizeof(this->myNonce);
    memcpy(&pubKeyMessageToSignBuffer[step],&this->serverNonce,sizeof(this->serverNonce));
    step += sizeof(this->serverNonce);
    uint16_t len_16t = pubKeyLength;
    memcpy(&pubKeyMessageToSignBuffer[step], &len_16t, sizeof(len_16t));
    step += sizeof(len_16t);
    memcpy(&pubKeyMessageToSignBuffer[step],pubKeyBuf,len_16t);
    step += len_16t;

    size_t signatureLength = step;
    unsigned char* signature = this->signatureManager->signTHisMessage(pubKeyMessageToSignBuffer,signatureLength);
    if(!signature) {
        cout<<"signature failed"<<endl;
        delete [] pubKeyMessageToSignBuffer;
        return nullptr;
    }

    size_t pubKeyMessageLength = step + sizeof(len_16t) + signatureLength;
    auto *pubKeyMessageBuffer = new unsigned char [pubKeyMessageLength];
    memcpy(pubKeyMessageBuffer,pubKeyMessageToSignBuffer,step);

    len_16t = signatureLength;
    memcpy(&pubKeyMessageBuffer[step],&len_16t,sizeof(len_16t));

    step += sizeof(len_16t);
    memcpy(&pubKeyMessageBuffer[step],signature,signatureLength);

    delete [] signature;
    delete [] pubKeyMessageToSignBuffer;

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

    unsigned char peerPubKeyMessageBuffer[4096];
    int ret = recv(this->serverSocket, peerPubKeyMessageBuffer, 4096, 0);

    if (ret <= 0) {
        cout<<"received "<<ret << " bytes"<<endl;
        return false;
    }

    if(peerPubKeyMessageBuffer[0] != PUBKEYMESSAGECODE){
        cout<<"wrong opcode "<<endl;
        return false;
    }
    uint32_t nonceRecv = 0;
    memcpy(&nonceRecv,&peerPubKeyMessageBuffer[1],sizeof(nonceRecv));

    if(nonceRecv != this->myNonce){
        cout<<"wrong client nonce "<<endl;
        return false;
    }

    memcpy(&nonceRecv,&peerPubKeyMessageBuffer[1 + sizeof(nonceRecv)],sizeof(nonceRecv));

    if(nonceRecv != this->serverNonce){
        cout<<"wrong server nonce "<<endl;
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
        return false;
    }
    cout<<"Signature verified correctly"<<endl;
    size_t pubKeyPosition = 1 +2*sizeof(this->serverNonce)+ sizeof(recvPubKeyLen);


    unsigned char peerpubkeyBuf[recvPubKeyLen];
    memcpy(peerpubkeyBuf,&peerPubKeyMessageBuffer[pubKeyPosition],recvPubKeyLen);
    size_t len = recvPubKeyLen;
    cout<<"Set peer pubkey"<<endl;
    this->diffieHellmannManager->setPeerPubKey(peerpubkeyBuf,len);
    cout<<"Peer pubkey set correctly"<<endl;
    return true;
}

unsigned char *ServerConnectionManager::createPlayersListRequestMessage(size_t & len) {
    size_t playersListMessageLength = 1 + AESGCMIVLENGTH + sizeof(this->counter) + 2 * AESBLOCKLENGTH + AESGCMTAGLENGTH;
    auto * playersListMessageBuffer =  new unsigned char[playersListMessageLength];

    playersListMessageBuffer[0] = LISTREQUESTMESSAGE;
    size_t step = 1;
    unsigned char ivBuf[AESGCMIVLENGTH];
    RAND_bytes(ivBuf,AESGCMIVLENGTH);
    memcpy(&playersListMessageBuffer[step],ivBuf,AESGCMIVLENGTH);
    step += AESGCMIVLENGTH;
    RAND_bytes((unsigned char*)&this->counter,sizeof(this->counter));
    memcpy(&playersListMessageBuffer[step],&this->counter,sizeof(this->counter));
    step += sizeof(this->counter);

    size_t ptLen = this->userName->length()+1;
    unsigned char usrBuf[ptLen];
    strcpy((char*)usrBuf,this->userName->c_str());

    size_t ivLen = AESGCMIVLENGTH;
    unsigned char* tag;
    unsigned char* cipherText;
    cipherText = this->symmetricEncryptionManager->encryptThisMessage(usrBuf,ptLen,playersListMessageBuffer,step,ivBuf,ivLen,tag);


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

bool ServerConnectionManager::waitForPlayers(std::vector<std::string*>*& pc) {
    size_t playersListMessageLen = 1 + AESGCMIVLENGTH + sizeof(this->counter) + 2 + MAXUSERNAMELENGTH*MAXPLAYERSONLINE + AESGCMTAGLENGTH + AESBLOCKLENGTH;
    const size_t aadLen = 1 + AESGCMIVLENGTH + sizeof(uint32_t);
    unsigned char aadBuf[aadLen];
    unsigned char ivBuf[AESGCMIVLENGTH];
    unsigned char tagBuf[AESGCMTAGLENGTH];
    unsigned int counterRecv;

    unsigned char playerListBuffer[playersListMessageLen];
    cout<<"waiting for Players list message"<<endl;
    int ret = recv(this->serverSocket,playerListBuffer,playersListMessageLen,0);

    if(ret<=0) {
        cout<<"Error in receiving Players list message"<<endl;
        return false;
    }

    if(playerListBuffer[0]!= PLAYERSLISTMESSAGECODE) {
        cout<<"Wrong message expected PLAYERSLISTMESSAGECODE "<<endl;
        return false;
    }

    memcpy(&counterRecv,&playerListBuffer[1 + AESGCMIVLENGTH],sizeof(counterRecv));
    if(counterRecv!= this->counter){
        cout<<"Wrong counter, expected "<<this->counter<<", received "<<counterRecv<<endl;
        return false;
    }
    this->counter++;


    memcpy(ivBuf,&playerListBuffer[1],AESGCMIVLENGTH);
    memcpy(tagBuf,&playerListBuffer[ret -AESGCMTAGLENGTH],AESGCMTAGLENGTH);
    memcpy(aadBuf,playerListBuffer,aadLen);
    size_t cipherTextLen = ret - (1 + AESGCMIVLENGTH + sizeof(this->counter) + AESGCMTAGLENGTH);
    unsigned char cipherText[cipherTextLen];
    memcpy(cipherText,&playerListBuffer[1 + AESGCMIVLENGTH + sizeof(this->counter)],cipherTextLen);


    unsigned char* decryptedPlayersList = this->symmetricEncryptionManager->decryptThisMessage(cipherText,cipherTextLen,
                                                                                               aadBuf,aadLen,tagBuf,ivBuf);


    if(!decryptedPlayersList){
        cout<<"error in decrypting Player list"<<endl;
        return false;
    }
    cout<<" Player list decrypted correctly"<<endl;

    uint16_t playersNumb;
    memcpy(&playersNumb,decryptedPlayersList,sizeof(uint16_t));
    if (playersNumb==0){
        delete [] decryptedPlayersList;
        pc = nullptr;
        cout<<"Received 0 players"<<endl;
        return true;
    }
    std::vector<std::string*>* playerList = new std::vector<std::string*>;

    size_t step = 0;
    char* players = (char*)&decryptedPlayersList[sizeof(playersNumb)];
    cout<<"There are "<<playersNumb<<"players On line"<<endl;

    for(std::size_t i = 0; i < playersNumb && step<cipherTextLen;i++){
        string* toInsert = new std::string(players);
        playerList->push_back(toInsert);
        step += toInsert->length() + 1;
        players += step;
    }
    pc= playerList;
    delete [] decryptedPlayersList;
    cout<<"Player list received correctly"<<endl;

    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////                                        BOTH CHALLENGER AND CHALLENGED UTILS                              ////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

unsigned char *ServerConnectionManager::createLogOutMessage(std::size_t& len) {
    size_t ivLen = AESGCMIVLENGTH;
    unsigned char ivBUf[AESGCMIVLENGTH];
    unsigned char* tagBuf = new unsigned char[AESGCMTAGLENGTH];
    size_t aadLen = 1 + AESGCMIVLENGTH + sizeof(this->counter);
    unsigned char aadBuf[aadLen];
    size_t plainTextLen = this->userName->length()+1;
    unsigned char plainText[plainTextLen];

    RAND_bytes(&ivBUf[0],AESGCMIVLENGTH);
    aadBuf[0] = LOGOUTMESSAGECODE;
    size_t step = 1;
    memcpy(&aadBuf[step], ivBUf,AESGCMIVLENGTH);
    step += AESGCMIVLENGTH;
    memcpy(&aadBuf[step],&this->counter,sizeof(this->counter));

    strcpy((char*)plainText,this->userName->c_str());
    size_t ctLen = plainTextLen;
    unsigned char* cipherText = this->symmetricEncryptionManager->encryptThisMessage(plainText, ctLen, aadBuf,
                                                                                     aadLen, ivBUf, ivLen, tagBuf);
    if(!cipherText)
        return nullptr;
    size_t logoutMessageBufferLen = aadLen + ctLen + AESGCMTAGLENGTH;
    auto* logoutMessageBuffer = new unsigned char[logoutMessageBufferLen];
    step = 0;
    memcpy(&logoutMessageBuffer[step],aadBuf,aadLen);
    step += aadLen;
    memcpy(&logoutMessageBuffer[step],cipherText,ctLen);
    step += ctLen;
    memcpy(&logoutMessageBuffer[step],tagBuf,AESGCMTAGLENGTH);

    delete [] tagBuf;
    delete [] cipherText;

    len = logoutMessageBufferLen;
    return logoutMessageBuffer;

}

unsigned char *ServerConnectionManager::createEndGameMessage(size_t& len) {
    size_t ivLen = AESGCMIVLENGTH;
    unsigned char ivBUf[AESGCMIVLENGTH];
    auto* tagBuf = new unsigned char[AESGCMTAGLENGTH];
    size_t aadLen = 1 + AESGCMIVLENGTH + sizeof(this->counter);
    unsigned char aadBuf[aadLen];
    size_t plainTextLen = this->userName->length()+1;
    unsigned char plainText[plainTextLen];

    RAND_bytes(&ivBUf[0],AESGCMIVLENGTH);
    aadBuf[0] = ENDGAMEMESSAGECODE;
    size_t step = 1;
    memcpy(&aadBuf[step], ivBUf,AESGCMIVLENGTH);
    step += AESGCMIVLENGTH;
    memcpy(&aadBuf[step],&this->counter,sizeof(this->counter));
    this->counter++;

    strcpy((char*)plainText,this->userName->c_str());
    size_t ctLen = plainTextLen;
    unsigned char* cipherText = this->symmetricEncryptionManager->encryptThisMessage(plainText, ctLen, aadBuf,
                                                                                     aadLen, ivBUf, ivLen, tagBuf);
    size_t endGameMessageBufferLen = aadLen + ctLen + AESGCMTAGLENGTH;
    auto* endGameMessageBuffer = new unsigned char[endGameMessageBufferLen];
    step = 0;
    memcpy(&endGameMessageBuffer[step], aadBuf, aadLen);
    step += aadLen;
    memcpy(&endGameMessageBuffer[step], cipherText, ctLen);
    step += ctLen;
    memcpy(&endGameMessageBuffer[step], tagBuf, AESGCMTAGLENGTH);

    delete [] tagBuf;
    delete [] cipherText;

    len = endGameMessageBufferLen;
    return endGameMessageBuffer;
}

bool ServerConnectionManager::sendLogOutMessage() {
    cout<<"Sending logout message"<<endl;
    size_t logOutMessageBufferLen = 0;
    unsigned char * logoutMessageBuffer = this->createLogOutMessage(logOutMessageBufferLen);
    int ret = send(this->serverSocket,logoutMessageBuffer,logOutMessageBufferLen,0);
    delete [] logoutMessageBuffer;
    if(ret!=logOutMessageBufferLen){
        cout<<"error in sending LogOutMessage"<<endl;
        return false;
    }
    cout<<"Logout message sent correctly"<<endl;
    return true;
}

bool ServerConnectionManager::sendEndGameMessage() {
    size_t endGameMessageBufferLen = 0;
    unsigned char * endGameMessageBuffer = this->createEndGameMessage(endGameMessageBufferLen);
    if(!endGameMessageBuffer){
        cout<<"error in creating endGameMessage"<<endl;
        return false;
    }
    int ret = send(this->serverSocket, endGameMessageBuffer, endGameMessageBufferLen, 0);
    delete [] endGameMessageBuffer;
    if(ret != endGameMessageBufferLen){
        cout<<"error in sending endGameMessage"<<endl;
        return false;
    }
    cout<<"Endgame message sent correctly"<<endl;

    return true;
}

bool ServerConnectionManager::waitForOpponentCredentials(EVP_PKEY** pubkey,struct in_addr& ip) {
    size_t opponentCredentialsMessageLen = 512;
    const size_t aadLen = 1 + AESGCMIVLENGTH + sizeof(uint32_t);
    unsigned char aadBuf[aadLen];
    unsigned char ivBuf[AESGCMIVLENGTH];
    unsigned char tagBuf[AESGCMTAGLENGTH];
    unsigned char* keyBuf;

    unsigned char msgReceivingBuf[opponentCredentialsMessageLen];
    int ret = recv(this->serverSocket,msgReceivingBuf,opponentCredentialsMessageLen,0);
    if(ret <= 0){
        cout<<"ERROR in receiving opponent credentials message"<<endl;
        return false;
    }else
        cout<<"received "<<ret<< " bytes as opponent credentials"<<endl;
    if(msgReceivingBuf[0]!= OPPONENTKEYMESSAGECODE ){
        cout<<"wrong opcode "<<endl;
        return false;
    }
    uint32_t receivedCounter;
    memcpy(&receivedCounter,&msgReceivingBuf[1 +AESGCMIVLENGTH],sizeof(receivedCounter));
    if(this->counter != receivedCounter){
        cout<<"Wrong counter, expected "<<this->counter<<", received "<<receivedCounter<<endl;
        return false;
    }

    this->counter++;
    memcpy(ivBuf,&msgReceivingBuf[1],AESGCMIVLENGTH);

    size_t cipherTextLen = ret - ( 1 + AESGCMIVLENGTH + sizeof(receivedCounter) + AESGCMTAGLENGTH);
    size_t tagPosition = 1 + AESGCMIVLENGTH + sizeof(receivedCounter) + cipherTextLen;

    memcpy(aadBuf,msgReceivingBuf,aadLen);
    memcpy(tagBuf,&msgReceivingBuf[tagPosition],AESGCMTAGLENGTH);

    auto* cipherText = new unsigned char[cipherTextLen];
    memcpy(cipherText,&msgReceivingBuf[aadLen],cipherTextLen);

    size_t plainTextLen = cipherTextLen;


    unsigned char* opponentCredentials = this->symmetricEncryptionManager->decryptThisMessage(cipherText,plainTextLen,aadBuf,aadLen,tagBuf,ivBuf);

    cout<<"creating opponent credentials"<<endl;
    memcpy(&ip,opponentCredentials,sizeof(ip));

    uint32_t port;
    memcpy(&port,&opponentCredentials[4],sizeof(P2Pport));

    this->P2Pport = htons(port);

    long pubkeyLen = plainTextLen -(sizeof(int)+ sizeof(in_addr));

    keyBuf = new unsigned char[pubkeyLen];
    memcpy(&keyBuf[0],&opponentCredentials[8],pubkeyLen);

    if (!d2i_PUBKEY(pubkey,(const unsigned char**) &keyBuf,pubkeyLen) ){
        std::cout<<"d2i_PUBKEY failed"<<std::endl;
        return false;
    }

    if(!pubkey){
        cout<<"error in deserializing pubkey"<<endl;
        return false;
    }
    cout<<"credentials obtained succefully"<<endl;
    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////                                        CHALLENGED FUNCTIONS                                              ////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

std::string* ServerConnectionManager::waitForChallengeRequest() {
    std::size_t waitingBufferLen = 65;
    uint32_t receivedCounter;
    size_t ivLength = AESGCMIVLENGTH;
    unsigned char ivBuf[AESGCMIVLENGTH];
    unsigned char cipherText[2*AESBLOCKLENGTH];
    size_t tagLen = AESGCMTAGLENGTH;
    unsigned char tagBuf[AESGCMTAGLENGTH];
    size_t aadLen = 1 +AESGCMIVLENGTH  +sizeof(this->counter);
    unsigned char aadBuf[aadLen];

    unsigned char waitingBuffer[waitingBufferLen];
    int ret = recv(this->serverSocket, waitingBuffer, waitingBufferLen, 0);
    if(ret <=0){
        std::cout<<"Server disconnection"<<endl;
        return nullptr;
    }

    if(waitingBuffer[0]!= PLAYERCHOSENMESSAGECODE ){
        cout<<"wrong opcode "<<endl;
        return nullptr;
    }

    memcpy(&receivedCounter,&waitingBuffer[1 +AESGCMIVLENGTH],sizeof(receivedCounter));
    if(this->counter != receivedCounter){
        cout<<"Wrong counter, expected "<<this->counter<<", received "<<receivedCounter<<endl;
        return nullptr;
    }
    this->counter++;
    size_t step = 1;
    memcpy(ivBuf, &waitingBuffer[step],ivLength);
    memcpy(aadBuf,waitingBuffer,aadLen);
    step += ivLength +sizeof(receivedCounter);
    size_t cipherTextLen = ret - (1 + ivLength + sizeof(receivedCounter) + tagLen);
    memcpy(cipherText,&waitingBuffer[step],cipherTextLen);
    step += cipherTextLen;
    memcpy(tagBuf,&waitingBuffer[step],tagLen);

    size_t plainTextLen = cipherTextLen;
    unsigned char* clearText = this->symmetricEncryptionManager->decryptThisMessage(cipherText,plainTextLen,aadBuf,
                                                                                    aadLen,tagBuf,ivBuf);
    if(!clearText){
        cout<<"error in decrypting challenge request"<<endl;
        return nullptr;
    }

    clearText[plainTextLen-1]= '\0';

    auto* challengerName = new std::string((char*)clearText);

    return challengerName;

}
unsigned char *ServerConnectionManager::createCHallengedReadyMessage(size_t& len) {
    const size_t aadLen = 1 + AESGCMIVLENGTH + sizeof(this->counter);
    unsigned char aadBuf[aadLen];
    size_t ivLen = AESGCMIVLENGTH;

    unsigned char ivBuf[ivLen];
    unsigned char counterBuf[sizeof(this->counter)];
    unsigned char* tagBuf;

    size_t plainTextLen = sizeof(this->getP2PPort()) + this->userName->length() + 1;
    auto* plainTextBuf = new unsigned char[plainTextLen];
    unsigned int port = this->getP2PPort();
    memcpy(plainTextBuf,&port, sizeof(port));
    strcpy((char*)&plainTextBuf[sizeof(port)], this->userName->c_str());
    aadBuf[0] = CHALLENGEDREADYFORCHALLENGEMESSAGECODE;
    RAND_bytes(ivBuf,AESGCMIVLENGTH);
    size_t step = 1 ;
    memcpy(&aadBuf[step],ivBuf,AESGCMIVLENGTH);
    step += AESGCMIVLENGTH;
    memcpy(&aadBuf[step],&this->counter,sizeof(this->counter));
    step += sizeof(this->counter);
    size_t ctLen = plainTextLen;

    unsigned char* encPayload = this->symmetricEncryptionManager->encryptThisMessage(plainTextBuf, ctLen,
                                                                                     aadBuf, aadLen, ivBuf, ivLen, tagBuf);

    if(!encPayload) {
        cout<<"Challenged ready message encryption Failed"<<endl;
        return nullptr;
    }

    size_t challengedReadyMessageLen = 1 + AESGCMIVLENGTH + sizeof(this->counter) + ctLen + AESGCMTAGLENGTH;
    auto* challengedReadyMessageBuf = new unsigned char[challengedReadyMessageLen];

    memcpy(challengedReadyMessageBuf, aadBuf, aadLen);
    memcpy(&challengedReadyMessageBuf[aadLen], encPayload, ctLen);
    delete [] encPayload;

    step = aadLen + ctLen;
    memcpy(&challengedReadyMessageBuf[step], tagBuf, AESGCMTAGLENGTH);
    delete [] tagBuf;

    len = challengedReadyMessageLen;

    return challengedReadyMessageBuf;

}

bool ServerConnectionManager::sendCHallengedReadyMessage() {
    std::size_t challengedReadyMessageLength=0;
    unsigned char* challengedReadyMessageBuffer = this->createCHallengedReadyMessage(challengedReadyMessageLength);
    if(!challengedReadyMessageBuffer){
        cout<<"ERROR in creating CHallengedReadyMessage"<<endl;
        return false;
    }

    int ret = send(this->serverSocket, challengedReadyMessageBuffer, challengedReadyMessageLength, 0);

    this->counter++;
    delete [] challengedReadyMessageBuffer;
    if(ret != challengedReadyMessageLength)
        return false;
    else
        return true;
}

bool ServerConnectionManager::sendChallengedResponse(string *opponent, char response) {

    unsigned char buffer[2048];

    size_t aad_len = OPCODELENGTH + AESGCMIVLENGTH + COUNTERLENGTH;
    unsigned char aad[aad_len];
    aad[0] = CHALLENGEDRESPONSEMESSAGECODE;

    size_t iv_len = AESGCMIVLENGTH;
    unsigned char * iv = new unsigned char [iv_len];
    RAND_bytes(iv, iv_len);


    memcpy(aad+1, iv, iv_len);
    memcpy(aad+iv_len+1, &this->counter, COUNTERLENGTH);

    auto* plainMsg = new unsigned char[opponent->length()+2];
    plainMsg[0] = response;
    strcpy((char*)plainMsg+1, opponent->c_str());

    size_t encrypted_len = opponent->length()+2;
    auto*tag = new unsigned char[AESGCMTAGLENGTH];
    unsigned char *encrypted = symmetricEncryptionManager->encryptThisMessage(plainMsg, encrypted_len, aad, aad_len, iv, iv_len, tag);

    delete [] iv;
    delete [] plainMsg;

    if(!encrypted){
        cout<<"Error encrypting challenged response message"<<endl;
        delete [] encrypted;
        delete [] tag;
        return false;
    }

    size_t pos = 0;
    memcpy(buffer, aad, aad_len);
    pos += aad_len;

    memcpy(buffer+pos, encrypted, encrypted_len);
    pos += encrypted_len;
    delete [] encrypted;

    memcpy(buffer+pos, tag, AESGCMTAGLENGTH);
    pos += AESGCMTAGLENGTH;
    delete [] tag;

    size_t ret = send(this->serverSocket, buffer, pos, 0);
    if(ret <= 0) {
        cout<<"Error sending challenged response message"<<endl;
        return false;
    }
    this->counter++;

    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////                                        CHALLENGER FUNCTIONS                                              ////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

unsigned char *ServerConnectionManager::createSelectedPlayerMessage(std::string * pl,size_t& len) {
    const size_t aadLen = 1 + AESGCMIVLENGTH + sizeof(this->counter);
    unsigned char aadBuf[aadLen];
    size_t ivLen = AESGCMIVLENGTH;

    unsigned char ivBuf[ivLen];
    unsigned char counterBuf[sizeof(this->counter)];
    unsigned char* tagBuf;

    size_t challengedNameLen = pl->length()+1;
    auto* challengedNameBuf = new unsigned char [challengedNameLen];
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

bool ServerConnectionManager::sendSelectedPlayer(string* selectedPlayer) {

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
        cout<<"Not a valid Number"<<endl;
        return false;
    }
    if(temp<0 || temp > limit)
        return false;
    output = temp;
    return true;
}

bool ServerConnectionManager::waitForChallengedResponseMessage() {

    size_t challengedResponseMessageLength = 1 + AESGCMIVLENGTH + sizeof(this->counter) + 2* AESBLOCKLENGTH + AESGCMTAGLENGTH;
    unsigned char challengedResponseMessageBuf[challengedResponseMessageLength];
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
        return false;
    }
    this->counter++;
    memcpy(ivBuf,&challengedResponseMessageBuf[1],AESGCMIVLENGTH);

    size_t cipherTextLen = ret - ( 1 + AESGCMIVLENGTH + sizeof(countRec) + AESGCMTAGLENGTH);
    size_t tagPosition = 1 + AESGCMIVLENGTH + sizeof(countRec) + cipherTextLen;

    memcpy(aadBuf,challengedResponseMessageBuf,aadLen);
    memcpy(tagBuf,&challengedResponseMessageBuf[tagPosition],AESGCMTAGLENGTH);

    unsigned char cipherText[cipherTextLen];
    memcpy(cipherText,&challengedResponseMessageBuf[aadLen],cipherTextLen);

    unsigned char* answer = this->symmetricEncryptionManager->decryptThisMessage(cipherText,cipherTextLen,aadBuf,aadLen,tagBuf,ivBuf);
    if(!answer) {
        cout<<"Error in decrypting challenged response"<<endl;
        return false;
    }
    else{
        cout<<"Challenged response message received correctly"<<endl;
        if ((const char)answer[0] == 'Y')
            return true;
        else
            return false;
    }

}

ServerConnectionManager::~ServerConnectionManager() {

    delete userName;
    delete symmetricEncryptionManager;
    delete signatureManager;
    delete certificateManager;
    delete diffieHellmannManager;

}

string *ServerConnectionManager::getUsername() {
    return this->userName;
}

int ServerConnectionManager::getP2PPort() {
    return this->P2Pport;
}

void ServerConnectionManager::setP2Pport(uint32_t port){
    this->P2Pport = port;
}
uint32_t ServerConnectionManager::getServerPort(){
    return this->serverAddr.sin_port;
}

EVP_PKEY *ServerConnectionManager::getPrvKey() {
    return this->signatureManager->getPrvkey();
}
