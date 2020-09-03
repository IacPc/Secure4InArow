//
// Created by Laura Lemmi on 02/09/2020.
//

#include "P2PConnectionManager.h"
#include "ServerConnectionManager.h"

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

    string* path = new std::string ("../Client/Client_Key/");
    path->append(this->myUsername->c_str());
    path->append("_prvkey.pem");
    this->signatureManager = new SignatureManager(path, nullptr);

    memset(&this->opponentAddr,0X00,sizeof(struct sockaddr_in));

    RAND_poll();

    diffieHellmannManager = new DiffieHellmannManager();

    std::cout<<"P2PConnectionManager created successfully"<<std::endl;
}



P2PConnectionManager::~P2PConnectionManager() {

    delete serverConnectionManager;
    delete signatureManager;
    delete symmetricEncryptionManager;

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////                                      BOTH CHALLENGED AND CHALLENGER FUNCTIONS                            ////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

unsigned char *P2PConnectionManager::createCoordinateMessage(uint8_t x, uint8_t y) {
    const size_t aadLen = 1 + AESGCMIVLENGTH + sizeof(this->counter);
    unsigned char aadBuf[aadLen];
    size_t ivLen = AESGCMIVLENGTH;

    unsigned char ivBuf[ivLen];
    unsigned char counterBuf[sizeof(this->counter)];
    unsigned char* tagBuf;

    size_t coordinatesBufLen = 2 * sizeof(uint8_t);
    auto* coordinatesBuf = new unsigned char[coordinatesBufLen];
    coordinatesBuf[0] = x;
    coordinatesBuf[1] = y;
    aadBuf[0] = COORDINATEMESSAGECODE;
    RAND_bytes(ivBuf,AESGCMIVLENGTH);
    size_t step = 1 ;
    memcpy(&aadBuf[step],ivBuf,AESGCMIVLENGTH);
    step += AESGCMIVLENGTH;
    memcpy(&aadBuf[step],&this->counter,sizeof(this->counter));
    step += sizeof(this->counter);


    unsigned char* encPayload = this->symmetricEncryptionManager->encryptThisMessage(coordinatesBuf, coordinatesBufLen,
                                                                                     aadBuf, aadLen, ivBuf, ivLen, tagBuf);
    coordinatesBuf[0] =coordinatesBuf[1] = 0XFF;
    delete [] coordinatesBuf;
    if(!encPayload){
        return nullptr;
    }
    auto* coordinateMessageBuffer = new unsigned char[COORDINATEMESSAGELENGTH];
    step = 0;
    memcpy(&coordinateMessageBuffer[step],aadBuf,aadLen);
    step += aadLen;
    memcpy(&coordinateMessageBuffer[step],encPayload,coordinatesBufLen);
    delete [] encPayload;
    step += coordinatesBufLen;
    memcpy(&coordinateMessageBuffer[step],tagBuf,AESGCMTAGLENGTH);

    return coordinateMessageBuffer;

}

bool P2PConnectionManager::sendCoordinateMessage(uint8_t x, uint8_t y) {
    size_t len = COORDINATEMESSAGELENGTH;
    unsigned char* message = this->createCoordinateMessage(x, y);
    if(!message){
        cout<<"Challenge message buffer not allocated"<<endl;
        return false;
    }
    int ret = send(this->opponentSocket,message,len,0);

    if(ret != len){
        cout<<"Challenge message buffer not sent"<<endl;
        return false;
    }

    return true;

}

bool P2PConnectionManager::tryParseY(std::string * input, uint8_t& output) {
    uint8_t temp;
    try{
        temp = std::stoi(input->c_str());
    } catch (std::invalid_argument) {
        return false;
    }
    if(temp < 1 || temp > 7)
        return false;
    else{
        output = temp;
        return true;
    }
}

bool P2PConnectionManager::tryParseX(std::string * input, uint8_t& output) {
    uint8_t temp;
    try{
        temp = std::stoi(input->c_str());
    } catch (std::invalid_argument) {
        return false;
    }
    if(temp < 1 || temp > 6)
        return false;
    else{
        output = temp;
        return true;
    }
}

bool P2PConnectionManager::waitForCoordinateMessage(uint8_t& x,uint8_t& y) {
    size_t len = COORDINATEMESSAGELENGTH;
    size_t ivLength = AESGCMIVLENGTH;
    unsigned char ivBuf[AESGCMIVLENGTH];
    unsigned char cipherText[AESBLOCKLENGTH];
    size_t tagLen = AESGCMTAGLENGTH;
    unsigned char tagBuf[AESGCMTAGLENGTH];
    size_t aadLen = 1 +AESGCMIVLENGTH  +sizeof(this->counter);
    unsigned char aadBuf[aadLen];

    auto* coordinateMessagebuf = new unsigned char[len];
    int ret = recv(this->opponentSocket,coordinateMessagebuf,len,0);
    if(ret!= len){
        cout<<"Error in receiving coordiante message"<<endl;
        return false;
    }
    if(coordinateMessagebuf[0] != COORDINATEMESSAGECODE){
        cout<<"wrong message,expected coordinate message"<<endl;
        delete [] coordinateMessagebuf;
        return false;
    }

    uint32_t receivedCounter;
    memcpy(&receivedCounter,&coordinateMessagebuf[1 +AESGCMIVLENGTH],sizeof(receivedCounter));

    if(this->counter != receivedCounter){
        cout<<"Wrong counter, expected "<<this->counter<<", received "<<receivedCounter<<endl;
        delete [] coordinateMessagebuf;
        return false;
    }
    this->counter++;
    size_t step = 1;
    memcpy(ivBuf, &coordinateMessagebuf[step],ivLength);
    memcpy(aadBuf,coordinateMessagebuf,aadLen);
    step += ivLength +sizeof(receivedCounter);
    size_t cipherTextLen = AESBLOCKLENGTH;
    memcpy(cipherText,&coordinateMessagebuf[step],cipherTextLen);
    step += cipherTextLen;
    memcpy(tagBuf,&coordinateMessagebuf[step],tagLen);

    size_t plainTextLen = cipherTextLen;
    unsigned char* clearText = this->symmetricEncryptionManager->decryptThisMessage(cipherText,plainTextLen,aadBuf,
                                                                                    aadLen,tagBuf,ivBuf);
    if(!clearText){
        cout<<"error in decrypting coordinate message"<<endl;
        return false;
    }
    x = clearText[0];
    y = clearText[1];

    if(x>5 || y>6){
        cout<<"NOT VALID coordinates!"<<endl;
        return false;
    }

    return true;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////                                        CHALLENGED FUNCTIONS                                              ////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void P2PConnectionManager::startTheGameAsChallengeD() {

    mySocket = socket(AF_INET, SOCK_STREAM, 0);
    myAddr.sin_family = AF_INET;
    myAddr.sin_port = htons(this->serverConnectionManager->getP2PPort());
    myAddr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(mySocket, (struct sockaddr *) &myAddr, sizeof(myAddr)) == -1) {
        cerr << "Error during bind" << endl;
        delete this;
        return;
    }

    if (!waitForChallengeRConnection()) {
        cerr << "Error during connection with challenger" << endl;
        delete this;
        return;
    }

    if (!establishSecureConnectionWithChallengeR()) {
        cerr << "Secure Connection not established" << endl;
        delete this;
        return;
    }
    cout << "Secure connection has been established. The game can start. " << endl;
    cout << "Wait for the challenger's first move" << endl;

    bool win;
    if (challengeDGame(win)) {
        if(win) {
            cout << "You won" << endl;
        }else{
            cout << "You lost the match" << endl;
        }
    }else{
        cout<<"Error during the match. The game cannot be finished"<<endl;
    }

    delete this;
    return;
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

    //set opponent pubkey
    string *path = new string("../Client/Client_Key/");
    path->append(this->opponentUsername->c_str());
    path->append("_pubkey.pem");
    FILE* pubkeyUser = fopen(path->c_str(),"r");
    EVP_PKEY* pubkey = PEM_read_PUBKEY(pubkeyUser,NULL,NULL,NULL);
    this->signatureManager->setPubkey(pubkey);

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

bool P2PConnectionManager::waitForChallengeRPubKey() {
    auto* buffer = new unsigned char[2048];
    size_t ret = recv(this->opponentSocket ,buffer, 2048, 0);
    if(ret <= 0){
        cout<<"Error receiving the public key message"<<endl;
        delete [] buffer;
        return false;
    }

    size_t pos = 0;
    if(buffer[pos] == PUBKEYMESSAGECODE) {
        cout << "Pubkey message opcode verified" << endl;
        pos++;
    }
    else{
        cout<<"Wrong message. Expected pubkey message."<<endl;
        delete [] buffer;
        return false;
    }

    //copio client nonce
    uint32_t receivedOpponentNonce;
    memcpy(&receivedOpponentNonce, (buffer + pos), NONCELENGTH);
    pos += NONCELENGTH;

    //copio il mio nonce
    uint32_t myReceivedNonce;
    memcpy(&myReceivedNonce, (buffer+pos), NONCELENGTH);
    pos += NONCELENGTH;

    bool differentNonces = (this->myNonce != myReceivedNonce) || (this->opponentNonce != receivedOpponentNonce);

    if(differentNonces){
        std::cout<<"Nonces does not match!"<<endl;
        std::cout<<"Challenged Nonce is "<<this->myNonce<<",received "<<myReceivedNonce<<endl;
        std::cout << "Challenger Nonce is " << this->opponentNonce << ",received " << receivedOpponentNonce << endl;
        return false;
    }

    //copio dimensione pubkey
    uint16_t pubkey_len;
    memcpy(&pubkey_len, (buffer+pos), sizeof(pubkey_len));
    pos += sizeof(pubkey_len);
    std::cout<<"pubkey_len="<<pubkey_len<<endl;
    //prelevo la pubkey
    auto* opponentPubKey = new unsigned char[pubkey_len];
    memcpy(opponentPubKey, (buffer+pos), pubkey_len);
    pos += pubkey_len;
    size_t messageToVerify_len = pos;

    //copio dimensione signature
    uint16_t signature_len;
    memcpy(&signature_len, (buffer+pos), sizeof(signature_len));
    pos += sizeof(signature_len);

    //pos contiene la lunghezza del buffer fino a Yc.
    auto *signature = new unsigned char[signature_len];
    auto *messageToVerify = new unsigned char[messageToVerify_len];
    memcpy(messageToVerify, buffer, messageToVerify_len);
    memcpy(signature, (buffer+pos), signature_len);


    cout<<signature_len<<endl;
    //verifico la firma
    if(!signatureManager->verifyThisSignature(signature, signature_len, messageToVerify, ret-signature_len-2)) {
        cout<<"Signature not verified"<<endl;
        delete [] buffer;
        delete [] signature;
        delete [] messageToVerify;
        delete [] opponentPubKey;
        return false;
    }
    cout<<"Signature verified correctly"<<endl;
    delete [] signature;
    delete [] messageToVerify;

    //chiamo DH

    diffieHellmannManager->setPeerPubKey(opponentPubKey, pubkey_len);

    cout<<"Set peer public key"<<endl;
    delete [] opponentPubKey;
    delete [] buffer;

    return true;

}

bool P2PConnectionManager::sendChallengeDPubKey() {

    auto *buffer = new unsigned char[2048];

    //inserisco opcode
    size_t pos = 0;
    buffer[pos] = PUBKEYMESSAGECODE;
    pos++;

    //inserisco client nonce
    memcpy((buffer+pos), &this->opponentNonce, NONCELENGTH);
    pos += NONCELENGTH;

    //inserisco myNonce
    memcpy((buffer+pos), &this->myNonce, NONCELENGTH);
    pos += NONCELENGTH;

    //inserisco la lunghezza e chiave
    size_t myKey_len;
    unsigned char* myKey = diffieHellmannManager->getMyPubKey(myKey_len);
    std::cout<<"my pubkey obtained succesfully of len "<<myKey_len<<endl;
    memcpy((buffer+pos), &myKey_len, sizeof(uint16_t));
    pos += sizeof(uint16_t);

    memcpy((buffer+pos), myKey, myKey_len);
    pos += myKey_len;

    //delete [] myKey;
    cout<<"now i do the signature"<<endl;
    //firmo il messaggio
    size_t signature_len = pos;
    unsigned char* signedMessage = signatureManager->signTHisMessage(buffer, signature_len);

    //copio la dimensione e la firma nel buffer
    memcpy((buffer+pos), &signature_len, SIZETLENGTH);
    pos += SIZETLENGTH;
    memcpy((buffer+pos), signedMessage, signature_len);
    pos += signature_len;

    //invio
    size_t ret = send(this->opponentSocket, buffer, pos, 0);
    if(ret != pos){
        cout<<"Error in sending my pubkey"<<endl;
        delete [] buffer;
        return false;
    }

    delete [] buffer;
    return true;
}

void P2PConnectionManager::createSessionKey() {


    size_t sharedSecret_len;
    unsigned char* sharedSecret = diffieHellmannManager->getSharedSecret(sharedSecret_len);
    auto* HashedSecret = new unsigned char[EVP_MD_size(EVP_sha256())];
    size_t dhSecretLen = 0;

    SHA256(sharedSecret,sharedSecret_len,HashedSecret);
    size_t aesKeyLen = EVP_CIPHER_key_length(EVP_aes_128_gcm());
    auto* simmetricKeyBuffer = new unsigned char[aesKeyLen];
    memcpy(&simmetricKeyBuffer[0],&HashedSecret[0],aesKeyLen);

    symmetricEncryptionManager = new SymmetricEncryptionManager(simmetricKeyBuffer, aesKeyLen);

    delete [] simmetricKeyBuffer;
    delete [] HashedSecret;
    delete diffieHellmannManager;
}

bool P2PConnectionManager::challengeDGame(bool& win) {

    bool finish = false;
    while(!finish){
        uint8_t x;
        uint8_t y;
        waitForCoordinateMessage(x, y);

        //TESTARE LA FINE DEL GIOCO

        string x_coordinate;
        do {
            x_coordinate.clear();
            cout << "Type the coordinate x: choose a number between 1 and 6" << endl;
            getline(cin, x_coordinate);
        } while (!tryParseX(&x_coordinate, x));

        string y_coordinate;
        do {
            y_coordinate.clear();
            cout << "Type the coordinate x: choose a number between 1 and 7" << endl;
            getline(cin, y_coordinate);
        } while (!tryParseY(&y_coordinate, x));

        if(!sendCoordinateMessage(x-1, y-1)){
            cout<<"Error: Coordinate message has not been sent"<<endl;
            return false;
        }

        //TESTARE LA FINE DELLA PARTITA

    }
    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////                                        CHALLENGER FUNCTIONS                                              ////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void P2PConnectionManager::startTheGameAsChallengeR() {


}

void P2PConnectionManager::setOpponentIp(struct in_addr ip) {

    this->opponentAddr.sin_family = AF_INET;
    this->opponentAddr.sin_port = this->serverConnectionManager->getP2PPort();
    this->opponentAddr.sin_addr = ip;

}

bool P2PConnectionManager::connectToChallengedUser() {
    int ret;
    this->opponentSocket = socket(AF_INET, SOCK_STREAM, 0);

    ret = connect(this->opponentSocket, (struct sockaddr*)&this->myAddr, sizeof(this->myAddr));
    if(ret < 0){
        cerr<<"Error during TCP connection with server\n";
        return false;
    }
    return true;
}


