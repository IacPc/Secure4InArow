//
// Created by Laura Lemmi on 02/09/2020.
//

#include "P2PConnectionManager.h"
#include "ServerConnectionManager.h"

P2PConnectionManager::P2PConnectionManager(EVP_PKEY *opponentKey, ServerConnectionManager *srvcnm) {

    if(!srvcnm){
        cout<<"not valid serverconnectionmanager"<<endl;
        return;
    }

    this->serverConnectionManager = srvcnm;
    myUsername.append(srvcnm->getUsername()->c_str());


    std::string prvkPath("../Client/Client_Key/");
    prvkPath.append(srvcnm->getUsername()->c_str());
    prvkPath.append("_prvkey.pem");
    signatureManager = new SignatureManager(&prvkPath);
    signatureManager->setPubkey(opponentKey);

    memset(&this->opponentAddr,0X00,sizeof(struct sockaddr_in));

    RAND_poll();

    diffieHellmannManager = new DiffieHellmannManager();

    std::cout<<"P2PConnectionManager created successfully"<<std::endl;
}

P2PConnectionManager::~P2PConnectionManager() {
    delete signatureManager;
    delete symmetricEncryptionManager;
    delete gameBoard;
    delete opponentUsername;
    delete diffieHellmannManager;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////                                      BOTH CHALLENGED AND CHALLENGER FUNCTIONS                            ////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool P2PConnectionManager::waitForHelloMessage() {
    cout<<"Waiting for challenger hello message"<<endl;
    unsigned char buffer[HELLOMESSAGELENGTH];
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
        return false;
    }


    memcpy((unsigned char*)&this->opponentNonce, &buffer[1], NONCELENGTH);

    buffer[ret-1] = '\0';
    this->opponentUsername = new string((const char*)&buffer[1 + NONCELENGTH]);

    cout<<"THE RECEIVED USERNAME IS: "<<this->opponentUsername->c_str()<<endl;
    return true;
}

bool P2PConnectionManager::sendHelloMessage() {

    size_t msg_len = 1 + NONCELENGTH + strlen(this->myUsername.c_str())+1;
    unsigned char buffer[msg_len];

    buffer[0] = HELLOMSGCODE;
    RAND_bytes((unsigned char*)&this->myNonce, sizeof(this->myNonce));
    memcpy(&buffer[1], (unsigned char*)&this->myNonce, NONCELENGTH);
    strcpy((char*)&buffer[1 + NONCELENGTH], this->myUsername.c_str());

    size_t ret = send(this->opponentSocket, buffer, msg_len, 0);
    if(ret != msg_len){
        cout<<"Error in sending my nonce"<<endl;
        return false;
    }

    return true;
}

unsigned char *P2PConnectionManager::createCoordinateMessage(uint8_t column) {
    const size_t aadLen = 1 + AESGCMIVLENGTH + sizeof(this->counter);
    unsigned char aadBuf[aadLen];
    size_t ivLen = AESGCMIVLENGTH;

    unsigned char ivBuf[ivLen];
    auto* tagBuf = new unsigned char[AESGCMTAGLENGTH];

    size_t coordinatesBufLen = sizeof(uint8_t);
    unsigned char coordinatesBuf;
    coordinatesBuf = column;

    aadBuf[0] = COORDINATEMESSAGECODE;
    RAND_bytes(ivBuf,AESGCMIVLENGTH);
    size_t step = 1 ;
    memcpy(&aadBuf[step],ivBuf,AESGCMIVLENGTH);
    step += AESGCMIVLENGTH;
    memcpy(&aadBuf[step],&this->counter,sizeof(this->counter));
    step += sizeof(this->counter);

    unsigned char* encPayload = this->symmetricEncryptionManager->encryptThisMessage(&coordinatesBuf, coordinatesBufLen,
                                                                                     aadBuf, aadLen, ivBuf, ivLen, tagBuf);

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
    delete [] tagBuf;

    return coordinateMessageBuffer;

}

bool P2PConnectionManager::sendCoordinateMessage(uint8_t column) {
    size_t len = COORDINATEMESSAGELENGTH;
    unsigned char* message = this->createCoordinateMessage(column);
    if(!message){
        cout<<"Challenge message buffer not allocated"<<endl;
        return false;
    }
    int ret = send(this->opponentSocket,message,len,0);

    if(ret != len){
        cout<<"Challenge message buffer not sent"<<endl;
        return false;
    }
    this->counter++;

    return true;

}

bool P2PConnectionManager::tryParseY(std::string * input, uint8_t & output) {
    unsigned int temp;
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
    unsigned int temp;
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

bool P2PConnectionManager::waitForCoordinateMessage(uint8_t& column, bool isFirstMessage) {
    size_t len = COORDINATEMESSAGELENGTH;
    size_t ivLength = AESGCMIVLENGTH;
    unsigned char ivBuf[AESGCMIVLENGTH];
    unsigned char cipherText[2*sizeof(uint8_t)];
    size_t tagLen = AESGCMTAGLENGTH;
    unsigned char tagBuf[AESGCMTAGLENGTH];
    size_t aadLen = 1 +AESGCMIVLENGTH  +sizeof(this->counter);
    unsigned char aadBuf[aadLen];

    unsigned char coordinateMessagebuf[COORDINATEMESSAGELENGTH];
    memset(coordinateMessagebuf,0X00,COORDINATEMESSAGELENGTH);

    int ret = recv(this->opponentSocket,coordinateMessagebuf,len,0);
    if(ret<=0){
        cout<<"opponentn disconnected"<<endl;
        return false;
    }
    if(ret!= len){
        cout<<"Error in receiving coordinate message"<<endl;
        return false;
    }
    if(coordinateMessagebuf[0] !=COORDINATEMESSAGECODE){
        cout<<"wrong message,expected coordinate message"<<endl;
        return false;
    }

    uint32_t receivedCounter;
    memcpy(&receivedCounter,&coordinateMessagebuf[1 +AESGCMIVLENGTH],sizeof(receivedCounter));

    if(!isFirstMessage){
        if (this->counter != receivedCounter) {
            cout << "Wrong counter, expected " << this->counter << ", received " << receivedCounter << endl;
            return false;
        }

    }else{
        this->counter= receivedCounter;
    }

    this->counter++;

    size_t step = 1;
    memcpy(ivBuf, &coordinateMessagebuf[step],ivLength);
    memcpy(aadBuf,coordinateMessagebuf,aadLen);
    step += ivLength +sizeof(receivedCounter);
    size_t cipherTextLen = sizeof(uint8_t);
    memcpy(cipherText,&coordinateMessagebuf[step],cipherTextLen);
    step += cipherTextLen;
    memcpy(tagBuf,&coordinateMessagebuf[step],tagLen);

    size_t plainTextLen = cipherTextLen;
    unsigned char* clearText = this->symmetricEncryptionManager->decryptThisMessage(cipherText,plainTextLen,aadBuf,
                                                                                    aadLen,tagBuf,ivBuf);

    column =(uint8_t) clearText[0];

    cout << "The received coordinate is COLUMN = " << (unsigned int)column << endl;

    memset(coordinateMessagebuf,0X00,COORDINATEMESSAGELENGTH);

    if(column < 1 || column > 7){
        cout<<"NOT VALID column!"<<endl;
        return false;
    }

    return true;
}

unsigned char *P2PConnectionManager::createPubKeyMessage(size_t& len) {
    size_t pubKeyLength = 0;
    unsigned char* pubKeyBuf = this->diffieHellmannManager->getMyPubKey(pubKeyLength);

    size_t pubKeyMessageToSignLength = 1 + 2*sizeof(this->opponentNonce) + sizeof(uint16_t) + pubKeyLength;

    unsigned char pubKeyMessageToSignBuffer[pubKeyMessageToSignLength];
    pubKeyMessageToSignBuffer[0] = PUBKEYMESSAGECODE;

    size_t step = 1;
    memcpy(&pubKeyMessageToSignBuffer[step],&this->myNonce,sizeof(this->myNonce));
    step += sizeof(this->myNonce);
    memcpy(&pubKeyMessageToSignBuffer[step],&this->opponentNonce,sizeof(this->opponentNonce));
    step += sizeof(this->opponentNonce);
    uint16_t len_16t = pubKeyLength;
    memcpy(&pubKeyMessageToSignBuffer[step], &len_16t, sizeof(len_16t));
    step += sizeof(len_16t);
    memcpy(&pubKeyMessageToSignBuffer[step],pubKeyBuf,len_16t);
    step += len_16t;

    //delete [] pubKeyBuf;
    size_t signatureLength = step;
    unsigned char* signature = this->signatureManager->signTHisMessage(pubKeyMessageToSignBuffer,signatureLength);
    if(!signature) {
        return nullptr;
    }
    size_t pubKeyMessageLength = step + sizeof(len_16t) + signatureLength;
    auto* pubKeyMessageBuffer = new unsigned char[pubKeyMessageLength];
    memcpy(pubKeyMessageBuffer,pubKeyMessageToSignBuffer,step);

    len_16t = signatureLength;
    memcpy(&pubKeyMessageBuffer[step],&len_16t,sizeof(len_16t));

    step += sizeof(len_16t);
    memcpy(&pubKeyMessageBuffer[step],signature,signatureLength);

    delete [] signature;

    len = pubKeyMessageLength;
    cout<<"Creation of PubKeyMessage of size "<<len<<" finished correctly "<<endl;

    return pubKeyMessageBuffer;
}

bool P2PConnectionManager::sendMyPubKey() {
    size_t len;
    unsigned char* pKeyMsg = createPubKeyMessage(len);
    if(!pKeyMsg){
        cerr<<"Error during public key Message creation\n";
        return false;
    }
    int ret = send(this->opponentSocket,pKeyMsg,len,0);
    delete [] pKeyMsg;
    if(ret!= len)
        return false;
    return true;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////                                        CHALLENGED FUNCTIONS                                              ////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


bool tryParse(std::string* input, unsigned int& output) {
    unsigned int temp;
    try{
        temp = std::stoi(input->c_str());
    } catch (std::invalid_argument) {
        return false;
    }
    if((temp > 65535) || (temp < 2000))
        return false;
    output = temp;
    return true;
}

void P2PConnectionManager::startTheGameAsChallengeD() {

    //SET p2pPort for the challenged
    string port_input;
    bool valid = false;
    uint32_t input_port;

    uint32_t serverPort = htons(serverConnectionManager->getServerPort());

    getline(cin, port_input);
    port_input.clear();
    while(!valid){
        valid = true;
        cout<<"Insert a port for the P2P communication "<<endl;
        getline(cin, port_input);
        valid = tryParse(&port_input, input_port);
        if(!valid || input_port == serverPort )
            valid = false;
        port_input.clear();
    }

    cout<<"Port has been given"<<endl;
    serverConnectionManager->setP2Pport(htons(input_port));


    mySocket = socket(AF_INET, SOCK_STREAM, 0);
    myAddr.sin_family = AF_INET;
    myAddr.sin_port = (unsigned short)this->serverConnectionManager->getP2PPort();

    myAddr.sin_addr.s_addr = INADDR_ANY;

    char buffer[INET_ADDRSTRLEN];
    inet_ntop( AF_INET, &myAddr.sin_addr.s_addr, buffer, sizeof( buffer ));
    printf( "Opponent address:%s\n", buffer );

    cout<<"Challenged address built"<<endl;

    if (::bind(mySocket, (struct sockaddr *) &myAddr, sizeof(myAddr)) == -1) {
        cerr << "Error during bind" << endl;
        return;
    }


    if (!waitForChallengeRConnection()) {
        cerr << "Error during connection with challenger" << endl;
        return;
    }

    if (!establishSecureConnectionWithChallengeR()) {
        cerr << "Secure Connection not established" << endl;
        return;
    }
    cout << "Secure connection has been established. The game can start. " << endl;
    cout << "Wait for the challenger's first move" << endl;
    gameBoard = new GameBoard(this->myUsername.c_str(),this->opponentUsername->c_str());
    if (!challengeDGame())
        cout<<"Error during the match. The game cannot be finished"<<endl;


}

bool P2PConnectionManager::waitForChallengeRConnection() {

    listen(this->mySocket, 10);

    if(!serverConnectionManager->sendCHallengedReadyMessage()){
        cout<<"Error sending challenged readiness message"<<endl;
        return false;
    }

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
        return false;
    }

    //set opponent pubkey
    string *path = new string("../Client/Client_Key/");
    path->append(this->opponentUsername->c_str());
    path->append("_pubkey.pem");
    FILE* pubkeyUser = fopen(path->c_str(),"r");
    EVP_PKEY* pubkey = PEM_read_PUBKEY(pubkeyUser,NULL,NULL,NULL);
    this->signatureManager->setPubkey(pubkey);
    fclose(pubkeyUser);
    if(!sendHelloMessage()){
        cerr<<"Error in sending my Hello Message"<<endl;
        return false;
    }

    if(!waitForChallengeRPubKey()){
        cerr<<"Error in receiving challenger pubkey"<<endl;
        return false;
    }else{
        cout<<"Challenger public key received successfully"<<endl;
    }


    if(!sendChallengeDPubKey()){
        cerr<<"Error in sending my pubkey"<<endl;
        return false;
    }else{
        cout<<"PubKey sent successfully"<<endl;
    }

    createSessionKey();

    return true;
}

bool P2PConnectionManager::waitForChallengeRPubKey() {
    unsigned char buffer[2048];
    size_t ret = recv(this->opponentSocket ,buffer, 2048, 0);
    if(ret <= 0){
        cout<<"Error receiving the public key message"<<endl;
        return false;
    }

    size_t pos = 0;
    if(buffer[pos] == PUBKEYMESSAGECODE) {
        cout << "Pubkey message opcode verified" << endl;
        pos++;
    }
    else{
        cout<<"Wrong message. Expected pubkey message."<<endl;
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
    //prelevo la pubkey
    unsigned char opponentPubKey[pubkey_len];
    memcpy(opponentPubKey, (buffer+pos), pubkey_len);
    pos += pubkey_len;
    size_t messageToVerify_len = pos;

    //copio dimensione signature
    uint16_t signature_len;
    memcpy(&signature_len, (buffer+pos), sizeof(signature_len));
    pos += sizeof(signature_len);

    //pos contiene la lunghezza del buffer fino a Yc.
    unsigned char signature[signature_len];
    unsigned char messageToVerify[messageToVerify_len];
    memcpy(messageToVerify, buffer, messageToVerify_len);
    memcpy(signature, (buffer+pos), signature_len);


    //verifico la firma
    if(!signatureManager->verifyThisSignature(signature, signature_len, messageToVerify, ret-signature_len-2)) {
        cout<<"Signature not verified"<<endl;
        return false;
    }
    cout<<"Signature verified correctly"<<endl;

    //chiamo DH

    diffieHellmannManager->setPeerPubKey(opponentPubKey, pubkey_len);

    return true;

}

bool P2PConnectionManager::sendChallengeDPubKey() {

    unsigned char buffer[2048];

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
        return false;
    }

    return true;
}

void P2PConnectionManager::createSessionKey() {


    size_t sharedSecret_len;
    unsigned char* sharedSecret = diffieHellmannManager->getSharedSecret(sharedSecret_len);
    auto* HashedSecret = new unsigned char[EVP_MD_size(EVP_sha256())];

    SHA256(sharedSecret,sharedSecret_len,HashedSecret);
    size_t aesKeyLen = EVP_CIPHER_key_length(EVP_aes_128_gcm());
    auto* simmetricKeyBuffer = new unsigned char[aesKeyLen];
    memcpy(&simmetricKeyBuffer[0],&HashedSecret[0],aesKeyLen);

    symmetricEncryptionManager = new SymmetricEncryptionManager(simmetricKeyBuffer, aesKeyLen);

    delete [] simmetricKeyBuffer;
    delete [] HashedSecret;
    delete diffieHellmannManager;
    diffieHellmannManager = nullptr;
}

bool P2PConnectionManager::challengeDGame() {

    bool finish = false;
    uint8_t x;
    uint8_t y;
    bool isFirstMEssage = true;
    int ret = 0;
    while(!finish){

        if(!waitForCoordinateMessage(y,isFirstMEssage)) {
            cout << "Error: Coordinate message has not been received correctly" << endl;
            return false;
        }
        isFirstMEssage = false;
        ret = gameBoard->insertOpponentMove( y);
        cout<<*gameBoard;
        if(ret == -1)
            return false;
        if(ret == 1){
            cout<<"You won!"<<endl;
            finish = true;
            continue;
        }
        if(ret == 2){
            cout<<"You lost!"<<endl;
            finish = true;
            continue;
        }

        x = y = 0;

        string y_coordinate;
        do{
            do {
                y_coordinate.clear();
                cout << "Type the column number: choose a number between 1 and 7" << endl;
                getline(cin, y_coordinate);
            } while (!tryParseY(&y_coordinate, y));

            cout << "Your coordinate => COLUMN=" << (unsigned int) y << endl;
            ret = gameBoard->insertMyMove(y);
        }while(ret == -2);

        cout<<*gameBoard;

        if(!sendCoordinateMessage(y)){
            cout<<"Error: Coordinate message has not been sent"<<endl;
            return false;
        }

        if(ret == -1)
            return false;
        if(ret == 1){
            cout<<"You won!"<<endl;
            finish = true;
        }
        if(ret == 2){
            cout<<"You lost!"<<endl;
            finish = true;
        }


        cout<<"coordinate message sent correctly, waiting for the next move.."<<endl;

    }
    return true;
}

bool P2PConnectionManager::waitForPeerPubkey() {

    unsigned char peerPubKeyMessageBuffer[2048];
    int ret = recv(this->opponentSocket, peerPubKeyMessageBuffer, 2048, 0);

    if (ret <= 0) {
        cout<<"PeerPubKey received "<<ret << " bytes"<<endl;
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

    if(nonceRecv != this->opponentNonce){
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

    size_t pubKeyPosition = 1 + 2*sizeof(this->opponentNonce) + sizeof(recvPubKeyLen);

    this->diffieHellmannManager->setPeerPubKey(&peerPubKeyMessageBuffer[pubKeyPosition],recvPubKeyLen);

    return true;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////                                        CHALLENGER FUNCTIONS                                              ////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool P2PConnectionManager::establishSecureConnectionWithChallengeD() {
    EVP_PKEY* pb;
    in_addr ip;
    if(!this->serverConnectionManager->waitForOpponentCredentials(&pb,ip)) {
        cout<<"error in receiving challenged pubkey"<<endl;
        return false;
    }
    cout<<"Received the opponent credentials"<<endl;
    this->signatureManager->setPubkey(pb);
    this->setOpponentIp(ip);

    if(!this->connectToChallengedUser()) {
        cout<<"error in connecting to challenged"<<endl;
        return false;
    }

    if(!this->sendHelloMessage()){
        cout<<"error in sending hello message"<<endl;
        return false;
    }

    if(!this->waitForHelloMessage()){
        cout<<"error in receiving hello message"<<endl;
        return false;
    }

    if(!this->sendMyPubKey()){
        cout<<"error in sending my pubkey"<<endl;
        return false;
    }

    if(!this->waitForPeerPubkey()){
        cout<<"error in receiving opponent pubkey"<<endl;
        return false;
    }

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

    return true;
}

void P2PConnectionManager::startTheGameAsChallengeR() {
   if(!establishSecureConnectionWithChallengeD()){
       return;
   }
   cout<<"established secure connection with challenged"<<endl;
   gameBoard = new GameBoard(this->myUsername.c_str(),this->opponentUsername->c_str());
   uint8_t coordX,coordY;
   RAND_bytes((unsigned char*)&this->counter,sizeof(this->counter));
   string x_coordinate,y_coordinate;
    int ret = 0;
    while (true){

        do{
            do {
                y_coordinate.clear();
                cout << "Type the column number: choose a number between 1 and 7" << endl;
                getline(cin, y_coordinate);
            } while (!tryParseY(&y_coordinate, coordY));

            cout << "Adversary coordinate => COLUMN=" << (unsigned int) coordY << endl;


            ret = gameBoard->insertMyMove(coordY);
        }while(ret ==-2);

        if (!sendCoordinateMessage(coordY)) {
            cout << "error in sending coordinate" << endl;
            return;
        }
       cout<<*gameBoard;
       if(ret == -1)
            return;
       if(ret == 1){
            cout<<"You won!"<<endl;
            return;
       }
       if(ret == 2){
            cout<<"You lost!"<<endl;
            return;
       }
       cout << "coordinate message sent correctly, waiting for the next move.." << endl;
       coordX = coordY = 0;
       if(!this->waitForCoordinateMessage(coordY,false)){
           cout<<"error in receiving coordinate"<<endl;
           return;
       }
        ret = gameBoard->insertOpponentMove(coordY);
        cout<<*gameBoard;
        if(ret == -1)
            return;
        if(ret == 1){
            cout<<"You won!"<<endl;
            return;
        }
        if(ret == 2){
            cout<<"You lost!"<<endl;
            return;
        }
       cout<<"received coordinate X="<<(unsigned int)coordX<<" Y= "<<(unsigned int)coordY<<endl;

   }

}

void P2PConnectionManager::setOpponentIp(struct in_addr ip) {
    this->opponentAddr.sin_family = AF_INET;
    this->opponentAddr.sin_port = htons((unsigned short )this->serverConnectionManager->getP2PPort());
    this->opponentAddr.sin_addr = ip;

}

bool P2PConnectionManager::connectToChallengedUser() {
    int ret;
    this->opponentSocket = socket(AF_INET, SOCK_STREAM, 0);

    ret = connect(this->opponentSocket, (struct sockaddr*)&this->opponentAddr, sizeof(this->opponentAddr));
    if(ret < 0){
        cerr<<"Error during TCP connection with challenged user\n";
        return false;
    }
    return true;
}





