//
// Created by iacopo on 14/08/20.
//

#include "UserConnectionManager.h"

UserConnectionManager::UserConnectionManager(Server *srv, sockaddr_in client_addr, int clSocket) {

    //setting UserConnectionManager attributes
    server = srv;
    clAdd = client_addr;
    userSocket = clSocket;

    RAND_poll();
    cout<<"UserConnectionManager created successfully\n";

}

void UserConnectionManager::openNewconnectionwithClient() {
    if(!this->establishSecureConnection()){
        server->removeUser(this->userName);
        delete this;
        return;
    }else
        cout<<"Secure connection established"<<std::endl;

    size_t players_num;

    if(!sendPlayerList(players_num)){
        cerr<<"Error in sending players list\n";
        delete this;
    }


    string *choice;
    bool isWaiting = false;
    choice = waitForChoice(isWaiting);
    if((choice == NULL) && isWaiting == true){
        //è lo sfidato
        string *opponent = waitForResponse();
        if(opponent == NULL){
            cerr << "The challenge cannot start \n";
            delete choice;
            delete opponent;
            delete this;
        }

        if(!sendOpponentKey(opponent)){
            cerr << "Error sending the opponent key to myClient \n";
            delete choice;
            delete opponent;
            delete this;
        }

        unsigned int port;
        if(!waitForOpponentReady(port)){
            cerr << "Error in receiving clientReady for challenge \n";
            delete choice;
            delete opponent;
            delete this;
        }
        if(!sendMyKeyToChallenger(opponent, port)) {
            cerr << "Error sending myClient key to the challenger \n";
            delete choice;
            delete opponent;
            delete this;
        }

    }else{
        if(choice  == NULL) {
            cerr << "Error in receiving the chosen player\n";
            delete choice;
            delete this;
        }else{
            //è lo sfidante
            sendChallengeMessage(choice);

            }
        }
    waitForEndOfGame();
}


bool UserConnectionManager::establishSecureConnection() {


    //wait for hello message
    if(!waitForHelloMessage()){
        cerr<<"Error in receiving Hello Message\n";
        delete this;
        return false;
    }


    //preparing certificate message
    size_t cert_msg_len;
    unsigned char *certificateMsg;
    certificateMsg = createCertificateMessage(cert_msg_len);

    //sending certificate message
    if(!sendCertificate(certificateMsg, cert_msg_len)){
        cerr<<"Error in sending certificate\n";
        delete this;
        return false;
    }else{
        cout<<"Certificate sent succesfully"<<endl;
    }

    //waiting for client
    if(!waitForClientBeReady()){
        cerr<<"Error in receiving Client Ready Message\n";
        delete this;
        return false;
    }

    //creating Symmetric Keys Message
    unsigned char *keysMsg;
    size_t keys_len;
    keysMsg = createKeyMessage(keys_len);

    //sending KeysMessage
    if(!sendSymmetricKeys(keysMsg, keys_len)){
        cerr<<"Error in sending keys\n";
        delete this;
        return false;
    }

    delete []keysMsg;
    //receiving client nonce
    unsigned char * client_nonce;
    size_t cl_nonce_len = CLIENTNONCEMSGLENGTH;
    client_nonce = waitForClientNonce(cl_nonce_len);
    if(client_nonce == NULL){
        cerr<<"Error in receiving Client Nonce\n";
        delete this;
        return false;
    }else
        std::cout<<"Client nonce created correctly"<<std::endl;


    //creating server nonce
    unsigned char* mynonce = new unsigned char[NONCELENGTH];
    size_t mynonce_len = NONCELENGTH;
    RAND_bytes((unsigned char*)&mynonce[0], mynonce_len);

    std::cout<<"Server nonce created correctly"<<std::endl;
     //sending server nonce
    if(!sendServerNonce(mynonce, mynonce_len, client_nonce, cl_nonce_len)){
        cerr<<"Error in sending server nonce\n";
        delete this;
        return false;
    }

    //waiting for my nonce
    unsigned char* receivedNonce;
    receivedNonce = waitForMyNonce();
    if(!verifyNonce(mynonce, receivedNonce)){
        cerr<<"Error in nonce received\n";
        delete this;
        return false;
    }

    server->insertUserConnectionInMap(*userName, this);


    return true;
}

bool UserConnectionManager::waitForHelloMessage(){
    cout<<"waitForHelloMessage\n";

    unsigned char*buffer;
    size_t ret;

    size_t bytes_max = MAXUSERNAMELENGTH+1;
    buffer = new unsigned char[bytes_max];
    ret = recv(userSocket, (void*)buffer, bytes_max, 0);
    if(ret <= 0){
        cout<<"Error in receiving HelloMessage\n";
        return false;
    }

    cout<<"Dimensione HelloMessage: "<<ret<<endl;
    if(buffer[0] == HELLOMSGCODE){
        cout<<"HelloMessage opcode verified\n";
        buffer[ret-1] = '\0';
        this->userName = new string((const char*)&buffer[1]);

        cout<<"THE RECEIVED USERNAME IS: "<<userName->c_str()<<endl;
        delete []buffer;
        return true;
    }else {
        cerr<<"Wrong message!\n";
        delete []buffer;
        return false;
    }


}

bool UserConnectionManager::sendCertificate(unsigned char* msg, size_t msg_len){
    cout<<"sendCertificate\n";

    size_t ret;
    ret = send(userSocket, (void*)msg, msg_len, 0);
    if(ret < msg_len){
        cout<<"Error in sending certificate\n";
        return false;
    }else
        return true;
}

unsigned char* UserConnectionManager::createCertificateMessage(size_t& msg_len){
    unsigned char *cert;
    int cert_len;
    cert = server->geti2dCertificate(cert_len);
    unsigned char *buffer  = new unsigned char[cert_len + 1];
    buffer[0] = CERTIFICATEMSGCODE;
    msg_len = (size_t)(cert_len+1);
    memcpy((buffer + 1), cert,(cert_len));
    cout<<"Certificate message created succesfully "<<endl;

    return buffer;
}

bool UserConnectionManager::waitForClientBeReady(){

    unsigned char *buffer;
    size_t ret;

    size_t bytes_max = userName->length()+1;
    buffer = new unsigned char[bytes_max];
    ret = recv(userSocket, buffer, bytes_max, 0);
    if(ret < 0){
        cout<<"Error in receiving Readiness Message\n";
        return false;
    }

    //Check the opcode
    if(buffer[0] == CLIENTREADYCODE){
        cout<<"Readiness opcode verified\n";
        return true;
    }else {
        cerr<<"Wrong message, expected Client ready message!\n";
        return false;
    }
}

bool UserConnectionManager::sendSymmetricKeys(unsigned char* keysMsg, size_t keysMsg_len){
    cout<<"sendSymmetricKeys\n";

    size_t ret;
    ret = send(userSocket, keysMsg, keysMsg_len, 0);
    if(ret < keysMsg_len){
        cout<<"Error in sending symmetric keys\n";
        return false;
    }else
        cout<<"Key establishment message has been sent\n";
    cout<<"SEND KEYS ret= "<<ret<<endl;
    return true;

}

unsigned char* UserConnectionManager::createKeyMessage(size_t& keys_len){

    size_t clearOpcodePlusSimKeysLen = KEYSLENGTH + 1;

    //keys takes the plain msg containing mac key, aes key and iv
    unsigned char *keys;
    keys = getKeyPlainMgs(clearOpcodePlusSimKeysLen);

    unsigned char* encryptedSimmetricKeys, *signedMsg, *ivEnvelope, *keyEnvelope;

    //passare mia chiave priv e key pub del client

    string *server_key = new string("../Server/Server_Keys/4InARowServerPrvkey.pem");
    string* path = new string("../Server/Users_Public_Keys/");
    path->append(userName->c_str());
    path->append("_pubkey.pem");

    this->rsaManager = new RSAManager(server_key, path);
    delete path;

    size_t encriptedKeyPlusOpcodeLen, textToBesignedLen, ivSize, keyEnvSize;
    encriptedKeyPlusOpcodeLen = clearOpcodePlusSimKeysLen;

    encryptedSimmetricKeys = rsaManager->encryptThisMessage(keys, encriptedKeyPlusOpcodeLen, keyEnvelope,
                                                            keyEnvSize,ivEnvelope, ivSize);

    std::cout<<"encriptedKeyPlusOpcodeLen = "<< encriptedKeyPlusOpcodeLen <<",keyEnvSize = "<<keyEnvSize <<",ivSize = "<<ivSize<<endl;

    textToBesignedLen = encriptedKeyPlusOpcodeLen + ivSize + keyEnvSize;
    auto* textToBesigned = new unsigned char[textToBesignedLen];
    int step =0;

    memcpy(&textToBesigned[step],encryptedSimmetricKeys,encriptedKeyPlusOpcodeLen);
    step += encriptedKeyPlusOpcodeLen;
    memcpy(&textToBesigned[step],ivEnvelope, ivSize);
    step += ivSize;
    memcpy(&textToBesigned[step],keyEnvelope, keyEnvSize);

    signedMsg = rsaManager->signThisMessage(textToBesigned, textToBesignedLen);
    std::cout<<"rsaManager->signThisMessage() returned "<<textToBesignedLen<<endl;
    int textSignedLen = textToBesignedLen;

    unsigned char *encrKeyMessagebuffer = new unsigned char[encriptedKeyPlusOpcodeLen + ivSize + keyEnvSize + textSignedLen];

    step = 0;
    memcpy(&encrKeyMessagebuffer[step], encryptedSimmetricKeys, encriptedKeyPlusOpcodeLen);
    step += encriptedKeyPlusOpcodeLen;
    memcpy(&encrKeyMessagebuffer[step], ivEnvelope, ivSize);
    step += ivSize;
    memcpy(&encrKeyMessagebuffer[step], keyEnvelope, keyEnvSize);
    step += keyEnvSize;
    memcpy(&encrKeyMessagebuffer[step], signedMsg, textSignedLen);
    step += textSignedLen;

    keys_len = step;
    cout<<"Key establishment message has been created, its legth is:"<<keys_len<<endl;

    delete [] textToBesigned;
    delete [] keys;
    delete [] encryptedSimmetricKeys;
    delete [] signedMsg;
    delete [] ivEnvelope;
    delete [] keyEnvelope;
    delete server_key;

    return encrKeyMessagebuffer;
}

unsigned char* UserConnectionManager::getKeyPlainMgs(size_t &keys_len){
    cout<<"createKeyMessage\n";

    unsigned char* key = new unsigned char[AESKEYLENGTH];
    RAND_bytes((unsigned char*)&key[0], AESKEYLENGTH);

    unsigned char *iv = new unsigned char[AESIVLENGTH];
    RAND_bytes((unsigned char*)&iv[0], AESIVLENGTH);

    unsigned char* hmac = new unsigned char[HMACKEYLENGTH];;
    RAND_bytes((unsigned char*)&hmac[0], HMACKEYLENGTH);
    //Inizializing symmetricEncryptionManager
    symmetricEncryptionManager = new SymmetricEncryptionManager(key, iv, hmac);


    unsigned char* symmComunicationkeyBuffer = new unsigned char[KEYSLENGTH];
    size_t hmac_len= HMACKEYLENGTH;
    memcpy(symmComunicationkeyBuffer, hmac, hmac_len);
    int pos = hmac_len;
    size_t aes_len= AESKEYLENGTH;
    memcpy((symmComunicationkeyBuffer + pos), key, aes_len);
    pos += aes_len;
    size_t iv_len= AESIVLENGTH;
    memcpy((symmComunicationkeyBuffer + pos), iv, iv_len);
    pos += iv_len;
    keys_len = pos;

    unsigned char *opcodePlusCommKeysBuffer = new unsigned char[KEYSLENGTH + 1];
    opcodePlusCommKeysBuffer[0] = KEYESTABLISHMENTCODE;
    memcpy(opcodePlusCommKeysBuffer + 1, symmComunicationkeyBuffer, KEYSLENGTH);
    delete [] symmComunicationkeyBuffer;

    cout<<"HMAC KEY, AES KEY and IV have been created succesfully\n";

    keys_len++;

    return opcodePlusCommKeysBuffer; //opcode + simmetric keys,this is what it will be sent (encrypted) trough the socket
}

unsigned char* UserConnectionManager::waitForClientNonce(size_t& clientNonceMsg_len){
    cout<<"waitForClientNonce\n";
    unsigned char *nonce;
    cout << "Expected clientNonceMsg_len: " << clientNonceMsg_len << endl;
    unsigned char* buffer = new unsigned char[clientNonceMsg_len + 1];
    //unsigned char* buffer = new unsigned char[clientNonceMsg_len];

    //Receive the client nonce msg
    size_t ret = 0;

    ret = recv(userSocket, buffer, clientNonceMsg_len + 1, MSG_WAITALL);
   // ret = recv(userSocket, buffer, clientNonceMsg_len, MSG_WAITALL);
    /*if(ret != clientNonceMsg_len + 1) {
        cout << "Error in receiving client nonce " << ret << "\n";
        return NULL;
    }*/
    cout<<"RET = "<<ret<<endl;

    unsigned char *plainMsg = new unsigned char[NONCELENGTH+1];
    memcpy(plainMsg, buffer+1, NONCELENGTH+1);

    unsigned char *macToVerify = new unsigned char[SHA256DIGESTLENGTH];
    memcpy(macToVerify, &buffer[NONCELENGTH+2], SHA256DIGESTLENGTH);
/*
    unsigned char *plainMsg = new unsigned char[NONCELENGTH+1];
    memcpy(plainMsg, buffer, NONCELENGTH+1);

    unsigned char *macToVerify = new unsigned char[SHA256DIGESTLENGTH];
    memcpy(macToVerify, &buffer[NONCELENGTH+1], SHA256DIGESTLENGTH);
    */
    //decripto e verifico
    size_t plain_len = NONCELENGTH+1;
    if(!symmetricEncryptionManager->verifyMac(macToVerify, plainMsg, plain_len)){
        cout<<"MAC has not been verified\n";
        return NULL;
    }


    if (plainMsg[0] == CLIENTNONCECODE) {
        nonce = new unsigned char[NONCELENGTH];
        cout << "ClientNonce opcode verified\n";
        memcpy(nonce, &plainMsg[1], NONCELENGTH);
        clientNonceMsg_len = NONCELENGTH;
        delete []plainMsg;
        delete []buffer;
        return nonce;
    } else {
        cerr << "Wrong message!\n";
        delete []plainMsg,
        delete []buffer,
        delete []nonce;
        return NULL;
    }
}

bool UserConnectionManager::sendServerNonce(unsigned char* serverNonce, size_t& server_len, unsigned char* clientNonce, size_t& client_len){
    cout<<"sendServerNonce\n";

    size_t ret, message_len;
    message_len = SERVERNONCEMSGLENGTH;

    unsigned char* buffer;
    buffer = createServerNonceMessage(serverNonce, server_len, clientNonce, client_len, message_len);

    ret = send(userSocket, buffer, message_len, 0);
    if(ret != message_len){
        cout<<"Error in sending symmetric keys,ret = "<< ret<<"\n";
        return false;
    }
    cout<<"Server nonce message has been sent, RET= "<<ret<<endl;

    for(int i = 0; i < server_len; i++)
        cout<<serverNonce[i];
    cout<<endl;

    return true;
}

unsigned char* UserConnectionManager::createServerNonceMessage(unsigned char *serverNonce, size_t& server_len, unsigned char *clientNonce, size_t& cl_len, size_t& message_len) {

    unsigned char *plainMsg, *hMacMsg;
    plainMsg = new unsigned char[2*NONCELENGTH+1];
    size_t pos = 0;
    plainMsg[0] = SERVERNONCECODE;
    pos++;
    cl_len = NONCELENGTH;
    memcpy((plainMsg+pos), clientNonce, cl_len);
    pos += cl_len;

    server_len = NONCELENGTH;
    memcpy((plainMsg+pos), serverNonce, server_len);
    pos += server_len;

    size_t hmac_len = pos;
    hMacMsg = symmetricEncryptionManager->computeMac(plainMsg, hmac_len);


    unsigned char *buffer = new unsigned char[pos+hmac_len];
    memcpy(buffer, plainMsg, pos);
    memcpy(buffer+pos, hMacMsg, hmac_len);
    message_len = hmac_len + pos;
    return buffer;

}

unsigned char* UserConnectionManager::waitForMyNonce(){
    cout<<"waitForMyNonce\n";

    unsigned char* buffer = new unsigned char[VERIFICATIONNONCEMSGLENGTH];
    size_t ret;


    //Receive the client nonce msg
    ret = recv(userSocket, buffer, VERIFICATIONNONCEMSGLENGTH, 0);
    if(ret != VERIFICATIONNONCEMSGLENGTH){
        cout<<"Error in receiving my nonce\n";
        return NULL;
    }

    auto *plainMsg = new unsigned char[NONCELENGTH + 1];
    auto *hmac = new unsigned char[SHA256DIGESTLENGTH];

    size_t pos = 0;
    memcpy(plainMsg, buffer+pos, NONCELENGTH+1);

    pos+= NONCELENGTH+1;
    memcpy(hmac, (buffer+pos), SHA256DIGESTLENGTH);

    delete []buffer;

    pos += SHA256DIGESTLENGTH;

    size_t toVerify = pos-SHA256DIGESTLENGTH;

    //verifico
    if(!symmetricEncryptionManager->verifyMac(hmac, plainMsg, toVerify)){
        cout<<"HMAC not verified\n";
        delete []hmac;
        delete []plainMsg;
        return NULL;
    }else
        cout<<"HMAC verified\n";

    delete []hmac;

    if (plainMsg[0] == SERVERNONCEVERIFICATIONCODE) {
        cout << "Server Nonce message opcode verified\n";
        auto *nonce = new unsigned char[NONCELENGTH];
        memcpy(nonce, plainMsg+1, NONCELENGTH);

        delete []plainMsg;

        return nonce;

    } else {
        cerr << "Wrong message!\n";
        delete []plainMsg;
        return NULL;
    }
}

bool UserConnectionManager::verifyNonce(unsigned char* myNonce, unsigned char* receivedNonce){
    //comparison between the two nonces

    cout<<"receivedNonce "<<endl;
    for(int i = 0; i < NONCELENGTH; i++)
        cout<<receivedNonce[i];
    cout<<endl;

    cout<<"myNonce "<<endl;
    for(int i = 0; i < NONCELENGTH; i++)
        cout<<myNonce[i];
    cout<<endl;

    if(CRYPTO_memcmp(myNonce, receivedNonce, NONCELENGTH) == 0) {
        cout<<"Nonce verified\n";
        return true;
    }
    else {
        cout<<"Nonce has not been verified\n";
        return false;
    }
}

bool UserConnectionManager::sendPlayerList(size_t& players_num) {

    vector<string> list;

    list = server->getUserList(userName);

   /* if(list.size() > 0) {
        for(auto& v: list)
            cout<<v.c_str()<<" ";
        cout<<endl;
      }
*/
   size_t msg_len;
   unsigned char *buffer = createPlayerListMsg(list, msg_len);

   size_t ret = send(userSocket, buffer, msg_len, 0);
   if (ret < 0) {
       cerr << "Error in sending players list\n";
       return false;
   }
   if(list.size() == 0){
        cout<<"No player available for the user\n";
    }
   players_num = list.size() == 0;
   cout << "Players list has been sent\n";
   return true;

}

unsigned char* UserConnectionManager::createPlayerListMsg(vector<string> list, size_t& msg_len) {

    unsigned char* buffer = (unsigned char*)malloc(MAXUSERNAMELENGTH*list.size());

    size_t pos = 0;
    for(auto i = list.begin(); i != list.end(); i++){
        memcpy(buffer+pos, i->c_str(), strlen(i->c_str())+1);
        pos += strlen(i->c_str())+1;
    }

    cout<<"Users in buffer: ";
    for(int j = 0; j < pos; j++) {
        if(buffer[j] == '\0')
            cout<<" ";
        cout << buffer[j];
    }

    cout<<endl;

    unsigned char *plainMsg = new unsigned char[pos+1+SIZETLENGTH];
    plainMsg[0] = PLAYERLISTCODE;

    size_t num_players = list.size();
    cout<<"NUMERO GIOCATORI "<<num_players<<endl;
    num_players = htons(num_players);
    memcpy(plainMsg+1, &(num_players), sizeof(size_t));

    memcpy(plainMsg+1+sizeof(size_t), buffer, pos);
/*    for(int i =1+sizeof(num_players); i < 1+sizeof(num_players)+pos; i++)
        cout<<plainMsg[i];
    cout<<endl; */

    size_t len = 1+sizeof(size_t)+pos;
    unsigned char *encrypted = symmetricEncryptionManager->encryptNMACThisMessage(plainMsg, len);
    msg_len = len;

    delete []plainMsg;
    return encrypted;

}

string *UserConnectionManager::waitForChoice(bool& waiting) {

    unsigned char *buffer = new unsigned char[MAXENCRYPTEDUSERLENGTH+HMACLENGTH];
    size_t ret = recv(userSocket, buffer, MAXENCRYPTEDUSERLENGTH+HMACLENGTH, 0);

    if(ret < 0){
        cerr<<"Error receiving the choice message\n";
        return NULL;
    }
    unsigned char *plainMsg = new unsigned char[MAXUSERNAMELENGTH + 2];
    plainMsg = symmetricEncryptionManager->decryptNVerifyMACThisMessage(buffer, ret);

    if(!plainMsg){
        delete [] buffer;
        waiting = false;
        return nullptr;
    }

    if(plainMsg[0] == PLAYERSELECTEDCODE)
        cout<<"Player choice message opcode verified\n";
    else{
        cerr<<"Wrong message\n";
        waiting = false;
        return NULL;
    }

    cout<<"RET IS: "<<ret<<endl;
    if(ret == 1){
        cout<<"The player is waiting for a challenger\n";
        waiting = true;
        return NULL;
    }

    string *player;
    waiting = false;
    plainMsg[ret-1] = '\0';
    player = new string((const char*)&plainMsg[1]);
    cout<<"The chosen player is: "<<player->c_str()<<endl;

    delete []buffer;
    return player;

}

UserConnectionManager::~UserConnectionManager() {

    close(userSocket);
    delete []server;
    delete userName;
    delete []symmetricEncryptionManager;
    delete []rsaManager;
}

EVP_PKEY *UserConnectionManager::getUserPubKey(string* opponent) {

    return server->getUserConnection(opponent->c_str())->rsaManager->getPubkey();
}

bool UserConnectionManager::sendChallengeMessage(string *challenged) {

    unsigned char *buffer = new unsigned char[MAXENCRYPTEDUSERLENGTH + HMACLENGTH];


    unsigned char* plainMsg = new unsigned char[1+userName->length()+1];
    plainMsg[0] = SENDCHALLENGECODE;
    memcpy(plainMsg+1, userName->c_str(), userName->length()+1);

    size_t ret, toEncrypt_len = 1 + userName->length()+1;

    UserConnectionManager * challengedUCM = server->getUserConnection(challenged->c_str());
    buffer = challengedUCM->symmetricEncryptionManager->encryptNMACThisMessage(plainMsg, toEncrypt_len);

    int challengedSocket = challengedUCM->userSocket;
    ret = send(challengedSocket, buffer, toEncrypt_len, 0);

    if(ret < 0){
        cerr<<"Error during sending challenge message to the challenged player\n";
        return false;
    }

    cout<<"Challenge message has been sent\n";
    return true;
}

string* UserConnectionManager::waitForResponse() {

    auto *buffer = new unsigned char[RESPONSEENCRYPTEDLENGTH + HMACLENGTH];
    size_t ret = recv(userSocket, buffer, RESPONSEENCRYPTEDLENGTH + HMACLENGTH, 0);

    if(ret < AESBLOCKLENGTH + HMACLENGTH){
        cerr<<"Error receiving the challenge response message\n";
        return NULL;
    }

    unsigned char *plainMsg;
    plainMsg = symmetricEncryptionManager->decryptNVerifyMACThisMessage(buffer, ret);

    delete []buffer;
    size_t plain_len = ret;
    if(plainMsg[0] == CHALLENGEDRESPONSECODE){
        cout<<"Response challenge message opcode verified\n";

    }else{
        cout<<"Wrong message. Response challenge message expected\n";
        return NULL;
    }

    char response;
    string *opponent = new string();
    opponent->append((const char *)(plainMsg+1));
    size_t pos = 1+opponent->length()+1;
    response= plainMsg[pos];
    cout<<"THE OPPONENT IS = "<<opponent->c_str()<<endl;

    delete[] plainMsg;

    if(response == 'Y'){
        cout<<"The player accepted the challenge\n";
        return opponent;
    }else {
        cout<<"The player refused the challenge\n";
        delete opponent;
        return NULL;
    }
}

bool UserConnectionManager::sendOpponentKey(string *opponent) {

    EVP_PKEY *opponentPubKey = getUserPubKey(opponent);

    struct in_addr ipOpponent = server->getUserConnection(opponent->c_str())->clAdd.sin_addr;
    size_t opponentPort = server->getUserConnection(opponent->c_str())->clAdd.sin_port;

    BIO *mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mbio, opponentPubKey);
    unsigned char* pubkey_buf;
    long pubkey_size = BIO_get_mem_data(mbio, &pubkey_buf);

    auto *plainMsg = new unsigned char[pubkey_size + IPLENGTH + SIZETLENGTH + 1];
    plainMsg[0] = OPPONENTKEYCODE;

    size_t htons_port = htons(opponentPort);

    int pos = 1;
    memcpy(plainMsg+pos, (void*)&ipOpponent, IPLENGTH);
    pos += IPLENGTH;

    memcpy(plainMsg+pos, &htons_port, SIZETLENGTH);
    pos += SIZETLENGTH;

    memcpy(plainMsg + pos, pubkey_buf, pubkey_size);
    pos+= pubkey_size;

    size_t toEncrypt_len = pos;
    unsigned char* buffer = symmetricEncryptionManager->encryptNMACThisMessage(plainMsg, toEncrypt_len);

    delete []plainMsg;
    BIO_free(mbio);

    size_t ret = send(userSocket, buffer, toEncrypt_len, 0);
    if(ret != toEncrypt_len){
        cerr<<"Error sending opponent key\n";
        return false;
    }
    cout<<"Adversary key and address sent correctly\n";
    return true;
}

bool UserConnectionManager::waitForOpponentReady(unsigned int& port) {

    auto *buffer = new unsigned char[MAXENCRYPTEDUSERLENGTH+HMACLENGTH];
    size_t ret = recv(userSocket, buffer, MAXENCRYPTEDUSERLENGTH+HMACLENGTH, 0);

    if(ret < AESBLOCKLENGTH+HMACLENGTH){
        cerr<<"Error in receving waitForOpponentReady message,received "<<ret<<" bytes"<<endl;
        return false;
    }

    unsigned char *plainMsg = symmetricEncryptionManager->decryptNVerifyMACThisMessage(buffer, ret);

    size_t plain_len = ret;

    if(plainMsg[0] == CLIENTREADY4CHALLENGECODE){
        cout<<"waitForOpponentReady message opcode has been verified\n";
    }else{
        cerr<<"Wrong message: waitForOpponentReady message was expected\n";
        return false;
    }

    unsigned int port_received;
    size_t port_len = sizeof(port);
    memcpy(&port_received, plainMsg+1, port_len);

    port = port_received;

    string *user = new string(reinterpret_cast<const char *>(&plainMsg[port_len+1]));

    return true;
}

bool UserConnectionManager::sendMyKeyToChallenger(string *challenger, int port) {

    EVP_PKEY *myClientPubKey = getUserPubKey(userName);

    struct in_addr myClientIP = this->clAdd.sin_addr;
    //uint32_t myClientIP = this->clAdd.sin_addr.s_addr;
    size_t myClientPort = this->clAdd.sin_port;


    char *IPbuffer = inet_ntoa(this->clAdd.sin_addr);
    printf("Host IP: %s", IPbuffer);

    BIO *mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mbio, myClientPubKey);
    unsigned char* pubkey_buf;
    long pubkey_size = BIO_get_mem_data(mbio, &pubkey_buf);

    auto *plainMsg = new unsigned char[pubkey_size + IPLENGTH + SIZETLENGTH + 1];
    plainMsg[0] = OPPONENTKEYCODE;

    size_t htons_port = port;

    int pos = 1;
    memcpy(plainMsg+pos, &myClientIP, IPLENGTH);
    pos += IPLENGTH;

    memcpy(plainMsg+pos, &htons_port, SIZETLENGTH);
    pos += SIZETLENGTH;

    memcpy(plainMsg + pos, pubkey_buf, pubkey_size);
    pos+= pubkey_size;

    size_t toEncrypt_len = pos;

    UserConnectionManager *challengerUCM = this->server->getUserConnection(challenger->c_str());
    unsigned char* buffer = challengerUCM->symmetricEncryptionManager->encryptNMACThisMessage(plainMsg, toEncrypt_len);

    delete []plainMsg;
    BIO_free(mbio);

    size_t ret = send(challengerUCM->userSocket, buffer, toEncrypt_len, 0);
    if(ret != toEncrypt_len){
        cerr<<"Error sending opponent key\n";
        return false;
    }

    return true;
}

void UserConnectionManager::waitForEndOfGame() {

    auto *buffer = new unsigned char [MAXMSGLENGTH];

    size_t ret = recv(userSocket, buffer, MAXMSGLENGTH, 0);

}
