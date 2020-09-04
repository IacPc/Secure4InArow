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

    diffieHellmannManager = new DiffieHellmannManager();
    cout<<"UserConnectionManager created successfully"<<endl;

}

void UserConnectionManager::openNewconnectionwithClient() {

    if(!this->establishSecureConnection()){
        server->removeUser(this->userName);
        return;
    }else
        cout<<"NEW CONNECTION ESTABLISHED WITH "<<this->userName->c_str()<<std::endl;

    if(!sharePlayersList()){
        cout<<"The game cannot start. Failed the players credential sharing"<<endl;
        return;
    }

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////                                         ESTABLISH SECURE CHANNEL                                         ////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool UserConnectionManager::establishSecureConnection() {

    cout<<"Starting establishing secure connection"<<endl;

    //wait for hello message

    if(!waitForHelloMessage()){
        cerr<<"Error in receiving Hello Message"<<endl;

        return false;
    }


    //preparing certificate message
    size_t cert_msg_len;
    unsigned char *certificateMsg;
    certificateMsg = createCertificateMessage(cert_msg_len);

    //sending certificate message
    if(!sendCertificate(certificateMsg, cert_msg_len)){
        cerr<<"Error in sending certificate"<<endl;

        return false;
    }else{
        cout<<"Certificate sent successfully"<<endl;
    }

    if(!waitForClientPubKey()){
        cerr<<"Error in receiving client pubkey"<<endl;

        return false;
    }else{
        cout<<"PubKey received successfully"<<endl;
    }

    if(!sendMyPubKey()){
        cerr<<"Error in sending my pubkey"<<endl;

        return false;
    }else{
        cout<<"PubKey sent successfully"<<endl;
    }

    createSessionKey();
    server->insertUserConnectionInMap(*userName, this);


    return true;
}
bool UserConnectionManager::waitForHelloMessage(){

    cout<<"Waiting for hello message"<<endl;
    auto *buffer = new unsigned char[HELLOMESSAGELENGTH];
    size_t ret;

    ret = recv(userSocket, buffer, HELLOMESSAGELENGTH, 0);
    if(ret <= 0){
        cout<<"Error in receiving HelloMessage\n";
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


    memcpy((unsigned char*)&this->clientNonce, &buffer[1], NONCELENGTH);

    buffer[ret-1] = '\0';
    this->userName = new string((const char*)&buffer[1 + NONCELENGTH]);

    cout<<"THE RECEIVED USERNAME IS: "<<userName->c_str()<<endl;
    delete []buffer;
    return true;

}
bool UserConnectionManager::sendCertificate(unsigned char* msg, size_t msg_len){
    cout<<"sendCertificate\n";
    size_t ret;
    ret = send(userSocket, msg, msg_len, 0);
    if(ret < msg_len){
        cout<<"Error in sending certificate\n";
        return false;
    }else
        return true;
}
unsigned char* UserConnectionManager::createCertificateMessage(size_t& msg_len){
    unsigned char *cert;
    int cert_len;
    int pos = 0;
    cert = server->geti2dCertificate(cert_len);

    //creo il buffer e copio opcode
    msg_len = (size_t)cert_len + NONCELENGTH + 1;
    auto *buffer  = new unsigned char[msg_len];
    buffer[pos] = CERTIFICATEMSGCODE;
    pos++;

    //creo nonce e lo copio nel buffer
    RAND_bytes((unsigned char*)&this->myNonce, NONCELENGTH);
    memcpy((buffer+pos), &myNonce, NONCELENGTH);
    pos += NONCELENGTH;

    //copio certificato nel buffer
    memcpy((buffer + pos), cert, (size_t)(cert_len));
    pos += (size_t)(cert_len);
    cout<<"Certificate message created successfully "<<endl;


    return buffer;
}
bool UserConnectionManager::waitForClientPubKey() {

    auto* buffer = new unsigned char[2048];
    size_t ret = recv(userSocket ,buffer, 2048, 0);
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
    uint32_t receivedClientNonce;
    memcpy(&receivedClientNonce, (buffer+pos), NONCELENGTH);
    pos += NONCELENGTH;

    //copio il mio nonce
    uint32_t myReceivedNonce;
    memcpy(&myReceivedNonce, (buffer+pos), NONCELENGTH);
    pos += NONCELENGTH;

    bool Noncesaredifferent = (this->myNonce != myReceivedNonce) || (this->clientNonce != receivedClientNonce);

    if(Noncesaredifferent){
        std::cout<<"Nonces does not match!"<<endl;
        std::cout<<"Server Nonce is "<<this->myNonce<<",received "<<myReceivedNonce<<endl;
        std::cout<<"Client Nonce is "<<this->clientNonce<<",received "<<receivedClientNonce<<endl;
        return false;
    }

    //copio dimensione pubkey
    uint16_t pubkey_len;
    memcpy(&pubkey_len, (buffer+pos), sizeof(pubkey_len));
    pos += sizeof(pubkey_len);
    //prelevo la pubkey
    auto* clientPubKey = new unsigned char[pubkey_len];
    memcpy(clientPubKey, (buffer+pos), pubkey_len);
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

    string* path = new std::string ("../Server/Server_Keys/4InARowServerPrvkey.pem");
    this->signatureManager = new SignatureManager(path, nullptr);
    path->clear();
    path->append("../Server/Users_Public_Keys/");
    path->append(this->userName->c_str());
    path->append("_pubkey.pem");
    FILE* pubkeyUser = fopen(path->c_str(),"r");
    EVP_PKEY* pubkey = PEM_read_PUBKEY(pubkeyUser,NULL,NULL,NULL);

    this->signatureManager->setPubkey(pubkey);

    //verifico la firma
    if(!signatureManager->verifyThisSignature(signature, signature_len, messageToVerify, ret-signature_len-2)) {
        cout<<"Signature not verified"<<endl;
        delete [] buffer;
        delete [] signature;
        delete [] messageToVerify;
        delete [] clientPubKey;
        return false;
    }
    cout<<"Signature verified correctly"<<endl;
    delete [] signature;
    delete [] messageToVerify;

    //chiamo DH

    diffieHellmannManager->setPeerPubKey(clientPubKey, pubkey_len);

    cout<<"Set peer public key"<<endl;
    delete [] clientPubKey;
    delete [] buffer;

    return true;

}

bool UserConnectionManager::sendMyPubKey() {
    auto *buffer = new unsigned char[2048];

    //inserisco opcode
    size_t pos = 0;
    buffer[pos] = PUBKEYMESSAGECODE;
    pos++;

    //inserisco client nonce
    memcpy((buffer+pos), &clientNonce, NONCELENGTH);
    pos += NONCELENGTH;

    //inserisco myNonce
    memcpy((buffer+pos), &myNonce, NONCELENGTH);
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
    size_t ret = send(userSocket, buffer, pos, 0);
    if(ret != pos){
        cout<<"Error in sending my pubkey"<<endl;
        delete [] buffer;
        return false;
    }

    delete [] buffer;
    return true;


}
void UserConnectionManager::createSessionKey() {

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


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////                                         SECURE CHANNEL CREATED                                           ////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////                                         SHARE PEERS CREDENTIALS                                          ////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool UserConnectionManager::sharePlayersList() {
    bool waiting = true;
    bool waitingForReadiness = false;
    bool waitingForEndGame = false;
    unsigned char buffer[4096];
    string *opponent;

    while(1) {

        size_t ret = recv(userSocket, buffer, 4096, 0);
        if (ret <= 0) {
            cout << "Error in receiving sharePlayersList message" << endl;
            server->removeUser(this->userName);
            return false;
        }

        unsigned char opcode = buffer[0];

        switch(opcode){
            case LISTREQUESTMESSAGE: {
                cout<<"Received LISTRESQUESTMESSAGE from "<<this->userName->c_str()<<endl;
                if (!waitForPlayersRequest(buffer, ret)) {
                    cout << "Error in players list request" << endl;
                    return false;
                }
                if (!sendPlayerList()) {
                    cout << "Error in sending players list" << endl;
                    return false;
                }
                break;
            }

            case LOGOUTMESSAGECODE:{
                logout(buffer, ret);
                break;
            }
            default:{
                cout<<"Error! This message was not expected in this moment!"<<endl;
                return false;
            }
        }

        while(waiting){
            size_t ret = recv(userSocket, buffer, 4096, 0);
            if (ret <= 0) {
                cout << "Error in receiving message" << endl;
                return false;
            }

            opcode = buffer[0];

            switch (opcode) {
                case PLAYERCHOSENMESSAGECODE: {
                    string *choice = waitForClientChoice(buffer, ret);
                    if (choice == nullptr) {
                        return false;
                    }
                    if (!sendChallengerRequest(choice)) {
                        delete choice;
                        return false;
                    }
                    delete choice;
                    break;
                }

                case CHALLENGEDRESPONSEMESSAGECODE: {
                    bool stillWait;
                    opponent = waitForChallengedResponse(buffer, ret, stillWait);
                    cout<<"The client has answered"<<endl;
                    if (opponent == nullptr) {
                        delete opponent;
                        return false;
                    }
                    if (!stillWait) {
                        if (!sendOpponentKeyToChallenged(opponent, 0)) {
                            delete opponent;
                            return false;
                        }
                        waitingForReadiness = true;
                    }else{
                        if (!sendPlayerList()) {
                            cout << "Error in sending players list" << endl;
                            return false;
                        }
                    }
                    break;
                }

                case CHALLENGEDREADYFORCHALLENGEMESSAGECODE: {
                    uint32_t challenged_port;
                    if (!waitForChallengedReady(buffer, ret, challenged_port, opponent)) {
                        waitingForReadiness = false;
                        delete opponent;
                        return false;
                    }
                    //invio la mia chiave al challenger
                    if (!sendMyKeyToChallenger(opponent, challenged_port)) {
                        waitingForReadiness = false;
                        delete opponent;
                        return false;
                    }
                    waitingForReadiness = false;
                    waitingForEndGame = true;
                    break;
                }

                case ENDGAMEMESSAGECODE: {
                    if (!endGame(buffer, ret)) {
                        delete opponent;
                        return false;
                    }
                    /*  Ho ricevuto il fine partita, allora gli rimando la lista dei giocatori:
                     *  - può scegliere il giocatore
                     *  - può decidere di aspettare una richiesta
                     *  - può mandarmi un messaggio di logout
                     */
                    waitingForEndGame = false;
                    if (!sendPlayerList()) {
                        cout << "Error in sending players list" << endl;
                        return false;
                    }

                    break;
                }

                case LOGOUTMESSAGECODE: {
                    //LOGOUT MESSAGE
                    logout(buffer, ret);
                    break;
                }
                default:{
                    cout<<"The message received was not expected"<<endl;
                    return false;
                }

            }
            //memset(buffer, 0x00, 4096);
            //opponent->clear();
        }

    }
    delete opponent;
    return true;
}
bool UserConnectionManager::waitForPlayersRequest(unsigned char*buffer, size_t buffer_len) {


    if(buffer_len <= 0){
        cout<<"Error receiving Players Request Message"<<endl;
        delete []buffer;
        return false;
    }

    if(buffer[0] == LISTREQUESTMESSAGE){
        cout<<"Players list request message verified"<<endl;
    }else{
        cout<<"Wrong message"<<endl;
        return false;
    }

    size_t pos = 1;

    //prelevo IV
    auto *iv = new unsigned char[AESGCMIVLENGTH];
    memcpy(iv, &buffer[pos], AESGCMIVLENGTH);
    pos += AESGCMIVLENGTH;

    //prelevo counter
    uint32_t cont;
    memcpy(&cont, &buffer[pos], COUNTERLENGTH);
    this->counter = cont;
    pos+= COUNTERLENGTH;

    //copio AAD
    size_t aad_len = OPCODELENGTH+AESGCMIVLENGTH+COUNTERLENGTH;
    auto* AAD = new unsigned char[aad_len];
    memcpy(AAD, buffer, aad_len);



    //copio dati criptati
    size_t encrypted_len = buffer_len - AESGCMTAGLENGTH - aad_len;
    auto* encryptedData = new unsigned char[encrypted_len];
    memcpy(encryptedData, buffer+pos, encrypted_len);
    pos += encrypted_len;

    //copio il tag
    size_t tag_len = AESGCMTAGLENGTH;
    auto *tag = new unsigned char[tag_len];
    memcpy(tag, buffer+pos, tag_len);
    pos += tag_len;



    unsigned char* plaintext = symmetricEncryptionManager->decryptThisMessage(encryptedData, encrypted_len, AAD, aad_len, tag, iv);
    if(plaintext)
        cout<<"LISTREQUESTMESSAGE decrypted correctly "<<endl;
    else
        return false;

    delete [] AAD;
    delete [] iv;
    delete [] encryptedData;
    delete [] tag;

    if(strcmp((const char*)plaintext, userName->c_str())!= 0){
        cout<<"Error! Unexpected username"<<endl;
        return false;
    }
    return true;

}
bool UserConnectionManager::sendPlayerList() {

    vector<string> list;

    list = server->getUserList(userName);
/*
    if(list.size() > 0) {
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
   if(list.empty()){
        cout<<"No player available for the user\n";
    }

   cout << "Players list has been sent\n";
   return true;

}

unsigned char* UserConnectionManager::createPlayerListMsg(vector<string> list, size_t& msg_len) {


    //prendo la lista dei giocatori e quanti e li metto nel buffer del messaggio in chiaro
    auto* playerList = (unsigned char*)malloc(MAXUSERNAMELENGTH * list.size());

    size_t pos = 0;
    for(auto & i : list){
        memcpy(playerList + pos, i.c_str(), strlen(i.c_str()) + 1);
        pos += strlen(i.c_str())+1;
    }

    cout<<"Users in buffer: ";
    for(int j = 0; j < pos; j++) {
        if(playerList[j] == '\0')
            cout<<" ";
        cout << playerList[j];
    }

    cout<<endl;


    auto* plainMessage = new unsigned char[pos + SIZETLENGTH];
    size_t num_players = list.size();
    cout<<"NUMERO GIOCATORI "<<num_players<<endl;
    memcpy(plainMessage, &(num_players), SIZETLENGTH);
    memcpy(plainMessage + SIZETLENGTH, playerList, pos);

    delete [] playerList;
    size_t plainMsg_len = pos + SIZETLENGTH;

    //preparo AAD

    auto *AAD = new unsigned char[OPCODELENGTH+AESGCMIVLENGTH+COUNTERLENGTH];
    AAD[0] = PLAYERSLISTMESSAGECODE;

    size_t iv_len = AESGCMIVLENGTH;
    auto *iv = new unsigned char[iv_len];
    RAND_bytes(iv, iv_len);

    counter++;
    memcpy(&AAD[1], iv, iv_len);
    memcpy(&AAD[1+iv_len], &counter, COUNTERLENGTH);
    size_t aad_len = 1 + AESGCMIVLENGTH + COUNTERLENGTH;

    auto *tag = new unsigned char[AESGCMTAGLENGTH];

    unsigned char *encryptedMessage = symmetricEncryptionManager->encryptThisMessage(plainMessage, plainMsg_len, AAD, aad_len, iv, iv_len, tag);

    delete [] AAD;

    auto *buffer = new unsigned char[aad_len+plainMsg_len+AESGCMTAGLENGTH];

    //copio opcode
    pos = 0;
    buffer[0] = PLAYERSLISTMESSAGECODE;
    pos++;

    //copio iv
    memcpy(buffer+pos, iv, iv_len);
    pos += iv_len;
    delete [] iv;

    //copio counter
    memcpy((buffer+pos), &this->counter, COUNTERLENGTH);
    pos += COUNTERLENGTH;

    //copio encrypted
    memcpy((buffer+pos), encryptedMessage, plainMsg_len);
    pos += plainMsg_len;
    delete[] encryptedMessage;

    //copio tag
    memcpy((buffer+pos), tag, AESGCMTAGLENGTH);
    pos += AESGCMTAGLENGTH;
    delete [] tag;

    msg_len = pos;

    pos = iv_len = plainMsg_len = aad_len = num_players = 0;
    return buffer;




}
string *UserConnectionManager::waitForClientChoice(unsigned char* buffer, size_t buffer_len) {


    if(buffer_len <= 0){
        cout<<"Error receiving Players Request Message"<<endl;
        return nullptr;
    }

    if(buffer[0] == PLAYERCHOSENMESSAGECODE){
        cout<<"Players choice message verified"<<endl;
    }else{
        cout<<"Wrong message"<<endl;
        return nullptr;
    }

    size_t pos = 1;

    //prelevo IV
    auto *iv = new unsigned char[AESGCMIVLENGTH];
    memcpy(iv, &buffer[pos], AESGCMIVLENGTH);
    pos += AESGCMIVLENGTH;

    //prelevo counter
    int cont;
    memcpy(&cont, &buffer[pos], COUNTERLENGTH);
    if(this->counter+1 != cont){
        cout<<"The counter has a wrong value"<<endl;
        delete [] iv;
        delete [] buffer;
        return nullptr;
    }
    this->counter++;
    pos+= COUNTERLENGTH;

    //copio AAD
    size_t aad_len = OPCODELENGTH+AESGCMIVLENGTH+COUNTERLENGTH;
    auto* AAD = new unsigned char[aad_len];
    memcpy(AAD, buffer, aad_len);



    //copio dati criptati
    size_t encrypted_len = buffer_len - AESGCMTAGLENGTH - aad_len;
    auto* encryptedData = new unsigned char[encrypted_len];
    memcpy(encryptedData, buffer+pos, encrypted_len);
    pos += encrypted_len;

    //copio il tag
    size_t tag_len = AESGCMTAGLENGTH;
    auto *tag = new unsigned char[tag_len];
    memcpy(tag, buffer+pos, tag_len);
    pos += tag_len;


    unsigned char* plaintext = symmetricEncryptionManager->decryptThisMessage(encryptedData, encrypted_len, AAD, aad_len, tag, iv);

    delete [] AAD;
    delete [] iv;
    delete [] encryptedData;
    delete [] tag;


    string *player;
    plaintext[encrypted_len-1] = '\0';
    player = new string((const char*)&plaintext[0]);
    cout<<"The chosen player is: "<<player->c_str()<<endl;

    if(!server->getUserConnection(*player)){
        return nullptr;
    }

    if(player->length() < 1){
        cout<<"Error, no player has been chosen!"<<endl;
        return nullptr;
    }else
        busy = true;

    return player;

}

bool UserConnectionManager::sendChallengerRequest(string *challenged) {
    //INVIO IL MIO USERNAME ALLO SFIDATO, QUINDI PRENDO IL SUO UCM
    size_t plain_len = userName->length()+1;
    auto* plainMsg = new unsigned char[plain_len];
    memcpy(plainMsg, userName->c_str(), plain_len);
    cout<<plainMsg<<endl;
    UserConnectionManager * challengedUCM = server->getUserConnection(*challenged);
    const std::lock_guard<std::mutex> lock(challengedUCM->ucmMutex);
    //AAD
    size_t aad_len = AADLENGTH;
    auto *AAD = new unsigned char[aad_len];

    //copio opcode
    AAD[0] = PLAYERCHOSENMESSAGECODE;

    //copio iv
    size_t iv_len = AESGCMIVLENGTH;
    auto *iv = new unsigned char[iv_len];
    RAND_bytes(iv,iv_len);
    memcpy(AAD+1, iv, iv_len);

    //copio counter
    challengedUCM->counter++;
    cout<<"COUNTER IS "<<challengedUCM<<endl;
    memcpy(AAD+1+iv_len, &challengedUCM->counter, COUNTERLENGTH);

    auto*tag = new unsigned char[AESGCMTAGLENGTH];
    unsigned char* encrypted = challengedUCM->symmetricEncryptionManager->encryptThisMessage(plainMsg, plain_len, AAD, aad_len, iv, iv_len, tag);
    delete [] plainMsg;
    delete [] iv;

    cout<<"encrypted len is "<<plain_len<<endl;
    if(plain_len < 0){
        cout<<"Error in encrypting the username"<<endl;
        delete [] encrypted;
        delete [] tag;
        delete [] AAD;
        return false;
    }

    size_t message_len = aad_len + plain_len + AESGCMTAGLENGTH;
    size_t pos = 0;

    //copio aad
    auto *buffer = new unsigned char[message_len];
    memcpy(buffer, AAD, aad_len);
    delete [] AAD;
    pos += aad_len;

    //copio encrypted
    memcpy(buffer+pos, encrypted, plain_len);
    delete [] encrypted;
    pos += plain_len;

    memcpy(buffer+pos, tag, AESGCMTAGLENGTH);
    delete [] tag;

    int challengedSocket = challengedUCM->userSocket;
    size_t ret = send(challengedSocket, buffer, message_len, 0);

    if(ret < message_len){
        cerr<<"Error during sending challenge message to the challenged player\n";
        return false;
    }
    challengedUCM->busy = true;
    message_len = iv_len = plain_len = aad_len = pos = 0;
    cout<<"Challenger request message has been sent\n";
    return true;
}
string* UserConnectionManager::waitForChallengedResponse(unsigned char*buffer, size_t buffer_len, bool& stillWaiting) {


    if(buffer_len <=0){
        cerr<<"Error receiving the challenge response message\n";
        stillWaiting = false;
        return nullptr;
    }

    //copio aad
    size_t pos = 0;
    size_t aad_len = AADLENGTH;
    auto *aad = new unsigned char[aad_len];
    memcpy(aad, buffer, aad_len);
    pos += aad_len;

    //controllo counter
    uint32_t cont;
    memcpy(&cont, aad + OPCODELENGTH + AESGCMIVLENGTH, COUNTERLENGTH);
    if(cont != this->counter+1){
        cout<<"The counter value was not the expencted one"<<endl;
        delete [] aad;
        stillWaiting = false;
        cout<<"THE Counter is "<<this->counter+1<<endl;
        cout<<"THE Counter received is "<<cont<<endl;
        return nullptr;
    }

    this->counter++;
    //controllo opcode
    if(aad[0] != CHALLENGEDRESPONSEMESSAGECODE){
        cout<<"Wrong message"<<endl;
        stillWaiting = false;
        delete [] aad;
        return nullptr;
    }else
        cout<<"WaitForChallengedResponse message opcode verified"<<endl;

    size_t iv_len = AESGCMIVLENGTH;
    auto *iv = new unsigned char[iv_len];
    memcpy(iv, aad+1, iv_len);

    size_t encrypted_len = buffer_len - AESGCMTAGLENGTH - pos;
    auto* encrypted = new unsigned char[encrypted_len];
    memcpy(encrypted, buffer+pos, encrypted_len);
    pos += encrypted_len;

    auto *tag = new unsigned char[AESGCMTAGLENGTH];
    memcpy(tag, buffer+pos, AESGCMTAGLENGTH);

    unsigned char*plainMessage = symmetricEncryptionManager->decryptThisMessage(encrypted, encrypted_len, aad, aad_len, tag, iv);

    delete [] aad;
    delete [] encrypted;
    delete [] iv;
    delete [] tag;

    char response;
    auto *opponent = new string();
    opponent->append((const char *)(plainMessage+1));
    response= plainMessage[0];
    cout<<"THE OPPONENT IS = "<<opponent->c_str()<<endl;

    delete[] plainMessage;
    encrypted_len = iv_len = aad_len = pos = cont = 0;

    if(response == 'Y'){
        cout<<"The player accepted the challenge\n";
        stillWaiting = false;

    }else {
        cout<<"The player refused the challenge\n";
        stillWaiting = true;
        this->busy = false;
        UserConnectionManager *ucm = server->getUserConnection(opponent->c_str());
        ucm->busy = false;

    }
    if(!sendResponseToChallenger(opponent, response)){
        return nullptr;
    }
    return opponent;
}
bool UserConnectionManager::sendResponseToChallenger(string *challenger, char response) {

    unsigned char buffer[2048];
    UserConnectionManager *challengerUCM = server->getUserConnection(challenger->c_str());
    size_t aad_len = OPCODELENGTH + AESGCMIVLENGTH + COUNTERLENGTH;
    auto *aad = new unsigned char[aad_len];
    aad[0] = CHALLENGEDRESPONSEMESSAGECODE;

    size_t iv_len = AESGCMIVLENGTH;
    auto * iv = new unsigned char[iv_len];
    RAND_bytes(iv, iv_len);

    challengerUCM->counter++;

    memcpy(aad+1, iv, iv_len);
    memcpy(aad+iv_len+1, &challengerUCM->counter, COUNTERLENGTH);

    auto* plainMsg = new unsigned char[challenger->length()+2];
    plainMsg[0] = response;
    strcpy((char*)plainMsg+1, challenger->c_str());

    size_t encrypted_len = challenger->length()+2;
    auto*tag = new unsigned char[AESGCMTAGLENGTH];
    unsigned char *encrypted = challengerUCM->symmetricEncryptionManager->encryptThisMessage(plainMsg, encrypted_len, aad, aad_len, iv, iv_len, tag);

    delete [] iv;
    delete [] plainMsg;

    if(!encrypted){
        cout<<"Error encrypting challenged response message"<<endl;
        delete [] aad;
        delete [] encrypted;
        delete [] tag;
        return false;
    }

    size_t pos = 0;
    memcpy(buffer, aad, aad_len);
    pos += aad_len;
    delete [] aad;

    memcpy(buffer+pos, encrypted, encrypted_len);
    pos += encrypted_len;
    delete [] encrypted;

    memcpy(buffer+pos, tag, AESGCMTAGLENGTH);
    pos += AESGCMTAGLENGTH;
    delete [] tag;

    size_t ret = send(challengerUCM->userSocket, buffer, pos, 0);
    if(ret <= 0) {
        cout<<"Error sending challenged response message"<<endl;
        return false;
    }
    cout<<"Challenged Response sent correctly to the challenger"<<endl;
    return true;
}

bool UserConnectionManager::sendOpponentKeyToChallenged(string *opponent, uint32_t opponentPort) {

    size_t key_len;
    unsigned char *opponentPubKey = getUserPubKey(opponent, key_len);
    if(opponentPubKey == nullptr){
        cout<<"Error retrieving the opponent pubkey"<<endl;
        return false;
    }


    struct in_addr ipOpponent = server->getUserConnection(opponent->c_str())->clAdd.sin_addr;
    size_t port_len = sizeof(uint32_t);


    //Preparo messaggio in chiaro.
    auto *plainMsg = new unsigned char[key_len + IPLENGTH + port_len];


    int pos = 0;
    memcpy(plainMsg+pos, (void*)&ipOpponent, IPLENGTH);
    pos += IPLENGTH;

    memcpy(plainMsg+pos, &opponentPort, port_len);
    pos += port_len;

    memcpy(plainMsg + pos, opponentPubKey, key_len);
    pos+= key_len;

    size_t plain_len = pos;

    //iv
    size_t iv_len = AESGCMIVLENGTH;
    auto *iv = new unsigned char[iv_len];
    RAND_bytes(iv, iv_len);

    //counter
    this->counter++;

    //preparo aad
    size_t aad_len = AADLENGTH;
    auto *aad = new unsigned char[aad_len];
    aad[0] = OPPONENTKEYMESSAGECODE;
    memcpy(aad+1, iv, iv_len);
    memcpy((aad+1+iv_len), &this->counter, COUNTERLENGTH);

    auto* tag = new unsigned char[AESGCMTAGLENGTH];

    unsigned char *encrypted = symmetricEncryptionManager->encryptThisMessage(plainMsg, plain_len, aad, aad_len, iv, iv_len, tag);
    delete [] iv;
    delete [] plainMsg;

    size_t msg_len = aad_len + plain_len + AESGCMTAGLENGTH;
    auto* buffer = new unsigned char[msg_len];
    pos = 0;

    memcpy(buffer+pos, aad, aad_len);
    delete [] aad;
    pos += aad_len;

    memcpy((buffer+pos), encrypted, plain_len);
    delete [] encrypted;
    pos += plain_len;

    memcpy((buffer+pos), tag, AESGCMTAGLENGTH);
    delete [] tag;


    size_t ret = send(userSocket, buffer, msg_len, 0);
    delete [] buffer;

    if(ret != msg_len){
        cerr<<"Error sending opponent key\n";
        return false;
    }
    cout<<"Adversary key and address sent correctly\n";
    return true;
}
unsigned char *UserConnectionManager::getUserPubKey(string* opponent, size_t& pubkey_len){

    UserConnectionManager *opponentUCM = server->getUserConnection(opponent->c_str());
    return opponentUCM->signatureManager->getPubkey(pubkey_len);
}
bool UserConnectionManager::waitForChallengedReady(unsigned char*buffer, size_t buffer_len, uint32_t& port, string* opponent) {


    if(buffer_len <=0){
        cerr<<"Error in receving Challenged Ready message,received "<<buffer_len<<" bytes"<<endl;
        delete [] buffer;
        return false;
    }

    uint32_t cont;
    memcpy(&cont, &buffer[1+AESGCMIVLENGTH], COUNTERLENGTH);
    if(cont != this->counter+1){
        cout<<"Different counter value expected"<<endl;
        delete [] buffer;
        return false;
    }
    this->counter++;

    if(buffer[0] != CHALLENGEDREADYFORCHALLENGEMESSAGECODE){
        cout<<"Wrong message"<<endl;
        delete [] buffer;
        return false;
    }else
        cout<<"Challenged readiness message opcode verified"<<endl;

    //copio iv
    size_t iv_len = AESGCMIVLENGTH;
    auto *iv = new unsigned char[iv_len];
    memcpy(iv, (buffer+1), iv_len);

    //copio aad
    size_t aad_len = AADLENGTH;
    auto *aad = new unsigned char[aad_len];
    memcpy(aad, buffer, aad_len);

    //copio encrypted message
    size_t encrypted_len = buffer_len-aad_len-AESGCMTAGLENGTH;
    auto *encrypted = new unsigned char[encrypted_len];
    memcpy(encrypted, (buffer+aad_len), encrypted_len);

    //copio tag
    auto *tag = new unsigned char[AESGCMTAGLENGTH];
    memcpy(tag, (buffer+aad_len+encrypted_len), AESGCMTAGLENGTH);

    delete [] buffer;

    unsigned char *plainMessage = symmetricEncryptionManager->decryptThisMessage(encrypted, encrypted_len, aad, aad_len, tag, iv);

    delete [] encrypted;
    delete [] iv;
    delete [] aad;
    delete [] tag;

    size_t port_len = sizeof(port);

    if(encrypted_len != port_len + opponent->length()+1){

        cout<<"Decrypt returned a wrong value"<<endl;
        delete [] plainMessage;
        return false;
    }

    uint32_t port_received;
    memcpy(&port_received, plainMessage, port_len);

    port = port_received;

    plainMessage[encrypted_len-1] = '\0';
    auto *user = new string(reinterpret_cast<const char *>(&plainMessage[port_len]));

    delete [] plainMessage;
    if(strcmp(user->c_str(), opponent->c_str()) != 0){
        delete user;
        cout<<"Received username was not expected"<<endl;
        return false;
    }

    delete user;
    return true;
}
bool UserConnectionManager::sendMyKeyToChallenger(string *challenger, uint32_t port) {

    size_t key_len;
    unsigned char *myPubKey = getUserPubKey(this->userName, key_len);
    if(myPubKey == nullptr){
        cout<<"Error retrieving the opponent pubkey"<<endl;
        delete [] myPubKey;
        return false;
    }

    UserConnectionManager *challengerUCM = server->getUserConnection(challenger->c_str());
    const std::lock_guard<std::mutex> lock(challengerUCM->ucmMutex);
    struct in_addr myIP = this->clAdd.sin_addr;
    size_t port_len = sizeof(uint32_t);


    //Preparo messaggio in chiaro.
    auto *plainMsg = new unsigned char[key_len + IPLENGTH + port_len];


    int pos = 0;
    memcpy(plainMsg+pos, (void*)&myIP, IPLENGTH);
    pos += IPLENGTH;

    memcpy(plainMsg+pos, &port, port_len);
    pos += port_len;

    memcpy(plainMsg + pos, myPubKey, key_len);
    delete [] myPubKey;
    pos+= key_len;

    size_t plain_len = pos;

    //iv
    size_t iv_len = AESGCMIVLENGTH;
    auto *iv = new unsigned char[iv_len];
    RAND_bytes(iv, iv_len);

    //counter
    challengerUCM->counter++;

    //preparo aad
    size_t aad_len = AADLENGTH;
    auto *aad = new unsigned char[aad_len];
    aad[0] = OPPONENTKEYMESSAGECODE;
    memcpy(aad+1, iv, iv_len);
    memcpy((aad+1+iv_len), &challengerUCM->counter, COUNTERLENGTH);

    auto* tag = new unsigned char[AESGCMTAGLENGTH];

    unsigned char *encrypted = challengerUCM->symmetricEncryptionManager->encryptThisMessage(plainMsg, plain_len, aad, aad_len, iv, iv_len, tag);
    delete [] iv;
    delete [] plainMsg;

    size_t msg_len = aad_len + plain_len + AESGCMTAGLENGTH;
    auto* buffer = new unsigned char[msg_len];
    pos = 0;

    memcpy(buffer+pos, aad, aad_len);
    delete [] aad;
    pos += aad_len;

    memcpy((buffer+pos), encrypted, plain_len);
    delete [] encrypted;
    pos += plain_len;

    memcpy((buffer+pos), tag, AESGCMTAGLENGTH);
    delete [] tag;


    size_t ret = send(challengerUCM->userSocket, buffer, msg_len, 0);
    delete [] buffer;

    if(ret != msg_len){
        cerr<<"Error sending opponent key\n";
        return false;
    }
    cout<<"Adversary key and address sent correctly\n";
    return true;
}
bool UserConnectionManager::endGame(unsigned char* buffer, size_t buffer_len) {

    if(buffer_len <= 0){
        cout<<"Error in receiving endGame message"<<endl;
        delete [] buffer;
        return false;
    }

    if(buffer[0] != ENDGAMEMESSAGECODE){
        cout<<"Wrong message. End Game message expected"<<endl;
        delete [] buffer;
        return false;
    }

    uint32_t cont;
    memcpy(&cont, &buffer[OPCODELENGTH+AESGCMIVLENGTH], COUNTERLENGTH);
    if(cont != this->counter+1){
        cout<<"Error! Wrong counter value!"<<endl;
        delete [] buffer;
        return false;
    }
    this->counter++;
    auto *iv = new unsigned char[AESGCMIVLENGTH];
    memcpy(iv, buffer+OPCODELENGTH, AESGCMIVLENGTH);

    size_t aad_len = AADLENGTH;
    auto *aad = new unsigned char[AADLENGTH];
    memcpy(aad, buffer, AADLENGTH);

    size_t encrypted_len = buffer_len-AADLENGTH-AESGCMTAGLENGTH;
    auto *encrypted = new unsigned char[encrypted_len];
    memcpy(encrypted, buffer+AADLENGTH, encrypted_len);

    auto *tag = new unsigned char[AESGCMTAGLENGTH];
    memcpy(tag, &buffer[AADLENGTH+encrypted_len], AESGCMTAGLENGTH);

    unsigned char* plainMessage = symmetricEncryptionManager->decryptThisMessage(encrypted, encrypted_len, aad, aad_len, tag, iv);

    delete [] tag;
    delete [] encrypted;
    delete [] aad;
    delete [] iv;
    delete [] buffer;

    if(strcmp((const char *)(plainMessage), this->userName->c_str()) != 0){
        cout<<"Error. Username not expected"<<endl;
        delete [] plainMessage;
        return false;
    }
    this->busy = false;
    delete [] plainMessage;
    return true;
}
void UserConnectionManager::logout(unsigned char *buffer, size_t buffer_len) {

    uint32_t cont;
    if(buffer_len < AADLENGTH+AESGCMTAGLENGTH+AESBLOCKLENGTH){
        cout<<"Error in receiving logout message"<<endl;

        return;
    }
    memcpy(&cont, &buffer[1+AESGCMIVLENGTH], COUNTERLENGTH);
    if(cont != this->counter+1){
        cout<<"Error! Wrong counter value"<<endl;

        return;
    }
    this->counter++;
    auto *iv = new unsigned char[AESGCMIVLENGTH];
    memcpy(iv, &buffer[1], AESGCMIVLENGTH);

    auto *aad = new unsigned char[AADLENGTH];
    size_t aad_len = AADLENGTH;
    memcpy(aad, buffer, aad_len);

    auto *tag = new unsigned char[AESGCMTAGLENGTH];
    memcpy(tag, &buffer[buffer_len-AESGCMTAGLENGTH], AESGCMTAGLENGTH);

    size_t encrypted_len = buffer_len-AESGCMTAGLENGTH-AADLENGTH;
    auto *encrypted = new unsigned char[encrypted_len];
    memcpy(encrypted, &buffer[aad_len], encrypted_len);

    delete [] buffer;

    unsigned char* plaintext = symmetricEncryptionManager->decryptThisMessage(encrypted, encrypted_len, aad, aad_len, tag, iv);

    delete [] iv;
    delete [] aad;
    delete [] tag;
    delete [] encrypted;

    if(strcmp((const char*)plaintext, this->userName->c_str()) != 0){
        cout<<"Wrong username for logout request "<<endl;
        delete[] plaintext;
        return;
    }

    delete [] plaintext;

}


UserConnectionManager::~UserConnectionManager() {

    close(userSocket);
    delete [] server;
    delete userName;
    delete [] symmetricEncryptionManager;
    delete [] signatureManager;
    delete diffieHellmannManager;
}

