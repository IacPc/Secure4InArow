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
