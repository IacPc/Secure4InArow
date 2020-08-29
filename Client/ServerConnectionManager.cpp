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
    cout<<"SCM port "<<serverAddr.sin_port<<endl;

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
        delete this;
        return false;
    }


    int certLen = MAXCERTIFICATELENGTH;
    //wait for server certificate
    unsigned char *serializedCertificate = waitForCertificate(certLen);
    if(serializedCertificate == NULL){
        cerr<<"Error receiving certificate\n";
        delete this;
        return false;
    }

    certificateManager = new CertificateManager();
    cout<<"The certificate has been received\n";

    //Inizializzo RSA
    string* path = new string("../Client/Client_Key/");
    path->append(userName->c_str());
    path->append("_prvkey.pem");
    this->rsaManager = new RSAManager(path);
   /* this->signatureManager = new SignatureManager(path);
    this->asymmetricEncryptionManager = new AsymmetricEncryptionManager(path);*/
    std::cout<<"veryfing the certificate"<<endl;


    if(!this->rsaManager->getAsymmetricEncryptionManager()->getPrvKey()){
        cerr<<"LA CHIAVE PRIVATA È NULL prima del controllo sul certificato\n";
        this->rsaManager->setPrvkey(path);
    }
    delete path;
    //verify the server certificate
    if(!verifyCertificate(serializedCertificate,certLen)){
        cerr<<"The certificate has not been verified\n";
        delete this;
        return false;
    }

    cout<<"The certificate has been verified\n";

    //create the readiness msg
    size_t readiness_len;
    unsigned char *readinessMsg = createReadiness(readiness_len);
    if(readinessMsg == NULL){
        cerr<<"Error during Readiness Message creation\n";
        delete this;
        return false;
    }


    //send the readiness msg
    if(!sendReadiness(readinessMsg, readiness_len)){
        cerr<<"Error during Readiness Message sending\n";
        delete this;
        return false;
    }
    std::cout<<"Readiness message sent correctly!"<<std::endl;

    //wait for keys message
    if(!waitForKeys()){
        cerr<<"Error in receiving keys message\n";
        delete this;
        return false;
    }
    cout<<"Creating nonce\n";
    //create client nonce
    unsigned char *myNonce = new unsigned char[NONCELENGTH];
    size_t myNonce_len = NONCELENGTH;
    RAND_bytes(&myNonce[0], myNonce_len);

    //send my nonce
    if(!sendClientNonce(myNonce, myNonce_len)){
        cerr<<"Error during Nonce Message sending\n";
        return false;
    }
    //wait for server nonce
    cout<<"Waiting for Server nonce\n";
    size_t serverNonce_len = NONCELENGTH;
    unsigned char *serverNonce = waitForServerNonce(serverNonce_len);
    if(serverNonce == NULL){
        cerr<<"Error in receiving nonce message\n";
        delete this;
        return false;
    }
    //send the server nonce
    if(!sendServerNonce(serverNonce, serverNonce_len)){
         cerr<<"Error sending server nonce\n";
         delete this;
         return false;
    }

    return true;
}

unsigned char* ServerConnectionManager::createHelloMessage(size_t &len) {

    size_t buf_len = sizeof(HELLOMSGCODE) + strlen(userName->c_str()) + 1;
    unsigned char*buffer = new unsigned char[buf_len];
    buffer[0] = HELLOMSGCODE;

    //memcpy(buffer+1, (const void*)&userName, userName->length());
    memcpy(buffer+1, userName->c_str(), strlen(userName->c_str())+1);
    cout<<"Hello Message created successfully, size: "<<userName->c_str()<< " "<<buf_len<<endl;
    len = buf_len;
    return buffer;

}

bool ServerConnectionManager::sendHelloMessage(unsigned char *hellomsg, size_t &len) {

    cout<<"HelloMessage size: "<<len<<endl;
    size_t ret;
    ret = send(serverSocket, (void*)hellomsg, len, 0);

    if(ret < len){
        cout<<"Error in sending hello message\n";
        return false;
    }else {
        cout<<"Length HelloMessage sent: "<<ret<<endl;
        return true;
    }
}

unsigned char* ServerConnectionManager::waitForCertificate(int& len){

    size_t ret;
    unsigned char* buffer = new unsigned char[MAXCERTIFICATELENGTH];

    cout<<"Waiting for certificate\n";
    ret = recv(serverSocket, (void*)buffer, MAXCERTIFICATELENGTH, 0);
    if(ret <= 0){
        cout<<"Error in receiving certificate message\n";
        return NULL;
    }

    if(buffer[0] != CERTIFICATEMSGCODE){
        cout<<"Wrong message\n";
        return NULL;
    }else{
        auto* cert = new unsigned char[ret-1];
        memcpy(cert, buffer+1, ret-1);

        delete []buffer;
        len = ret - 1;
        cout<<"Certificate has been received\n";
        return cert;
    }

}

bool ServerConnectionManager::verifyCertificate(unsigned char *cert, int len) {

    if(certificateManager->verifyCertificate(cert,len)){
        EVP_PKEY* pubkey = certificateManager->extractPubKey(cert, len);
        this->rsaManager->getAsymmetricEncryptionManager()->setPubkey(pubkey);
        this->rsaManager->signatureManager->setPubkey(pubkey);
        if(pubkey)
            return true;
    }
    return false;

}

unsigned char* ServerConnectionManager::createReadiness(size_t &len) {
    if(!this->rsaManager->getAsymmetricEncryptionManager()->getPrvKey()){
        cout<<"A INIZIO createReadiness sono NULL!\n";
    }
    unsigned char*buffer = new unsigned char[userName->length()+1];
    buffer[0] = CLIENTREADYCODE;

    memcpy(buffer+1, userName->c_str(), userName->length()+1);
    len = userName->length()+2;
    cout<<"Readiness message has been created\n";
    return buffer;
}

bool ServerConnectionManager::sendReadiness(unsigned char *readyMsg, size_t len) {

    if(!rsaManager->asymmetricEncryptionManager->getPrvKey()){
        cout<<"A INIZIO sendReadiness sono NULL!\n";
    }
    size_t ret;
    ret = send(serverSocket, readyMsg, len, 0);
    if(ret <= 0){
        cout<<"Error in sending readiness message\n";
        return false;
    }else {
        cout << "Readiness Massage has been sent. Length: "<<ret<<endl;
        return true;
    }
}

bool ServerConnectionManager::waitForKeys() {

    if(!rsaManager->asymmetricEncryptionManager->getPrvKey()){
        cout<<"A INIZIO waitForKeys sono NULL!\n";
    }
    size_t ret;
    size_t max = MSGTOSIGNLENGTH + SIGNEDMESSAGELENGTH;
    unsigned char* buffer = new unsigned char[max];
    ret = recv(serverSocket, buffer, max, 0);
    if(ret <= 0){
        cout<<"Error in receving keys message\n";
        return false;
    }
    if(ret != MSGTOSIGNLENGTH + SIGNEDMESSAGELENGTH)
        cout<<"Error in receving message ret = "<<ret<< " expected "<<MSGTOSIGNLENGTH + SIGNEDMESSAGELENGTH<<endl;

    //decrypt the message
    unsigned char* plainMsg, *encryptedMsg, *ivEnvelope, *keyEnvelope;
    size_t plain_len, ivEnv_len, keyEnv_len;
    encryptedMsg = new unsigned char[ENCRYPTEDKEYLENGTH];
    ivEnvelope = new unsigned char[IVENVELOPELENGTH];
    keyEnvelope = new unsigned char[KEYENVELOPELENGTH];

    memcpy(encryptedMsg, buffer, ENCRYPTEDKEYLENGTH);
    memcpy(ivEnvelope, buffer+ENCRYPTEDKEYLENGTH, IVENVELOPELENGTH);
    memcpy(keyEnvelope, buffer+ENCRYPTEDKEYLENGTH+IVENVELOPELENGTH, KEYENVELOPELENGTH);

    plain_len = ENCRYPTEDKEYLENGTH;
    ivEnv_len = IVENVELOPELENGTH;
    keyEnv_len = KEYENVELOPELENGTH;

    plainMsg = rsaManager->decryptThisMessage(encryptedMsg, plain_len, keyEnvelope, keyEnv_len, ivEnvelope, ivEnv_len);

    delete [] ivEnvelope;
    delete [] encryptedMsg;
    delete [] keyEnvelope;

    //verifico opcode
    if(plainMsg[0] != KEYESTABLISHMENTCODE){
        cout<<"Wrong message\n";
        delete [] plainMsg;
        delete []buffer;
        return false;
    }

    unsigned char* msgToVerify = new unsigned char[MSGTOSIGNLENGTH];
    int msgtosignlength = MSGTOSIGNLENGTH;

    if(!memcpy(msgToVerify, buffer, msgtosignlength))
        cout<<"error in memcpy\n";

    //verify the signature
    auto* signedMsg = new unsigned char[SIGNEDMESSAGELENGTH];
    size_t sign_len, toVerify_len;
    toVerify_len = MSGTOSIGNLENGTH;
    int signedMessageLength = SIGNEDMESSAGELENGTH;

    if(!memcpy(signedMsg, &buffer[MSGTOSIGNLENGTH], signedMessageLength))
        cout<<"error in memcpy\n";

    cout<<"verifying signature\n";

    if(!rsaManager->verifyThisSignature(signedMsg, signedMessageLength, msgToVerify, toVerify_len)){
        cout<<"Sign not verified\n";
        delete [] plainMsg;
        delete [] buffer;
        delete [] msgToVerify;
        delete [] signedMsg;
        return false;
    }

    cout<<"Signature verified\n";

    if(plain_len != AESIVLENGTH + AESKEYLENGTH + HMACLENGTH + 1){
        cout<<"Problem with the message length: plain_len= "<<plain_len<<" AESIVLENGTH + AESKEYLENGTH + HMACLENGTH + 1 = "<<AESIVLENGTH + AESKEYLENGTH + HMACLENGTH + 1<<endl;
    }
    symmetricEncryptionManager = new SymmetricEncryptionManager();
    symmetricEncryptionManager->setAESKey(obtainAES(plainMsg));
    symmetricEncryptionManager->setAESIV(obtainIV(plainMsg));
    symmetricEncryptionManager->sethmacKey(obtainHMAC(plainMsg));

    cout<<"Keys obtained successfully\n";
    delete [] plainMsg;
    delete []buffer;
    delete []msgToVerify;
    delete []signedMsg;
    return true;

}

unsigned char* ServerConnectionManager::obtainAES(unsigned char* msg){
    unsigned char *aes_key = new unsigned char[AESKEYLENGTH];
    memcpy(aes_key, &msg[HMACKEYLENGTH + 1], AESKEYLENGTH);
    return aes_key;
}

unsigned char *ServerConnectionManager::obtainIV(unsigned char* msg){
    unsigned char *iv = new unsigned char[AESIVLENGTH];
    memcpy(iv, &msg[HMACKEYLENGTH+AESKEYLENGTH+1], AESIVLENGTH);
    return iv;
}

unsigned char *ServerConnectionManager::obtainHMAC(unsigned char* msg){
    unsigned char *hmac_key = new unsigned char[HMACKEYLENGTH];
    memcpy(hmac_key, (msg+1), HMACKEYLENGTH);
    return hmac_key;
}

bool ServerConnectionManager::sendClientNonce(unsigned char* nonce, size_t len){

    cout<<"Sending nonce\n";
    len = NONCELENGTH;
    unsigned char *plainMsg = new unsigned char[len+1];
    size_t ret;

    plainMsg[0] = CLIENTNONCECODE;

    memcpy(plainMsg+1, nonce, len);

    size_t auth_message_len = len+1;
    unsigned char *authenticatedMsg = symmetricEncryptionManager->computeMac(plainMsg, auth_message_len);


    unsigned char * buffer = new unsigned char[len+1 + auth_message_len];
    size_t pos = 0;
    memcpy(buffer+pos, plainMsg, len+1);
    pos+= len+1;
    memcpy(buffer+pos, authenticatedMsg, auth_message_len);
    pos+= auth_message_len;



    ret = send(serverSocket, buffer, pos, 0);
    for(int i = 0; i < NONCELENGTH+1; i++)
        cout<<(int)buffer[i]<<", ";
    cout<<endl;
    //BIO_dump_fp(stdout,(const char*)&buffer, ret);
    cout<<"RET = "<<ret<<endl;
    if(ret != pos){
        cout<<"Error in sending nonce message, ret = "<<ret<<"\n";
        delete []plainMsg;
        delete []buffer;
        return false;
    }else {
        delete [] plainMsg;
        delete [] buffer;
        cout<<"The nonce has been sent successfully, ret= " <<ret <<"\n";
        return true;
    }

}

unsigned char* ServerConnectionManager::waitForServerNonce(size_t& serverNonce_len) {

    unsigned char *plainMsg, *serverNonce, *hmacMsg, *buffer;

    int ret;
    buffer = new unsigned char[SERVERNONCEMSGLENGTH];
    plainMsg = new unsigned char[2*NONCELENGTH+1];
    serverNonce = new unsigned char[NONCELENGTH];
    hmacMsg = new unsigned char[SHA256DIGESTLENGTH];


    ret = recv(serverSocket, buffer, SERVERNONCEMSGLENGTH, 0);
    if(ret < SERVERNONCEMSGLENGTH){
        cerr<<"Error during Server nonce receving, ret = "<<ret<<"\n";
        delete [] plainMsg;
        delete []buffer;
        delete [] serverNonce;
        delete [] hmacMsg;
        return NULL;
    }else {
        cout << "Server Nonce received:" << ret << endl;

        //ottengo il messaggio decriptato

        size_t plain_len = 2*NONCELENGTH + 1;

        memcpy(plainMsg, buffer, plain_len);

        memcpy(hmacMsg, buffer + plain_len, SHA256DIGESTLENGTH);

        if ((symmetricEncryptionManager->verifyMac(hmacMsg, plainMsg, plain_len)) == false) {
            cout << "HMAC not verified\n";
            delete[] plainMsg;
            delete[]buffer;
            delete[] serverNonce;
            delete[] hmacMsg;
            return NULL;
        }
        cout<<"HMAC has been verified\n";

        //verifico opcode
        if (plainMsg[0] != SERVERNONCECODE) {
            cerr << "Wrong message\n";
            delete[] plainMsg;
            delete[]buffer;
            delete[] serverNonce;
            delete[] hmacMsg;
            return NULL;
        }else
            cout<<"Server nonce message opcode has been verified\n";


        memcpy(serverNonce, (plainMsg + NONCELENGTH + 1), NONCELENGTH);

        for(int i = 0; i < NONCELENGTH; i++)
            cout<<serverNonce[i];
        cout<<endl;

        delete[] plainMsg;
        delete[]buffer;
        delete[] hmacMsg;

        serverNonce_len = NONCELENGTH;
        return serverNonce;
    }
}

string* ServerConnectionManager::waitForPlayers(bool& challenger) {

    string *userSelected = new string();
    size_t ret;
    unsigned char *buffer = new unsigned char[MAXMSGLENGTH];
    //ricevo il messaggio
    ret = recv(serverSocket, buffer, MAXMSGLENGTH, 0);
    if(ret < 0){
        cerr<<"Error in receiving Players List Message\n";
        return NULL;
    }

    //chiamo la funzione per decriptare e verificare il messaggio
    unsigned char *plainMsg;
    plainMsg = symmetricEncryptionManager->decryptNVerifyMACThisMessage(buffer, ret);


    //controllo l'opcode
    if(plainMsg[0] != PLAYERLISTCODE){
        cerr<<"Wrong message\n";
        return NULL;
    }else

        cout<<"Players List received correctly\n";

    //prelevo il numero dei giocatori dal buffer
    size_t num_players;
    memcpy(&(num_players), plainMsg + 1, sizeof(size_t));

    size_t players_username_length = ret - 1 - sizeof(size_t);
    //prelevo i giocatori
    unsigned char* players = new unsigned char[players_username_length];
    memcpy(players, plainMsg+1+sizeof(size_t), players_username_length);

    num_players = ntohs(num_players);
    //dichiaro le variabili necessarie al prelievo del singolo giocatore
    size_t j = 0, k = 0;
    unsigned char* player = new unsigned char[MAXUSERNAMELENGTH];

    //prelevo ogni giocatore e lo inserisco nel vettore di stringhe
    vector<string> list;
    for(int i = 0; i < players_username_length; i++)
        cout<<players[i];
    cout<<endl;

    for(int i = 0; i <  players_username_length && j < num_players; ){
        strcpy((char *)(player), (const char *)(players+i));
            list.push_back((string)(const char *)(player));
            i += strlen(reinterpret_cast<const char *>(player)) + 1;
            j++;
            cout<<"PLAYER "<<j+1<<" = "<<player<<endl;
    }
    if(num_players > 0)
        challenger = true;
    else
        challenger = false;

    //stampo la lista dei giocatori
    printf("The number of players currently online is: %zu\n", num_players);
    printf("The number of players currently online is: %zu\n", list.size());
    if(list.size() > 0) {
        if((userSelected = selectPlayer(list)) != NULL){
            if(userSelected->length() == 0)
                challenger = false;
            cout<<"Player selected correctly\n";
            return userSelected;
        }
    }
    cout<<"No players available. Wait for challenger\n";
    challenger = false;
    return nullptr;

}

string* ServerConnectionManager::selectPlayer(vector<string> list){

    int i = 0;
    for(auto& v: list) {
        cout <<i+1<<") " <<v.c_str() << "\n";
        i++;
    }

    cout<<"Type a number to select the player you play with or just press enter:\n";
    unsigned int choice;

    string *temp = new string();
    getline(std::cin, *temp);
    if(temp->length() == 0){
        return temp;
    }

    getline(std::cin, *temp);
    bool isNumberValid = tryParse(temp, choice);
    isNumberValid = (choice >=1 && choice <= list.size() );

    while(!isNumberValid){
        cout<<"Error: enter a number between 1 and "<<list.size()<<" ";
        temp->clear();
        getline(std::cin, *temp);
        isNumberValid = tryParse(temp, choice);
        isNumberValid = ( choice >=1 && choice <= list.size() );
    }

    string *user = new string();
    user->append(list[choice-1].c_str());
    cout<<"The choice is: "<<choice<<" "<<user->c_str()<<"\n";

    return user;
}

bool ServerConnectionManager::sendSelection(string *userSelected) {

    unsigned char *plainMsg;
    size_t len;
    if(userSelected != NULL) {
        plainMsg = new unsigned char[1 + userSelected->length() + 1];
        plainMsg[0] = PLAYERSELECTEDCODE;
        memcpy(plainMsg + 1, userSelected->c_str(), userSelected->length() + 1);

        len = 1 + userSelected->length() + 1;
    }else{
        plainMsg = new unsigned char[OPCODELENGTH];
        plainMsg[0] = PLAYERSELECTEDCODE;
        len = 1;
    }
    cout<<"LEN IS :"<<len<<endl;
    unsigned char *encrypted;
    encrypted =symmetricEncryptionManager->encryptNMACThisMessage(plainMsg, len);

    size_t ret;
    ret = send(serverSocket, encrypted, len, 0);


    if(ret < 0){
        cout<<"Error during sending the selected player\n";
        return false;
    }
    if(userSelected != NULL)
        cout<<"The selected player has been sent\n";
    else
        cout<<"Waiting for challenger message has been sent\n";
    return true;

}

bool ServerConnectionManager::sendServerNonce(unsigned char *serverNonce, size_t nonce_len) {

    unsigned char *buffer, *plainMsg, *hmac;
    //nonce_len = NONCELENGTH;
    cout<<"NONCE LEN= "<<nonce_len<<endl;
    plainMsg = new unsigned char[nonce_len+1];

    plainMsg[0] = SERVERNONCEVERIFICATIONCODE;
    memcpy(plainMsg+1, serverNonce, nonce_len);

    size_t pos = 0, toMac = nonce_len+1;
    hmac = symmetricEncryptionManager->computeMac(plainMsg, toMac);

    buffer = new unsigned char[VERIFICATIONNONCEMSGLENGTH];
    memcpy(buffer, plainMsg, nonce_len+1);
    pos += nonce_len+1;
    memcpy(buffer+pos, hmac, toMac);
    pos += toMac;

    delete []plainMsg;
    delete []hmac;
    size_t ret = send(serverSocket, buffer, pos, 0);

    for(int i = 1; i < NONCELENGTH+1; i++)
        cout<<buffer[i];
    cout<<endl;

    delete []buffer;
    if(ret != VERIFICATIONNONCEMSGLENGTH){
        cerr<<"Error in sending nonce verification message\n";
        return false;
    }
    cout<<"Nonce Verification message has been sent\n";
    return true;
}

bool ServerConnectionManager::tryParse(std::string* input, unsigned int& output) {
    unsigned int temp;
    try{
        cout<<"SONO DENTRO IL TRY"<<endl;
        temp = std::stoi(input->c_str());
    } catch (std::invalid_argument) {
        return false;
    }
    output = temp;
    return true;
}

ServerConnectionManager::~ServerConnectionManager() {

    close(serverSocket);
    delete userName;
    delete []rsaManager;
    delete []symmetricEncryptionManager;
    delete []certificateManager;

}

string * ServerConnectionManager::waitForChallenge() {

    unsigned char *buffer = new unsigned char[MAXENCRYPTEDUSERLENGTH+HMACLENGTH];
    size_t ret = recv(serverSocket, buffer, MAXENCRYPTEDUSERLENGTH+HMACLENGTH, 0);

    if(ret < AESBLOCKLENGTH + HMACLENGTH){
        cerr<<"Error receiving challenge request message, RET= "<<ret<<endl;
        delete []buffer;
        return NULL;
    }

    unsigned char *plainMsg;
    plainMsg = symmetricEncryptionManager->decryptNVerifyMACThisMessage(buffer, ret);
    size_t plain_len = ret;

    delete []buffer;
    if(plainMsg[0] == SENDCHALLENGECODE){
        cout<<"Challenge request message verified\n";
    }else{
        cout<<"Wrong message. Expected challenge request message\n";
        delete [] plainMsg;
        return NULL;
    }

    plainMsg[plain_len-1] = '\0';
    string *opponent = new string((const char*)&plainMsg[1]);

    delete []plainMsg;
    return opponent;
}

bool ServerConnectionManager::sendResponse(string* opponent) {

    unsigned char* buffer;

    size_t ret;

    char response;
    cout<<opponent->c_str()<<" wants to challenge you. Do you accept? [Y or N]"<<endl;
    cin>>response;

    while(response != 'Y' && response != 'N'){
        cout<<"wrong input\n";
        cin>>response;
    }

    if(response == 'Y') {

        size_t plain_len = 1 + opponent->length()+1 + 1;
        auto *plainMsg = new unsigned char[plain_len];
        plainMsg[0] = CHALLENGEDRESPONSECODE;

        int pos = 1;
        memcpy(plainMsg+pos, opponent->c_str(), opponent->length()+1);
        pos += opponent->length()+1;

        plainMsg[pos] = response;
        pos += 1;

        size_t toEncryptLen = pos;
        buffer = symmetricEncryptionManager->encryptNMACThisMessage(plainMsg, toEncryptLen);

        delete [] plainMsg;
        ret = send(serverSocket, buffer, toEncryptLen, 0);

        delete [] buffer;
        if(ret != toEncryptLen){
            cerr<<"Error during sending message\n";
            return false;
        }
        return true;
    }
    else
        return false;


}

bool ServerConnectionManager::clientReadyForChallenge() {

    unsigned int htons_port = P2Pport;
    size_t port_len = sizeof(htons_port);
    size_t username_len = this->userName->length()+ port_len +1;
    auto *plainMsg = new unsigned char[username_len+1];
    plainMsg[0] = CLIENTREADY4CHALLENGECODE;
    int pos = 1;

    memcpy(plainMsg+pos, &htons_port, port_len);
    pos += port_len;

    memcpy(plainMsg+pos, userName->c_str(), username_len);

    size_t toBeEncrypted_len = pos + username_len;

    unsigned char*buffer = symmetricEncryptionManager->encryptNMACThisMessage(plainMsg, toBeEncrypted_len);

    delete []plainMsg;

    size_t ret, encrypted_len = toBeEncrypted_len;

    ret = send(serverSocket, buffer, encrypted_len, 0);
    if(ret != encrypted_len){
        cout<<"Error sending the client ready for challenge message\n";
        return false;
    }
    cout<<"readiness msg has been sent\n";
    return true;
}

EVP_PKEY *ServerConnectionManager::waitForOpponentKey(struct in_addr& ipOpponent, size_t& port) {

    auto* buffer = new unsigned char[MAXMSGLENGTH];

    size_t ret = recv(serverSocket, buffer, MAXMSGLENGTH, 0);
    if(ret < 0){
        cerr<<"Error receving the opponent key message\n";
        return nullptr;
    }

    unsigned char *plainMsg;
    plainMsg = symmetricEncryptionManager->decryptNVerifyMACThisMessage(buffer, ret);
    delete [] buffer;
    size_t plain_len = ret;

    if(plainMsg[0] == OPPONENTKEYCODE){
        cout<<"waitForOpponentKeyMessage opcode verified\n";
    }else{
        cout<<"Wrong message! waitForOpponentKeyMessage opcode expected\n";
        return nullptr;
    }

    int pos = 1;

    memcpy(&ipOpponent, plainMsg+pos, IPLENGTH);
    pos += IPLENGTH;


    size_t htons_port;
    memcpy(&htons_port, plainMsg+pos, SIZETLENGTH);
    pos += SIZETLENGTH;
    port = ntohs(htons_port);

    long pubkey_size = plain_len-pos;
    unsigned char *pubkey_buf = (unsigned char*)malloc(pubkey_size);

    memcpy(pubkey_buf, plainMsg+pos, pubkey_size);
    BIO *mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, pubkey_buf, pubkey_size);
    EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    BIO_free(mbio);

    cout<<"Adversary public key obtained correctly\n";
    return pubkey;
}

EVP_PKEY* ServerConnectionManager::createNewChallenge(bool& challenger, struct in_addr& ipOpponent) {

    string *user;
    user = waitForPlayers(challenger);

    //Controllo che non sia null
    if(user != NULL)
        cout<<"SECURE THE CONNECTION: "<<user->c_str()<<endl;

    if(!sendSelection(user)){
        cerr<<"Error in sending the choice\n";
        delete this;
        return nullptr;
    }

    size_t port;
    EVP_PKEY *opponentKey;

    if(challenger) {

        opponentKey = waitForOpponentKey(ipOpponent, port);
        P2Pport = htons(port);
        cout<<"P2Pport has been intialized with "<<ntohs(P2Pport)<<endl;
        if(opponentKey == NULL)
            return nullptr;
        cout<<"Received credentials of "<<user->c_str()<<endl;


    }else{
        string *opponent = waitForChallenge();
        if(opponent == NULL){
            return nullptr;
        }
        cout<<"The challenge request comes from: "<<opponent->c_str()<<endl;
        if(!sendResponse(opponent)){
            return nullptr;
        }
        opponentKey = waitForOpponentKey(ipOpponent, port);
        if(opponentKey == NULL)
            return nullptr;

        unsigned int port;


        string *port_input = new string();
        //cin.ignore(numeric_limits<streamsize>::max(), '\n');
        bool valid;
        do{
            valid = true;
            cout<<"Insert a port for the P2P communication"<<endl;
            getline(std::cin, *port_input);
            valid = tryParse(port_input, port);
            if((port > 65535) || (port < 2000) || (port == this->serverAddr.sin_port) ) {
                valid = false;
                cout << "Error! Type a valid port number" << endl;
                port_input->clear();
            }

        }while(!valid);

        P2Pport = htons(port);


        cout<<"Received credentials of "<<opponent->c_str()<<endl;

    }
    return opponentKey;
}

int ServerConnectionManager::getPort() {
    return P2Pport;
}

const char* ServerConnectionManager::getUserName() {
    return (this->userName->c_str());
}

void ServerConnectionManager::sendEndOfGame(){

    auto *buffer = new unsigned char [MAXMSGLENGTH];

    size_t ret = send(serverSocket, buffer, MAXMSGLENGTH, 0);

}

EVP_PKEY *ServerConnectionManager::getPrvKey() {
    return this->rsaManager->getPrivateKey();
}

EVP_PKEY *ServerConnectionManager::getPubKey() {
    return this->rsaManager->getPubkey();
}

void ServerConnectionManager::setPwd(string* p) {
    this->pwd = p;
}
