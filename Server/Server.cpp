//
// Created by Laura Lemmi on 13/08/2020.
//

#include "Server.h"

Server::Server(int port) {

    certificatePath = "Server_Keys";
    portNo = port;
    listenFd = socket(AF_INET, SOCK_STREAM, 0);
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(port);
    srvAddr.sin_addr.s_addr = INADDR_ANY;

    if(::bind(listenFd, (struct sockaddr*)&srvAddr, sizeof(srvAddr)) == -1){
        cerr<<"Error during bind\n";
        exit(-1);
    }

}

void Server::waitForNewConnections(){
    listen(listenFd, 10);

    struct sockaddr_in client_addr;
    int len, connFd;
    len = sizeof(client_addr);
    nThreads = 0;
    while(nThreads < 10){

        cout<<"Server is listening\n";

        connFd = accept(listenFd, (struct sockaddr*)&client_addr, reinterpret_cast<socklen_t *>(&len));
        if(connFd < 0){
            cerr<<"The connection cannot be accepted\n";
            continue;
        }else
            cout<<"Connection successful\n";

        UserConnectionManager *ucm = new UserConnectionManager(this, client_addr, connFd);
        std::thread t(&UserConnectionManager::openNewconnectionwithClient, ucm);
        t.detach();
        nThreads++;

    }

}

bool Server::checkUserPresence(string user) {

    std::unordered_map<string, UserConnectionManager*>::const_iterator it = usersConnectedMap.find(user);
    if(it == usersConnectedMap.end())
        return false;
    else
        return true;

}

bool Server::insertUserConnectionInMap(string user, UserConnectionManager* ucm) {

    if(checkUserPresence(user)) {
        cout << "The user is already present in map\n";
        return false;
    }
    const std::lock_guard<std::mutex> lock(this->mapMutex);

    usersConnectedMap.insert({user, ucm});

    if(checkUserPresence(user)) {
        cout << "Insert: Elements in map: \nKeys: ";
        for (auto x = usersConnectedMap.begin(); x != usersConnectedMap.end(); ++x)
            cout <<x->first<<" ";
        cout << endl;

        return true;
    }else
       return false;


}

UserConnectionManager* Server::getUserConnection(string user) {
    //Given the username, I search in the map the correspondent UCM
    const std::lock_guard<std::mutex> lock(this->mapMutex);

    std::unordered_map<string, UserConnectionManager*>::const_iterator it = usersConnectedMap.find(user);
    if(it == usersConnectedMap.end()) {
        cout << "Client not found\n";
        return NULL;
    }
    else
        return it->second;


}


std::vector<string> Server::getUserList(string *user) {
    const std::lock_guard<std::mutex> lock(this->mapMutex);

    vector<string> list;
    cout<<"Get Users List: \n";
    for (auto x = usersConnectedMap.begin(); x != usersConnectedMap.end(); ++x) {
        if(strcmp(x->first.c_str(), user->c_str())!=0)
            list.push_back(x->first.c_str());
    }
/*
    for(auto &v : list)
        cout<<v.c_str()<<" ";
    cout<<endl;
*/
    return list;

}

bool Server::removeUser(string* user) {

    if(!user)
        return true;
    const std::lock_guard<std::mutex> lock(this->mapMutex);

    if(!checkUserPresence(*user)) {
        return false;
    }else {
        auto* ucm = usersConnectedMap.at(*user);
        delete ucm;
        usersConnectedMap.erase(*user);

        this->nThreads--;
        return true;
    }
}


unsigned char* Server::geti2dCertificate(int &len) {
    //load CA certificate
    string cacert_file_name("../Server/Server_Keys/4InARowServer_cert.pem");
    FILE *cacert_file = fopen(cacert_file_name.c_str(), "r");
    if(!cacert_file){
        cerr<<"Error: cannot open the file\n";
        return NULL;
    }

    X509 *cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
    fclose(cacert_file);

    //serialize the certificate to be sent to a client
    unsigned char *buffer = NULL;
    int cert_size = i2d_X509(cacert, &buffer);
    X509_free(cacert);
    cout<<"Server: Certificate length: "<<cert_size<<endl;
    len = cert_size;
    if(cert_size < 0){
        cerr<<"Error during certificate serialization\n";
        return NULL;
    }
    return buffer;
}

Server::~Server() {

    for (auto x = usersConnectedMap.begin(); x != usersConnectedMap.end(); ++x) {
        delete x->second;
        usersConnectedMap.erase(x);
    }
    close(listenFd);
}


/**/