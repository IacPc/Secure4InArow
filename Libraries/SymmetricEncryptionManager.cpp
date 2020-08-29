//
// Created by iacopo on 14/08/20.
//

#include "SymmetricEncryptionManager.h"

SymmetricEncryptionManager::SymmetricEncryptionManager(unsigned char* enc, unsigned char* iv, unsigned char* hmac) {
    this->aesManager = new AESManager(enc,iv);
    this->hmacManager = new HMACManager(hmac);

}
SymmetricEncryptionManager::SymmetricEncryptionManager() {
    this->aesManager = new AESManager();
    this->hmacManager = new HMACManager();
}


unsigned char *SymmetricEncryptionManager::decryptNVerifyMACThisMessage(unsigned char* toDecryptNVerify, size_t& messageLength){

    size_t digestLength = EVP_MD_size(this->hmacManager->getHashFunction());
    if(messageLength <= digestLength){
        std::cerr<<"FATAL ERROR: received a message whose length is shorter than message digest"<<std::endl;
        messageLength = 0;
        return nullptr;

    }
    std::cout<<"messageLength = "<< messageLength <<std::endl;
    std::cout<<"digestLength: "<<digestLength<<std::endl;

    // This message is composed by two contiguos chunks: 1 encrypted with AES128 and 1 chunk long exactly 32 byte
    // that is the HMAC of the encrypted cipherText. The part to be decrypted is the one formed by the firsts
    // aeskeylength bytes

    size_t HMACLength =  SHA256DIGESTLENGTH;
    size_t chunkToBeDecryptedLen  = messageLength - SHA256DIGESTLENGTH;
    std::cout<<"HMACLength = "<< HMACLength <<std::endl;

    if(!this->hmacManager->verifyMAC(&toDecryptNVerify[chunkToBeDecryptedLen], toDecryptNVerify, chunkToBeDecryptedLen)){
        std::cerr<<"FATAL ERROR: HMAC DOES NOT COINCIDES!!"<<std::endl;
        messageLength = 0;
        return nullptr;
    }else
        std::cout<<"MAC VERIFIED CORRECTLY"<<std::endl;

    unsigned char* decryptedChunk = this->aesManager->decryptThisMessage(toDecryptNVerify, chunkToBeDecryptedLen);
    messageLength = chunkToBeDecryptedLen;
    return decryptedChunk;

}

unsigned char *SymmetricEncryptionManager::encryptNMACThisMessage(unsigned char* m, size_t& l) {
    size_t encryptedMessageLength, hmacLength, totalLength;

    unsigned char* encryptedMessage = this->aesManager->encryptThisMessage(m, l);

    if(!encryptedMessage){
        return encryptedMessage;
    }

    encryptedMessageLength = l;
    totalLength = encryptedMessageLength;

    unsigned char* hmacBuffer = this->hmacManager->computeMAC(encryptedMessage, l);
    if(!hmacBuffer) return hmacBuffer;
    hmacLength = l;
    totalLength += hmacLength;

    auto* encPlusMacBuffer = new unsigned char[totalLength];

    memcpy(encPlusMacBuffer,encryptedMessage,encryptedMessageLength);
    memcpy(&encPlusMacBuffer[encryptedMessageLength],hmacBuffer,hmacLength);

    l = totalLength;


    return encPlusMacBuffer;
}

unsigned char *SymmetricEncryptionManager::getAESKey() {
    return this->aesManager->getAESKey();
}


unsigned char *SymmetricEncryptionManager::getHMacKey() {
    return this->hmacManager->getHMacKey();
}

unsigned char *SymmetricEncryptionManager::getIV() {
    return this->aesManager->getIV();
}

void SymmetricEncryptionManager::setAESKey(unsigned char *k) {

    this->aesManager->setAESKey(k);
}

void SymmetricEncryptionManager::setAESIV(unsigned char *iv) {
    this->aesManager->setAESIV(iv);
}

void SymmetricEncryptionManager::sethmacKey(unsigned char * hk) {
    this->hmacManager->sethmacKey(hk);
}

unsigned char *SymmetricEncryptionManager::computeMac(unsigned char * txt, size_t & l) {
    return this->hmacManager->computeMAC(txt,l);
}

bool SymmetricEncryptionManager::verifyMac(unsigned char * hmacRec, unsigned char* txtToMac,size_t& txtl) {
    return this->hmacManager->verifyMAC(hmacRec,txtToMac,txtl);
}

