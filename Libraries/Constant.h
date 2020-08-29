//
// Created by iacopo on 17/08/20.
//

#ifndef PROGETTO_CONSTANT_H
#define PROGETTO_CONSTANT_H

#endif //PROGETTO_CONSTANT_H
#define OPCODELENGTH 1
#define PUBKEYLENGTH 72
#define SIGNATURELENGTH 256
#define USEFULSECRETLENGTH 16


#define AESKEYLENGTH 16
#define AESBLOCKLENGTH 16
#define AESGCMIVLENGTH 12
#define AESGCMTAGLENGTH 16 // RFC 5116
#define SHA256DIGESTLENGTH 32
#define MAXMSGLENGTH 8191
#define NONCELENGTH 4
#define MAXUSERNAMELENGTH 17
#define KEYSLENGTH AESKEYLENGTH + AESIVLENGTH + HMACKEYLENGTH
#define ENCRYPTEDKEYLENGTH AESBLOCKLENGTH * 5
#define IVENVELOPELENGTH 16
#define KEYENVELOPELENGTH 256
#define MSGTOSIGNLENGTH ENCRYPTEDKEYLENGTH + IVENVELOPELENGTH + KEYENVELOPELENGTH
#define MAXCERTIFICATELENGTH 4096
#define SIZETLENGTH 2
#define IPLENGTH 4
#define MAXENCRYPTEDUSERLENGTH 32
#define HMACLENGTH 32

////////////////////////////////////////////////////////////////////
//                      MESSAGE LENGTH                          ////
////////////////////////////////////////////////////////////////////
#define HELLOMESSAGELENGTH MAXUSERNAMELENGTH + NONCELENGTH + 1
#define MAXPUBKEYMESSAGELENGTH OPCODELENGTH + 2*NONCELENGTH + MAXUSERNAMELENGTH + PUBKEYLENGTH + SIGNATURELENGTH

////////////////////////////////////////////////////////////////////
//                      MESSAGE OPCODE                          ////
////////////////////////////////////////////////////////////////////
#define HELLOMSGCODE 0x01
#define CERTIFICATEMSGCODE 0x02
#define PUBKEYMESSAGECODE 0x03