//
// Created by iacopo on 17/08/20.
//

#ifndef PROGETTO_CONSTANT_H
#define PROGETTO_CONSTANT_H

#endif //PROGETTO_CONSTANT_H

#define AESKEYLENGTH 16
#define AESBLOCKLENGTH 16
#define AESIVLENGTH 16
#define HMACKEYLENGTH 32
#define SHA256DIGESTLENGTH 32
#define MAXMSGLENGTH 8191
#define NONCELENGTH 4
#define MAXUSERNAMELENGTH 17
#define KEYSLENGTH AESKEYLENGTH + AESIVLENGTH + HMACKEYLENGTH
#define ENCRYPTEDKEYLENGTH AESBLOCKLENGTH * 5
#define IVENVELOPELENGTH 16
#define KEYENVELOPELENGTH 256
#define SIGNEDMESSAGELENGTH 256
#define MSGTOSIGNLENGTH ENCRYPTEDKEYLENGTH + IVENVELOPELENGTH + KEYENVELOPELENGTH
#define MAXCERTIFICATELENGTH 4096
#define SIZETLENGTH 2
#define IPLENGTH 4
#define MAXENCRYPTEDUSERLENGTH 32
#define HMACLENGTH 32

////////////////////////////////////////////////////////////////////
//                      MESSAGE LENGTH                          ////
////////////////////////////////////////////////////////////////////

#define CLIENTNONCEMSGLENGTH NONCELENGTH + SHA256DIGESTLENGTH + 1
#define VERIFICATIONNONCEMSGLENGTH NONCELENGTH + SHA256DIGESTLENGTH + 1
#define SERVERNONCEMSGLENGTH 2*NONCELENGTH + SHA256DIGESTLENGTH + 1
#define RESPONSEENCRYPTEDLENGTH 32

////////////////////////////////////////////////////////////////////
//                      MESSAGE OPCODE                          ////
////////////////////////////////////////////////////////////////////
