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
#define COUNTERLENGTH 4

#define AESKEYLENGTH 32
#define AESBLOCKLENGTH 16
#define AESGCMIVLENGTH 12
#define AESGCMTAGLENGTH 16 // RFC 5116
#define AADLENGTH OPCODELENGTH + AESGCMIVLENGTH + COUNTERLENGTH
#define SHA256DIGESTLENGTH 32
#define MAXMSGLENGTH 8191
#define NONCELENGTH 4
#define MAXUSERNAMELENGTH 17
#define MAXENCRYPTEDUSERNAMELENGTH 32
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
#define MAXPUBKEYMESSAGELENGTH OPCODELENGTH + 2*NONCELENGTH + 4 + PUBKEYLENGTH + SIGNATURELENGTH
#define MAXPLAYERSREQUESTMESSAGELENGTH OPCODELENGTH + AESGCMIVLENGTH + COUNTERLENGTH + MAXENCRYPTEDUSERNAMELENGTH + AESGCMTAGLENGTH
#define MAXPLAYERSONLINE 5
#define MAXPLAYERSCHOICEMESSAGELENGTH OPCODELENGTH + AESGCMIVLENGTH + COUNTERLENGTH + MAXENCRYPTEDUSERNAMELENGTH + AESGCMTAGLENGTH
#define MAXCHALLENGEDRESPONSEMESSAGELENGTH OPCODELENGTH + AESGCMIVLENGTH + COUNTERLENGTH + MAXENCRYPTEDUSERNAMELENGTH + AESGCMTAGLENGTH
#define MAXREADYFORCHALLENGEMESSAGELENGTH OPCODELENGTH + AESGCMIVLENGTH + COUNTERLENGTH + MAXENCRYPTEDUSERNAMELENGTH + AESGCMTAGLENGTH
////////////////////////////////////////////////////////////////////
//                      MESSAGE OPCODE                          ////
////////////////////////////////////////////////////////////////////
#define HELLOMSGCODE 0x01
#define CERTIFICATEMSGCODE 0x02
#define PUBKEYMESSAGECODE 0x03
#define LISTREQUESTMESSAGE 0x04
#define PLAYERSLISTMESSAGECODE 0x05
#define PLAYERCHOSENMESSAGECODE 0x06
#define CHALLENGEDRESPONSEMESSAGECODE 0x07
#define OPPONENTKEYMESSAGECODE 0x08
#define CLIENTREADYFORCHALLENGEMESSAGECODE 0x09