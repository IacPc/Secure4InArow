//
// Created by iacopo on 17/08/20.
//

#ifndef PROGETTO_CONSTANT_H
#define PROGETTO_CONSTANT_H

#endif //PROGETTO_CONSTANT_H
#define OPCODELENGTH 1
#define COUNTERLENGTH 4

#define AESBLOCKLENGTH 16
#define AESGCMIVLENGTH 12
#define AESGCMTAGLENGTH 16 // RFC 5116
#define AADLENGTH OPCODELENGTH + AESGCMIVLENGTH + COUNTERLENGTH
#define NONCELENGTH 4
#define MAXUSERNAMELENGTH 17
#define MAXCERTIFICATELENGTH 4096
#define SIZETLENGTH 2

#define ROWSNUMBER 6
#define COLUMNSNUMBER 7
////////////////////////////////////////////////////////////////////
//                      MESSAGE LENGTH                          ////
////////////////////////////////////////////////////////////////////
#define HELLOMESSAGELENGTH MAXUSERNAMELENGTH + NONCELENGTH + 1
#define MAXPLAYERSONLINE 5
#define COORDINATEMESSAGELENGTH AADLENGTH + 1 + AESGCMTAGLENGTH
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
#define CHALLENGEDREADYFORCHALLENGEMESSAGECODE 0x09
#define LOGOUTMESSAGECODE 0x0A
#define ENDGAMEMESSAGECODE 0x0B
#define COORDINATEMESSAGECODE 0X0C