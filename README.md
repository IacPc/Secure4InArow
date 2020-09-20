# Secure4InArow

## Description
Here we present a simple implementation of the game “Four-in-a-Row”, in this
implementation the focus is not the user experience but the security of the overall
communications.
Especially when the client application starts, Server and Client
First authenticate with their public keys: in this scenario anyone who wants to play must ask first
to the server administrator to register his public key, and only after that he(or she) can use it to
authenticate himself.
Server public key is certified by SimpleAuthority CA, for this reason every
player has the burden to check the validity of said public key.
Once done all the verifications, those keys are used together with a 2048-bits DH public key to
compute a shared secret hence a symmetric key to encrypt and authenticate all the exchanged
messages.
After the authentication and negotiation phases a newly joined user can see other available users
logged to the server and he (or she) can challenge one of them, the latter can either accept or
refuse.
If the challenge is accepted, a secure channel is being established by means of a protocol
pretty similar to C/S one.
The users proceed to play using a peer-to-peer communication and for
each move a 6X7 grid is printed to terminal with all the moves done until that moment.

## Installation of the program
The project can be imported and executed using the Clion IDE or the cmake environment.
Private key file password coincides with the file name itself(aka Alice_prvkey.pem file 
password is "Alice_prvkey.pem")

## Contributors
[Laura Lemmi](https://github.com/llemmi)      
[Iacopo Pacini](https://github.com/IacPc)
