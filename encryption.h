//
//  encryption.h
//  EchoCS
//
//  Created by Kaley Chicoine on 1/26/18.
//  Copyright © 2018 Kaley Chicoine. All rights reserved.
//

#ifndef encryption_h
#define encryption_h

#include <stdio.h>
#include <openssl/rsa.h>

#define packed __attribute__((packed))
#define BUFSIZE 1024


struct sendMsg {
    size_t enLen;
    unsigned char msg[BUFSIZE*2];
} packed;

int encryptMsg(char* ptMsg, char* ctMsg, RSA* keypair);
void decryptMsg(char* ctMsg, char* ptMsg, RSA* keypair, int encrypt_len);
int aesEncrypt(const unsigned char* aesKey, unsigned char* aesIV, unsigned char* msg, unsigned char** enMsg );
int aesDecrypt(const unsigned char* aesKey, unsigned char* aesIV, unsigned char* enMsg, unsigned char** deMsg, size_t enMsgLen);

#endif /* encryption_h */
