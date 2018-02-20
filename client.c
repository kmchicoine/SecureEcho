//
//  client.c
//  EchoCS
//
//  Created by Kaley Chicoine on 1/22/18.
//  Copyright © 2018 Kaley Chicoine. All rights reserved.
//

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include "client.h"
#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/time.h>


#define MAXLEN 1024

static EVP_PKEY *localKeypair = NULL;
EVP_PKEY *remotePublicKey = NULL;

#define AES_KEYLEN 256
#define AES_ROUNDS 6

char *aesKey;
char *aesIv;


struct timeval start, end;

int main(int argc, const char * argv[]) {
    int sockfd;
    unsigned short serverPort = 1234;
    const char* serverName = "localhost";
    struct sockaddr_in serverAddr;
    struct sockaddr_in clientAddr;
    socklen_t len = sizeof(struct sockaddr_in);
    char msg[BUFSIZE+1];
    int rec = 0;
    char buf[BUFSIZE+1];
    struct sendMsg sender;
    //RSA* keypair;
    //keypair = RSA_generate_key(2048,3, NULL, NULL);

    
    //TODO: read in command line args
    printf("Message to encrypt: ");
    fgets(msg, BUFSIZE, stdin);
    msg[strlen(msg)-1] = '\0';

    //init AES
    aesKey = (char*)malloc(AES_KEYLEN);
    aesIv = (char*)malloc(AES_KEYLEN);
    
    FILE *file = fopen("aeskey.txt", "r");
    char readbuf[AES_KEYLEN];
    for(int i = 0; fgets(readbuf, AES_KEYLEN, file); i++) {
        if (i==0) {
            //get rid of newline char
            readbuf[strlen(readbuf)-1] = '\0';
            strcpy(aesKey, readbuf);
        } else if (i==1){
            readbuf[strlen(readbuf)-1] = '\0';
            strcpy(aesIv, readbuf);
        } else {
            continue;
        }
    }
    
    unsigned char* enMsg = NULL;
    printf("msg size: %i\n", sizeof(msg));

    size_t enLen = aesEncrypt((unsigned char*)aesKey, (unsigned char*)aesIv, (unsigned char*)msg, &enMsg);
    sender.enLen = enLen;
    memcpy(sender.msg, enMsg, enLen);
    
    unsigned char* testbuf = NULL;
    int dRes = aesDecrypt((unsigned char*)aesKey, (unsigned char*)aesIv, sender.msg, &testbuf, sender.enLen);
    printf("Encrypted message: %s\n", sender.msg);
    printf("Decrypted message: %s\n", testbuf);
    
    


    //create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("Could not create socket.\n");
        return 1;
    }
    

    
    
    memset(&clientAddr, 0, len);
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_addr.s_addr = INADDR_ANY;
    clientAddr.sin_port = htons(0); //bind to any port
    
    memset(&serverAddr, 0, len);
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, serverName, &serverAddr.sin_addr);
    serverAddr.sin_port = htons(serverPort);

    printf("sending: %s\n", sender.msg);
    sendto(sockfd, &sender, sizeof(struct sendMsg), 0, (struct sockaddr *) &serverAddr, len);
    memset(&buf, 0, len);
    rec = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *) &serverAddr, &len);
    buf[rec] = '\0';
    printf("echo: %s\n", buf);
    return 0;
}
