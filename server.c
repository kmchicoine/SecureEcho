//
//  main.c
//  EchoCS
//
//  Created by Kaley Chicoine on 1/19/18.
//  Copyright © 2018 Kaley Chicoine. All rights reserved.
//

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "encryption.h"
#define BUFSIZE 1024 + 30
#define AES_KEYLEN 256

char *aesKey;
char *aesIv;

int main(int argc, const char * argv[]) {
    int sockfd;
    unsigned short serverPort = 1234;
    struct sockaddr_in serverAddr;
    struct sockaddr_in clientAddr;
    socklen_t len = sizeof(struct sockaddr_in);
    unsigned char buf[BUFSIZE+1];
    int rec;
    struct sendMsg recMsg;
    
    //TODO: read in command line args
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
        
    //create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("Could not create socket.\n");
        return 1;
    }
    memset(&serverAddr, 0, len);
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(serverPort);
    
    //bind to port
    if ((bind(sockfd,(struct sockaddr*) &serverAddr, sizeof(serverAddr))) < 0) {
        perror("Could not bind to port\n");
        return 1;
    }
    
    
    while(1) { //main loop
        memset(&buf, 0, len);
        memset(&recMsg, 0, sizeof(struct sendMsg));
        rec = recvfrom(sockfd, &recMsg, sizeof(struct sendMsg), 0, (struct sockaddr *) &clientAddr, &len);
        
        unsigned char* deMsg;
        printf("size: %i, received: %s\n", recMsg.enLen, recMsg.msg);

        int res = aesDecrypt((unsigned char*)aesKey, (unsigned char*)aesIv, recMsg.msg, &deMsg, recMsg.enLen);

        printf("echoing: %s\n", deMsg);
        sendto(sockfd, deMsg, BUFSIZE, 0, (struct sockaddr *) &clientAddr, len);
    }

    
    return 0;
}


