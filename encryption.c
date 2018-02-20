//
//  encryption.c
//  EchoCS
//
//  Created by Kaley Chicoine on 1/26/18.
//  Copyright © 2018 Kaley Chicoine. All rights reserved.
//

#include "encryption.h"
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
#include <errno.h>


char* err;
EVP_CIPHER_CTX *rsaEncryptCtx;
EVP_CIPHER_CTX *aesEncryptCtx;

EVP_CIPHER_CTX *rsaDecryptCtx;
EVP_CIPHER_CTX *aesDecryptCtx;

/*NON EVP FUNCTIONS*/
int encryptMsg(char* ptMsg, char* ctMsg, RSA* keypair) {
    //keypair = RSA_new();
    
    //void *encrypt = malloc(RSA_size(keypair));
    int encrypt_len;
    err = (char*)malloc(130);
    if((encrypt_len = RSA_public_encrypt(strlen(ptMsg)+1, (unsigned char*)ptMsg,
                                         (unsigned char*)ctMsg, keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
        return -1;
    } else {
        return encrypt_len;
    }
}

void decryptMsg(char* ctMsg, char* ptMsg, RSA* keypair, int encrypt_len) {
    //char *decrypt = (char*)malloc(RSA_size(keypair));
    if(RSA_private_decrypt(encrypt_len, (unsigned char*)ctMsg, (unsigned char*)ptMsg,
                           keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
    }
}

/*EVP FUNCTIONS*/
int aesEncrypt(const unsigned char* aesKey, unsigned char* aesIV, unsigned char* msg, unsigned char** enMsg ) {
    size_t blockLen  = 0;
    size_t encMsgLen = 0;

    aesEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
    if(aesEncryptCtx == NULL) {
        return -1;
    }
    EVP_CIPHER_CTX_init(aesEncryptCtx);
    
    size_t msgLen = BUFSIZE;
    *enMsg = (unsigned char*)malloc(msgLen + AES_BLOCK_SIZE);
    if(enMsg == NULL){
        return -1;
    }
    if(!EVP_EncryptInit_ex(aesEncryptCtx, EVP_aes_256_cbc(), NULL, aesKey, aesIV)) {
        return -1;
    }
    if(!EVP_EncryptUpdate(aesEncryptCtx, *enMsg, (int*)&blockLen, (unsigned char*)msg, msgLen)) {
        return -1;
    }
    encMsgLen += blockLen;
    
    if(!EVP_EncryptFinal_ex(aesEncryptCtx, *enMsg + encMsgLen, (int*)&blockLen)) {
        return -1;
    }
    
    EVP_CIPHER_CTX_cleanup(aesEncryptCtx);
    return encMsgLen + blockLen;
}

int aesDecrypt(const unsigned char* aesKey, unsigned char* aesIV, unsigned char* enMsg, unsigned char** deMsg, size_t enMsgLen) {
    ERR_load_crypto_strings();
    size_t deLen = 0;
    size_t blockLen = 0;

    aesDecryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
    if(aesDecryptCtx == NULL) {
        return -1;
    }
    EVP_CIPHER_CTX_init(aesDecryptCtx);
    
    *deMsg = (unsigned char*)malloc(enMsgLen);
    if(*deMsg == NULL) return -1;
    
    if(!EVP_DecryptInit_ex(aesDecryptCtx, EVP_aes_256_cbc(), NULL, aesKey, aesIV)) {
        printf("error_in_decrypt_init\n");
        
        ERR_print_errors_fp(stderr);
        return -2;
    }
    
    if(!EVP_DecryptUpdate(aesDecryptCtx, (unsigned char*)*deMsg + deLen, (int*)&blockLen, enMsg, (int)enMsgLen)) {
        printf("error_in_decrypt_update\n");
        
        ERR_print_errors_fp(stderr);
        return -3;
    }
    deLen += blockLen;
    
    if(!EVP_DecryptFinal_ex(aesDecryptCtx, (unsigned char*)*deMsg + deLen, (int*)&blockLen)) {
        printf("error_in_decrypt_final\n");

        ERR_print_errors_fp(stderr);
        return -4;

    }
    
    EVP_CIPHER_CTX_cleanup(aesDecryptCtx);
    return deLen + blockLen;
}

int rsaEncrypt(EVP_PKEY *localKeypair, EVP_PKEY *remoteKeypair) {
    rsaEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(rsaEncryptCtx);


    return 0;
}
int rsaDecrypt(EVP_PKEY *localKeypair, EVP_PKEY *remoteKeypair) {
    rsaDecryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(rsaDecryptCtx);


    return 0;
}
/*int main() {
    #define AES_KEYLEN 256
    unsigned char *aesKey;
    unsigned char *aesIv;
    char msg[2048/8];
    
    printf("Message to encrypt: ");
    fgets(msg, 2048/8, stdin);
    msg[strlen(msg)-1] = '\0';
    
    //init AES
    aesKey = (unsigned char*)malloc(AES_KEYLEN/8);
    aesIv = (unsigned char*)malloc(AES_KEYLEN/8);
    
    unsigned char *aesPass = (unsigned char*)malloc(AES_KEYLEN/8);
    unsigned char *aesSalt = (unsigned char*)malloc(8);
    
    FILE *file = fopen("aeskey.txt", "r");
    char buf[AES_KEYLEN];
    for(int i = 0; fgets(buf, AES_KEYLEN, file); i++) {
        if (i==0) {
            strcpy((char*)aesKey, buf);
        } else {
            strcpy((char*)aesIv, buf);
        }
    }
    printf("key: %s, iv: %s\n", aesKey, aesIv);
    
    unsigned char* enMsg = NULL;
    aesEncrypt(aesKey, aesIv, msg, enMsg);
    return 0;
}*/
