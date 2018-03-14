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
#include <openssl/ec.h>
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
int aesEncrypt(const unsigned char* aesKey, unsigned char* aesIV, unsigned char* msg, unsigned char** enMsg, int size ) {
    size_t blockLen  = 0;
    size_t encMsgLen = 0;

    aesEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
    if(aesEncryptCtx == NULL) {
        return -1;
    }
    //EVP_CIPHER_CTX_init(aesEncryptCtx);

    *enMsg = (unsigned char*)malloc((size/16+1)*16);
    printf("size: %i\n", (size/16+1)*16);
    if(enMsg == NULL){
        return -1;
    }
    if(!EVP_EncryptInit_ex(aesEncryptCtx, EVP_aes_128_gcm(), NULL, aesKey, NULL)) {
        return -1;
    }

    if(!EVP_EncryptUpdate(aesEncryptCtx, *enMsg, (int*)&blockLen, (unsigned char*)msg, size)) {
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
    
    if(!EVP_DecryptInit_ex(aesDecryptCtx, EVP_aes_256_gcm(), NULL, aesKey, NULL)) {
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
//EVP_PKEY_CTX *paramCtx;
//EVP_PKEY_CTX *keyCtx;
EVP_PKEY_CTX *sharedCtx = NULL;
//EVP_PKEY *params = NULL;
//EVP_PKEY *pkey = NULL;
int eccGenerateSecret(EVP_PKEY *myPriv, EVP_PKEY *myPub, EVP_PKEY *theirPub, unsigned char **secret) {
    size_t secretlen;
    //check otherPubKey for validity?
    printf("1\n");
    if(!(sharedCtx = EVP_PKEY_CTX_new(myPriv, NULL))) {
        printf("error in pkey ctx\n");
        return -1;
    }
    printf("2\n");

    if(EVP_PKEY_derive_init(sharedCtx) <= 0) {
        printf("error in pkey derive init\n");
        return -1;
    }
    printf("3\n");

    if(EVP_PKEY_derive_set_peer(sharedCtx, theirPub) <= 0) {
        printf("error in derive set peer\n");
        return -1;
    }
    printf("4\n");

    if(EVP_PKEY_derive(sharedCtx, NULL, &secretlen) <= 0) {
        printf("error in derive\n");
        return -1;
    }
    printf("5\n");
    
    *secret = (unsigned char*)OPENSSL_malloc(secretlen);
    if(!*secret) {
        printf("error in secret malloc\n");
        return -1;
    }
    printf("6\n");

    if((EVP_PKEY_derive(sharedCtx, *secret, &secretlen)) <= 0) {
        printf("error derive secret\n");
        return -1;
    }
    printf("secret len: %i\n", secretlen);
    printf("shared secret: %s\n", *secret);
    printf("7\n");

    EVP_PKEY_CTX_free(sharedCtx);
    //EVP_PKEY_free(peerkey);
    //EVP_PKEY_free(pkey);
    //EVP_PKEY_CTX_free(keyCtx);
    //EVP_PKEY_free(params);
    //EVP_PKEY_CTX_free(paramCtx);
    return secretlen;
    
}























