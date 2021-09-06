#ifndef __SHARED_CONTEXT_H__

#define __SHARED_CONTEXT_H__

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "os.h"
#include "cx.h"

#define MAX_BIP32_PATH 10

#define MAX_TOKEN 2

#define WEI_TO_ETHER 18

#define SELECTOR_LENGTH 4

#define ADDRESS_LENGTH 20
#define INT256_LENGTH  32

typedef struct publicKeyContext_t {
    cx_ecfp_public_key_t publicKey;
    char address[41];
    uint8_t chainCode[INT256_LENGTH];
    bool getChaincode;
} publicKeyContext_t;
/*
typedef struct transactionContext_t {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint8_t hash[INT256_LENGTH];
    tokenDefinition_t tokens[MAX_TOKEN];
    uint8_t tokenSet[MAX_TOKEN];
    uint8_t currentTokenIndex;
} transactionContext_t;
*/
typedef struct messageSigningContext_t {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint8_t hash[INT256_LENGTH];
    uint32_t remainingLength;
} messageSigningContext_t;

typedef struct messageSigningContext712_t {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint8_t domainHash[32];
    uint8_t messageHash[32];
} messageSigningContext712_t;
/*
typedef union {
    publicKeyContext_t publicKeyContext;
    transactionContext_t transactionContext;
    messageSigningContext_t messageSigningContext;
    messageSigningContext712_t messageSigningContext712;
} tmpCtx_t;
*/
extern cx_sha3_t global_sha3;
//extern tmpCtx_t tmpCtx;

#endif