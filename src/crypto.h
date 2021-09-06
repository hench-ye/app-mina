#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "os.h"
#include "cx.h"

#ifdef LEDGER_BUILD
    #include <os.h>
#endif

#define BIP32_PATH_LEN 5
#define BIP32_HARDENED_OFFSET 0x80000000

#define FIELD_BYTES    32
#define SCALAR_BYTES   32
#define SCALAR_BITS    256
#define SCALAR_OFFSET  2     // Scalars only use 254 bits

#define SIGNATURE_LEN    129 // as strings,
#define MINA_ADDRESS_LEN 47  // includes null-bytes

#define COIN 1000000000ULL

#define TESTNET_ID 0x00
#define MAINNET_ID 0x01

typedef uint8_t Field[FIELD_BYTES];
typedef uint8_t Scalar[SCALAR_BYTES];

typedef struct group_t {
    Field X;
    Field Y;
    Field Z;
} Group;

typedef struct affine_t {
    Field x;
    Field y;
} Affine;

typedef struct compressed_t {
    Field x;
    bool is_odd;
} Compressed;

typedef struct signature_t {
    Field rx;
    Scalar s;
} Signature;

typedef struct keypair_t {
    Affine pub;
    Scalar priv;
} Keypair;

typedef struct roinput_t ROInput; // Forward declaration

void field_copy(Field b, const Field a);
void field_add(Field c, const Field a, const Field b);
void field_mul(Field c, const Field a, const Field b);
void field_sq(Field b, const Field a);
void field_pow(Field c, const Field a, const Field e);

void scalar_copy(Scalar b, const Scalar a);
bool scalar_eq(const Scalar a, const Scalar b);
void scalar_add(Scalar c, const Scalar a, const Scalar b);
void scalar_mul(Scalar c, const Scalar a, const Scalar b);
void scalar_negate(Field b, const Field a);

void affine_add(Affine *r, const Affine *p, const Affine *q);
void affine_scalar_mul(Affine *q, const Scalar k, const Affine *p);
void affine_negate(Affine *q, const Affine *p);
bool affine_eq(const Affine *p, const Affine *q);
bool affine_is_on_curve(const Affine *p);

void generate_keypair(Keypair *keypair, uint32_t account);
void generate_pubkey(Affine *pub_key, const Scalar priv_key);
bool generate_address(char *address, const size_t len, const Affine *pub_key);
bool validate_address(const char *address);

bool sign(Signature *sig, const Keypair *kp, const ROInput *input, const uint8_t network_id);
void getEthAddressFromKey(cx_ecfp_public_key_t *publicKey, uint8_t *out, cx_sha3_t *sha3Context);