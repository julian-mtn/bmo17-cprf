#ifndef RSA_H
#define RSA_H

#include <openssl/bn.h>
#include <openssl/evp.h>


typedef struct {
    BIGNUM *n;   //modulo
    BIGNUM *e;   //clé public
    BIGNUM *d;   //clé privée
} rsa_key_t;

/*
 * génère une clé RSA sécurisée
*/
rsa_key_t *rsa_keygen();

/*
 * libère la mémoire d'une clé rsa
*/
void rsa_key_free(rsa_key_t *key);

/*
 *  Évalue la permutation RSA avec la clé public
*/
int rsa_eval_public(BIGNUM *out,const BIGNUM *in,const rsa_key_t *key,BN_CTX *ctx);

/*
*  Évalue la permutation RSA avec la clé privée
*/
int rsa_eval_private(BIGNUM *out,const BIGNUM *in,const rsa_key_t *key,BN_CTX *ctx);

/*
* hash une entrée avec SHA-256 pour pouvoir l'utiliser dans RSA (pour la permutation à trappe)
* applique aussi modulo n
*/
int rsa_hash_to_bn(BIGNUM *out,const unsigned char *msg,size_t msg_len,const rsa_key_t *key,BN_CTX *ctx);

#endif
