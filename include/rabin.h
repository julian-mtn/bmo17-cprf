#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>

typedef struct {
    BIGNUM *n;   // n = p*q (clé publique)
    BIGNUM *p;   // secret
    BIGNUM *q;   // secret
} rabin_key;

/*
 * Génère une clé Rabin de taille `bits` pour n
 * p et q ≡ 3 (mod 4)
 */
rabin_key *rabin_keygen(int bits);

/*
 * Libère la mémoire d'une clé Rabin
 */
void rabin_key_free(rabin_key *key);

/*
 * Évalue le cryptosystème de Rabin : y = x^2 mod n
 */
int rabin_eval(BIGNUM *y, const BIGNUM *x, const BIGNUM *n, BN_CTX *ctx);

/*
 * Calcule les 4 racines carrées de y modulo n avec la clé privée Rabin
 * Retourne 1 en cas de succès, 0 en cas d'erreur
 * 
 * Résoud : x^2 ≡ y (mod n)
 */
int rabin_solve(BIGNUM *X, const BIGNUM *y, const rabin_key *key, BN_CTX *ctx);
