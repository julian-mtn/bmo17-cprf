#ifndef BMO17_H
#define BMO17_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

#include "rsa.h"
#include "rabin.h"



/*
 * Mode de fonctionnement de l'oracle CPRF
 */
typedef enum {
    MODE_NORMAL,   // CPRF BMO17 standard
    MODE_HASHED,   // CPRF hashée (contre-mesure CJ25)
    MODE_LAZY      // Lazy sampling (extension / expérimental)
} oracle_mode;


/*///////////////////// key structures ////////////////////////*/

/*
 * Clé maîtresse BMO17 (permutation RSA)
 */
typedef struct {
    BIGNUM *ST0;     // état initial
    rsa_key *SK;     // clé privée RSA pour la permutation
} bmo17_master_key;

/*
 * Clé maîtresse BMO17 (permutation Rabin)
 */
typedef struct{
    BIGNUM *ST0;     // état initial
    rabin_key *SK;   // clé privée Rabin pour la permutation
} bmo17_master_key_rabin;

/*
 * Clé contrainte BMO17 (RSA)
 */
typedef struct {
    BIGNUM *e;           // clé publique RSA (exposant)
    BIGNUM *STn;         // état après n inversions
    BIGNUM *N;           // modulo RSA
    unsigned int n;      // contrainte (nombre d'inversions)
} bmo17_constrained_key;

/*
 * Clé contrainte BMO17 (Rabin)
 */
typedef struct {
    BIGNUM *STn;         // état après n applications Rabin
    BIGNUM *N;           // modulo Rabin
    unsigned int n;      // contrainte (nombre d'inversions)
} bmo17_constrained_key_rabin;


/*///////////////////// key generation ////////////////////////*/

/*
 * génère la clé maitresse de BMO17
 */
bmo17_master_key * bmo17_master_keygen();

/*
 * génère la clé maitresse de BM017 pour la permutation rabin
 */
bmo17_master_key_rabin * bmo17_master_keygen_rabin();

/*
 * génère la clé contrainte de BMO17
 */
bmo17_constrained_key * bmo17_constrained_keygen(bmo17_master_key * mk, int n);

/*
 * génère la clé contrainte de BMO17 pour la permutation rabin
 */
bmo17_constrained_key_rabin * bmo17_constrained_keygen_rabin(bmo17_master_key_rabin * mk, int n);



/*///////////////////// CPRF evaluation — master key ////////////////////////*/

/*
 * Evaluation de la CPRF avec la clé maîtresse :
 * applique c fois l’inverse de la permutation à partir de l’état initial ST0
 */
void bmo17_eval_master_key(BIGNUM * out, bmo17_master_key * mk, int c);

/*
 * Evaluation de la CPRF avec la clé maîtresse rabin :
 * applique c fois la permutation de rabin à partir de l’état initial ST0
 */
void bmo17_eval_master_key_rabin(BIGNUM * out, bmo17_master_key_rabin * mk, int c);

/*
 * Evaluation de la CPRF hashée avec la clé maîtresse :
 * variante sécurisée contre l’attaque CJ25
 */
void bmo17_eval_master_key_hash(BIGNUM * out, bmo17_master_key * mk, int c);



/*///////////////////// CPRF evaluation — constrained key ////////////////////////*/


/*
 * Evaluation de la CPRF avec la clé contrainte :
 * applique n-c fois la permutation à partir de l’état STn
 */
void bmo17_eval_constrained_key(BIGNUM * out,
                                BIGNUM * e,
                                BIGNUM * N,
                                BIGNUM * STn,
                                unsigned int n,
                                BIGNUM * c);

/*
 * Evaluation de la CPRF avec la clé contrainte de rabin :
 * applique n-c fois la permutation de rabin à partir de l’état STn
 */
void bmo17_eval_constrained_key_rabin(BIGNUM * out,
                                      BIGNUM * N,
                                      BIGNUM * STn,
                                      unsigned int n,
                                      BIGNUM * c);

/*
 * Evaluation de la CPRF hashée avec la clé contrainte :
 * correction BMO17 contre l’attaque CJ25
 */
void bmo17_eval_constrained_key_hash(BIGNUM * out,
                                     BIGNUM * e,
                                     BIGNUM * N,
                                     BIGNUM * STn,
                                     unsigned int n,
                                     BIGNUM * c);






/*
 * génère un nombre aléatoire sécurisé à partir de /dev/urandom
 */
BIGNUM *random_bn_from_urandom(int num_bytes);

void bmo17_master_key_free(bmo17_master_key * mk);
void bmo17_master_key_rabin_free(bmo17_master_key_rabin * mk);
void bmo17_constrained_key_free(bmo17_constrained_key * ck);
void bmo17_constrained_key_rabin_free(bmo17_constrained_key_rabin * ck);

#endif
