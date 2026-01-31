#ifndef BMO17_H
#define BMO17_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include "rsa.h"

typedef struct {
    BIGNUM *ST0;     // état initial
    rsa_key *SK;   // clé privée RSA pour la permutation
} bmo17_master_key;

typedef struct {
    BIGNUM *e;   //clé publique RSA = e
    BIGNUM *STn;     // état après n inversions
    BIGNUM *N;  //modulo rsa
    unsigned int n;  // contrainte (nb permutation)
} bmo17_constrained_key;

/*
 * génère la clé maitresse de BMO17
*/
bmo17_master_key * bmo17_master_keygen();

/*
 * génère la clé contrainte de BMO17
*/
bmo17_constrained_key * bmo17_constrained_keygen(bmo17_master_key * mk, int n);

/*
 * génère un nombre aléatoire sécurisé
*/
BIGNUM *random_bn_from_urandom(int num_bytes);

/*
* Evaluation de la CPRF avec la clé maîtresse : 
* applique c fois l’inverse de la permutation à partir de l’état initial ST0
*/
void bmo17_eval_master_key(BIGNUM * out,bmo17_master_key * mk, int c);

/*
* Evaluation de la CPRF avec la clé contrainte : 
* applique c-n fois la permutation à partir de l’état STn
*/
void bmo17_eval_constrained_key(BIGNUM * out, BIGNUM *e,  BIGNUM *N, BIGNUM * STn,  unsigned int n, BIGNUM * c);

void bmo17_master_key_free(bmo17_master_key *mk);
void bmo17_constrained_key_free(bmo17_constrained_key *ck);


#endif