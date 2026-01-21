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
    rsa_key *PK;   // clé publique RSA
    BIGNUM *STn;     // état après n inversions
    unsigned int n;  // contrainte
} bmo17_constrained_key;

/*
 * génère la clé maitresse de BMO17
*/
bmo17_master_key * bmo17_master_keygen();


/*
 * génère un nombre aléatoire sécurisé
*/
BIGNUM *random_bn_from_urandom(int num_bytes);

#endif