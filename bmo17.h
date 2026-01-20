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



#endif