// fweak.h
#ifndef FWEAK_H
#define FWEAK_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

/*
 * Clé maîtresse Fweak : matrice S (M x N) à coefficients dans Z/pZ
 */
typedef struct {
    BIGNUM ***S;     // matrice M x N (tableau de lignes)
    BIGNUM *p;       // modulo premier
    int M;           // dimension de sortie
    int N;           // dimension d'entrée
} fweak_master_key;

/*
 * Clé contrainte Fweak : matrice S_y = S + d·y^T
 */
typedef struct {
    BIGNUM ***S_y;   // matrice M x N
    BIGNUM *p;       // modulo premier
    BIGNUM **y;      // vecteur contrainte (taille N)
    int M;
    int N;
} fweak_constrained_key;

BIGNUM **fweak_random_vector(BIGNUM *p, int len);

BIGNUM **fweak_copy_vector(BIGNUM **src, int len);

/*///////////////////// key generation ////////////////////////*/

fweak_master_key *fweak_master_keygen(int M, int N);
fweak_constrained_key *fweak_constrained_keygen(fweak_master_key *mk, BIGNUM **y, int y_len);

/*///////////////////// CPRF evaluation: master key ////////////////////////*/

void fweak_eval_master_key(BIGNUM **out, fweak_master_key *mk, BIGNUM **x);

/*///////////////////// CPRF evaluation: constrained key ////////////////////////*/

void fweak_eval_constrained_key(BIGNUM **out, fweak_constrained_key *ck, BIGNUM **x);

/*///////////////////// memory ////////////////////////*/

void fweak_master_key_free(fweak_master_key *mk);
void fweak_constrained_key_free(fweak_constrained_key *ck);
void fweak_free_vector(BIGNUM **vec, int len);


#endif