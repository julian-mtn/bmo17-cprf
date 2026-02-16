#ifndef LAZY_SAMPLING_H
#define LAZY_SAMPLING_H

#include <openssl/bn.h>

/*
 * Lazy Sampling pour CPRF
 *
 * Hashmap pour mémoriser
 * les paires (x -> y) déjà générées. 
 * Si une entrée x a déjà été évaluée, on renvoie y associé,
 * sinon on génère un nouveau y aléatoire et on l'ajoute à la table.
 */

/**
 * Applique le lazy sampling sur une sortie CPRF.
 */
void lazy_sampling_hash(BIGNUM *out, BIGNUM *in);


void lazy_sampling_free(void);

#endif 
