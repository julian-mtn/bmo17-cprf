#include "../include/rabin.h"

/*
 * Génère une clé Rabin de taille `bits` pour n
 * p et q ≡ 3 (mod 4)
 */
rabin_key *rabin_keygen(int bits) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return NULL;

    rabin_key *key = malloc(sizeof(rabin_key));
    if (!key) {
        BN_CTX_free(ctx);
        return NULL;
    }

    key->p = BN_new();
    key->q = BN_new();
    key->n = BN_new();
    if (!key->p || !key->q || !key->n) {
        BN_free(key->p);
        BN_free(key->q);
        BN_free(key->n);
        free(key);
        BN_CTX_free(ctx);
        return NULL;
    }

    unsigned long r;

    // Génération de p ≡ 3 (mod 4)
    do {
        if (!BN_generate_prime_ex(key->p, bits / 2, 0, NULL, NULL, NULL)) {
            // erreur génération
            BN_free(key->p); BN_free(key->q); BN_free(key->n);
            free(key); BN_CTX_free(ctx);
            return NULL;
        }
        r = BN_mod_word(key->p, 4);
    } while (r != 3);

    // Génération de q ≡ 3 (mod 4)
    do {
        if (!BN_generate_prime_ex(key->q, bits / 2, 0, NULL, NULL, NULL)) {
            BN_free(key->p); BN_free(key->q); BN_free(key->n);
            free(key); BN_CTX_free(ctx);
            return NULL;
        }
        r = BN_mod_word(key->q, 4);
    } while (r != 3);

    // n = p * q
    if (!BN_mul(key->n, key->p, key->q, ctx)) {
        BN_free(key->p); BN_free(key->q); BN_free(key->n);
        free(key); BN_CTX_free(ctx);
        return NULL;
    }

    BN_CTX_free(ctx);
    return key;
}

/*
 * Libère la mémoire d'une clé Rabin
 */
void rabin_key_free(rabin_key *key) {
    if (!key) return;
    BN_free(key->p);
    BN_free(key->q);
    BN_free(key->n);
    free(key);
}

/*
 * Évalue le cryptosystème de Rabin : y = x^2 mod n
 */
int rabin_eval(BIGNUM *y, const BIGNUM *x, const BIGNUM *n, BN_CTX *ctx) {
    return BN_mod_mul(y, x, x, n, ctx);
}

/*
 * Calcule les 4 racines carrées de y modulo n avec la clé privée Rabin
 * Retourne 1 en cas de succès, 0 en cas d'erreur
 * 
 * Résoud : x^2 ≡ y (mod n)
 */
int rabin_solve(BIGNUM * X, const BIGNUM *y, const rabin_key *key, BN_CTX *ctx) {

    BN_CTX_start(ctx);

    BIGNUM *yp = BN_CTX_get(ctx);
    BIGNUM *yq = BN_CTX_get(ctx);
    BIGNUM *rp = BN_CTX_get(ctx);
    BIGNUM *rq = BN_CTX_get(ctx);
    
    BIGNUM *qinv = BN_CTX_get(ctx);
    BIGNUM *pinv = BN_CTX_get(ctx);
    BIGNUM *tmp1 = BN_CTX_get(ctx);
    BIGNUM *tmp2 = BN_CTX_get(ctx);

    if (!tmp2) return 0;

    // y mod p, y mod q
    BN_mod(yp, y, key->p, ctx);
    BN_mod(yq, y, key->q, ctx);

    // rp = y^((p+1)/4) mod p
    BN_copy(tmp1, key->p);
    BN_add_word(tmp1, 1);
    BN_rshift(tmp1, tmp1, 2);
    BN_mod_exp(rp, yp, tmp1, key->p, ctx);

    // rq = y^((q+1)/4) mod q
    BN_copy(tmp1, key->q);
    BN_add_word(tmp1, 1);
    BN_rshift(tmp1, tmp1, 2);
    BN_mod_exp(rq, yq, tmp1, key->q, ctx);

    // inverses CRT
    BN_mod_inverse(qinv, key->q, key->p, ctx);
    BN_mod_inverse(pinv, key->p, key->q, ctx);

    // Combinaison CRT pour obtenir les 4 racines
    // X[0] = (rp * q * qinv + rq * p * pinv) mod n
    BN_mul(tmp1, rp, key->q, ctx);
    BN_mul(tmp1, tmp1, qinv, ctx);
    BN_mul(tmp2, rq, key->p, ctx);
    BN_mul(tmp2, tmp2, pinv, ctx);
    BN_add(X, tmp1, tmp2);
    BN_mod(X, X, key->n, ctx);

    BN_CTX_end(ctx);
    return 1;
}

