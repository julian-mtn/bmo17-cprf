#include "../include/rsa.h"


/*
 * génère une clé RSA sécurisée
*/
rsa_key *rsa_keygen() {

    int bits = 4096; //TODO : changer à 4096

    //mémoire temporaire pour BIGNUM
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return NULL;

    rsa_key *key = malloc(sizeof(rsa_key));
    if (!key) {
        BN_CTX_free(ctx);
        return NULL;
    }

    //initialisation de la mémoire des variables
    key->n = BN_new();
    key->e = BN_new();
    key->d = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *p1 = BN_new();
    BIGNUM *q1 = BN_new();

    //////////////////RSA//////////////////

    //générer p et q premiers
    BN_generate_prime_ex(p,bits/2,0,NULL,NULL,NULL);
    BN_generate_prime_ex(q,bits/2,0,NULL,NULL,NULL);

    //n = p*q
    BN_mul(key->n,p,q,ctx);

    //phi = (p-1)(q-1)
    BN_copy(p1,p);
    BN_copy(q1,q);
    BN_sub_word(p1,1);
    BN_sub_word(q1,1);
    BN_mul(phi,p1,q1,ctx);

    //e = 65537
    BN_set_word(key->e,65537);

    //d = e^-1 mod phi
    BN_mod_inverse(key->d,key->e,phi,ctx);

    BN_free(p); BN_free(q); BN_free(phi); BN_free(p1); BN_free(q1); BN_CTX_free(ctx);

    return key;
}

/*
 * libère la mémoire d'une clé rsa
*/
void rsa_key_free(rsa_key *key) {
    if (!key) return;
    BN_free(key->e);
    BN_free(key->d);
    BN_free(key->n);
    free(key);
}

/*
 *  Évalue la permutation RSA avec la clé public
*/
int rsa_eval_public(BIGNUM *out,const BIGNUM *in,BIGNUM * e, BIGNUM * n,BN_CTX *ctx) 
{
    if (!out || !in || !e || !n || !ctx) return 0;

    //Vérifier que 0 <= in < n 
    if (BN_is_negative(in) || BN_cmp(in,n) >= 0) return 0;

    //vérifie la clé publique
    if (!BN_mod_exp(out, in, e, n, ctx)) return 0;

    return 1;
}

/*
*  Évalue la permutation RSA avec la clé privée
*/
int rsa_eval_private(BIGNUM *out,const BIGNUM *in,const rsa_key *key,BN_CTX *ctx) 
{
    if (!out || !in || !key || !ctx) return 0;
    if (BN_is_negative(in) || BN_cmp(in, key->n) >= 0) return 0;

    //vérifie la clé privée de manière protégée (avec consttime)
    if (!BN_mod_exp_mont_consttime(out, in, key->d, key->n, ctx,NULL))return 0;

    return 1;
}

/*
* hash une entrée avec SHA-256 pour pouvoir l'utiliser dans RSA (pour la permutation à trappe)
* applique aussi modulo n
*/
int rsa_hash_to_bn(BIGNUM *out,const unsigned char *msg,size_t msg_len,const rsa_key *key,BN_CTX *ctx)
 {
    if (!out || !msg || !key || !ctx) return 0;

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    //hash SHA-256 du message 
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return 0;

    //init,ajoute et termine le hash
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) goto err;
    if (EVP_DigestUpdate(mdctx, msg, msg_len) != 1) goto err;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) goto err;
    EVP_MD_CTX_free(mdctx);

    //convertir le hash en bignum
    if (!BN_bin2bn(hash, hash_len, out)) return 0;

    //modulo n
    if (!BN_mod(out, out, key->n, ctx)) return 0;

    return 1;

    err:
    EVP_MD_CTX_free(mdctx);
    return 0;

}
