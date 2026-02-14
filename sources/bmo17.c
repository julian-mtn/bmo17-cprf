
#include "../include/bmo17.h"
#include <openssl/sha.h>

/*
 * génère un nombre aléatoire sécurisé
*/
BIGNUM *random_bn_from_urandom(int num_bytes) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        perror("fopen /dev/urandom");
        return NULL;
    }
    unsigned char *buf = malloc(num_bytes);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    int r = fread(buf, 1, num_bytes, f);
    fclose(f);

    if (r != num_bytes) {
        free(buf);
        return NULL;
    }

    BIGNUM *bn = BN_bin2bn(buf, num_bytes, NULL);
    free(buf);

    return bn;
}

/*
 * génère la clé maitresse de BMO17
*/
bmo17_master_key * bmo17_master_keygen(){

    bmo17_master_key * mk = malloc(sizeof(bmo17_master_key));
    if (!mk) return NULL;

    mk->SK = rsa_keygen(2048);
    if (!mk->SK) {
        printf("Erreur génération clé RSA\n");
        exit(1);
    }

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *g = BN_new();

    do {
        mk->ST0 = random_bn_from_urandom(256); // taille >= n
        BN_mod(mk->ST0, mk->ST0, mk->SK->n, ctx);
        BN_gcd(g, mk->ST0, mk->SK->n, ctx);
    } while (!BN_is_one(g));

    BN_free(g);
    BN_CTX_free(ctx);

    return mk;
}


/*
 * génère la clé maitresse de BM017 pour la permutation rabin
 */

bmo17_master_key_rabin * bmo17_master_keygen_rabin(){
    bmo17_master_key_rabin * mk = malloc(sizeof(bmo17_master_key_rabin));
    if (!mk) return NULL;

    mk->SK = rabin_keygen(2048);
    if (!mk->SK) {
        printf("Erreur génération clé Rabin\n");
        exit(1);
    }

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *g = BN_new();

    do {
        mk->ST0 = random_bn_from_urandom(256); // taille >= n
        BN_mod(mk->ST0, mk->ST0, mk->SK->n, ctx);
        BN_gcd(g, mk->ST0, mk->SK->n, ctx);
    } while (!BN_is_one(g));

    BN_free(g);
    BN_CTX_free(ctx);

    return mk;

}


/*
 * génère la clé contrainte de BMO17
*/
bmo17_constrained_key * bmo17_constrained_keygen(bmo17_master_key * mk, int n){

    bmo17_constrained_key * ck = malloc(sizeof(bmo17_constrained_key));
    if(!ck) return NULL;

    ck->STn = BN_new();
    if (!ck->STn) return NULL;

    ck->e = BN_dup(mk->SK->e);
    ck->N = BN_dup(mk->SK->n);  

    if (!ck->e || !ck->N) {
        printf("Erreur duplication clé publique RSA\n");
        exit(1);
    }

    ck->n = n;

    bmo17_eval_master_key(ck->STn, mk, n);

    return ck;
}

/*
* génère la clé contrainte de BMO17 pour la permutation rabin
*/
bmo17_constrained_key_rabin * bmo17_constrained_keygen_rabin(bmo17_master_key_rabin * mk, int n){
    
    bmo17_constrained_key_rabin * ck = malloc(sizeof(bmo17_constrained_key_rabin));
    if(!ck) return NULL;

    ck->STn = BN_new();
    if (!ck->STn) return NULL;

    ck->N = BN_dup(mk->SK->n);  

    if (!ck->N) {
        printf("Erreur duplication clé publique Rabin\n");
        exit(1);
    }

    ck->n = n;

    bmo17_eval_master_key_rabin(ck->STn, mk, n);

    return ck;
}


/*
* Evaluation de la CPRF avec la clé maîtresse : 
* applique c fois l’inverse de la permutation à partir de l’état initial ST0
*/
void bmo17_eval_master_key(BIGNUM * out, bmo17_master_key * mk, int c){

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx){
        printf("erreur bmo17_eval_master_key : ctx\n");
        exit(1);
    }

    BN_copy(out, mk->ST0);

    for(int i = 0; i < c; i++){
        if(rsa_eval_private(out, out, mk->SK, ctx)==0){
            printf("erreur rsa_eval_private\n");
            exit(1);
        }
    }

    BN_CTX_free(ctx);
}


/* Evaluation de la CPRF avec la clé maîtresse rabin : 
* applique c fois la résolution de rabin à partir de l’état initial ST0
*/
void bmo17_eval_master_key_rabin(BIGNUM * out, bmo17_master_key_rabin * mk, int c){
    
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx){
        printf("erreur bmo17_eval_master_key_rabin : ctx\n");
        exit(1);
    }

    BN_copy(out, mk->ST0);

    BIGNUM *X = BN_new();


    for(int i = 0; i < c; i++){
        // Résout out^2 ≡ y (mod n) et récupère les 4 racines
        if (!rabin_solve(X, out, mk->SK, ctx)){
            printf("erreur rabin_solve\n");
            exit(1);
        }
        
        // Choisit la plus petite racine de manière déterministe
        BN_copy(out, X);
    }

    BN_free(X);
    BN_CTX_free(ctx);
}

void bmo17_eval_master_key_hash(BIGNUM * out, bmo17_master_key * mk, int c){

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx){
        printf("erreur bmo17_eval_master_key : ctx\n");
        exit(1);
    }

    BN_copy(out, mk->ST0);

    for(int i = 0; i < c; i++){
        if(rsa_eval_private(out, out, mk->SK, ctx)==0){
            printf("erreur rsa_eval_private\n");
            exit(1);
        }
    }

    int len = BN_num_bytes(out);
    unsigned char *buf = malloc(len);
    if (!buf) {
        printf("erreur malloc\n");
        exit(1);
    }

    BN_bn2bin(out, buf); //convertir le résultat de la CPRF en bytes pour le hasher
    unsigned char hash[SHA256_DIGEST_LENGTH]; //
    SHA256(buf, len, hash); //hasher le résultat de la CPRF
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, out); //mettre le hash en bignum
        
    free(buf);
    BN_CTX_free(ctx);
}

/*
* Evaluation de la CPRF avec la clé contrainte : 
* applique c-n fois la permutation à partir de l’état STn
*/
void bmo17_eval_constrained_key(BIGNUM * out, BIGNUM *e, BIGNUM *N, BIGNUM * STn, unsigned int n, BIGNUM * c){

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx){
        printf("erreur bmo17_eval_constrained_key : ctx\n");
        exit(1);
    }

    BIGNUM *bn_n = BN_new();
    BN_set_word(bn_n, n);

    BIGNUM *zero = BN_new();
    BN_zero(zero);

    if(BN_cmp(c, zero) < 0 || BN_cmp(c, bn_n) > 0){
        printf("erreur : c < 0 ou c > n\n");
        exit(1);
    }

    BN_copy(out, STn);

    BIGNUM* nb_permutation = BN_new();
    BN_sub(nb_permutation, bn_n, c);

    BIGNUM* i = BN_new();
    BN_zero(i);
    while (BN_cmp(i, nb_permutation) < 0) {
        rsa_eval_public(out, out, e, N, ctx);
        BN_add_word(i, 1);
    }

    BN_free(zero);
    BN_free(nb_permutation);
    BN_free(i);
    BN_free(bn_n);
    BN_CTX_free(ctx);
}


/* Evaluation de la CPRF avec la clé contrainte de rabin : 
* applique c-n fois la permutation de rabin à partir de l’état STn
*/
void bmo17_eval_constrained_key_rabin(BIGNUM * out, BIGNUM *N, BIGNUM * STn, unsigned int n, BIGNUM * c){
    
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx){
        printf("erreur bmo17_eval_constrained_key_rabin : ctx\n");
        exit(1);
    }

    BIGNUM *bn_n = BN_new();
    BN_set_word(bn_n, n);

    BIGNUM *zero = BN_new();
    BN_zero(zero);

    if(BN_cmp(c, zero) < 0 || BN_cmp(c, bn_n) > 0){
        printf("erreur : c < 0 ou c > n\n");
        exit(1);
    }

    BN_copy(out, STn);

    BIGNUM* nb_permutation = BN_new();
    BN_sub(nb_permutation, bn_n, c);

    BIGNUM* i = BN_new();
    BN_zero(i);
    while (BN_cmp(i, nb_permutation) < 0) {
        rabin_eval(out, out, N, ctx);
        BN_add_word(i, 1);
    }

    BN_free(zero);
    BN_free(nb_permutation);
    BN_free(i);
    BN_free(bn_n);
    BN_CTX_free(ctx);
}

void bmo17_eval_constrained_key_hash(BIGNUM * out, BIGNUM *e, BIGNUM *N, BIGNUM * STn, unsigned int n, BIGNUM * c){

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx){
        printf("erreur bmo17_eval_constrained_key : ctx\n");
        exit(1);
    }

    BIGNUM *bn_n = BN_new();
    BN_set_word(bn_n, n);

    BIGNUM *zero = BN_new();
    BN_zero(zero);

    if(BN_cmp(c, zero) < 0 || BN_cmp(c, bn_n) > 0){
        printf("erreur : c < 0 ou c > n\n");
        exit(1);
    }

    BN_copy(out, STn);

    BIGNUM* nb_permutation = BN_new();
    BN_sub(nb_permutation, bn_n, c);

    BIGNUM* i = BN_new();
    BN_zero(i);
    while (BN_cmp(i, nb_permutation) < 0) {
        rsa_eval_public(out, out, e, N, ctx);
        BN_add_word(i, 1);
    }

    int len = BN_num_bytes(out);
    unsigned char *buf = malloc(len);
    if (!buf) {
        printf("erreur malloc\n");
        exit(1);
    }

    BN_bn2bin(out, buf); //convertir le résultat de la CPRF en bytes pour le hasher
    unsigned char hash[SHA256_DIGEST_LENGTH]; //
    SHA256(buf, len, hash); //hasher le résultat de la CPRF
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, out); //mettre le hash en bignum
        
    free(buf);
    BN_free(zero);
    BN_free(nb_permutation);
    BN_free(i);
    BN_free(bn_n);
    BN_CTX_free(ctx);
}


void bmo17_constrained_key_free(bmo17_constrained_key *ck) {
    if (!ck) return;

    BN_free(ck->e);
    BN_free(ck->N);
    BN_free(ck->STn);
    free(ck);
}


void bmo17_constrained_key_rabin_free(bmo17_constrained_key_rabin *ck) {
    if (!ck) return;

    BN_free(ck->N);
    BN_free(ck->STn);
    free(ck);
}

void bmo17_master_key_free(bmo17_master_key *mk) {
    if (!mk) return;

    BN_free(mk->ST0);
    rsa_key_free(mk->SK);
    free(mk);
}

void bmo17_master_key_rabin_free(bmo17_master_key_rabin *mk) {
    if (!mk) return;

    BN_free(mk->ST0);
    rabin_key_free(mk->SK);
    free(mk);
}
