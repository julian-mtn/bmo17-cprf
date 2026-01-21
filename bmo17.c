
#include "bmo17.h"

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

    size_t r = fread(buf, 1, num_bytes, f);
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

    bmo17_master_key * mk =  malloc(sizeof(bmo17_master_key));

    mk->ST0 = random_bn_from_urandom(32);
    if(mk->ST0 == NULL){
        printf("Erreur génération ST0");
        exit(1);
    }

    mk->SK = rsa_keygen(2048);
    
    return mk;
}

/*
 * génère la clé contrainte de BMO17
*/
bmo17_constrained_key * bmo17_constrained_keygen(bmo17_master_key * mk, int n){


    bmo17_constrained_key * ck = malloc(sizeof(bmo17_constrained_key));
    if(!ck) return NULL;

    ck->e = mk->SK->e;
    ck->n = n;    
    bmo17_eval_master_key(ck->STn,mk,n);

    return ck;
    
}

/*
* Evaluation de la CPRF avec la clé maîtresse : 
* applique c fois l’inverse de la permutation à partir de l’état initial ST0
*/
void bmo17_eval_master_key(BIGNUM * out,bmo17_master_key * mk, int c){
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return NULL;

    out = mk->ST0;
    for(int i=0; i<=c;i++){
        rsa_eval_private(out,out,mk->SK,ctx);
    }

}

/*
* Evaluation de la CPRF avec la clé contrainte : 
* applique c-n fois la permutation à partir de l’état STn
*/
BIGNUM * bmo17_eval_constrained_key(BIGNUM *e, BIGNUM * STn, int n, int c){
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return NULL;

    if(c<0 || c>n){
        printf("erreur : c<0 ou c>n");
        exit(1);
    }

    BIGNUM * out = STn;
    int nb_permutation = n-c;
    for(int i=0; i<= nb_permutation; i++){
        rsa_eval_public(out,out,e,n,ctx);
    }

    return out;
}