
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
    if (!ctx){
        printf("erreur bmo17_eval_master_key : ctx ");
        exit(1);
    }

    out = mk->ST0;
    for(int i=0; i<=c;i++){
        rsa_eval_private(out,out,mk->SK,ctx);
    }

}

/*
* Evaluation de la CPRF avec la clé contrainte : 
* applique c-n fois la permutation à partir de l’état STn
*/
BIGNUM * bmo17_eval_constrained_key(BIGNUM *e, BIGNUM * STn, BIGNUM * n, BIGNUM * c){
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx){
        printf("erreur bmo17_eval_constrained_key : ctx ");
        exit(1);
    }

    BIGNUM *zero = BN_new();
    BN_zero(zero) ;

    if(BN_cmp(c,zero) <0 || BN_cmp(c,n) > 0){
        printf("erreur : c<0 ou c>n");
        exit(1);
    }

    BIGNUM * out = STn;
    BIGNUM* nb_permutation = BN_new();
    BN_sub(nb_permutation,n,c);

    BIGNUM* i = BN_new();
    
    for(BN_zero(i); BN_cmp(i,nb_permutation) <= 0; BN_add_word(i,1)){
        rsa_eval_public(out,out,e,n,ctx);
    }

    return out;
}