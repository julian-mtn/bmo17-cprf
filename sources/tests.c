#include <stdio.h>
#include <stdlib.h>
#include "../include/rsa.h"
#include "../include/bmo17.h"

void test_rsa(char * msg){
    printf("=== Test RSA ===\n");

    BN_CTX *ctx = BN_CTX_new();

    rsa_key *key = rsa_keygen();
    if (!key) { 
        printf("Erreur génération clé\n"); 
        return;
    }

    //hash du message
    BIGNUM *x = BN_new();
    rsa_hash_to_bn(x, (const unsigned char *)msg, 5, key, ctx);

    //Évaluer la permutation publique
    BIGNUM *y_pub = BN_new();
    rsa_eval_public(y_pub, x, key->e,key->n, ctx);

    //Évaluer la permutation privée
    BIGNUM *y_priv = BN_new();
    rsa_eval_private(y_priv, y_pub, key, ctx);

    //Comparer x et y_priv
    if (BN_cmp(x, y_priv) == 0) {
        printf("[Test OK]\n");
    } else {
        printf("[Test échoué] : x != y_priv\n");
    }

    BN_free(x);
    BN_free(y_pub);
    BN_free(y_priv);
    rsa_key_free(key);
    BN_CTX_free(ctx);

}

void test_bmo17() {
    printf("=== Test BMO17 ===\n");

    //Génération de la clé maîtresse
    bmo17_master_key *mk = bmo17_master_keygen();
    if (!mk) {
        printf("Erreur génération clé maîtresse\n");
        return;
    }

    //choix de n
    int n = 10;

    //Génération de la clé contrainte
    bmo17_constrained_key *ck = bmo17_constrained_keygen(mk, n);
    if (!ck) {
        printf("Erreur génération clé contrainte\n");
        return;
    }

    //Choix d'un c tel que 0 <= c <= n
    int c_val = 4;

    BIGNUM *c = BN_new();
    BN_set_word(c, c_val);

    //Évaluation avec la clé maîtresse
    BIGNUM *y_master = BN_new();
    bmo17_eval_master_key(y_master, mk, c_val);

    BIGNUM *y_constrained = BN_new();
    //Évaluation avec la clé contrainte
    bmo17_eval_constrained_key(
        y_constrained,  
        ck->e,          
        ck->N,          
        ck->STn,        
        ck->n,          
        c               
    );

    if (BN_cmp(y_master, y_constrained) == 0) {
        printf("[Test OK]\n");
    } else {
        printf("[Test échoué]\n");
    }


    BN_free(c);
    BN_free(y_master);
    BN_free(y_constrained);
}


int main() {

    test_rsa("coucou ceci est un test");
    test_bmo17();
    return 0;
}
