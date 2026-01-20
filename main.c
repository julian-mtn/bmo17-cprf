#include <stdio.h>
#include <stdlib.h>
#include "rsa.h"


void test_rsa(){
    
    BN_CTX *ctx = BN_CTX_new();

    rsa_key_t *key = rsa_keygen();
    if (!key) { 
        printf("Erreur génération clé\n"); 
        return;
    }

    //hash du message
    BIGNUM *x = BN_new();
    const unsigned char *msg = (unsigned char *)"Alice";
    rsa_hash_to_bn(x, msg, 5, key, ctx);

    //Évaluer la permutation publique
    BIGNUM *y_pub = BN_new();
    rsa_eval_public(y_pub, x, key, ctx);

    //Évaluer la permutation privée
    BIGNUM *y_priv = BN_new();
    rsa_eval_private(y_priv, y_pub, key, ctx);

    //Comparer x et y_priv
    if (BN_cmp(x, y_priv) == 0) {
        printf("Test OK\n");
    } else {
        printf("Test échoué : x != y_priv\n");
    }
    
    char *s = BN_bn2dec(y_pub);
    printf("x^e mod n = %s\n", s);
    OPENSSL_free(s);

    BN_free(x);
    BN_free(y_pub);
    BN_free(y_priv);
    rsa_key_free(key);
    BN_CTX_free(ctx);

}

int main() {

    test_rsa();

    return 0;
}
