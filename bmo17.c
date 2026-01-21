
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