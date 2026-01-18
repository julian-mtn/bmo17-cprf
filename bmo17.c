// bmo17.c
#include "bmo17.h"
#include <openssl/sha.h> 
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>  

/*test commit*/



/*
 * Génère une clé maître aléatoire pour BMO17 CPRF (version GGM)
*/
bmo17_master_key* bmo17_keygen() {
    bmo17_master_key* mk = malloc(sizeof(bmo17_master_key));
    if (!mk) {
        fprintf(stderr, "Erreur d'allocation mémoire (Masterkey) \n");
        return NULL;
    }
    
    // Générateur aléatoire pour la clé maître
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        fprintf(stderr, "Impossible d'ouvrir /dev/urandom\n");
        free(mk);
        return NULL;
    }
    
    // Lire KEY_SIZE octets aléatoires
    size_t read_bytes = fread(mk->root_key, 1, KEY_SIZE, urandom);
    fclose(urandom);
    if (read_bytes != KEY_SIZE) {
        fprintf(stderr, "Échec de lecture aléatoire\n");
        free(mk);
        return NULL;
    }
    
    printf("[SUCCESS] bmo17_keygen completed\n");
    return mk;
}


/*
 * Libère une clé maître
*/
void bmo17_free_master(bmo17_master_key* mk) {
    if (mk) {
        memset(mk->root_key, 0, KEY_SIZE);
        free(mk);
    }
}