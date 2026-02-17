#include <openssl/bn.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define LAZY_HASHMAP_SIZE 1024

/*
Structure de la hashmap (liste de couples (x->y), chaîné si plusieurs entrées ont la même valeur de hash)
*/
typedef struct lazy_entry {
    BIGNUM *x;
    BIGNUM *y;
    struct lazy_entry *next;
} lazy_entry;

static lazy_entry *lazy_table[LAZY_HASHMAP_SIZE] = {0};

/*
Retourne le h associé à l'entrée
*/
static unsigned int bn_hash(BIGNUM *bn) {
    // somme des bytes modulo taille table
    int num_bytes = BN_num_bytes(bn);
    unsigned char buf[num_bytes];
    BN_bn2bin(bn, buf);
    unsigned int h = 0;
    for (int i = 0; i < num_bytes; i++) {
        h = (h * 31 + buf[i]) % LAZY_HASHMAP_SIZE;
    }
    return h;
}

void lazy_sampling_hash(BIGNUM *out, BIGNUM *in) {
    unsigned int h = bn_hash(in);
    lazy_entry *cur = lazy_table[h];

    while (cur) { //on parcours hash de l'entrée
        if (BN_cmp(cur->x, in) == 0) {
            BN_copy(out, cur->y);  // trouvé
            return;
        }
        cur = cur->next;
    }

    //si pas dans le hashmap, on renvoit un élément aléatoire de 256 bits
    BN_rand(out, 256, -1, 0); 

    // insertion dans la hashmap
    lazy_entry *entry = malloc(sizeof(lazy_entry));
    entry->x = BN_dup(in);
    entry->y = BN_dup(out);
    entry->next = lazy_table[h];
    lazy_table[h] = entry;
}

void lazy_sampling_free() {
    for (int i = 0; i < LAZY_HASHMAP_SIZE; i++) {
        lazy_entry *cur = lazy_table[i];
        while (cur) {
            lazy_entry *next = cur->next;
            BN_free(cur->x);
            BN_free(cur->y);
            free(cur);
            cur = next;
        }
        lazy_table[i] = NULL;
    }
}
