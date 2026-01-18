#ifndef BMO17_H
#define BMO17_H

#include <stdint.h>
#include <stdlib.h>

// Taille des clés (256 bits)
#define KEY_SIZE 32

// Structure pour la clé maître GGM
typedef struct {
    uint8_t root_key[KEY_SIZE];  // Clé racine pour l'arbre GGM
} bmo17_master_key;

// Structure pour la clé contrainte (plage [0, n])
typedef struct {
    uint8_t** covering_nodes;    // Noeuds qui "couvrent" la plage
    int num_nodes;               // Nombre de noeuds donnés
    int n;                       // Limite supérieure 
} bmo17_constrained_key;

/*
 * Génère une clé maître aléatoire pour BMO17 CPRF (version GGM)
*/
bmo17_master_key* bmo17_keygen();

/*
 * Libère une clé maître
 */
void bmo17_free_master(bmo17_master_key* mk);



#endif