#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h> 
#include <math.h>

#include "../include/fweak.h"

#define MAX_TRIES 10 



/*
 * effectuer une attaque sur la cprf (avec y=(0,0,...,0,1))
*/
void attaque(fweak_constrained_key *ck) {
    int is_cprf;
    BIGNUM ***S;

    S = alloc_matrix(ck->M, ck->N);

    // calcule des N-1 premieres colonnes de S 
    for(int i = 0 ; i < ck->M ; i++){
        for(int j = 0 ; j < ck->N - 1 ; j++){
            S[i][j] = ck->S_y[i][j];
        }
        S[i][ck->N-1] = 0;
    }

    // init dictionnaire D

    // D = ...
    
    // Faire des tests sur MAX_TRIES vecteurs
    for (int i = 0 ; i < MAX_TRIES; i++) {

        BIGNUM **x = malloc(ck->N * sizeof(BIGNUM*));

        // Generer x aleatoire
        for (int j = 0; j < ck->N-1 ; j++) {
            x[j] = BN_new();
            random_mod(x[j], ck->p);
        }

        x[ck->N-1] = BN_new();
        random_mod(x[ck->N-1], ck->p);
        
        // Assurer que le dernier element de x est non nul pour assurer que x n'est pas orthogonal à y
        while(BN_is_zero(x[ck->N-1])){
            random_mod(x[ck->N-1], ck->p);
        }

        BIGNUM **y = malloc(ck->M * sizeof(BIGNUM*));

        // y = oracle(x) // Eval(x)

        // derniere colonne de S
        BIGNUM **Sn = malloc(ck->M * sizeof(BIGNUM*));

        for (int j = 0; j < ck->M ; j++) {
            Sn[j] = BN_new();
            // Sn[j] = ....
        }


        /*
        if (!vec_in_dict(D, Sn)){
            inserer_dict(D, Sn, 0);
        } else {
            inserer_dict(D, Sn, D(Sn) + 1); 
        }

        if(is_max_dict(D, Sn)){
            is_cprf = 1;
        } else {
            is_cprf = 0; 
        }

        send_oracle(is_cprf);

        receive_oracle(valid) ??
        */
    }
}