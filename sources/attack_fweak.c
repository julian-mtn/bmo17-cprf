#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h> 
#include <math.h>

#include "../include/fweak.h"

#define PORT 4242
#define BUF_SIZE 4096
#define MAX_TRIES 10 


// A revoir
#define M_SIZE 10
#define N_SIZE 100


/*
 * lire ligne sur la connexion, reçevoir message du serveur
*/
void recv_line(int sock, char *buf, size_t size) {
    memset(buf, 0, size);
    size_t i = 0;
    while (i < size - 1) {
        if (read(sock, &buf[i], 1) <= 0) break;
        if (buf[i] == '\n') break;
        i++;
    }
}



// Faire un code sur init_dict, is_max_dict, inserer_dict, vec_in_dict

/*
 * effectuer une attaque sur la cprf (avec y=(0,0,...,0,1))
*/
int attaque(fweak_constrained_key *ck) {
    FILE *log = fopen("attack_fweak_results.txt", "w"); // écriture dans un fichier if (!log) { perror("fopen"); exit(1); }
    int guess = 0;
    int next_progress = 10;
    int is_cprf;
    int valid;
    BIGNUM ***S;
    
    BIGNUM **x = malloc(ck->N * sizeof(BIGNUM*));
    BIGNUM **y = malloc(ck->M * sizeof(BIGNUM*));
    BIGNUM **Sn = malloc(ck->M * sizeof(BIGNUM*));

    BIGNUM *x_1 = BN_new();
    BIGNUM *tmp = BN_new();

    BN_CTX *ctx = BN_CTX_new();

    S = alloc_matrix(ck->M, ck->N);

    // calcule des N-1 premieres colonnes de S 
    for(int i = 0 ; i < ck->M ; i++){
        for(int j = 0 ; j < ck->N - 1 ; j++){
            S[i][j] = ck->S_y[i][j];
        }
        S[i][ck->N-1] = 0;
    }

    for (int j = 0; j < ck->N ; j++) {
        x[j] = BN_new();
    }

    for (int j = 0; j < ck->M ; j++) {
        y[j] = BN_new();
    }

    for (int j = 0; j < ck->M ; j++) {
        Sn[j] = BN_new();
    }

    // init dictionnaire D

    // D = ...
    
    // Faire des tests sur MAX_TRIES vecteurs
    for (int i = 0 ; i < MAX_TRIES; i++) {


        // Generer x aleatoire
        for (int j = 0; j < ck->N-1 ; j++) {
            random_mod(x[j], ck->p);
        }

        random_mod(x[ck->N-1], ck->p);
        
        // Assurer que le dernier element de x est non nul pour assurer que x n'est pas orthogonal à y
        while(BN_is_zero(x[ck->N-1])){
            random_mod(x[ck->N-1], ck->p);
        }

        BN_mod_inverse(x_1, x[ck->N-1], ck->p, ctx);

        // y = oracle(x) // Eval(x)

        // derniere colonne de S
        for (int j = 0; j < ck->M ; j++) {
            BN_zero(Sn[j]);

            for(int k = 0 ; k < ck->N-1 ; ck++){
                BN_mod_mul(tmp, S[j][k], x[k], ck->p, ctx);
                BN_mod_sub(Sn[j], Sn[j], tmp, ck->p, ctx);
            }

            BN_mod_add(Sn[j], Sn[j], y[j], ck->p, ctx);
            BN_mod_mul(Sn[j], Sn[j], x_1, ck->p, ctx);
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

        if(valid){
            guess = guess + 1
        }
        */

        fprintf(log, "%d %d %d\n", i, is_cprf, valid);  //écriture dans fichier

        int progress = (int) floor((double)(i-1) / MAX_TRIES * 100); // % accompli
        if(progress >= next_progress) {
            printf("[*] Progression : %3d%%\n", next_progress);
            fflush(stdout);
            next_progress += 10;
        }

        
    }
    printf("[*] Attaque terminée\n");
    if(guess)
        printf("[!!!] PRF détectée pour %d/%d tests\n", guess, MAX_TRIES);
    else
        printf("Aucune PRF détectée pour les %d testés\n", MAX_TRIES);

    fprintf(log, "# Total detected: %d/%d\n", guess, MAX_TRIES);
    fclose(log);

    BN_free(tmp);
    BN_free(x_1);

    fweak_free_vector(x, ck->N);
    fweak_free_vector(y, ck->M);
    fweak_free_vector(Sn, ck->M);

    free_matrix(S ,ck->M ,ck->N);

    BN_CTX_free(ctx);

    return guess;
}













int main(int argc, char *argv[]) {

    /*
    if (argc != 3) {
        fprintf(stderr, "Usage: %s -n|-h|-l <taille>\n", argv[0]);
        exit(1);
    }
    

    oracle_mode mode;
    int MAX_N = atoi(argv[2]);

    if (MAX_N <= 0) {
        fprintf(stderr, "Erreur: taille invalide\n");
        exit(1);
    }

    if (strcmp(argv[1], "-n") == 0) {
        mode = MODE_NORMAL;
    } else if (strcmp(argv[1], "-h") == 0) {
        mode = MODE_HASHED;
    } else if (strcmp(argv[1], "-l") == 0) {
        mode = MODE_LAZY;
    } else {
        fprintf(stderr, "Mode invalide: %s\n", argv[1]);
        exit(1);
    }
    */

    printf("[*] Connecté au serveur PORT %d\n", PORT);
    printf("[*] Attaque en cours ...\n");
    int found = 0;
    int next_progress = 10;
    

    int sock;
    int guess;
    struct sockaddr_in addr;
    char buffer[BUF_SIZE];

    /* --- connexion --- */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(1);
    }

    BIGNUM **y = malloc(M_SIZE * sizeof(BIGNUM*));
    BIGNUM ***Sy;
    BIGNUM *p = BN_new();

    Sy = alloc_matrix(M_SIZE, N_SIZE);

    for (int j = 0; j < M_SIZE - 1 ; j++) {
        y[j] = BN_new();
        BN_zero(y[j]);
    }
    y[M_SIZE - 1] = BN_new();
    BN_one(y[M_SIZE - 1]);

    /* ---- CONSTRAIN ---- */
    /*
    Envoyer y puis recevoir Sy et p
    */

    fweak_constrained_key *ck;

    ck->M = M_SIZE;
    ck->N = N_SIZE;
    ck->p = p;
    ck->S_y = Sy;
    ck->y = y;

    /* ---- attaque ---- */
    clock_t start = clock(); 
    guess = attaque(ck);
    clock_t end = clock();

    double elapsed_ms = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;

    BN_free(p);
    fweak_free_vector(y, M_SIZE);
    free_matrix(Sy ,M_SIZE ,N_SIZE);

    return 0;
}