#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#include <openssl/bn.h>

#include "../include/fweak.h"

#define PORT 4242 //TODO à modifier

/* //////////////socket////////////// */


void send_bn(int sock, BIGNUM *bn){
    int len = BN_num_bytes(bn);
    write(sock, &len, sizeof(int));

    unsigned char *buf = malloc(len);
    BN_bn2bin(bn, buf);

    write(sock, buf, len);
    free(buf);
}

void recv_bn(int sock, BIGNUM *bn){
    int len;
    read(sock, &len, sizeof(int));

    unsigned char *buf = malloc(len);
    read(sock, buf, len);

    BN_bin2bn(buf, len, bn);
    free(buf);
}

/* ////////////// ORACLE ////////////// */


int main(int argc, char * argv[]) {

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <taille_N> <taille_M>\n", argv[0]);
    }

    int N_SIZE = atoi(argv[1]);
    int M_SIZE = atoi(argv[2]);
    
    if (N_SIZE <= 0 || M_SIZE <=0) {
        fprintf(stderr, "Erreur: taille invalide\n");
        exit(1);
    }

    srand(time(NULL));

    int server_fd, client_fd;
    struct sockaddr_in addr;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 1);

    printf("[*] Oracle en attente sur port %d...\n", PORT);

    client_fd = accept(server_fd, NULL, NULL);
    printf("[*] Client connecté\n");


    /* ====== SETUP FWEAK ======== */

    //générer clé maitresse S
    fweak_master_key *mk = fweak_master_keygen(M_SIZE, N_SIZE);

    
    /*reçevoir y*/

    BIGNUM **y = malloc(N_SIZE * sizeof(BIGNUM*));

    for(int i = 0; i < N_SIZE; i++){
        y[i] = BN_new();
        recv_bn(client_fd, y[i]);
    }

    /* générer clé contrainte S_y = S + d*y^T */

    fweak_constrained_key *ck = fweak_constrained_keygen(mk, y, N_SIZE);

    /* envoyer p et S_y */

    send_bn(client_fd, ck->p);

    for(int i = 0; i < ck->M; i++){
        for(int j = 0; j < ck->N; j++){
            send_bn(client_fd, ck->S_y[i][j]);
        }
    }

    /*  ORACLE LOOP  */

    
    while(1){

        BIGNUM **x = malloc(N_SIZE * sizeof(BIGNUM*));
        for(int i = 0; i < N_SIZE; i++){
            x[i] = BN_new();
            recv_bn(client_fd, x[i]);
        }

        BIGNUM **out = malloc(M_SIZE * sizeof(BIGNUM*));
        for(int i = 0; i < M_SIZE; i++){
            out[i] = BN_new();
        }
        int is_real_cprf = rand() %2; //1 chance sur deux que l'oracle soit en mode aléatoire
        
        if(is_real_cprf){
            printf("[*] Mode : CPRF\n");
        }
        else{
            printf("[*] Mode : RANDOM\n");
        }

        //si mode cprf, on renvoie S*x, sinon élément random
        if(is_real_cprf){
            fweak_eval_master_key(out, mk, x);
        } else {
            for(int i = 0; i < M_SIZE; i++){
                BN_rand_range(out[i], ck->p);
            }
        }

        for(int i = 0; i < M_SIZE; i++){
            send_bn(client_fd, out[i]);
        }


        int guess;
        read(client_fd, &guess, sizeof(int));

        int valid = (guess == is_real_cprf);
        write(client_fd, &valid, sizeof(int));

        fweak_free_vector(x, N_SIZE);
        fweak_free_vector(out, M_SIZE);
    }

    fweak_master_key_free(mk);
    fweak_constrained_key_free(ck);
    //fweak_free_vector(y, N_SIZE);

    close(client_fd);
    close(server_fd);

    return 0;
}