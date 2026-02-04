#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "../include/rsa.h"
#include "../include/bmo17.h"

#define PORT 4242
#define BUF_SIZE 4096
<<<<<<< HEAD
#define MAX_TRIES 10 // = x 
=======
#define NB_PERMUTATION 50 // nombre max de permutations à tester
#define NB_ATTACKS 50 // nombre d'attaques max = nb de contraintes

>>>>>>> a887bf5 (attack server)

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

/*
 * effectuer une attaque sur la cprf
*/
int attaque_cprf(int sock, int n, int max_tries, BIGNUM *e, BIGNUM *N, BIGNUM *STn, BN_CTX *ctx) {
    char buffer[BUF_SIZE];
    int found = 0;
    printf("[*] Attaque pour n = %d\n", n);
    for (int x = n + 1; x < n + max_tries; x++) {

        /* ---- oracle EVAL ---- */
        dprintf(sock, "EVAL %d\n", x);
        recv_line(sock, buffer, BUF_SIZE); //Stx

        char *hex_STx = strchr(buffer, ' ');
        if (!hex_STx)
            continue;
        hex_STx++; // skip espace

        BIGNUM *STx = BN_new();
        BN_hex2bn(&STx, hex_STx);

        BIGNUM *tmp = BN_dup(STx);

        // appliquer les permutations 
        for (int i = 0; i < x - n; i++) {
            if(rsa_eval_public(tmp, tmp, e, N, ctx)==0){
                printf("erreur rsa_eval_public\n");
                exit(1);
            }
        }

        if (BN_cmp(tmp, STn) == 0) {
            printf("[!!!] PRF détectée pour x = %d\n", x);
            found = 1;
            BN_free(STx);
            BN_free(tmp);
            break; // on arrête dès détection
        }

        BN_free(STx);
        BN_free(tmp);

        //printf("[*] x = %d : pas de PRF détectée\n", x);
    }
    return found;
}

int main() {

    int sock;
    struct sockaddr_in addr;

    //connexion au serveur
    sock = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(1);
    }

    printf("paramètres de l'attaque : \n");
    printf(" - nombre de permutations par attaque : %d\n", NB_PERMUTATION);
    printf(" - nombre d'attaques (contraintes) : %d\n", NB_ATTACKS);

    int found = 0;
    printf("[*] Attaque en cours ...\n");
    for (int n = 2; n <= NB_ATTACKS ; n++) {

        char buffer[BUF_SIZE];

        BN_CTX *ctx = BN_CTX_new();

        
        /* ---- CONSTRAIN ---- */
        dprintf(sock, "CONSTRAIN %d\n", n); 
        recv_line(sock, buffer, BUF_SIZE); //Stn

        char e_hex[1024], N_hex[4096], STn_hex[4096];
        int n_recv;

        sscanf(buffer, "OK %s %s %s %d", e_hex, N_hex, STn_hex, &n_recv);

        BIGNUM *e = BN_new();
        BIGNUM *N = BN_new();
        BIGNUM *STn = BN_new();

        BN_hex2bn(&e, e_hex);
        BN_hex2bn(&N, N_hex);
        BN_hex2bn(&STn, STn_hex);

        //printf("[*] Clé contrainte reçue (n = %d)\n", n);

        /* ---- attaque ---- */
        int found = attaque_cprf(sock, n, MAX_TRIES, e, N, STn, ctx); //Stx

        if (!found)
            printf("Aucune PRF détectée\n");


        BN_free(e);
        BN_free(N);
        BN_free(STn);
        BN_CTX_free(ctx);
  
        
    }
    close(sock);
    printf("[*] Attaque terminée\n");
    if(found)
        printf("[!!!] PRF détectée pour au moins un n\n");
    else
        printf("[*] Aucune faille détectée\n");
    return 0;
}

