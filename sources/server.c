#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include "../include/bmo17.h"
#include "../include/rsa.h"

#define PORT 4242
#define BUF_SIZE 1024


void send_bn(int sock, BIGNUM *bn) {
    char *hex = BN_bn2hex(bn);
    dprintf(sock, "%s\n", hex);
    OPENSSL_free(hex);
}

void send_constrained_key(int sock, bmo17_constrained_key *ck) {
    char *e_hex  = BN_bn2hex(ck->e);
    char *N_hex  = BN_bn2hex(ck->N);
    char *ST_hex = BN_bn2hex(ck->STn);

    dprintf(sock, "%s %s %s %d\n", e_hex, N_hex, ST_hex, ck->n);

    OPENSSL_free(e_hex);
    OPENSSL_free(N_hex);
    OPENSSL_free(ST_hex);
}



int main() {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    char buffer[BUF_SIZE];

    printf("[Initialisation serveur BMO17]\n");

    //Génération clé maîtresse
    bmo17_master_key *mk = bmo17_master_keygen();
    if (!mk) {
        perror("bmo17_master_keygen");
        exit(1);
    }

    // --- connection ---
    // socket tcp
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(1);
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }
    listen(server_fd, 1);
    listen(server_fd, 10);
    printf("[*] Serveur en écoute sur le port %d\n", PORT);
    //----------------------------
    
    while (1) {
        printf("[*] En attente d'un client...\n");
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        srand(time(NULL) ^ getpid()); 
        int challenge_bit = rand() % 2; // 0 : PRF, 1 : aléatoire

        printf("[*] Client connecté\n");

        while (1) {
            memset(buffer, 0, BUF_SIZE);
            int r = read(client_fd, buffer, BUF_SIZE - 1);
            if (r <= 0) {
                printf("[*] Client déconnecté\n");
                break;
            }

            if (strncmp(buffer, "EVAL", 4) == 0) {
                int x = atoi(buffer + 5);
                BIGNUM *y = BN_new();
                
                
                if (challenge_bit == 0) {
                    //  PRF
                    bmo17_eval_master_key(y, mk, x); //Stx
                } else {
                    //  aléatoire
                    BN_rand(y, 256, 0, 0); // même taille que Stx
                }


                dprintf(client_fd, "OK ");
                send_bn(client_fd, y);

                BN_free(y);
            }
            else if (strncmp(buffer, "CONSTRAIN", 9) == 0) {
                int n = atoi(buffer + 10);

                bmo17_constrained_key *ck =bmo17_constrained_keygen(mk, n); //PK, Stn, n

                if (!ck) {
                    dprintf(client_fd, "ERR\n");
                    continue;
                }

                dprintf(client_fd, "OK ");
                send_constrained_key(client_fd, ck);
                bmo17_constrained_key_free(ck);
            }
            else {
                dprintf(client_fd, "UNKNOWN COMMAND\n");
            }
        }
        close(client_fd); 
    }
}

