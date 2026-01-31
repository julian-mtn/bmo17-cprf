#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "../include/rsa.h"
#include "../include/bmo17.h"

#define PORT 4242
#define BUF_SIZE 4096
#define MAX_TRIES 100

void recv_line(int sock, char *buf, size_t size) {
    memset(buf, 0, size);
    size_t i = 0;
    while (i < size - 1) {
        if (read(sock, &buf[i], 1) <= 0) break;
        if (buf[i] == '\n') break;
        i++;
    }
}

int main() {
    int sock;
    struct sockaddr_in addr;
    char buffer[BUF_SIZE];

    BN_CTX *ctx = BN_CTX_new();

    //--- connexion au serveur ---
    sock = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(1);
    }
    printf("[*] Connecté au serveur\n");

    //----------------------------

    int n = 11; // contrainte fixée

    // ---- oracle CONSTRAIN ----
    dprintf(sock, "CONSTRAIN %d\n", n); //STn
    recv_line(sock, buffer, BUF_SIZE);

    char e_hex[1024], N_hex[4096], STn_hex[4096];
    int n_recv;
    sscanf(buffer, "OK %s %s %s %d", e_hex, N_hex, STn_hex, &n_recv);

    BIGNUM *e = BN_new();
    BIGNUM *N = BN_new();

    BN_hex2bn(&e, e_hex);
    BN_hex2bn(&N, N_hex);

    printf("[*] Clé contrainte reçue (n = %d)\n", n);
    //----------------------------

    // ---- attaque ----
    int found =0;
    printf("[*] Attaque en cours ...\n");
    for (int x = n + 1; x < n + MAX_TRIES; x++) {

        // ---- oracle EVAL ----
        dprintf(sock, "EVAL %d\n", x); //STx
        recv_line(sock, buffer, BUF_SIZE);

        char *hex_STx = strchr(buffer, ' ') + 1;
        BIGNUM *STx = BN_new();
        BN_hex2bn(&STx, hex_STx);

        // on appllique les permutations sur STx
        BIGNUM *tmp = BN_dup(STx);
        for (int i = 0; i < x - n; i++) {
            rsa_eval_public(tmp, tmp, e, N, ctx);
        }

        if (BN_cmp(tmp, STx) == 0) {
            printf("[!!!] PRF détectée pour x = %d\n", x);
            BN_free(STx);
            BN_free(tmp);
            found =1;;
        }

        BN_free(STx);
        BN_free(tmp);
    }

    printf("[*] Attaque terminée \n");
    if(!found) printf("Aucune PRF détectée \n");
    BN_free(e);
    BN_free(N);
    BN_CTX_free(ctx);
    close(sock);

    return 0;
}
