#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h> 
#include <math.h>

#include "../include/rsa.h"
#include "../include/bmo17.h"

#define PORT 4242
#define BUF_SIZE 4096
#define MAX_TRIES 10 // = x 
#define MAX_N 50

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
int attaque_cprf(int sock, int n, int max_tries, int *guess, BIGNUM *e, BIGNUM *N, BIGNUM *STn, int ishashed) {
    char buffer[BUF_SIZE];
    char buffer_ans[BUF_SIZE];
    int found = 0;

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

        /* appliquer les permutations */
        BIGNUM *bn_n = BN_new();
        BN_set_word(bn_n, n);
        if(ishashed){
            bmo17_eval_constrained_key_hash(tmp,e,N,STx,x, bn_n);
        }
        else{
            bmo17_eval_constrained_key(tmp,e,N,STx,x,bn_n);
        }
        
        if (BN_cmp(tmp, STn) == 0) {
            //printf("[!!!] PRF détectée pour x = %d\n", x);
            found = 1;
        }

        BN_free(STx);
        BN_free(tmp);
        //printf("[*] x = %d : pas de PRF détectée\n", x);

        dprintf(sock, "ANSWER %d\n", found);

        int r = 0;
        r = read(sock, buffer_ans, BUF_SIZE - 1);
        if(r<=0){
            printf("[*] Erreur lecture réponse du serveur");
            break;
        }

        *guess = atoi(buffer_ans);
    }

    return found;
}

int main(int argc, char * argv[]) {

    int hashed = 0;
    if(argc > 1){
        hashed = atoi(argv[1]);
    }

    FILE *log = fopen("attack_results.txt", "w"); // écriture dans un fichier
    if (!log) {
        perror("fopen");
        exit(1);
    }

    printf("[*] Connecté au serveur PORT %d\n", PORT);
    printf("[*] Attaque en cours ...\n");
    int found = 0;
    int next_progress = 10;
    for (int n = 2; n <= MAX_N+1; n++) {

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

        /* ---- CONSTRAIN ---- */
        dprintf(sock, "CONSTRAIN %d\n", n); //demande une clé contrainte pour n
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
        clock_t start = clock(); 
        int tmp = attaque_cprf(sock, n, MAX_TRIES, &guess, e, N, STn, hashed);
        clock_t end = clock();
        if(tmp) found += 1;

        double elapsed_ms = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;

        fprintf(log, "%d %d %d %.3f\n", n, tmp, guess, elapsed_ms);  //écriture dans fichier

        int progress = (int) floor((double)(n-1) / MAX_N * 100); // % accompli
        if(progress >= next_progress) {
            printf("[*] Progression : %3d%%\n", next_progress);
            fflush(stdout);
            next_progress += 10;
        }

        BN_free(e);
        BN_free(N);
        BN_free(STn);
        close(sock);
    }
    printf("[*] Attaque terminée\n");
    if(found)
        printf("[!!!] PRF détectée pour %d/%d tests\n", found, MAX_N);
    else
        printf("Aucune PRF détectée pour les %d testés\n", MAX_N);

    fprintf(log, "# Total detected: %d/%d\n", found, MAX_N);
    fclose(log);
    return 0;
}

