#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>
#include <openssl/bn.h>
#include "../include/fweak.h"

#define PORT 4242
#define BUF_SIZE 4096
#define MAX_TRIES 50
#define M_SIZE 10
#define N_SIZE 100

/* --- DICTIONNAIRE --- */

typedef struct DictEntry {
    BIGNUM **y;
    int N;
    int count;
    struct DictEntry *next;
} DictEntry;

typedef struct {
    DictEntry **buckets;
    size_t capacity;
    size_t size;
} Dict;

static size_t hash_key(BIGNUM **y, int N, size_t capacity) {
    size_t h = 5381;
    for (int i = 0; i < N; i++) {
        int bn_len = BN_num_bytes(y[i]);
        if (bn_len > 0) {
            unsigned char *buf = malloc(bn_len);
            if (buf) {
                BN_bn2bin(y[i], buf);
                for (int j = 0; j < bn_len; j++)
                    h = ((h << 5) + h) ^ buf[j];
                free(buf);
            }
        }
    }
    h = ((h << 5) + h) ^ (size_t)(unsigned int)N;
    return h % capacity;
}

static int keys_equal(BIGNUM **y1, int N1, BIGNUM **y2, int N2) {
    if (N1 != N2) return 0;
    for (int i = 0; i < N1; i++)
        if (BN_cmp(y1[i], y2[i]) != 0) return 0;
    return 1;
}

static DictEntry *find_entry(DictEntry *head, BIGNUM **y, int N) {
    DictEntry *e = head;
    while (e) {
        if (keys_equal(e->y, e->N, y, N)) return e;
        e = e->next;
    }
    return NULL;
}

Dict *dict_init(size_t capacity) {
    if (capacity == 0) capacity = 64;
    Dict *d = malloc(sizeof(Dict));
    if (!d) return NULL;
    d->buckets = calloc(capacity, sizeof(DictEntry*));
    if (!d->buckets) { free(d); return NULL; }
    d->capacity = capacity;
    d->size = 0;
    return d;
}

void dict_free(Dict *d) {
    if (!d) return;
    for (size_t i = 0; i < d->capacity; i++) {
        DictEntry *e = d->buckets[i];
        while (e) {
            DictEntry *next = e->next;
            fweak_free_vector(e->y, e->N);
            free(e);
            e = next;
        }
    }
    free(d->buckets);
    free(d);
}

int dict_insert(Dict *d, BIGNUM **y, int N, int count) {
    if (!d || !y || N <= 0) return -1;
    size_t idx = hash_key(y, N, d->capacity);
    DictEntry *e = find_entry(d->buckets[idx], y, N);
    if (e) { e->count = count; return 0; }
    e = malloc(sizeof(DictEntry));
    if (!e) return -1;
    e->y = fweak_copy_vector(y, N);
    if (!e->y) { free(e); return -1; }
    e->N = N;
    e->count = count;
    e->next = d->buckets[idx];
    d->buckets[idx] = e;
    d->size++;
    return 0;
}

int dict_contains(const Dict *d, BIGNUM **y, int N) {
    if (!d || !y || N <= 0) return 0;
    size_t idx = hash_key(y, N, d->capacity);
    return find_entry(d->buckets[idx], y, N) != NULL;
}

int dict_get(const Dict *d, BIGNUM **y, int N, int *out_count) {
    if (!d || !y || N <= 0) return 0;
    size_t idx = hash_key(y, N, d->capacity);
    DictEntry *e = find_entry(d->buckets[idx], y, N);
    if (!e) return 0;
    if (out_count) *out_count = e->count;
    return 1;
}

int dict_update(Dict *d, BIGNUM **y, int N, int new_count) {
    if (!d || !y || N <= 0) return 0;
    size_t idx = hash_key(y, N, d->capacity);
    DictEntry *e = find_entry(d->buckets[idx], y, N);
    if (!e) return 0;
    e->count = new_count;
    return 1;
}

int dict_max(const Dict *d, BIGNUM ***out_y, int *out_N, int *out_count) {
    DictEntry *best = NULL;
    if (!d || d->size == 0) return 0;
    for (size_t i = 0; i < d->capacity; i++) {
        DictEntry *e = d->buckets[i];
        while (e) {
            if (!best || e->count > best->count) best = e;
            e = e->next;
        }
    }
    if (!best) return 0;
    if (out_y) *out_y = best->y;
    if (out_N) *out_N = best->N;
    if (out_count) *out_count = best->count;
    return 1;
}

/* --- SOCKET --- */

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

/* --- ATTAQUE --- */

int attaque(fweak_constrained_key *ck, int client_fd) {
    FILE *log = fopen("attack_fweak_results.txt", "w");
    if (!log) { perror("fopen"); exit(1); }

    int guess = 0;
    int next_progress = 10;
    int is_cprf, valid;

    BIGNUM **x = malloc(ck->N * sizeof(BIGNUM*));
    BIGNUM **y = malloc(ck->M * sizeof(BIGNUM*));
    BIGNUM **Sn = malloc(ck->M * sizeof(BIGNUM*));
    BIGNUM *x_1 = BN_new();
    BIGNUM *tmp = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    
    BIGNUM **out_y;

    for(int j = 0; j < ck->N; j++) x[j] = BN_new();
    for(int j = 0; j < ck->M; j++){
        y[j] = BN_new();
        Sn[j] = BN_new();
    }

    Dict *d = dict_init(MAX_TRIES);

    for(int i = 0; i < MAX_TRIES; i++){
        for(int j = 0; j < ck->N-1; j++) random_mod(x[j], ck->p);
        do { random_mod(x[ck->N-1], ck->p); } while(BN_is_zero(x[ck->N-1]));
        BN_mod_inverse(x_1, x[ck->N-1], ck->p, ctx);

        // envoyer x
        for(int k = 0; k < ck->N; k++) send_bn(client_fd, x[k]);
        for(int k = 0; k < ck->M; k++) recv_bn(client_fd, y[k]);

        for(int j = 0; j < ck->M; j++){
            BN_zero(Sn[j]);
            for(int k = 0; k < ck->N-1; k++){

                BN_mod_mul(tmp, ck->S_y[j][k], x[k], ck->p, ctx);
                BN_mod_sub(Sn[j], Sn[j], tmp, ck->p, ctx);
            }
            BN_mod_add(Sn[j],Sn[j],y[j],ck->p,ctx);
            BN_mod_mul(Sn[j], Sn[j], x_1, ck->p, ctx);
        }

        int count;
        if (!dict_contains(d, Sn, ck->M)) dict_insert(d, Sn, ck->M, 1);
        else { dict_get(d, Sn, ck->M, &count); dict_update(d, Sn, ck->M, count + 1); }

        int out_N, out_count;
        dict_max(d, &out_y, &out_N, &out_count);
        is_cprf = keys_equal(Sn, ck->M, out_y, out_N);

        write(client_fd, &is_cprf, sizeof(int));
        read(client_fd, &valid, sizeof(int));

        if(valid) guess++;
        fprintf(log, "%d %d %d\n", i, is_cprf, valid);

        int progress = (int)floor((double)(i+1)/MAX_TRIES*100);
        if(progress >= next_progress){ printf("[*] Progression : %3d%%\n", next_progress); next_progress += 10; }
    }

    printf("[*] Attaque terminée\n[*] Attaque réussie pour %d/%d tests\n", guess, MAX_TRIES);
    fprintf(log, "# Total attaque réussie : %d/%d\n", guess, MAX_TRIES);
    fclose(log);

    BN_free(tmp); BN_free(x_1);
    fweak_free_vector(x, ck->N);
    fweak_free_vector(y, ck->M);
    fweak_free_vector(Sn, ck->M);
    dict_free(d);
    BN_CTX_free(ctx);

    return guess;
}

/* --- MAIN --- */

int main() {
    printf("[*] Connecté au serveur PORT %d\n", PORT);
    printf("[*] Attaque en cours ...\n");

    int client_fd;
    struct sockaddr_in addr;

    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if(connect(client_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0){
        perror("connect"); exit(1);
    }

    BIGNUM **y = fweak_random_vector(get_prime(), N_SIZE);
    for(int i = 0; i < N_SIZE-1; i++) BN_zero(y[i]);
    BN_one(y[N_SIZE-1]);

    BIGNUM ***Sy = alloc_matrix(M_SIZE, N_SIZE);
    BIGNUM *p = BN_new();

    // Envoi y
    for(int i=0; i<N_SIZE; i++) send_bn(client_fd, y[i]);

    // Reception p
    recv_bn(client_fd, p);

    // Reception S_y
    for(int i=0; i<M_SIZE; i++)
        for(int j=0; j<N_SIZE; j++)
            recv_bn(client_fd, Sy[i][j]);

    fweak_constrained_key *ck = malloc(sizeof(fweak_constrained_key));
    ck->M = M_SIZE; ck->N = N_SIZE; ck->p = p; ck->S_y = Sy; ck->y = y;

    clock_t start = clock();
    attaque(ck, client_fd);
    clock_t end = clock();
    printf("[*] Temps total : %.2f ms\n", (double)(end-start)/CLOCKS_PER_SEC*1000.0);

    BN_free(p);
    fweak_free_vector(y, N_SIZE);
    free_matrix(Sy, M_SIZE, N_SIZE);
    free(ck);
    close(client_fd);

    return 0;
}