#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h> 
#include <math.h>
#include <stddef.h>

#include "../include/fweak.h"


#ifndef BIGNUM_DICT_H
#define BIGNUM_DICT_H
#endif /* BIGNUM_DICT_H */

#define PORT 4242
#define BUF_SIZE 4096
#define MAX_TRIES 10 


// A revoir
#define M_SIZE 10
#define N_SIZE 100





 
 
// Structure d'une entrée d'un dictionnaire
typedef struct DictEntry {
    BIGNUM **y;      
    int N; // Taile de y  
    int count;   
    struct DictEntry *next; // Structure en liste chainé
} DictEntry;
 
//Structure principal d'un dictionnaire
typedef struct {
    DictEntry **buckets;   // tableau de listes chaînées
    size_t      capacity;  // nombre de buckets
    size_t      size;      // nombre d'éléments stockés
} Dict;


// Faire un code sur init_dict, is_max_dict, inserer_dict, vec_in_dict





/* -----------------------------------------------------------------------
 * hash_key
 *
 * y est un tableau de N BIGNUM*. On hache chaque BIGNUM octet par octet
 * avec djb2-xor, puis on intègre N à la fin.
 * ----------------------------------------------------------------------- */
static size_t hash_key(BIGNUM **y, int N, size_t capacity)
{
    size_t h = (size_t)5381;
    int i;
 
    for (i = 0; i < N; i++) {
        int bn_len = BN_num_bytes(y[i]);
        if (bn_len > 0) {
            unsigned char *buf = (unsigned char *)malloc((size_t)bn_len);
            if (buf) {
                int j;
                BN_bn2bin(y[i], buf);
                for (j = 0; j < bn_len; j++)
                    h = ((h << 5) + h) ^ buf[j]; /* djb2 xor */
                free(buf);
            }
        }
    }
 
    /* Intègre N pour distinguer des tableaux de tailles différentes */
    h = ((h << 5) + h) ^ (size_t)(unsigned int)N;
 
    return h % capacity;
}
 
/* -----------------------------------------------------------------------
 * keys_equal
 *
 * Compare deux clés (y1, N1) et (y2, N2).
 * Deux clés sont égales si N1 == N2 et BN_cmp(y1[i], y2[i]) == 0 pour tout i.
 * ----------------------------------------------------------------------- */
static int keys_equal(BIGNUM **y1, int N1, BIGNUM **y2, int N2)
{
    int i;
    if (N1 != N2) return 0;
    for (i = 0; i < N1; i++) {
        if (BN_cmp(y1[i], y2[i]) != 0)
            return 0;
    }
    return 1;
}
 
 
/* -----------------------------------------------------------------------
 * Recherche dans un bucket (liste chaînée)
 * ----------------------------------------------------------------------- */
static DictEntry *find_entry(DictEntry *head, BIGNUM **y, int N)
{
    DictEntry *e = head;
    while (e) {
        if (keys_equal(e->y, e->N, y, N))
            return e;
        e = e->next;
    }
    return NULL;
}
 
/* -----------------------------------------------------------------------
 * dict_init
 * ----------------------------------------------------------------------- */
Dict *dict_init(size_t capacity)
{
    Dict *d;
    if (capacity == 0) capacity = 64;
 
    d = (Dict *)malloc(sizeof(Dict));
    if (!d) return NULL;
 
    d->buckets = (DictEntry **)calloc(capacity, sizeof(DictEntry *));
    if (!d->buckets) { free(d); return NULL; }
 
    d->capacity = capacity;
    d->size     = 0;
    return d;
}
 
/* -----------------------------------------------------------------------
 * dict_free
 * ----------------------------------------------------------------------- */
void dict_free(Dict *d)
{
    size_t i;
    if (!d) return;
 
    for (i = 0; i < d->capacity; i++) {
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
 
/* -----------------------------------------------------------------------
 * dict_insert  (insert ou update)
 * ----------------------------------------------------------------------- */
int dict_insert(Dict *d, BIGNUM **y, int N, int count)
{
    size_t     idx;
    DictEntry *e;
 
    if (!d || !y || N <= 0) return -1;
 
    idx = hash_key(y, N, d->capacity);
    e   = find_entry(d->buckets[idx], y, N);
 
    if (e) {
        /* Clé déjà présente : mise à jour de la valeur uniquement */
        e->count = count;
        return 0;
    }
 
    /* Nouvelle entrée */
    e = (DictEntry *)malloc(sizeof(DictEntry));
    if (!e) return -1;
 
    e->y = fweak_copy_vector(y, N);
    if (!e->y) { free(e); return -1; }
 
    e->N     = N;
    e->count = count;
    e->next  = d->buckets[idx];
 
    d->buckets[idx] = e;
    d->size++;
    return 0;
}
 
/* -----------------------------------------------------------------------
 * dict_contains
 * ----------------------------------------------------------------------- */
int dict_contains(const Dict *d, BIGNUM **y, int N)
{
    size_t idx;
    if (!d || !y || N <= 0) return 0;
    idx = hash_key(y, N, d->capacity);
    return find_entry(d->buckets[idx], y, N) != NULL;
}
 
/* -----------------------------------------------------------------------
 * dict_get
 * ----------------------------------------------------------------------- */
int dict_get(const Dict *d, BIGNUM **y, int N, int *out_count)
{
    size_t     idx;
    DictEntry *e;
 
    if (!d || !y || N <= 0) return 0;
    idx = hash_key(y, N, d->capacity);
    e   = find_entry(d->buckets[idx], y, N);
    if (!e) return 0;
 
    if (out_count) *out_count = e->count;
    return 1;
}
 
/* -----------------------------------------------------------------------
 * dict_update  (update uniquement, pas d'insertion)
 * ----------------------------------------------------------------------- */
int dict_update(Dict *d, BIGNUM **y, int N, int new_count)
{
    size_t     idx;
    DictEntry *e;
 
    if (!d || !y || N <= 0) return 0;
    idx = hash_key(y, N, d->capacity);
    e   = find_entry(d->buckets[idx], y, N);
    if (!e) return 0;
 
    e->count = new_count;
    return 1;
}
 
/* -----------------------------------------------------------------------
 * dict_max
 * ----------------------------------------------------------------------- */
int dict_max(const Dict *d, BIGNUM ***out_y, int *out_N, int *out_count)
{
    size_t     i;
    DictEntry *best = NULL;
 
    if (!d || d->size == 0) return 0;
 
    for (i = 0; i < d->capacity; i++) {
        DictEntry *e = d->buckets[i];
        while (e) {
            if (!best || e->count > best->count)
                best = e;
            e = e->next;
        }
    }
 
    if (!best) return 0;
 
    if (out_y)     *out_y     = best->y;   /* pointeur interne, ne pas libérer */
    if (out_N)     *out_N     = best->N;
    if (out_count) *out_count = best->count;
    return 1;
}







/*
 * lire ligne sur la connexion, reçevoir message du serveur
*/
/*
void recv_line(int sock, char *buf, size_t size) {
    memset(buf, 0, size);
    size_t i = 0;
    while (i < size - 1) {
        if (read(sock, &buf[i], 1) <= 0) break;
        if (buf[i] == '\n') break;
        i++;
    }
}
*/


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




/*
 * effectuer une attaque sur la cprf (avec y=(0,0,...,0,1))
*/
int attaque(fweak_constrained_key *ck, int server_fd) {
    FILE *log = fopen("attack_fweak_results.txt", "w"); // écriture dans un fichier if (!log) { perror("fopen"); exit(1); }

    int guess = 0;
    int next_progress = 10;
    int is_cprf;
    int valid;

    int *out_count;
    int *out_N;

    BIGNUM ***out_y;
    *out_y = malloc(ck->M * sizeof(BIGNUM*));

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
    Dict *d = dict_init(MAX_TRIES);
    
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
        for(int k = 0 ; k < N_SIZE ; k++){
            send_bn(server_fd, x[k]);
        }

        for(int k = 0 ; k < M_SIZE ; k++){
            recv_bn(server_fd, y[k]);
        }

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

        if (!dict_contains(d, Sn, ck->M)){
            dict_insert(d, Sn, ck->M, 0);
        } else {
            dict_get(d, Sn, ck->M, out_count);
            dict_update(d, Sn, ck->M, (*out_count) + 1); 
        }

        // On prend dans *out_y l'element max du dictionnaire d
        dict_max(d, out_y, out_N, out_count);

        // Si Sn est le max du dictionnaire, alors Sn est probablement le vrai Sn, donc c'est probablement un cprf
        if(keys_equal(Sn, ck->M, *out_y, *out_N)){
            is_cprf = 1;
        } else {
            is_cprf = 0; 
        }

        // send_oracle(is_cprf);
        write(server_fd, &is_cprf, sizeof(int));

        // receive_oracle(valid);
        read(server_fd, &valid, sizeof(int));

        if(valid){
            guess = guess + 1;
        }

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
        printf("[!!!] Attaque réussi pour %d/%d tests\n", guess, MAX_TRIES);
    else
        printf("Aucune attaque réussi pour les %d testés\n", MAX_TRIES);
    
    fprintf(log, "# Total attaque réussi : %d/%d\n", guess, MAX_TRIES);
    fclose(log);

    BN_free(tmp);
    BN_free(x_1);

    fweak_free_vector(x, ck->N);
    fweak_free_vector(y, ck->M);
    fweak_free_vector(Sn, ck->M);
    
    fweak_free_vector(*out_y, ck->M);

    free_matrix(S ,ck->M ,ck->N);

    BN_CTX_free(ctx);

    return guess;
}












int main(int argc, char *argv[]) {

    

    printf("[*] Connecté au serveur PORT %d\n", PORT);
    printf("[*] Attaque en cours ...\n");

    int server_fd, client_fd;
    struct sockaddr_in addr;
    char buffer[BUF_SIZE];

    /* --- connexion --- */
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(1);
    }


    



    int found = 0;
    int next_progress = 10;
    int guess;

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
    for(int i = 0; i < N_SIZE; i++){
        send_bn(server_fd, y[i]);
    }

    recv_bn(server_fd, p);

    for(int i = 0 ; i < M_SIZE ; i++){
        for(int j = 0 ; j < N_SIZE ; j++){
            recv_bn(server_fd, Sy[i][j]);
        }
    }


    fweak_constrained_key *ck;

    ck->M = M_SIZE;
    ck->N = N_SIZE;
    ck->p = p;
    ck->S_y = Sy;
    ck->y = y;

    /* ---- attaque ---- */
    clock_t start = clock(); 
    guess = attaque(ck, server_fd);
    clock_t end = clock();

    double elapsed_ms = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;

    BN_free(p);
    fweak_free_vector(y, M_SIZE);
    free_matrix(Sy ,M_SIZE ,N_SIZE);

    return 0;
}