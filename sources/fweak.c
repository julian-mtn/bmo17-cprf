// fweak.c
#include "../include/fweak.h"


static BIGNUM *get_prime(void) {
    static BIGNUM *p = NULL;
    if (p == NULL) {
        p = BN_new();
        BN_set_word(p, 2147483647);
    }
    return p;
}

// Remplit un BIGNUM avec un nombre aléatoire dans [0, p-1]
static void random_mod(BIGNUM *dest, BIGNUM *p) {
    BN_rand_range(dest, p);
}

// Alloue une matrice M x N de BIGNUM* 
static BIGNUM ***alloc_matrix(int M, int N) {
    BIGNUM ***mat = malloc(M * sizeof(BIGNUM**));
    for (int i = 0; i < M; i++) {
        mat[i] = malloc(N * sizeof(BIGNUM*));
        for (int j = 0; j < N; j++) {
            mat[i][j] = BN_new();
        }
    }
    return mat;
}

// Libère une matrice M x N
static void free_matrix(BIGNUM ***mat, int M, int N) {
    if (!mat) return;
    for (int i = 0; i < M; i++) {
        if (mat[i]) {
            for (int j = 0; j < N; j++) {
                BN_free(mat[i][j]);
            }
            free(mat[i]);
        }
    }
    free(mat);
}

BIGNUM **fweak_random_vector(BIGNUM *p, int len) {
    BIGNUM **vec = malloc(len * sizeof(BIGNUM*));
    for (int i = 0; i < len; i++) {
        vec[i] = BN_new();
        random_mod(vec[i], p);
    }
    return vec;
}


BIGNUM **fweak_copy_vector(BIGNUM **src, int len) {
    BIGNUM **dst = malloc(len * sizeof(BIGNUM*));
    for (int i = 0; i < len; i++) {
        dst[i] = BN_dup(src[i]);
    }
    return dst;
}


// Multiplication matrice-vecteur : out = mat * x (mod p)
static void matrix_vector_mult(BIGNUM **out, BIGNUM ***mat, int M, int N, BIGNUM **x, BIGNUM *p) {
    BN_CTX *ctx = BN_CTX_new();
    for (int i = 0; i < M; i++) {
        BN_zero(out[i]);
        for (int j = 0; j < N; j++) {
            BIGNUM *tmp = BN_new();
            BN_mod_mul(tmp, mat[i][j], x[j], p, ctx);
            BN_mod_add(out[i], out[i], tmp, p, ctx);
            BN_free(tmp);
        }
    }
    BN_CTX_free(ctx);
}

// Addition de deux matrices : dest = A + B (mod p)
static void matrix_add(BIGNUM ***dest, BIGNUM ***A, BIGNUM ***B, int M, int N, BIGNUM *p) {
    BN_CTX *ctx = BN_CTX_new();
    for (int i = 0; i < M; i++) {
        for (int j = 0; j < N; j++) {
            BN_mod_add(dest[i][j], A[i][j], B[i][j], p, ctx);
        }
    }
    BN_CTX_free(ctx);
}

// Produit externe : mat = d * y^T (mod p)
static void outer_product(BIGNUM ***mat, BIGNUM **d, int M, BIGNUM **y, int N, BIGNUM *p) {
    BN_CTX *ctx = BN_CTX_new();
    for (int i = 0; i < M; i++) {
        for (int j = 0; j < N; j++) {
            BN_mod_mul(mat[i][j], d[i], y[j], p, ctx);
        }
    }
    BN_CTX_free(ctx);
}

/*///////////////////// key generation ////////////////////////*/

fweak_master_key *fweak_master_keygen(int M, int N) {
    fweak_master_key *mk = malloc(sizeof(fweak_master_key));
    if (!mk) return NULL;
    mk->p = BN_dup(get_prime());
    mk->M = M;
    mk->N = N;
    mk->S = alloc_matrix(M, N);
    // Remplir S avec des éléments aléatoires
    for (int i = 0; i < M; i++) {
        for (int j = 0; j < N; j++) {
            random_mod(mk->S[i][j], mk->p);
        }
    }
    return mk;
}

fweak_constrained_key *fweak_constrained_keygen(fweak_master_key *mk, BIGNUM **y, int y_len) {
    if (y_len != mk->N) {
        fprintf(stderr, "Erreur: y_len != N\n");
        return NULL;
    }

    fweak_constrained_key *ck = malloc(sizeof(fweak_constrained_key));
    if (!ck) return NULL;
    ck->p = BN_dup(mk->p);
    ck->M = mk->M;
    ck->N = mk->N;

    // Copier y
    ck->y = malloc(mk->N * sizeof(BIGNUM*));
    for (int j = 0; j < mk->N; j++) {
        ck->y[j] = BN_dup(y[j]);
    }

    // Générer d aléatoire (vecteur de taille M)
    BIGNUM **d = malloc(mk->M * sizeof(BIGNUM*));
    for (int i = 0; i < mk->M; i++) {
        d[i] = BN_new();
        random_mod(d[i], ck->p);
    }

    // Construire la matrice d·y^T
    BIGNUM ***outer = alloc_matrix(mk->M, mk->N);
    outer_product(outer, d, mk->M, ck->y, mk->N, ck->p);

    // Allouer S_y et copier S
    ck->S_y = alloc_matrix(mk->M, mk->N);
    for (int i = 0; i < mk->M; i++) {
        for (int j = 0; j < mk->N; j++) {
            BN_copy(ck->S_y[i][j], mk->S[i][j]);
        }
    }
    // Ajouter outer à S_y
    matrix_add(ck->S_y, ck->S_y, outer, mk->M, mk->N, ck->p);

    // Libération des temporaires
    for (int i = 0; i < mk->M; i++) BN_free(d[i]);
    free(d);
    free_matrix(outer, mk->M, mk->N);

    return ck;
}

/*///////////////////// evaluation ////////////////////////*/

void fweak_eval_master_key(BIGNUM **out, fweak_master_key *mk, BIGNUM **x) {
    matrix_vector_mult(out, mk->S, mk->M, mk->N, x, mk->p);
}

void fweak_eval_constrained_key(BIGNUM **out, fweak_constrained_key *ck, BIGNUM **x) {
    matrix_vector_mult(out, ck->S_y, ck->M, ck->N, x, ck->p);
}

/*///////////////////// memory ////////////////////////*/

void fweak_master_key_free(fweak_master_key *mk) {
    if (!mk) return;
    free_matrix(mk->S, mk->M, mk->N);
    BN_free(mk->p);
    free(mk);
}

void fweak_constrained_key_free(fweak_constrained_key *ck) {
    if (!ck) return;
    free_matrix(ck->S_y, ck->M, ck->N);
    for (int j = 0; j < ck->N; j++) BN_free(ck->y[j]);
    free(ck->y);
    BN_free(ck->p);
    free(ck);
}

void fweak_free_vector(BIGNUM **vec, int len) {
    if (!vec) return;
    for (int i = 0; i < len; i++) BN_free(vec[i]);
    free(vec);
}

