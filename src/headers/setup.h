# include <stdio.h>
# include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <openssl/bn.h>
#include "random.h"

typedef struct
{
    /* data 


    # public key
    # nonce pair list []
    # nonce commitments pair list []
    */

int index;
int threshold;
int participants;
BN_CTX* ctx;
BIGNUM* secret_share;
BIGNUM* verify_share;
BIGNUM* public_key; 
struct coeff_list *coefficient_list;
struct pub_commit_packet *pub_commit;
    
} participant;

typedef struct
{
    /* data

    # message
    # public key
    # participal indexes list []
    # commitments pair list []
    # nonce commitment pair list []

    */
int index;
int threshold;
int participants;   
} aggregator;


typedef struct 
{
size_t  coefficient_list_len;
BIGNUM* coeff;
} coeff_list;


typedef struct {

    int sender_index;
    size_t commit_len;
    BIGNUM* commit;
} pub_commit_packet;


typedef struct
{
    int coefficient;
    int exponent;
} term;

typedef struct
{
    int n;
    struct term *t;    
} poly;



/*Pedersen Distributed Key Generation*/
void init_coeff_list(participant* participant);

void free_coeff_list(participant* participant);

BIGNUM* define_polynomyial(participant* participant, int r_participant_index);

void free_polynomial(BIGNUM* polynomial);

pub_commit_packet init_pub_commit(participant* participant);

void free_pub_commit(pub_commit_packet* pub_commit);

bool accept_pub_commit(participant* r_participant, pub_commit_packet* pub_commit);

BIGNUM* init_sec_share(participant* participant, int r_participant_index);

bool accept_sec_share(participant* s_participant, int r_participant_index, BIGNUM* sec_share);

bool gen_keys(participant* s_participant);

