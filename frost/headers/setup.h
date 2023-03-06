#ifndef PARTICIPANT_ATRIBUTES
#define PARTICIPANT_ATRIBUTES

# include <stdio.h>
# include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <openssl/bn.h>


typedef struct {
    size_t  coefficient_list_len;
    BIGNUM** coeff;
} coeff_list;


typedef struct {

    int sender_index;
    size_t commit_len;
    BIGNUM** commit;
} pub_commit_packet;


typedef struct{
    int sender_index;
    BIGNUM** pub_share;
} pub_share_packet;


typedef struct{
    BIGNUM* coefficient;
    BIGNUM* exponent;
} term;


typedef struct{
    int n;
    term *t;    
} poly;


typedef struct
{
    size_t  num_packets;
    pub_commit_packet* rcvd_packets;
} rcvd_pub_commits;



typedef struct{
    int index;
    int threshold;
    int participants;
    BIGNUM* secret_share;
    BIGNUM* verify_share;
    BIGNUM* public_key;
    BIGNUM* nonce; 
    coeff_list* list;
    pub_commit_packet* pub_commit;
    pub_share_packet* pub_share;
    poly* func;
    rcvd_pub_commits* rcvd_commits;
    BIGNUM** rcvd_sec_share;
} participant;






/*Pedersen Distributed Key Generation*/

pub_commit_packet* init_pub_commit(participant* p);

void free_pub_commit(pub_commit_packet* pub_commit);

bool accept_pub_commit(participant* reciever, pub_commit_packet* pub_commit);

BIGNUM* init_sec_share(participant* sender, int reciever_index);

bool accept_sec_share(participant* reciever, int sender_index, BIGNUM* sec_share);

bool gen_keys(participant* p);

#endif