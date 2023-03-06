#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../headers/setup.h"
#include "../headers/globals.h"    



void init_coeff_list(participant* p)
{

/*
zavola sa v init_pub_commit
funkcia alokuje a ulozi do struktury participant
# 
# alocate coefficient list []; (size of list is always t)
# fulfill with random numbers: (a_i_0, . . ., a_i_(t - 1)) <- $ ℤq
*/

    int threshold = p->threshold;
    p->list = malloc(sizeof(coeff_list));
    p->list->coefficient_list_len = threshold;
    p->list->coeff = OPENSSL_malloc(sizeof(BIGNUM*) * threshold); // Note the use of sizeof(BIGNUM*)

    // Fill the coefficient_list with random BIGNUMs
    for (int i = 0; i < threshold; i++) {
        p->list->coeff[i] = BN_new(); // Call BN_new() before allocating memory
        BN_copy(p->list->coeff[i], generate_rand());
    }
}

void free_coeff_list( participant* p)
{}


pub_commit_packet* init_pub_commit(participant* p)
{
int threshold = p->threshold;

/* call init_coeff_list */
init_coeff_list(p);

/* allocate memory for the public commit array */
p->pub_commit = malloc(sizeof(pub_commit_packet));
p->pub_commit->sender_index = p->index;
p->pub_commit->commit_len = threshold;
p->pub_commit->commit = OPENSSL_malloc(sizeof(BIGNUM*) * threshold);


/* fulfill with G ^ a_i_j where: 0 ≤ j ≤ t - 1 */
for(int j=0; j<threshold; j++)
{
    p->pub_commit->commit[j] = BN_new();
    BIGNUM* result = BN_new();
    BN_mod_exp(result, b_generator, p->list->coeff[j], order, BN_CTX_new());
    BN_copy(p->pub_commit->commit[j],result);
}


return p->pub_commit;
}


void free_pub_commit(pub_commit_packet* pub_commit)
{}


bool accept_pub_commit( participant* receiver, pub_commit_packet* pub_commit)
{
 /*1. P_i broadcast public commitment (whole list) to all participants P_j
 P_j saves it to matrix_rcvd_commits*/

int threshold = receiver->threshold;
int num_packets = receiver->participants;


if (receiver->rcvd_commits == NULL) {
// Allocate memory for received commits
receiver->rcvd_commits = malloc(sizeof(rcvd_pub_commits));
receiver->rcvd_commits->num_packets = num_packets;
receiver->rcvd_commits->rcvd_packets = malloc(sizeof(pub_commit_packet) * num_packets);

    // Allocate memory for each packet
    for (int i = 0; i < num_packets; i++) {
        receiver->rcvd_commits->rcvd_packets[i].commit_len = 0;
        receiver->rcvd_commits->rcvd_packets[i].sender_index = -1;
        receiver->rcvd_commits->rcvd_packets[i].commit = NULL;
    }
}

    //Fullfil array
    for(int i = 0; i < num_packets; i++){
        if(pub_commit->sender_index == i){
          // Allocate memory for packet commit array
          if (receiver->rcvd_commits->rcvd_packets[i].commit == NULL) {
            receiver->rcvd_commits->rcvd_packets[i].commit = OPENSSL_malloc(sizeof(BIGNUM*) * pub_commit->commit_len);
        }
        // Copy values from pub_commit packet to received packet
        receiver->rcvd_commits->rcvd_packets[i].commit_len = pub_commit->commit_len;
        receiver->rcvd_commits->rcvd_packets[i].sender_index = pub_commit->sender_index;
        BN_copy(receiver->rcvd_commits->rcvd_packets[i].commit, pub_commit->commit);
        }
    }

return true;
}


BIGNUM* init_sec_share( participant* sender, int reciever_index)
{

int threshold = sender->threshold;
BIGNUM* result = BN_new();
//convert integer r_index to bignum
BIGNUM* b_index = BN_new();
BN_set_word(b_index, reciever_index);

sender->func = malloc(sizeof(poly));
sender->func->n = threshold;
sender->func->t = malloc(sizeof(term) * threshold);

/*
# 1. Define a polynomial
# f_i(x) = ∑ a_i_j * x^j, 0 ≤ j ≤ t - 1
*/
 for (int i = 0; i < threshold; i++) {
    sender->func->t[i].coefficient = BN_new();
    BN_copy(sender->func->t[i].coefficient, sender->list->coeff[i]);
    
    //convert integer exponent to bignum
    BIGNUM* b_expo = BN_new();
    BN_set_word(b_expo, i);
    sender->func->t[i].exponent = b_expo;
    }

/*
# 2. Calculate a polynomial
# f_i(x) = ∑ a_i_j * x^j, 0 ≤ j ≤ t - 1
*/
for (int i = 0; i < sender->func->n; i++){
    BIGNUM* expo_product = BN_new();
    BIGNUM* multi_product = BN_new();

    BN_mod_exp(expo_product, b_index, sender->func->t[i].exponent, order, BN_CTX_new());
    BN_mod_mul(multi_product, sender->func->t[i].coefficient, expo_product, order, BN_CTX_new());
    BN_mod_add(result, result, multi_product, order, BN_CTX_new());
}


return result; 
}


bool accept_sec_share(participant* receiver, int sender_index, BIGNUM* sec_share)
{
int threshold = receiver->threshold;
receiver->rcvd_sec_share = OPENSSL_malloc(sizeof(BIGNUM*) * threshold);

/*
# 1. Save sent sec_share to rcvd_sec_share[]
*/









/*
# 2. Every participant Pi verifies the share they received from each other participant Pj , where i != j, by verifying:
# # G ^ f_j(i) ≟ ∏ 𝜙_j_k ^ (i ^ k mod G)  : 0 ≤ k ≤ t - 1
#
*/
}


bool gen_keys( participant* p)
{
/*
# 1. will create long-lived secret share:
# s_i = ∑ f_j(i), 1 ≤ j ≤ n
# sum of share list [] -> store secret share;
#
#
# 2. Each participant then calculates their own public verification share:
# Y_i = G ^ s_i
#
# 3. Each participant then calculates public key:
# Y = ∏ 𝜙_j_0
*/
}