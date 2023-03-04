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

BIGNUM* define_polynomyial( participant* sender, int reciever_index)
{
/*
za kazdym volanim bude vraciat uz vysledok hodnoty
vytiahne uz ulozene coefficienty a dosadi r_index
vola sa v init_sec_share

# 1. Every participant Pi define a polynomial
# f_i(x) = ∑ a_i_j * x^j, 0 ≤ j ≤ t - 1
# 
# for loop inserting terms to struct poly
#
# Horner method ?
*/
}

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
    BN_mod_exp(result, generator, p->list->coeff[j], order, BN_CTX_new());
    BN_copy(p->pub_commit->commit[j],result);
}


return p->pub_commit;
}


void free_pub_commit(pub_commit_packet* pub_commit)
{}


bool accept_pub_commit( participant* reciever, pub_commit_packet* pub_commit)
{
 /*2. P_i broadcast public commitment (whole list) to all participants P_j
 P_j saves it to rcvd_pub_commit[]
*/
}


BIGNUM* init_sec_share( participant* sender, int reciever_index)
{
/*
volaj define polynomial kde dosadis s_participant, r_participant_index
# 1 .Each participant Pi securely sends to each other participant Pj a secret share:
# (j, f_i(j))
# save it and each share append to share list []
*/

 
}


bool accept_sec_share(participant* reciever, int sender_index, BIGNUM* sec_share)
{
/*
# 1. Every participant Pi verifies the share they received from each other participant Pj , where i != j, by verifying:
# # G ^ f_j(i) ≟ ∏ 𝜙_j_k ^ (i ^ k mod G)  : 0 ≤ k ≤ t - 1
#
# if (success){pass}
# else {abort & investigate??} 
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