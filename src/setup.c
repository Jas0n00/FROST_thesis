#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <openssl/bn.h>
#include "headers/setup.h"



void init_coeff_list(participant* participant)
{
/*
zavola sa v init_pub_commit
funkcia alokuje a ulozi do struktury participant
# 
# alocate coefficient list []; (size of list is always t)
# fulfill with random numbers: (a_i_0, . . ., a_i_(t - 1)) <- $ ℤq
*/
}


void free_coeff_list( participant* participant)
{}

BIGNUM* define_polynomyial( participant* participant, int r_participant_index)
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

pub_commit_packet init_pub_commit(participant* participant)
{
int threshold = participant->threshold;
pub_commit_packet packet;

/* call init_coeff_list */

/*pull coefficients from particpant*/

/* allocate memory for the commit array */

/* fulfill with G ^ a_i_j where: 0 ≤ j ≤ t - 1 */
for(int j=0; j<threshold; j++)
{
    /* compute G ^ a_i_j and store in commit[j] */
}


return packet;
}


void free_pub_commit(pub_commit_packet* pub_commit)
{}


bool accept_pub_commit( participant* r_participant, pub_commit_packet* pub_commit)
{
 /*2. P_i broadcast public commitment (whole list) to all participants P_j
 P_j saves it to rcvd_pub_commit[]
*/
}


BIGNUM* init_sec_share( participant* s_participant, int r_participant_index)
{
/*
volaj define polynomial kde dosadis s_participant, r_participant_index
# 1 .Each participant Pi securely sends to each other participant Pj a secret share:
# (j, f_i(j))
# save it and each share append to share list []
*/

 BIGNUM* share = BN_new();
}


bool accept_sec_share(participant* s_participant, int r_participant_index, BIGNUM* sec_share)
{
/*
# 1. Every participant Pi verifies the share they received from each other participant Pj , where i != j, by verifying:
# # G ^ f_j(i) ≟ ∏ 𝜙_j_k ^ (i ^ k mod G)  : 0 ≤ k ≤ t - 1
#
# if (success){pass}
# else {abort & investigate??} 
*/
}


bool gen_keys( participant* participant)
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