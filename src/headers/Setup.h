#include "random.h"


struct participant
{
    /* data 

    # int index
    # int treshold
    # int participants
    # coefficient list [] 
    # coefficient commitment []
    # share list []
    # verification share
    # secret signing share 
    # nonce pair list []
    # nonce commitments pair list []

    */

    
};

struct aggregator
{
    /* data

    # message
    # public key
    # participal indexes list []
    # commitments pair list []
    # nonce commitment pair list []

    */
};


/*Pedersen Distributed Key Generation*/
unsigned char init_pub_commit()
{



/*
# 1. Generate polynomial with random coefficients, and with degree equal to the t-1.
#
# create coefficient list []; 
# (a_i_0, . . ., a_i_(t - 1)) <- $ ℤq

#  2. broadcast coefficient commitment to all participants P_i where
# coefficient commitment[]:  𝜙_i_j == G ^ a_i_j : 0 ≤ j ≤ t - 1
#
*/

}    
unsigned char define_polynomyial()
{
    /*
# 1. Every participant Pi define a polynomial
# f_i(x) = ∑ a_i_j * x^j, 0 ≤ j ≤ t - 1
#
# Horner method ?
   
int horner(int coefficient list[], int n, int x)
{
    int result = coefficient list[0]; // Initialize result
 
   // Evaluate value of polynomial using Horner's method
    for (int i=1; i<n; i++)
        result = result*x + coefficient list[i];
 
    return result;
}
int coefficient list[];
int n = sizeof(coefficient list)/sizeof(coefficient list[0]);

# return y % secp256k1.Q
*/
}

unsigned char fwd_sec_share()
{
/*
# 1 .Each participant Pi securely sends to each other participant Pj a secret share:
# (j, f_i(j))
*/

}



unsigned int verify_sec_share()
{

/*
# 1. Every participant Pi verifies the share they received from each other participant Pj , where i != j, by verifying:
# # g ^ f_j(i) ≟ ∏ 𝜙_j_k ^ (i ^ k mod q)  : 0 ≤ k ≤ t - 1
#
# if (success){pass}
# else {abort & investigate??} 
*/

}

unsigned char gen_keys()
{

/*
# 1. will create long-lived private signing share:
# s_i = ∑ f_j(i), 1 ≤ j ≤ n
#
# stores s_i
#
# 2. Each participant then calculates their own public verification share:
# Y_i = G ^ s_i
*/

}