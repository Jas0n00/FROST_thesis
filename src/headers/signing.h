#include "random.h"


/*Preprocess stage*/
unsigned char fwd_nonces_commit ()
{
/*
# create nonce list [];
#
# 1. Preprocess(π) ⭢  (i, ⟨D_i_j⟩), 1 ≤ j ≤ π | i - participant idetifier 
where : (D_ij) is nonce pair of G over random number -> (g^d_ij)
#
# 2. stores locally (d_i, ⟨D_i_j⟩;
# broadcast nonce commitments pair list to aggregator[];
*/

}

/*Signing stage*/

unsigned char fwd_group_pub_commit ()
{
/*
# 1. Aggregator computes the signing group’s public commitment ∏ D_ij
# selected participants P_i broadcast tuple (m, R, S, D_ij ) to every one of them.
#
*/
}

unsigned char fwd_sig_commit()
{

    /*
    #
    # 1. checks to make sure that D_ij corresponds to a valid unused nonce d_ij
    # 2. Each P_i computes the challenge c = H(m, R).
    # 3. Each Pi computes their response z_i, using their long-lived secret share s_i
    where: zi = di + λi * si *c, using S to determine λi (S is set of idetifiers of t participant)
    # 4. sent response z_i to aggregator
    */
}

unsigned int verify_sig_commit()
{

    /*
    # Verifies the validity of each response by checking g
    zi ?= Di * Yi ^ (c * λi)
    */
}

unsigned char signature()
{

    /*
    # 1. Compute the group’s response z = ∑ z_i
    # 2. Publish the signature σ = (z, c) along with the message m
    */
}