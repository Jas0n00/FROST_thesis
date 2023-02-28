# include <stdio.h>
# include <stdlib.h>
#include <stdint.h>
#include <openssl/bn.h>
#include "headers/setup.h"

int main(int argc, char const *argv[])
{
    

int threshold = 2;
int participants = 3;

/*Initialize Participants*/
participant p0 = {.index = 0, .threshold = threshold, .participants = participants};
participant p1 = {.index = 1, .threshold = threshold, .participants = participants};
participant p2 = {.index = 2, .threshold = threshold, .participants = participants};

/*Initialize Public Commitments*/
pub_commit_packet p0_pub_commit = init_pub_commit(&p0);
pub_commit_packet p1_pub_commit = init_pub_commit(&p1);
pub_commit_packet p2_pub_commit = init_pub_commit(&p2);

/*Broadcast*/
accept_pub_commit(&p0, &p1_pub_commit);
accept_pub_commit(&p0, &p2_pub_commit);
accept_pub_commit(&p1, &p0_pub_commit);
accept_pub_commit(&p1, &p2_pub_commit);
accept_pub_commit(&p2, &p0_pub_commit);
accept_pub_commit(&p2, &p1_pub_commit);

/*Send & Verifies Secret Shares*/
BIGNUM* p01_sec_share = init_sec_share(&p0, p1.index);
accept_sec_share(&p0, p1.index, p01_sec_share);
BIGNUM* p02_sec_share = init_sec_share(&p0, p2.index);
accept_sec_share(&p0, p2.index, p02_sec_share);
BIGNUM* p10_sec_share = init_sec_share(&p1, p0.index);
accept_sec_share(&p1, p0.index, p10_sec_share);
BIGNUM* p12_sec_share = init_sec_share(&p1, p2.index);
accept_sec_share(&p1, p2.index, p12_sec_share);  
BIGNUM* p20_sec_share = init_sec_share(&p2, p0.index);
accept_sec_share(&p2, p0.index, p20_sec_share);
BIGNUM* p21_sec_share = init_sec_share(&p2, p1.index);
accept_sec_share(&p2, p1.index, p21_sec_share);

/*Generate Keys*/
gen_keys(&p0);
gen_keys(&p1);
gen_keys(&p2);


return 0;
}
