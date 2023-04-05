#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>

#include "../headers/setup.h"
#include "../headers/signing.h"

int main(int argc, char const* argv[]) {
  int threshold = 3;
  int participants = 5;

  /*Initialize Participants*/
  participant p0 = {.index = 0,
                    .threshold = threshold,
                    .participants = participants,
                    .pub_commit = NULL,
                    .rcvd_commit_head = NULL,
                    .rcvd_sec_share_head = NULL};
  participant p1 = {.index = 1,
                    .threshold = threshold,
                    .participants = participants,
                    .pub_commit = NULL,
                    .rcvd_commit_head = NULL,
                    .rcvd_sec_share_head = NULL};
  participant p2 = {.index = 2,
                    .threshold = threshold,
                    .participants = participants,
                    .pub_commit = NULL,
                    .rcvd_commit_head = NULL,
                    .rcvd_sec_share_head = NULL};
  participant p3 = {.index = 3,
                    .threshold = threshold,
                    .participants = participants,
                    .pub_commit = NULL,
                    .rcvd_commit_head = NULL,
                    .rcvd_sec_share_head = NULL};
  participant p4 = {.index = 4,
                    .threshold = threshold,
                    .participants = participants,
                    .pub_commit = NULL,
                    .rcvd_commit_head = NULL,
                    .rcvd_sec_share_head = NULL};

  /*Initialize Public Commitments*/
  pub_commit_packet* p0_pub_commit = init_pub_commit(&p0);
  pub_commit_packet* p1_pub_commit = init_pub_commit(&p1);
  pub_commit_packet* p2_pub_commit = init_pub_commit(&p2);
  pub_commit_packet* p3_pub_commit = init_pub_commit(&p3);
  pub_commit_packet* p4_pub_commit = init_pub_commit(&p4);

  /*Broadcast*/
  accept_pub_commit(&p0, p1_pub_commit);
  accept_pub_commit(&p0, p2_pub_commit);
  accept_pub_commit(&p0, p3_pub_commit);
  accept_pub_commit(&p0, p4_pub_commit);

  accept_pub_commit(&p1, p0_pub_commit);
  accept_pub_commit(&p1, p2_pub_commit);
  accept_pub_commit(&p1, p3_pub_commit);
  accept_pub_commit(&p1, p4_pub_commit);

  accept_pub_commit(&p2, p0_pub_commit);
  accept_pub_commit(&p2, p1_pub_commit);
  accept_pub_commit(&p2, p3_pub_commit);
  accept_pub_commit(&p2, p4_pub_commit);

  accept_pub_commit(&p3, p0_pub_commit);
  accept_pub_commit(&p3, p1_pub_commit);
  accept_pub_commit(&p3, p2_pub_commit);
  accept_pub_commit(&p3, p4_pub_commit);

  accept_pub_commit(&p4, p0_pub_commit);
  accept_pub_commit(&p4, p1_pub_commit);
  accept_pub_commit(&p4, p2_pub_commit);
  accept_pub_commit(&p4, p3_pub_commit);

  /*Send & Verifies Secret Shares*/
  BIGNUM* p0_sec_share = init_sec_share(&p0, p0.index);
  accept_sec_share(&p0, p0.index, p0_sec_share);
  BIGNUM* p01_sec_share = init_sec_share(&p0, p1.index);
  accept_sec_share(&p1, p0.index, p01_sec_share);
  BIGNUM* p02_sec_share = init_sec_share(&p0, p2.index);
  accept_sec_share(&p2, p0.index, p02_sec_share);
  BIGNUM* p03_sec_share = init_sec_share(&p0, p3.index);
  accept_sec_share(&p3, p0.index, p03_sec_share);
  BIGNUM* p04_sec_share = init_sec_share(&p0, p4.index);
  accept_sec_share(&p4, p0.index, p04_sec_share);

  BIGNUM* p1_sec_share = init_sec_share(&p1, p1.index);
  accept_sec_share(&p1, p1.index, p1_sec_share);
  BIGNUM* p10_sec_share = init_sec_share(&p1, p0.index);
  accept_sec_share(&p0, p1.index, p10_sec_share);
  BIGNUM* p12_sec_share = init_sec_share(&p1, p2.index);
  accept_sec_share(&p2, p1.index, p12_sec_share);
  BIGNUM* p13_sec_share = init_sec_share(&p1, p3.index);
  accept_sec_share(&p3, p1.index, p13_sec_share);
  BIGNUM* p14_sec_share = init_sec_share(&p1, p4.index);
  accept_sec_share(&p4, p1.index, p14_sec_share);

  BIGNUM* p2_sec_share = init_sec_share(&p2, p2.index);
  accept_sec_share(&p2, p2.index, p2_sec_share);
  BIGNUM* p20_sec_share = init_sec_share(&p2, p0.index);
  accept_sec_share(&p0, p2.index, p20_sec_share);
  BIGNUM* p21_sec_share = init_sec_share(&p2, p1.index);
  accept_sec_share(&p1, p2.index, p21_sec_share);
  BIGNUM* p23_sec_share = init_sec_share(&p2, p3.index);
  accept_sec_share(&p3, p2.index, p23_sec_share);
  BIGNUM* p24_sec_share = init_sec_share(&p2, p4.index);
  accept_sec_share(&p4, p2.index, p24_sec_share);

  BIGNUM* p3_sec_share = init_sec_share(&p3, p3.index);
  accept_sec_share(&p3, p3.index, p3_sec_share);
  BIGNUM* p30_sec_share = init_sec_share(&p3, p0.index);
  accept_sec_share(&p0, p3.index, p30_sec_share);
  BIGNUM* p31_sec_share = init_sec_share(&p3, p1.index);
  accept_sec_share(&p1, p3.index, p31_sec_share);
  BIGNUM* p32_sec_share = init_sec_share(&p3, p2.index);
  accept_sec_share(&p2, p3.index, p32_sec_share);
  BIGNUM* p34_sec_share = init_sec_share(&p3, p4.index);
  accept_sec_share(&p4, p3.index, p34_sec_share);

  BIGNUM* p4_sec_share = init_sec_share(&p4, p4.index);
  accept_sec_share(&p4, p4.index, p4_sec_share);
  BIGNUM* p40_sec_share = init_sec_share(&p4, p0.index);
  accept_sec_share(&p0, p4.index, p40_sec_share);
  BIGNUM* p41_sec_share = init_sec_share(&p4, p1.index);
  accept_sec_share(&p1, p4.index, p41_sec_share);
  BIGNUM* p42_sec_share = init_sec_share(&p4, p2.index);
  accept_sec_share(&p2, p4.index, p42_sec_share);
  BIGNUM* p43_sec_share = init_sec_share(&p4, p3.index);
  accept_sec_share(&p3, p4.index, p43_sec_share);

  /*Generate Keys*/
  gen_keys(&p0);
  gen_keys(&p1);
  gen_keys(&p2);
  gen_keys(&p3);
  gen_keys(&p4);

  /*### Signing ###*/

  participant threshold_set[] = {p0, p1, p2};
  char message[] = "17896543758";
  size_t m_len = sizeof(message);
  size_t set_size = sizeof(threshold_set) / sizeof(participant);

  aggregator agg = {
      .threshold = threshold,
      .rcvd_pub_share_head = NULL,
  };

  /*Initialize Public Share commitment with nonces*/
  pub_share_packet* p0_pub_share = init_pub_share(&p1);
  pub_share_packet* p1_pub_share = init_pub_share(&p0);
  pub_share_packet* p2_pub_share = init_pub_share(&p2);

  accept_pub_share(&agg, p0_pub_share);
  accept_pub_share(&agg, p1_pub_share);
  accept_pub_share(&agg, p2_pub_share);

  tuple_packet* agg_tuple =
      init_tuple_packet(&agg, message, m_len, threshold_set, set_size);

  accept_tuple(&p1, agg_tuple);
  accept_tuple(&p0, agg_tuple);
  accept_tuple(&p2, agg_tuple);

  BIGNUM* sig_share_p0 = init_sig_share(&p0);
  BIGNUM* sig_share_p1 = init_sig_share(&p1);
  BIGNUM* sig_share_p2 = init_sig_share(&p2);

  accept_sig_share(&agg, sig_share_p0, p0.index);
  accept_sig_share(&agg, sig_share_p1, p1.index);
  accept_sig_share(&agg, sig_share_p2, p2.index);

  signature_packet sig = signature(&agg);

  printf("\nSignature: ");
  BN_print_fp(stdout, sig.signature);
  printf("\nHash: ");
  BN_print_fp(stdout, sig.hash);
  printf("\n");

  verify_signature(&sig, message, p0.public_key);
  return 0;
}
