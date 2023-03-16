#include <openssl/bn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../headers/setup.h"
#include "../headers/signing.h"

int main(int argc, char const* argv[]) {
  /*### Ped-DKG ###*/
  int threshold = 2;
  int participants = 3;

  /*Initialize Participants*/
  participant p0 = {.index = 0,
                    .threshold = threshold,
                    .participants = participants,
                    .pub_commit = NULL,
                    .rcvd_commit_head = NULL,
                    .rcvd_sec_share = NULL};
  participant p1 = {.index = 1,
                    .threshold = threshold,
                    .participants = participants,
                    .pub_commit = NULL,
                    .rcvd_commit_head = NULL,
                    .rcvd_sec_share = NULL};
  participant p2 = {.index = 2,
                    .threshold = threshold,
                    .participants = participants,
                    .pub_commit = NULL,
                    .rcvd_commit_head = NULL,
                    .rcvd_sec_share = NULL};

  /*Initialize Public Commitments*/
  pub_commit_packet* p0_pub_commit = init_pub_commit(&p0);
  pub_commit_packet* p1_pub_commit = init_pub_commit(&p1);
  pub_commit_packet* p2_pub_commit = init_pub_commit(&p2);

  /*Broadcast*/
  accept_pub_commit(&p0, p1_pub_commit);
  accept_pub_commit(&p0, p2_pub_commit);
  accept_pub_commit(&p1, p0_pub_commit);
  accept_pub_commit(&p1, p2_pub_commit);
  accept_pub_commit(&p2, p0_pub_commit);
  accept_pub_commit(&p2, p1_pub_commit);

  /*Send & Verifies Secret Shares*/
  BIGNUM* p01_sec_share = init_sec_share(&p0, p1.index);
  accept_sec_share(&p1, p0.index, p01_sec_share);
  BIGNUM* p02_sec_share = init_sec_share(&p0, p2.index);
  accept_sec_share(&p2, p0.index, p02_sec_share);
  BIGNUM* p10_sec_share = init_sec_share(&p1, p0.index);
  accept_sec_share(&p0, p1.index, p10_sec_share);
  BIGNUM* p12_sec_share = init_sec_share(&p1, p2.index);
  accept_sec_share(&p2, p1.index, p12_sec_share);
  BIGNUM* p20_sec_share = init_sec_share(&p2, p0.index);
  accept_sec_share(&p0, p2.index, p20_sec_share);
  BIGNUM* p21_sec_share = init_sec_share(&p2, p1.index);
  accept_sec_share(&p1, p2.index, p21_sec_share);

  /*Generate Keys*/
  gen_keys(&p0);
  gen_keys(&p1);
  gen_keys(&p2);

  /*### Signing ###*/

  participant threshold_set[] = {p0, p1};
  char message[] = "Hello";
  size_t m_len = sizeof(message) / sizeof(char) - 1;

  aggregator agg = {
      .threshold = threshold, .rcvd_pub_shares = NULL, .rcvd_sig_shares = NULL};

  /*Initialize Public Share commitment with nonces*/
  pub_share_packet* p0_pub_share = init_pub_share(&p0);
  pub_share_packet* p1_pub_share = init_pub_share(&p1);

  accept_pub_share(&agg, p0_pub_share);
  accept_pub_share(&agg, p1_pub_share);

  tuple_packet* agg_tuple =
      init_tuple_packet(&agg, message, m_len, threshold_set, threshold);

  accept_tuple(&p0, agg_tuple);
  accept_tuple(&p1, agg_tuple);

  BIGNUM* sig_share_p0 = init_sig_share(&p0);
  BIGNUM* sig_share_p1 = init_sig_share(&p1);

  accept_sig_share(&agg, sig_share_p0);
  accept_sig_share(&agg, sig_share_p1);

  BIGNUM* sig = signature(&agg);
  return 0;
}
