#include "../headers/signing.h"

#include <openssl/bn.h>

#include "../headers/setup.h"

/*Preprocess stage*/
pub_share_packet init_pub_share(participant* p) {
  /*
  # create nonce list [];
  #
  # 1. Preprocess(π) ->  (i, ⟨D_i_j⟩), 1 ≤ j ≤ π | i - participant idetifier
  where : (D_ij) is nonce pair of G over random number -> (g^d_ij)
  #
  # 2. stores locally (d_i, ⟨D_i_j⟩;
  # broadcast nonce commitments pair list to aggregator[];
  */
}

/*Signing stage*/

bool accept_pub_share(aggregator* reciever, pub_share_packet* packet) {
  /*
  # 1. Aggregator computes the signing group’s public commitment ∏ D_ij
  # selected participants P_i broadcast tuple (m, R, S, D_ij ) to every one of
  them.
  #
  */
}

int lagrange_coefficient(int self, int* participant_indexes,
                         int num_participants) {
  /*
  For a fixed set S = {p1, . . . , pt} of t participant identifiers in the
  signing operation, let λi = π xpj /(x_pj − x_pi) denote the ith Lagrange
  coefficient for interpolating over S
  */
  mpz_t numerator, denominator, res, q;
  mpz_init(numerator);
  mpz_init(denominator);
  mpz_init(res);
  mpz_init(q);

  mpz_set_ui(numerator, 1);
  mpz_set_ui(denominator, 1);

  mpz_set_str(q, Q, 10);

  for (int i = 0; i < num_participants; i++) {
    int index = participant_indexes[i];
    if (index == self) {
      continue;
    }
    mpz_mul_ui(numerator, numerator, index);
    mpz_mul_ui(denominator, denominator, (index - self));
  }

  mpz_invert(denominator, denominator, q);
  mpz_mul(res, numerator, denominator);
  mpz_mod(res, res, q);

  int result = mpz_get_ui(res);

  mpz_clear(numerator);
  mpz_clear(denominator);
  mpz_clear(res);
  mpz_clear(q);

  return result;
}

bool accept_tuple(participant* reciever, tuple_packet* packet) {}

BIGNUM* init_sig_share(participant* p) {
  /*
  #
  # 1. checks to make sure that D_ij corresponds to a valid unused nonce d_ij
  # 2. Each P_i computes the challenge c = H(m, R).
  # 3. Each Pi computes their response z_i, using their long-lived secret share
  s_i where: zi = di + λi * si *c, using S to determine λi (S is set of
  idetifiers of t participant) # 4. sent response z_i to aggregator
  */
}

bool accept_sig_share(aggregator* reciever, BIGNUM* sig_share) {
  /*
  # Verifies the validity of each response by checking g
  zi ?= Di * Yi ^ (c * λi)
  */
}

BIGNUM* signature(aggregator* p) {
  /*
  # 1. Compute the group’s response z = ∑ z_i
  # 2. Publish the signature σ = (z, c) along with the message m
  */
}