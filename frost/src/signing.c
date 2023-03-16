#include "../headers/signing.h"

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../headers/globals.h"
#include "../headers/setup.h"

/*Preprocess stage*/
pub_share_packet* init_pub_share(participant* p) {
  /*
  # create nonce list [];
  #
  # 1. Preprocess(π) ->  (i, ⟨D_i_j⟩), 1 ≤ j ≤ π | i - participant idetifier
  where : (D_ij) is nonce pair of G over random number -> (g^d_ij)
  #
  # 2. stores locally (d_i, ⟨D_i_j⟩;
  # broadcast nonce commitments pair list to aggregator[];
  */
  p->pub_share = malloc(sizeof(pub_share_packet));
  p->pub_share->sender_index = p->index;
  p->pub_share->pub_share = OPENSSL_malloc(sizeof(BIGNUM*));
  p->pub_share->pub_share = BN_new();

  BN_copy(p->nonce, generate_rand());
  BN_mod_exp(p->pub_share->pub_share, b_generator, p->nonce, order,
             BN_CTX_new());

  return p->pub_share;
}

/*Signing stage*/

bool accept_pub_share(aggregator* receiver, pub_share_packet* packet) {
  int threshold = receiver->threshold;
  int sender_index = packet->sender_index;

  if (receiver->rcvd_pub_shares == NULL) {
    receiver->rcvd_pub_shares = malloc(sizeof(rcvd_pub_shares));
    receiver->rcvd_pub_shares->num_pub_shares = threshold;
    receiver->rcvd_pub_shares->rcvd_packets =
        OPENSSL_malloc(sizeof(pub_share_packet) * threshold);

    for (int i = 0; i < threshold; i++) {
      receiver->rcvd_pub_shares->rcvd_packets[i].sender_index = -1;
      receiver->rcvd_pub_shares->rcvd_packets[i].pub_share = NULL;
    }
  }

  if (receiver->rcvd_pub_shares->rcvd_packets[sender_index].pub_share = NULL) {
    receiver->rcvd_pub_shares->rcvd_packets[sender_index].sender_index =
        packet->sender_index;
    receiver->rcvd_pub_shares->rcvd_packets[sender_index].pub_share = BN_new();
    BN_copy(receiver->rcvd_pub_shares->rcvd_packets[sender_index].pub_share,
            packet->pub_share);
    return true;
  } else {
    printf("Accepting public share failed! ");
    return false;
  }
}

BIGNUM* lagrange_coefficient(participant* p) {
  BIGNUM *numerator, *denominator, *res, *tmp;
  int i, index;
  int num_participants = p->rcvd_tuple->S_size;
  // Initialize BIGNUMs
  numerator = BN_new();
  denominator = BN_new();
  res = BN_new();
  tmp = BN_new();

  // Set values for numerator, denominator and q
  BN_one(numerator);
  BN_one(denominator);

  for (i = 0; i < num_participants; i++) {
    index = p->rcvd_tuple->S[i].index;
    if (index == p->index) {
      continue;
    }
    BN_mul_word(numerator, index);
    BN_sub(tmp, BN_new_word(index), BN_new_word(p->index));
    BN_mul(denominator, denominator, tmp, NULL);
  }

  BN_mod_inverse(tmp, denominator, order, NULL);
  BN_mul(res, numerator, tmp, NULL);
  BN_mod(res, res, order, NULL);

  // Free BIGNUMs
  BN_free(numerator);
  BN_free(denominator);
  BN_free(res);
  BN_free(tmp);

  return res;
}

bool R_pub_commit_compute(aggregator* a, participant* set, int set_size) {
  /*
 # 1. Aggregator computes the signing group’s public commitment ∏ D_ij
 # selected participants P_i broadcast tuple (m, R, S, D_ij ) to every one of
 them.
 #
 */
  int size_check = 0;

  for (int i = 0; i < set_size; i++) {
    for (int j = 0; j < a->rcvd_pub_shares->num_pub_shares; j++) {
      if (set[i].index == a->rcvd_pub_shares->rcvd_packets[j].sender_index) {
        size_check++;
      }
    }
  }

  if (size_check == set_size) {
    BIGNUM* res_R_pub_commit = BN_new();
    BN_set_word(res_R_pub_commit, 1);

    for (int j = 0; j < a->rcvd_pub_shares->num_pub_shares; j++) {
      BN_mod_add(res_R_pub_commit, res_R_pub_commit,
                 a->rcvd_pub_shares->rcvd_packets[j].pub_share, order,
                 BN_CTX_new());
    }
    a->R_pub_commit = res_R_pub_commit;
    return true;
  } else {
    printf("Mismatch of received public shares!");
    return false;
  }
}

tuple_packet* init_tuple_packet(aggregator* a, char* m, size_t m_size,
                                participant* set, int set_size) {
  if (R_pub_commit_compute(a, set, set_size)) {
    a->tuple = malloc(sizeof(tuple_packet));
    a->tuple->m = malloc(sizeof(char) * m_size);
    a->tuple->m_size = m_size;
    BN_copy(a->tuple->R, a->R_pub_commit);
    a->tuple->S = malloc(sizeof(participant) * set_size);
    a->tuple->S_size = a->threshold;

    for (int i = 0; i < set_size; i++) {
      a->tuple->S[i] = set[i];
    }
    for (int i = 0; i < m_size; i++) {
      a->tuple->m[i] = m[i];
    }
  }

  return a->tuple;
}
bool accept_tuple(participant* receiver, tuple_packet* packet) {
  receiver->rcvd_tuple = malloc(sizeof(tuple_packet));
  BN_copy(receiver->rcvd_tuple->m, packet->m);
  BN_copy(receiver->rcvd_tuple->R, packet->R);
  receiver->rcvd_tuple->S_size = packet->S_size;
  receiver->rcvd_tuple->S = malloc(sizeof(participant) * packet->S_size);

  for (int i = 0; i < packet->S_size; i++) {
    receiver->rcvd_tuple->S[i] = packet->S[i];
  }

  return true;
}

BIGNUM* init_sig_share(participant* p) {
  /*
  #
  # 1. checks to make sure that D_ij corresponds to a valid unused nonce d_ij
  # 2. Each P_i computes the challenge c = H(m, R).
  # 3. Each Pi computes their response z_i, using their long-lived secret share
  s_i where: zi = di + λi * si *c, using S to determine λi (S is set of
  idetifiers of t participant) # 4. sent response z_i to aggregator
  */
  size_t m_size = p->rcvd_tuple->m_size;
  size_t R_size = BN_num_bytes(p->rcvd_tuple->R);
  char* R_commit_converted = BN_bn2hex(p->rcvd_tuple->R);
  char hex_m[2 * m_size + 1];
  char* hash_string = malloc(m_size + R_size + 1);

  for (int i = 0; i < m_size; i++) {
    sprintf(&hex_m[2 * i], "%02x", p->rcvd_tuple->m[i]);
  }

  strcpy(hash_string, hex_m);
  strcat(hash_string, R_commit_converted);

  unsigned char hash[SHA256_DIGEST_LENGTH];

  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, hash_string, strlen(hash_string));
  SHA256_Final(hash, &sha256);
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