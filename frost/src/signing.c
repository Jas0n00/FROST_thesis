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
  p->pub_share->pub_share = BN_new();
  p->pub_share->verify_share = BN_new();
  p->nonce = BN_new();
  p->pub_share->sender_index = p->index;

  BN_copy(p->pub_share->verify_share, p->verify_share);
  BN_copy(p->nonce, generate_rand());
  BN_mod_exp(p->pub_share->pub_share, b_generator, p->nonce, order,
             BN_CTX_new());

  return p->pub_share;
}

rcvd_pub_shares* create_node_pub_share(pub_share_packet* rcvd_packet) {
  rcvd_pub_shares* newNode = (rcvd_pub_shares*)malloc(sizeof(rcvd_pub_shares));
  newNode->rcvd_packets = malloc(sizeof(pub_share_packet));
  newNode->next = NULL;
  newNode->rcvd_packets->verify_share = BN_new();
  newNode->rcvd_packets->pub_share = BN_new();

  newNode->rcvd_packets->sender_index = rcvd_packet->sender_index;
  BN_copy(newNode->rcvd_packets->pub_share, rcvd_packet->pub_share);
  BN_copy(newNode->rcvd_packets->verify_share, rcvd_packet->verify_share);

  return newNode;
}

void insert_node_pub_share(aggregator* agg, pub_share_packet* rcvd_packet) {
  rcvd_pub_shares* newNode = create_node_pub_share(rcvd_packet);
  newNode->next = agg->rcvd_pub_share_head;
  agg->rcvd_pub_share_head = newNode;
}

bool accept_pub_share(aggregator* receiver, pub_share_packet* packet) {
  if (receiver->rcvd_pub_share_head == NULL) {
    receiver->rcvd_pub_share_head = create_node_pub_share(packet);
    return true;
  } else {
    insert_node_pub_share(receiver, packet);
    return true;
  }
  return false;
}

bool search_pub_share(rcvd_pub_shares* head, int sender_index) {
  rcvd_pub_commits* current = head;  // Initialize current
  while (current != NULL) {
    if (current->rcvd_packet->sender_index == sender_index) return true;
    current = current->next;
  }
  printf("Sender's public share were not found!");
  return false;
}

bool R_pub_commit_compute(aggregator* a, participant* set, int set_size) {
  /*
 # 1. Aggregator computes the signing group’s public commitment ∏ D_ij
 # selected participants P_i broadcast tuple (m, R, S, D_ij ) to every one of
 them.
 #
 */
  bool all_found = true;
  rcvd_pub_shares* currect = a->rcvd_pub_share_head;

  for (int i = 0; i < set_size; i++) {
    if (!search_pub_share(a->rcvd_pub_share_head, set[i].index)) {
      all_found = false;
      break;
    }
  }

  if (all_found) {
    BIGNUM* res_R_pub_commit = BN_new();
    BN_zero(res_R_pub_commit);

    while (currect != NULL) {
      BN_mod_add(res_R_pub_commit, res_R_pub_commit,
                 a->rcvd_pub_share_head->rcvd_packets->pub_share, order,
                 BN_CTX_new());
      currect = currect->next;
    }
    a->R_pub_commit = res_R_pub_commit;
    return true;
  } else {
    printf("Mismatch of signing participant and received shares!");
    return false;
  }
}

tuple_packet* init_tuple_packet(aggregator* a, char* m, size_t m_size,
                                participant* set, int set_size) {
  if (R_pub_commit_compute(a, set, set_size)) {
    a->tuple = malloc(sizeof(tuple_packet));
    a->tuple->m = malloc(sizeof(char) * m_size);
    a->tuple->S = malloc(sizeof(participant) * set_size);
    a->tuple->R = BN_new();

    a->tuple->m_size = m_size;
    BN_copy(a->tuple->R, a->R_pub_commit);
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
  receiver->rcvd_tuple->S = malloc(sizeof(participant) * packet->S_size);
  receiver->rcvd_tuple->m = malloc(sizeof(char) * packet->m_size + 1);
  receiver->rcvd_tuple->R = BN_new();

  BN_copy(receiver->rcvd_tuple->R, packet->R);
  receiver->rcvd_tuple->S_size = packet->S_size;
  receiver->rcvd_tuple->m_size = packet->m_size;

  for (int i = 0; i < packet->S_size; i++) {
    receiver->rcvd_tuple->S[i] = packet->S[i];
  }

  for (int i = 0; i < packet->m_size; i++) {
    receiver->rcvd_tuple->m[i] = packet->m[i];
  }
  return true;
}

BIGNUM* lagrange_coefficient(participant* p) {
  int num_participants = p->rcvd_tuple->S_size;

  // Initialize BIGNUMs
  BIGNUM* numerator = BN_new();
  BIGNUM* denominator = BN_new();
  BIGNUM* res = BN_new();
  BIGNUM* tmp = BN_new();

  // Set values for numerator, denominator
  BN_one(numerator);
  BN_one(denominator);

  for (int i = 0; i < num_participants; i++) {
    int index = p->rcvd_tuple->S[i].index;
    BIGNUM* b_index = BN_new();
    BN_set_word(b_index, index);
    BIGNUM* b_p_index = BN_new();
    BN_set_word(b_p_index, p->index);

    if (index == p->index) {
      continue;
    }
    BN_mul_word(numerator, index);
    BN_sub(tmp, b_index, b_p_index);
    BN_mul(denominator, denominator, tmp, BN_CTX_new());
  }

  BN_mod_inverse(tmp, denominator, order, BN_CTX_new());
  BN_mul(res, numerator, tmp, BN_CTX_new());
  BN_mod(res, res, order, BN_CTX_new());

  return res;
}

BIGNUM* init_sig_share(participant* p) {
  char* R_hex = BN_bn2dec(p->rcvd_tuple->R);
  size_t hash_len = strlen(p->rcvd_tuple->m) + strlen(R_hex);
  char* concat = (char*)malloc(hash_len + 1);

  printf("hash_len: %zu \n", hash_len);

  strcpy(concat, p->rcvd_tuple->m);
  printf("R_hex: %s \n", concat);
  strcat(concat, R_hex);
  printf("R_hex: %s \n", concat);

  unsigned char hash[SHA256_DIGEST_LENGTH];

  EVP_MD_CTX* mdctx;
  const EVP_MD* md;
  md = EVP_sha256();

  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, concat, hash_len);
  EVP_DigestFinal_ex(mdctx, hash, NULL);
  EVP_MD_CTX_free(mdctx);

  char hex_hash[SHA256_DIGEST_LENGTH * 2 + 1];
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    sprintf(&hex_hash[i * 2], "%02x", hash[i]);
  }
  hex_hash[SHA256_DIGEST_LENGTH * 2] = '\0';

  printf("SHA256 hash value: %s\n", hex_hash);
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