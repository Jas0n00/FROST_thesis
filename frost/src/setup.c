#include "../headers/setup.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../headers/globals.h"

rcvd_pub_commits* create_node_commit(pub_commit_packet* rcvd_packet) {
  size_t commit_len = rcvd_packet->commit_len;

  rcvd_pub_commits* newNode =
      (rcvd_pub_commits*)malloc(sizeof(rcvd_pub_commits));
  newNode->rcvd_packet = malloc(sizeof(pub_commit_packet));
  newNode->rcvd_packet->commit = OPENSSL_malloc(sizeof(BIGNUM*) * commit_len);
  newNode->next = NULL;

  newNode->rcvd_packet->commit_len = rcvd_packet->commit_len;
  newNode->rcvd_packet->sender_index = rcvd_packet->sender_index;
  for (int j = 0; j < commit_len; j++) {
    newNode->rcvd_packet->commit[j] = BN_new();
    BN_copy(newNode->rcvd_packet->commit[j], rcvd_packet->commit[j]);
  }

  return newNode;
}

void insert_node_commit(participant* p, pub_commit_packet* rcvd_packet) {
  rcvd_pub_commits* new_node = create_node_commit(rcvd_packet);
  new_node->next = p->rcvd_commit_head;
  p->rcvd_commit_head = new_node;
}

pub_commit_packet* search_node_commit(rcvd_pub_commits* head,
                                      int sender_index) {
  rcvd_pub_commits* current = head;  // Initialize current
  while (current != NULL) {
    if (current->rcvd_packet->sender_index == sender_index)
      return current->rcvd_packet;
    current = current->next;
  }
  printf("Sender's public commitment were not found!");
}

void init_coeff_list(participant* p) {
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
  p->list->coeff = OPENSSL_malloc(
      sizeof(BIGNUM*) * threshold);  // Note the use of sizeof(BIGNUM*)

  // Fill the coefficient_list with random BIGNUMs
  for (int i = 0; i < threshold; i++) {
    p->list->coeff[i] = BN_new();  // Call BN_new() before allocating memory
    BN_copy(p->list->coeff[i], generate_rand());
  }
}

void free_coeff_list(participant* p) {}

pub_commit_packet* init_pub_commit(participant* p) {
  int threshold = p->threshold;

  /* call init_coeff_list */
  init_coeff_list(p);

  /* allocate memory for the public commit array */
  p->pub_commit = malloc(sizeof(pub_commit_packet));
  p->pub_commit->sender_index = p->index;
  p->pub_commit->commit_len = threshold;
  p->pub_commit->commit = OPENSSL_malloc(sizeof(BIGNUM*) * threshold);

  /* fulfill with G ^ a_i_j where: 0 ≤ j ≤ t - 1 */
  for (int j = 0; j < threshold; j++) {
    p->pub_commit->commit[j] = BN_new();
    BIGNUM* result = BN_new();
    BN_mod_exp(result, b_generator, p->list->coeff[j], order, BN_CTX_new());
    BN_copy(p->pub_commit->commit[j], result);
  }

  return p->pub_commit;
}

void free_pub_commit(pub_commit_packet* pub_commit) {}

bool accept_pub_commit(participant* receiver, pub_commit_packet* pub_commit) {
  /*1. P_i broadcast public commitment (whole list) to all participants P_j
  P_j saves it to matrix_rcvd_commits*/

  if (receiver->rcvd_commit_head == NULL) {
    receiver->rcvd_commit_head = create_node_commit(pub_commit);
    return true;
  } else {
    insert_node_commit(receiver, pub_commit);
    return true;
  }
  return false;
}

BIGNUM* init_sec_share(participant* sender, int receiver_index) {
  int threshold = sender->threshold;
  BIGNUM* result = NULL;
  // convert integer r_index to bignum
  BIGNUM* b_index = BN_new();
  BN_set_word(b_index, receiver_index);

  sender->func = malloc(sizeof(poly));
  sender->func->n = threshold;
  sender->func->t = malloc(sizeof(term) * threshold);

  /*
  # 1. Define a polynomial
  # f_i(x) = ∑ a_i_j * x^j, 0 ≤ j ≤ t - 1
  */
  for (int i = 0; i < threshold; i++) {
    sender->func->t[i].coefficient = BN_new();
    BN_copy(sender->func->t[i].coefficient, sender->list->coeff[i]);

    // convert integer exponent to bignum
    BIGNUM* b_expo = BN_new();
    BN_set_word(b_expo, i);
    sender->func->t[i].exponent = b_expo;
  }

  /*
  # 2. Calculate a polynomial
  # f_i(x) = ∑ a_i_j * x^j, 0 ≤ j ≤ t - 1
  */
  for (int i = 0; i < sender->func->n; i++) {
    BIGNUM* expo_product = BN_new();
    BIGNUM* multi_product = BN_new();

    BN_mod_exp(expo_product, b_index, sender->func->t[i].exponent, order,
               BN_CTX_new());
    BN_mod_mul(multi_product, sender->func->t[i].coefficient, expo_product,
               order, BN_CTX_new());
    if (result == NULL) {
      result = BN_new();
      BN_copy(result, multi_product);
    } else {
      BN_mod_add(result, result, multi_product, order, BN_CTX_new());
    }
  }
  return result;
}

bool accept_sec_share(participant* receiver, int sender_index,
                      BIGNUM* sec_share) {
  int participants = receiver->participants;
  int threshold = receiver->threshold;
  pub_commit_packet* sender_pub_commit =
      search_node_commit(receiver->rcvd_commit_head, sender_index);
  receiver->len_rcvd_sec_share = (receiver->participants) - 1;

  // Allocate memory for array & set it to default
  if (receiver->rcvd_sec_share == NULL) {
    receiver->rcvd_sec_share = OPENSSL_malloc(participants * sizeof(BIGNUM*));
    for (int i = 0; i < participants; i++) {
      receiver->rcvd_sec_share[i] = BN_new();
    }
  }

  // Save sent sec_share to rcvd_sec_share[]
  BN_copy(receiver->rcvd_sec_share[sender_index], sec_share);

  /*
  # 2. Every participant Pi verifies the share they received from each other
  participant Pj , where i != j, by verifying: # # G ^ f_j(i) ≟ ∏ 𝜙_j_k ^ (i ^ k
  mod G)  : 0 ≤ k ≤ t - 1
  #
  */
  BIGNUM* b_index = BN_new();
  BIGNUM* res_G_over_fj = BN_new();
  BIGNUM* res_commits = NULL;
  BN_set_word(b_index, receiver->index);

  BN_mod_exp(res_G_over_fj, b_generator, sec_share, order, BN_CTX_new());

  for (int k = 0; k < threshold; k++) {
    BIGNUM* b_k = BN_new();
    BIGNUM* res_power = BN_new();
    BIGNUM* commit_powered = BN_new();
    BN_set_word(b_k, k);

    BN_mod_exp(res_power, b_index, b_k, order, BN_CTX_new());
    BN_mod_exp(commit_powered, sender_pub_commit->commit[k], res_power, order,
               BN_CTX_new());
    if (res_commits == NULL) {
      res_commits = BN_new();
      BN_copy(res_commits, commit_powered);
    } else {
      BN_mod_mul(res_commits, res_commits, commit_powered, order, BN_CTX_new());
    }
  }
  BN_mod(res_commits, res_commits, order, BN_CTX_new());
  printf("\n \n");
  BN_print_fp(stdout, res_G_over_fj);
  printf("\n \n");
  BN_print_fp(stdout, res_commits);
}

bool gen_keys(participant* p) {
  /*
  # 1. will create long-lived secret share:
  # s_i = ∑ f_j(i), 1 ≤ j ≤ n
  # sum of share list [] -> store secret share;
  */
  BIGNUM* res_sec_share = BN_new();
  BIGNUM* res_ver_share = BN_new();
  BIGNUM* res_pub_key = BN_new();
  BN_set_word(res_sec_share, 0);
  BN_set_word(res_pub_key, 1);

  for (int i = 0; i < p->len_rcvd_sec_share; i++) {
    BN_mod_add(res_sec_share, res_sec_share, p->rcvd_sec_share[i], order,
               BN_CTX_new());
  }
  /*
  # 2. Each participant then calculates their own public verification share:
  # Y_i = G ^ s_i
  */
  BN_mod_exp(res_ver_share, b_generator, res_sec_share, order, BN_CTX_new());
  /*
  # 3. Each participant then calculates public key:
  # Y = ∏ 𝜙_j_0
  */
  for (int i = 0; i < p->rcvd_commits->num_packets; i++) {
    if (p->rcvd_commits->rcvd_packets[i].sender_index != -1) {
      BN_mod_mul(res_pub_key, res_pub_key,
                 p->rcvd_commits->rcvd_packets[i].commit[0], order,
                 BN_CTX_new());
    }
  }

  p->secret_share = res_pub_key;
  p->verify_share = res_ver_share;
  p->public_key = res_pub_key;
}