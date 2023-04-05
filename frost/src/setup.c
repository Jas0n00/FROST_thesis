#include "../headers/setup.h"

#include <assert.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "../headers/globals.h"

void init_coeff_list(participant* p) {
  /*
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
    BIGNUM* rand = generate_rand();
    BN_copy(p->list->coeff[i], rand);
    BN_clear_free(rand);
  }
}

void free_coeff_list(participant* p) {
  for (int i = 0; i < p->list->coefficient_list_len; i++) {
    BN_clear_free(p->list->coeff[i]);
  }
  OPENSSL_free(p->list->coeff);
  p->list->coefficient_list_len = 0;
  p->list->coeff = NULL;
  free(p->list);
  p->list = NULL;
}

pub_commit_packet* init_pub_commit(participant* p) {
  int threshold = p->threshold;
  BN_CTX* ctx = BN_CTX_new();
  /* call init_coeff_list */
  init_coeff_list(p);

  /* allocate memory for the public commit array */
  p->pub_commit = malloc(sizeof(pub_commit_packet));
  p->pub_commit->sender_index = p->index;
  p->pub_commit->commit_len = threshold;
  p->pub_commit->commit = OPENSSL_malloc(sizeof(BIGNUM*) * threshold);

  /* fulfill with G ^ a_i_j where: 0 ≤ j ≤ t - 1 */
  for (int j = 0; j < threshold; j++) {
    BN_CTX_start(ctx);

    p->pub_commit->commit[j] = BN_new();
    BIGNUM* result = BN_new();
    BN_mul(result, b_generator, p->list->coeff[j], ctx);
    BN_copy(p->pub_commit->commit[j], result);

    BN_CTX_end(ctx);
    BN_clear_free(result);
  }

  BN_CTX_free(ctx);
  return p->pub_commit;
}

void free_pub_commit(pub_commit_packet* pub_commit) {
  for (int i = 0; i < pub_commit->commit_len; i++) {
    BN_clear_free(pub_commit->commit[i]);
  }
  OPENSSL_free(pub_commit->commit);
  pub_commit->commit_len = 0;
  pub_commit->sender_index = 0;
  pub_commit->commit = NULL;
}

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
  rcvd_pub_commits* newNode = create_node_commit(rcvd_packet);
  newNode->next = p->rcvd_commit_head;
  p->rcvd_commit_head = newNode;
}

void free_rcvd_pub_commits(rcvd_pub_commits* head) {
  if (head == NULL) {
    return;
  }
  free_rcvd_pub_commits(head->next);
  for (int j = 0; j < head->rcvd_packet->commit_len; j++) {
    BN_clear_free(head->rcvd_packet->commit[j]);
  }
  OPENSSL_free(head->rcvd_packet->commit);
  free(head->rcvd_packet);
  free(head);
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

BIGNUM* init_sec_share(participant* sender, int reciever_index) {
  int threshold = sender->threshold;
  BN_CTX* ctx = BN_CTX_new();
  BN_CTX* ctx2 = BN_CTX_new();
  BIGNUM* result = NULL;
  // convert integer r_index to bignum
  BIGNUM* b_index = BN_new();
  BN_set_word(b_index, reciever_index);

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
    BN_copy(sender->func->t[i].exponent, b_expo);
    /*BN_clear_free(b_expo);*/
  }

  /*
  # 2. Calculate a polynomial
  # f_i(x) = ∑ a_i_j * x^j, 0 ≤ j ≤ t - 1
  */
  for (int i = 0; i < sender->func->n; i++) {
    BIGNUM* expo_product = BN_new();
    BIGNUM* multi_product = BN_new();
    BN_CTX_start(ctx);
    BN_CTX_start(ctx2);

    BN_mod_exp(expo_product, b_index, sender->func->t[i].exponent, order, ctx);
    BN_mod_mul(multi_product, sender->func->t[i].coefficient, expo_product,
               order, ctx2);
    if (result == NULL) {
      result = BN_new();
      BN_copy(result, multi_product);
    } else {
      BN_mod_add(result, result, multi_product, order, ctx2);
    }

    BN_CTX_end(ctx);
    BN_CTX_end(ctx2);
    BN_clear_free(expo_product);
    BN_clear_free(multi_product);
  }

  BN_CTX_free(ctx);
  BN_CTX_free(ctx2);
  BN_clear_free(b_index);

  return result;
}

void free_poly(participant* p) {
  for (int i = 0; i < p->func->n; i++) {
    BN_clear_free(p->func->t[i].coefficient);
    BN_clear_free(p->func->t[i].exponent);
  }
  free(p->func->t);
  free(p->func);
}

rcvd_sec_shares* create_node_share(BIGNUM* sec_share) {
  rcvd_sec_shares* newNode = (rcvd_sec_shares*)malloc(sizeof(rcvd_sec_shares));
  newNode->rcvd_share = BN_new();
  newNode->next = NULL;

  BN_copy(newNode->rcvd_share, sec_share);

  return newNode;
}

void free_rcvd_sec_shares(rcvd_sec_shares* head) {
  rcvd_sec_shares* curr = head;
  while (curr != NULL) {
    rcvd_sec_shares* next = curr->next;
    BN_clear_free(curr->rcvd_share);
    OPENSSL_free(curr);
    curr = next;
  }
}

void insert_node_share(participant* p, BIGNUM* sec_share) {
  rcvd_sec_shares* newNode = create_node_share(sec_share);

  newNode->next = p->rcvd_sec_share_head;
  p->rcvd_sec_share_head = newNode;
}

bool accept_sec_share(participant* receiver, int sender_index,
                      BIGNUM* sec_share) {
  int threshold = receiver->threshold;

  if (receiver->rcvd_sec_share_head == NULL) {
    receiver->rcvd_sec_share_head = create_node_share(sec_share);
  } else {
    insert_node_share(receiver, sec_share);
  }
  /*
  # 2. Every participant Pi verifies the share they received from each other
  participant Pj , where i != j, by verifying: # # G ^ f_j(i) ≟ ∏ 𝜙_j_k ^ (i ^ k
  mod G)  : 0 ≤ k ≤ t - 1
  #
  */

  // TODO:
  if (sender_index == receiver->index) {
    BN_clear_free(sec_share);
    return true;
  }

  pub_commit_packet* sender_pub_commit =
      search_node_commit(receiver->rcvd_commit_head, sender_index);

  BN_CTX* ctx = BN_CTX_new();
  BN_CTX* ctx2 = BN_CTX_new();
  BN_CTX* ctx3 = BN_CTX_new();
  BN_CTX* ctx4 = BN_CTX_new();
  BN_CTX* ctx5 = BN_CTX_new();
  BIGNUM* b_index = BN_new();
  BIGNUM* res_G_over_fj = BN_new();
  BIGNUM* res_commits = NULL;
  BN_set_word(b_index, receiver->index);

  BN_mod_mul(res_G_over_fj, b_generator, sec_share, order, ctx);

  for (int k = 0; k < threshold; k++) {
    BN_CTX_start(ctx2);
    BN_CTX_start(ctx3);
    BN_CTX_start(ctx4);
    BIGNUM* b_k = BN_new();
    BIGNUM* res_power = BN_new();
    BIGNUM* commit_powered = BN_new();
    BN_set_word(b_k, k);

    BN_mod_exp(res_power, b_index, b_k, order, ctx2);
    BN_mod_mul(commit_powered, sender_pub_commit->commit[k], res_power, order,
               ctx3);
    if (res_commits == NULL) {
      res_commits = BN_new();
      BN_copy(res_commits, commit_powered);
    } else {
      BN_mod_add(res_commits, res_commits, commit_powered, order, ctx4);
    }
    BN_clear_free(b_k);
    BN_clear_free(res_power);
    BN_clear_free(commit_powered);
    BN_CTX_end(ctx2);
    BN_CTX_end(ctx3);
    BN_CTX_end(ctx4);
  }

  if (!BN_cmp(res_G_over_fj, res_commits)) {
    BN_clear_free(b_index);
    BN_clear_free(res_G_over_fj);
    BN_clear_free(res_commits);
    BN_clear_free(sec_share);
    BN_CTX_free(ctx);
    BN_CTX_free(ctx2);
    BN_CTX_free(ctx3);
    BN_CTX_free(ctx4);
    BN_CTX_free(ctx5);

    return true;
  } else {
    printf("\nVerification of public commitments failed!\n");
    abort();
  }
}

bool gen_sec_share(participant* p, rcvd_sec_shares* head) {
  BIGNUM* sum = BN_new();
  BN_CTX* ctx = BN_CTX_new();
  BN_zero(sum);
  rcvd_sec_shares* current = head;

  while (current != NULL) {
    BN_CTX_start(ctx);
    BN_mod_add(sum, sum, current->rcvd_share, order, ctx);
    BN_CTX_end(ctx);
    current = current->next;
  }

  BN_copy(p->secret_share, sum);
  BN_free(sum);
  BN_CTX_free(ctx);
  return true;
}

bool gen_pub_key(participant* p, rcvd_pub_commits* head, BIGNUM* self_commit) {
  BIGNUM* product = BN_new();
  BN_CTX* ctx = BN_CTX_new();
  BN_copy(product, self_commit);

  while (head != NULL) {
    BN_CTX_start(ctx);
    BN_add(product, product, head->rcvd_packet->commit[0]);
    BN_CTX_end(ctx);
    head = head->next;
  }

  BN_copy(p->public_key, product);
  BN_free(product);
  BN_CTX_free(ctx);

  return true;
}

void gen_keys(participant* p) {
  p->secret_share = BN_new();
  p->verify_share = BN_new();
  p->public_key = BN_new();
  bool success = true;
  BN_CTX* ctx = BN_CTX_new();
  /*
  # 1. will create long-lived secret share:
  # s_i = ∑ f_j(i), 1 ≤ j ≤ n
  # sum of share list [] -> store secret share;
  */

  if (!gen_sec_share(p, p->rcvd_sec_share_head)) {
    success = false;
    printf("\nFailed to generate keys!\n");
    abort();
  }

  /*
  # 2. Each participant then calculates their own public verification share:
  # Y_i = G ^ s_i
  */

  if (!BN_mul(p->verify_share, b_generator, p->secret_share, ctx)) {
    success = false;
    printf("\nFailed to generate keys!\n");
    abort();
  }

  /*
  # 3. Each participant then calculates public key:
  # Y = ∏ 𝜙_j_0
  */

  if (!gen_pub_key(p, p->rcvd_commit_head, p->pub_commit->commit[0])) {
    success = false;
    printf("\nFailed to generate keys!\n");
    abort();
  }

  if (success) {
    printf("\nParticipant[%d] successfully generated the keys!\n", p->index);
  }

  // Free used memory for every participant
  BN_CTX_free(ctx);
  free_coeff_list(p);
  free_pub_commit(p->pub_commit);
  free_poly(p);
  free_rcvd_pub_commits(p->rcvd_commit_head);
  free_rcvd_sec_shares(p->rcvd_sec_share_head);
}