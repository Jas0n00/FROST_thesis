#include <openssl/bn.h>
#include <stdint.h>

#include "setup.h"

typedef struct node_pub_share {
  pub_share_packet* rcvd_packets;
  struct node_pub_share* next;
} rcvd_pub_shares;

typedef struct {
  /* data

  # message
  # public key
  # participal indexes list []
  # commitments pair list []
  # nonce commitment pair list []

  */
  int threshold;
  BIGNUM* public_key;
  BIGNUM* R_pub_commit;
  tuple_packet* tuple;
  rcvd_pub_shares* rcvd_pub_share_head;
  BIGNUM* rcvd_sig_shares;
  size_t len_shares;

} aggregator;

pub_share_packet* init_pub_share(participant* p);

bool accept_pub_share(aggregator* receiver, pub_share_packet* packet);

tuple_packet* init_tuple_packet(aggregator* a, char* m, size_t m_size,
                                participant* set, int set_size);

bool accept_tuple(participant* receiver, tuple_packet* packet);

BIGNUM* init_sig_share(participant* p);

bool accept_sig_share(aggregator* receiver, BIGNUM* sig_share);

BIGNUM* signature(aggregator* a);
