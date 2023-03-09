#include <openssl/bn.h>
#include <stdint.h>

#include "setup.h"

typedef struct {
  BIGNUM* m;
  BIGNUM* R;
  participant* S;

} tuple_packet;

typedef struct {
  /* data

  # message
  # public key
  # participal indexes list []
  # commitments pair list []
  # nonce commitment pair list []

  */
  BIGNUM* public_key;
  tuple_packet* tuple;
  uint32_t* rcvd_pub_shares;
  uint32_t* rcvd_sig_shares;
  size_t len_shares;

} aggregator;

pub_share_packet init_pub_share(participant* p);

bool accept_pub_share(aggregator* reciever, pub_share_packet* packet);

tuple_packet init_tuple_packet(aggregator* a, BIGNUM* m, participant* set);

bool accept_tuple(participant* reciever, tuple_packet* packet);

BIGNUM* init_sig_share(participant* p);

bool accept_sig_share(aggregator* reciever, BIGNUM* sig_share);

BIGNUM* signature(aggregator* a);
