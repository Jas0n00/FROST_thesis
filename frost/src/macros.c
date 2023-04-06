#include <openssl/bn.h>
#include <openssl/ec.h>

BIGNUM* order;
BIGNUM* modulo;
BIGNUM* b_generator;
EC_POINT* p_generator;
EC_GROUP* ec_group;