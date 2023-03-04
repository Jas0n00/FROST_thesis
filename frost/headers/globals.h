#include <openssl/ec.h>
#include <openssl/bn.h>


extern EC_GROUP* ec_group;
extern const EC_POINT* generator;
extern const BIGNUM* order;
extern const BIGNUM* modulo;
#define NUM_BYTES 32


void free_curve_parameters();

BIGNUM* generate_rand();