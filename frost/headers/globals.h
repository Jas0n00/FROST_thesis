#include <openssl/bn.h>
#include <openssl/ec.h>

extern EC_GROUP* ec_group;
extern const EC_POINT* p_generator;
extern const BIGNUM* b_generator;
extern const BIGNUM* order;
extern const BIGNUM* modulo;
#define NUM_BYTES 32

void initialize_curve_parameters();

void free_curve();

BIGNUM* generate_rand();