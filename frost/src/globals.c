#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <../headers/globals.h>

void initialize_curve_parameters()
{
    ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_group)
    {
        printf("Error creating EC group\n");
        return;
    }

    generator = EC_GROUP_get0_generator(ec_group);
    order = EC_GROUP_get0_order(ec_group);
    modulo = EC_GROUP_get0_field(ec_group);
}

void free_curve_parameters()
{
 if (ec_group)
    {
        EC_GROUP_clear_free(ec_group);
        ec_group = NULL;
    }
}


BIGNUM* generate_rand()
    {
    BIGNUM* rand_num;
    unsigned char buffer[NUM_BYTES];

    // generate random bytes
    if (RAND_bytes(buffer, NUM_BYTES) != 1) {
        printf("Error generating random bytes\n");
        exit(EXIT_FAILURE);
    }

    // convert buffer to a bignum
    rand_num = BN_bin2bn(buffer, NUM_BYTES, NULL);
    
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM *result = BN_new();
    BN_mod(result, rand_num, order, ctx);

    
    OPENSSL_cleanse(buffer, sizeof(buffer)); // free the memory allocated for buffer

    return result;
    }