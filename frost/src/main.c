#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>

#include "../headers/setup.h"
#include "../headers/signing.h"

int main(int argc, char const* argv[]) {
    int threshold, participants;

    // Ask the user for input
    printf("Enter the threshold: ");
    scanf("%d", &threshold);
    printf("Enter the number of participants: ");
    scanf("%d", &participants);

    // Dynamically allocate memory for participants
    participant* p = (participant*)malloc(participants * sizeof(participant));
    if (p == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    }

    // Initialize participants
    for (int i = 0; i < participants; i++) {
        p[i].index = i;
        p[i].threshold = threshold;
        p[i].participants = participants;
        p[i].pub_commit = NULL;
        p[i].rcvd_commit_head = NULL;
        p[i].rcvd_sec_share_head = NULL;
    }

    // Initialize public commitments for each participant
    pub_commit_packet** pub_commits = (pub_commit_packet**)malloc(participants * sizeof(pub_commit_packet*));
    if (pub_commits == NULL) {
        printf("Memory allocation for public commitments failed\n");
        free(p);
        return 1;
    }

    for (int i = 0; i < participants; i++) {
        pub_commits[i] = init_pub_commit(&p[i]);
    }

    // Simulate broadcasting the public commitments to all other participants
    for (int i = 0; i < participants; i++) {
        for (int j = 0; j < participants; j++) {
            if (i != j) {
                accept_pub_commit(&p[i], pub_commits[j]);
            }
        }
    }

    // Initialize and exchange secret shares
    for (int i = 0; i < participants; i++) {
        BIGNUM* self_share = init_sec_share(&p[i], p[i].index);
        accept_sec_share(&p[i], p[i].index, self_share);

        for (int j = 0; j < participants; j++) {
            if (i != j) {
                BIGNUM* sec_share = init_sec_share(&p[i], p[j].index);
                accept_sec_share(&p[j], p[i].index, sec_share);
            }
        }
    }

    // Generate keys for all participants
    for (int i = 0; i < participants; i++) {
        gen_keys(&p[i]);
    }

    // ### Signing process ###
    participant* threshold_set = (participant*)malloc(threshold * sizeof(participant));
    if (threshold_set == NULL) {
        printf("Memory allocation for threshold set failed\n");
        free(p);
        free(pub_commits);
        return 1;
    }

    // Ask user to select participants for signing
    printf("Enter the indices of %d participants for signing (0 to %d):\n", threshold, participants - 1);
    int* indices = (int*)malloc(threshold * sizeof(int));
    if (indices == NULL) {
        printf("Memory allocation for indices failed\n");
        free(p);
        free(pub_commits);
        free(threshold_set);
        return 1;
    }

    for (int i = 0; i < threshold; i++) {
        printf("Enter index for participant %d. Range of index [0 - %d] ", i + 1, participants - 1);
        scanf("%d", &indices[i]);

        // Check if the input is valid
        if (indices[i] < 0 || indices[i] >= participants) {
            printf("Invalid index! Please enter a number between 0 and %d.\n", participants - 1);
            i--;  // Redo the iteration for invalid input
        } else {
            // Assign the participant to the threshold set
            threshold_set[i] = p[indices[i]];
        }
    }

    // Ask user to input the message to be signed
    char message[256];  // Assume a max message length of 255 characters
    printf("Enter the message to be signed: ");
    scanf(" %[^\n]%*c", message);  // This will capture the full line including spaces
    size_t m_len = strlen(message);

    size_t set_size = threshold;

    aggregator agg = {
        .threshold = threshold,
        .rcvd_pub_share_head = NULL,
    };

    // Initialize public share commitments for chosen participants
    pub_share_packet** pub_shares = (pub_share_packet**)malloc(threshold * sizeof(pub_share_packet*));
    if (pub_shares == NULL) {
        printf("Memory allocation for public shares failed\n");
        free(p);
        free(pub_commits);
        free(threshold_set);
        free(indices);
        return 1;
    }

    for (int i = 0; i < threshold; i++) {
        pub_shares[i] = init_pub_share(&threshold_set[i]);
        accept_pub_share(&agg, pub_shares[i]);
    }

    // Generate and accept tuple packets
    tuple_packet* agg_tuple = init_tuple_packet(&agg, message, m_len, threshold_set, set_size);
    for (int i = 0; i < threshold; i++) {
        accept_tuple(&threshold_set[i], agg_tuple);
    }

    // Generate signature shares
    for (int i = 0; i < threshold; i++) {
        BIGNUM* sig_share = init_sig_share(&threshold_set[i]);
        accept_sig_share(&agg, sig_share, threshold_set[i].index);
    }

    // Finalize the signature
    signature_packet sig = signature(&agg);

    printf("\nSignature: ");
    BN_print_fp(stdout, sig.signature);
    printf("\nHash: ");
    BN_print_fp(stdout, sig.hash);
    printf("\n");

    // Verify the signature
    verify_signature(&sig, message, p[0].public_key);

    // Clean up dynamically allocated memory
    free(p);
    free(pub_commits);
    free(pub_shares);
    free(threshold_set);
    free(indices);

    return 0;
}

