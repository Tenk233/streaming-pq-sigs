#include "api.h"
#include "streaming.h"
#include "types.h"

/* SPHINCS header */
#include "address.h"
#include "fors.h"
#include "hash.h"
#include "hash_state.h"
#include "params.h"
#include "thash.h"
#include "utils.h"
#include "wots.h"

#include <string.h>

static u8 pk[CRYPTO_PUBLICKEYBYTES];
/* This is where the actual known PK would go */
u8 fixed_pk[CRYPTO_PUBLICKEYBYTES] = {0};

stream_state cur_state = 0;
unsigned char root[N];
uint32_t wots_addr[8] = {0};
uint64_t tree;
uint32_t idx_leaf;
uint32_t tree_addr[8] = {0};
unsigned char wots_pk[WOTS_BYTES];
uint32_t wots_pk_addr[8] = {0};
unsigned char leaf[N];
u32 wots_tree_counter = 0;
// TODO: check, can this be omitted?
hash_state hash_state_seeded;

int crypto_sign_open_init_stream(crypto_stream_ctx *ctx, u32 smlen, u8 *pk_hash_init) {
    size_t i;
    /* Stream sm one byte at a time */
    ctx->sm_len = smlen;
    ctx->sm_chunk_size = FORS_BYTES + N; /* All FORS tree stuff + R */
    ctx->pk_chunk_size = CRYPTO_PUBLICKEYBYTES;
    cur_state = STREAM_STATE_BEGIN;


    // Warning: In the real world the pk_hash would be embedded into the firmware.
    // As we don't want to do that in our experiments, we just copy it here
    for(i=0;i<CRYPTO_PUBLICKEYBYTES;i++){
        fixed_pk[i] = pk_hash_init[i];
    }
    /* Initialize state */
    return 0;
}

int crypto_sign_open_hash_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos) {
    (void)ctx;
    (void)pk_pos;
    /* Entire public key easily fits into memory, no need for hashing */
    unsigned char cc = 0;
    for (unsigned int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
        cc |= (fixed_pk[i] ^ chunk[i]);
    }
    if (cc) {
        return -1;
    }
    return 0;
}

int crypto_sign_open_consume_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos){
    for (u32 i = 0; i < ctx->pk_chunk_size; ++i)
    {
        pk[pk_pos++] = chunk[i];
    }
    ctx->pk_chunk_size = 0;
    
    set_type(wots_pk_addr, ADDR_TYPE_WOTSPK);
    set_type(tree_addr, ADDR_TYPE_HASHTREE);

    return 0;
}


int crypto_sign_open_consume_sm_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t sm_pos){
    (void)sm_pos;
    u8 *sm_ptr = chunk;
    const unsigned char *pub_seed = pk;
    
    // Handle FORS stuff
    if (cur_state == STREAM_STATE_BEGIN) {
        unsigned char mhash[FORS_MSG_BYTES];
        
        /* This hook allows the hash function instantiation to do whatever
        preparation or computation it needs, based on the public seed. */
        initialize_hash_function(
            &hash_state_seeded,
            pub_seed, NULL);

        set_type(wots_addr, ADDR_TYPE_WOTS);

        /* Derive the message digest and leaf index from R || PK || M. */
        /* The additional N is a result of the hash domain separator. */
        hash_message(
            mhash, &tree, &idx_leaf, sm_ptr, pk, NULL, 0, &hash_state_seeded);
        sm_ptr += N;
        /* Layer correctly defaults to 0, so no need to set_layer_addr */
        set_tree_addr(wots_addr, tree);
        set_keypair_addr(
            wots_addr, idx_leaf);

        fors_pk_from_sig(
            root, sm_ptr, mhash, pub_seed, wots_addr, &hash_state_seeded);

        // FORS_BYTES = 4800
        // sm_ptr += FORS_BYTES;
        cur_state = STREAM_STATE_RECOVERD_FORS_ROOT;
        ctx->sm_chunk_size = WOTS_MULT_CHUNK_SIZE;
    } else if (cur_state == STREAM_STATE_RECOVERD_FORS_ROOT) {
        /* For each subtree.. */
        u32 limit = MIN((wots_tree_counter + WOTS_TREES_PER_CHUNK),D);
        
        for (; wots_tree_counter < limit; wots_tree_counter++) {
            set_layer_addr(tree_addr, wots_tree_counter);
            set_tree_addr(tree_addr, tree);

            copy_subtree_addr(
                wots_addr, tree_addr);
            set_keypair_addr(
                wots_addr, idx_leaf);

            copy_keypair_addr(
                wots_pk_addr, wots_addr);

            /* The WOTS public key is only correct if the signature was correct. */
            /* Initially, root is the FORS pk, but on subsequent iterations it is
            the root of the subtree below the currently processed subtree. */
            wots_pk_from_sig(
                wots_pk, sm_ptr, root, pub_seed, wots_addr, &hash_state_seeded);
            // 560B
            sm_ptr += WOTS_BYTES;

            /* Compute the leaf node using the WOTS public key. */
            thash_WOTS_LEN(
                leaf, wots_pk, pub_seed, wots_pk_addr, &hash_state_seeded);
            
            /* Compute the root node of this subtree. */
            compute_root(
                root, leaf, idx_leaf, 0, sm_ptr, TREE_HEIGHT,
                pub_seed, tree_addr, &hash_state_seeded);
            // 144
            sm_ptr += TREE_HEIGHT * N;

            /* Update the indices for the next layer. */
            idx_leaf = (tree & ((1 << TREE_HEIGHT) - 1));
            tree = tree >> TREE_HEIGHT;
        }

        if (wots_tree_counter + WOTS_TREES_PER_CHUNK > D) {
            ctx->sm_chunk_size = (D - wots_tree_counter) * WOTS_CHUNK_SIZE;
        }
        
        if (wots_tree_counter == D) {
            // We are done
            ctx->sm_chunk_size = 0;
        }
    }

    return 0;
}


int crypto_sign_open_get_result(crypto_stream_ctx *ctx, u8 *m, u32 *mlen){
    (void)m;
    (void)ctx;
    if (memcmp(root, pk + N, N) != 0) {
        return -1;
    }
    /* For now we only have signatures with len(m) = 0 */
    *mlen = 0;
    return 0;
}

