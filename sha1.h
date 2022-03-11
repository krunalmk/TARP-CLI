#ifndef SHA1_H
#define SHA1_H

/*
   SHA-1 in C
   By Steve Reid <steve@edmweb.com>
   100% Public Domain
 */

#include "stdint.h"

typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX_CUSTOM;

void SHA1TransformCustom(
        uint32_t *state,
        const unsigned char *buffer
);

void SHA1InitCustom(
        SHA1_CTX_CUSTOM * context
);

void SHA1UpdateCustom(
        SHA1_CTX_CUSTOM * context,
        const unsigned char *data,
        uint32_t len
);

void SHA1FinalCustom(
        unsigned char *digest,
        SHA1_CTX_CUSTOM * context
);

void SHA1Custom(
        char *hash_out,
        const char *str,
        int len);

#endif /* SHA1_H */