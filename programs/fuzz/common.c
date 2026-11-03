#include "common.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mbedtls/ctr_drbg.h"

#if defined(MBEDTLS_PLATFORM_TIME_ALT)
mbedtls_time_t dummy_constant_time(mbedtls_time_t *time)
{
    (void) time;
    return 0x5af2a056;
}
#endif

void dummy_init(void)
{
#if defined(MBEDTLS_PLATFORM_TIME_ALT)
    mbedtls_platform_set_time(dummy_constant_time);
#else
    fprintf(stderr, "Warning: fuzzing without constant time\n");
#endif
}

int dummy_send(void *ctx, const unsigned char *buf, size_t len)
{
    //silence warning about unused parameter
    (void) ctx;
    (void) buf;

    //pretends we wrote everything ok
    if (len > INT_MAX) {
        return -1;
    }
    return (int) len;
}

int fuzz_recv(void *ctx, unsigned char *buf, size_t len)
{
    //reads from the buffer from fuzzer
    fuzzBufferOffset_t *biomemfuzz = (fuzzBufferOffset_t *) ctx;

    if (biomemfuzz->Offset == biomemfuzz->Size) {
        //EOF
        return 0;
    }
    if (len > INT_MAX) {
        return -1;
    }
    if (len + biomemfuzz->Offset > biomemfuzz->Size) {
        //do not overflow
        len = biomemfuzz->Size - biomemfuzz->Offset;
    }
    memcpy(buf, biomemfuzz->Data + biomemfuzz->Offset, len);
    biomemfuzz->Offset += len;
    return (int) len;
}

int dummy_random(void *p_rng, unsigned char *output, size_t output_len)
{
    int ret;

#if defined(MBEDTLS_CTR_DRBG_C)
    //mbedtls_ctr_drbg_random requires a valid mbedtls_ctr_drbg_context in p_rng
    if (p_rng != NULL) {
        //use mbedtls_ctr_drbg_random to find bugs in it
        ret = mbedtls_ctr_drbg_random(p_rng, output, output_len);
    } else {
        //fall through to pseudo-random
        ret = 0;
    }
#else
    (void) p_rng;
    ret = 0;
#endif
    //replace result with pseudo random
    while (output_len > 0) {
        #if (RAND_MAX >= 0x00FFFFFF)
        *output = (unsigned char) (rand() >> 16);
        #else
        *output = (unsigned char) rand() ; /* e. g. Visual C */
        #endif
        output += 1;
        output_len -= 1;
    }
    return ret;
}

int dummy_entropy(void *data, unsigned char *output, size_t len)
{
    (void) data;

    //use mbedtls_entropy_func to find bugs in it
    //test performance impact of entropy
    //ret = mbedtls_entropy_func(data, output, len);
    //replace result with pseudo random
    while (len > 0) {
        #if (RAND_MAX >= 0x00FFFFFF)
        *output = (unsigned char) (rand() >> 16);
        #else
        *output = (unsigned char) rand() ; /* e. g. Visual C */
        #endif
        output += 1;
        len -= 1;
    }
    return 0;
}

int fuzz_recv_timeout(void *ctx, unsigned char *buf, size_t len,
                      uint32_t timeout)
{
    (void) timeout;

    return fuzz_recv(ctx, buf, len);
}
