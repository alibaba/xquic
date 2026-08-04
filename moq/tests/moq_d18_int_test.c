#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "moq/moq_transport/draft18/xqc_moq_d18_int.h"

#define CHECK(condition) do {                                                \
    if (!(condition)) {                                                      \
        fprintf(stderr, "check failed at %s:%d: %s\n",                     \
                __FILE__, __LINE__, #condition);                             \
        return 1;                                                            \
    }                                                                        \
} while (0)

typedef struct {
    uint64_t value;
    uint8_t wire[9];
    size_t wire_len;
} moqint_vector_t;

int
main(void)
{
    static const moqint_vector_t vectors[] = {
        {0, {0x00}, 1},
        {127, {0x7f}, 1},
        {128, {0x80, 0x80}, 2},
        {0x10c, {0x81, 0x0c}, 2},
        {0x3fff, {0xbf, 0xff}, 2},
        {0x4000, {0xc0, 0x40, 0x00}, 3},
        {0x1fffff, {0xdf, 0xff, 0xff}, 3},
        {0xfffffff, {0xef, 0xff, 0xff, 0xff}, 4},
        {0x7ffffffffULL, {0xf7, 0xff, 0xff, 0xff, 0xff}, 5},
        {0x3ffffffffffULL, {0xfb, 0xff, 0xff, 0xff, 0xff, 0xff}, 6},
        {0x1ffffffffffffULL,
            {0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 7},
        {0xffffffffffffffULL,
            {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 8},
        {UINT64_MAX,
            {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 9},
    };
    uint8_t encoded[9];
    for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        memset(encoded, 0, sizeof(encoded));
        CHECK(xqc_moq_d18_int_len(vectors[i].value) == vectors[i].wire_len);
        CHECK((size_t)(xqc_moq_d18_int_write(encoded, vectors[i].value)
                       - encoded) == vectors[i].wire_len);
        CHECK(memcmp(encoded, vectors[i].wire, vectors[i].wire_len) == 0);
        uint64_t decoded = 0;
        CHECK(xqc_moq_d18_int_read(encoded,
            encoded + vectors[i].wire_len, &decoded)
            == (int)vectors[i].wire_len);
        CHECK(decoded == vectors[i].value);
        if (vectors[i].wire_len > 1) {
            CHECK(xqc_moq_d18_int_read(encoded,
                encoded + vectors[i].wire_len - 1, &decoded) < 0);
        }
    }
    CHECK(xqc_moq_d18_int_read(NULL, NULL, NULL) < 0);
    puts("moq draft-18 integer tests passed");
    return 0;
}
