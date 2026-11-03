/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "src/common/xqc_log.h"
#include "tests/test_log.h"
#include "xqc_test_log_test.h"

static void xqc_test_log_check(const void *buf, size_t size);

static void
xqc_test_log_check(const void *buf, size_t size)
{
    unsigned char  actual[XQC_MAX_LOG_LEN + 2];
    FILE          *file = tmpfile();

    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    CU_ASSERT_EQUAL(xqc_test_log_write(fileno(file), buf, size), 0);
    CU_ASSERT_EQUAL(fseek(file, 0, SEEK_SET), 0);
    size_t n = fread(actual, 1, sizeof(actual), file);
    CU_ASSERT_EQUAL(n, size + 1);
    if (n == size + 1) {
        if (size != 0) {
            CU_ASSERT_EQUAL(memcmp(actual, buf, size), 0);
        }
        CU_ASSERT_EQUAL(actual[size], '\n');
    }
    fclose(file);
}

void
xqc_test_log_write_text(void)
{
    static const char text[] = "ordinary log";
    static const char suffix[] = "wanted-unwanted";

    xqc_test_log_check(text, sizeof(text) - 1);
    xqc_test_log_check(suffix, sizeof("wanted") - 1);
    xqc_test_log_check(NULL, 0);
}

void
xqc_test_log_write_binary(void)
{
    static const unsigned char binary[] =
        "|client_alpn:a\0b h3 |selected_alpn:h3|";
    unsigned char full[XQC_MAX_LOG_LEN];

    xqc_test_log_check(binary, sizeof(binary) - 1);
    memset(full, 'X', sizeof(full));
    xqc_test_log_check(full, sizeof(full));
}

void
xqc_test_log_write_errors(void)
{
    FILE *file = tmpfile();

    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    errno = 0;
    CU_ASSERT_EQUAL(xqc_test_log_write(fileno(file), NULL,
                                     XQC_MAX_LOG_LEN + 1), -1);
    CU_ASSERT_EQUAL(errno, EINVAL);
    CU_ASSERT_EQUAL(fseek(file, 0, SEEK_END), 0);
    CU_ASSERT_EQUAL(ftell(file), 0);
    fclose(file);

    errno = 0;
    CU_ASSERT_EQUAL(xqc_test_log_write(-1, "log", 3), -1);
    CU_ASSERT_EQUAL(errno, EBADF);

    /* An empty payload must still report failure to write its newline. */
    errno = 0;
    CU_ASSERT_EQUAL(xqc_test_log_write(-1, NULL, 0), -1);
    CU_ASSERT_EQUAL(errno, EBADF);
}
