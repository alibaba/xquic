#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "moq/xqc_moq.h"
#include "moq/moq_transport/version/xqc_moq_version.h"

#define XQC_TEST_ASSERT(expr)                                             \
    do {                                                                  \
        if (!(expr)) {                                                    \
            fprintf(stderr, "assert failed: %s:%d: %s\n",                \
                    __FILE__, __LINE__, #expr);                            \
            return -1;                                                    \
        }                                                                 \
    } while (0)

static int
xqc_test_profile_lookup(void)
{
    const xqc_moq_alpn_policy_t *policy;

    XQC_TEST_ASSERT(strcmp(XQC_ALPN_MOQ_QUIC, "moq-quic") == 0);
    XQC_TEST_ASSERT(strcmp(XQC_ALPN_MOQ_DRAFT_05, "moq-05") == 0);
    XQC_TEST_ASSERT(strcmp(XQC_ALPN_MOQ_DRAFT_14, "moq-14") == 0);

    policy = xqc_moq_version_policy_for_alpn("moq-quic", 8);
    XQC_TEST_ASSERT(policy != NULL);
    XQC_TEST_ASSERT(policy->profile != NULL);
    XQC_TEST_ASSERT(policy->profile->wire_version == XQC_MOQ_VERSION_5);
    XQC_TEST_ASSERT(policy->profile->control_codecs != NULL);

    policy = xqc_moq_version_policy_for_alpn("moq-05", 6);
    XQC_TEST_ASSERT(policy != NULL);
    XQC_TEST_ASSERT(policy->profile != NULL);
    XQC_TEST_ASSERT(policy->profile->wire_version == XQC_MOQ_VERSION_5);
    XQC_TEST_ASSERT(policy->profile->control_codecs != NULL);

    policy = xqc_moq_version_policy_for_alpn("moq-14", 6);
    XQC_TEST_ASSERT(policy != NULL);
    XQC_TEST_ASSERT(policy->profile != NULL);
    XQC_TEST_ASSERT(policy->profile->wire_version == XQC_MOQ_VERSION_14);
    XQC_TEST_ASSERT(policy->profile->control_codecs != NULL);

    XQC_TEST_ASSERT(xqc_moq_version_policy_for_alpn("moq-00", 6) == NULL);
    XQC_TEST_ASSERT(xqc_moq_version_policy_for_alpn("unknown", 7) == NULL);

    XQC_TEST_ASSERT(xqc_moq_version_profile_for_version(XQC_MOQ_VERSION_5)
                    == xqc_moq_v5_profile());
    XQC_TEST_ASSERT(xqc_moq_version_profile_for_version(XQC_MOQ_VERSION_14)
                    == xqc_moq_v14_profile());
    XQC_TEST_ASSERT(!xqc_moq_profile_has_capability(
        xqc_moq_v5_profile(), XQC_MOQ_CAP_SUBGROUP_STREAM));
    XQC_TEST_ASSERT(xqc_moq_profile_has_capability(
        xqc_moq_v14_profile(), XQC_MOQ_CAP_SUBGROUP_STREAM));
    return 0;
}

int
main(void)
{
    return xqc_test_profile_lookup() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
