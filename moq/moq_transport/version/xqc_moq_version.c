#include <string.h>

#include "moq/moq_transport/version/xqc_moq_version.h"

static const xqc_moq_alpn_policy_t xqc_moq_alpn_policies[] = {
    {
        XQC_ALPN_MOQ_LEGACY,
        sizeof(XQC_ALPN_MOQ_LEGACY) - 1,
        &xqc_moq_v5_profile_definition,
    },
    {
        XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1,
        &xqc_moq_v5_profile_definition,
    },
    {
        XQC_ALPN_MOQ_DRAFT_14,
        sizeof(XQC_ALPN_MOQ_DRAFT_14) - 1,
        &xqc_moq_v14_profile_definition,
    },
};

const xqc_moq_alpn_policy_t *
xqc_moq_version_policy_for_alpn(const char *alpn, size_t alpn_len)
{
    size_t i;

    if (alpn == NULL || alpn_len == 0) {
        return NULL;
    }

    for (i = 0; i < sizeof(xqc_moq_alpn_policies)
                    / sizeof(xqc_moq_alpn_policies[0]); ++i)
    {
        const xqc_moq_alpn_policy_t *policy = &xqc_moq_alpn_policies[i];
        if (policy->alpn_len == alpn_len
            && memcmp(policy->alpn, alpn, alpn_len) == 0)
        {
            return policy;
        }
    }

    return NULL;
}

const xqc_moq_version_profile_t *
xqc_moq_version_profile_for_version(uint64_t wire_version)
{
    switch (wire_version) {
    case XQC_MOQ_VERSION_5:
        return xqc_moq_v5_profile();
    case XQC_MOQ_VERSION_14:
        return xqc_moq_v14_profile();
    default:
        return NULL;
    }
}

xqc_bool_t
xqc_moq_profile_has_capability(const xqc_moq_version_profile_t *profile,
    xqc_moq_capability_t capability)
{
    if (profile == NULL) {
        return XQC_FALSE;
    }

    return (profile->capabilities & (uint64_t) capability) != 0;
}
