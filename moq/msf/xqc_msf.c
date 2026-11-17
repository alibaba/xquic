/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include <moq/xqc_msf.h>
#include "moq/cjson/cJSON.h"
#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str.h"

#define XQC_MSF_MAX_NODES 4096

struct xqc_msf_catalog_s {
    cJSON             *root;
    size_t             count;
    xqc_msf_track_t    tracks[XQC_MSF_MAX_TRACKS];
    char               inherited[XQC_MSF_MAX_STRING + 1];
};

typedef struct {
    const char    *name;
    size_t         offset;
} xqc_msf_field_t;

static const xqc_msf_field_t xqc_msf_strings[] = {
    {"name", offsetof(xqc_msf_track_t, name)},
    {"namespace", offsetof(xqc_msf_track_t, track_namespace)},
    {"codec", offsetof(xqc_msf_track_t, codec)},
    {"mimeType", offsetof(xqc_msf_track_t, mime_type)},
    {"role", offsetof(xqc_msf_track_t, role)},
    {"channelConfig", offsetof(xqc_msf_track_t, channel_config)},
};

static const xqc_msf_field_t xqc_msf_numbers[] = {
    {"width", offsetof(xqc_msf_track_t, width)},
    {"height", offsetof(xqc_msf_track_t, height)},
    {"samplerate", offsetof(xqc_msf_track_t, samplerate)},
    {"timescale", offsetof(xqc_msf_track_t, timescale)},
};

static xqc_int_t xqc_msf_utf8(const uint8_t *buf, size_t len);
static xqc_int_t xqc_msf_string(const char *str);
static xqc_int_t xqc_msf_json_check(const uint8_t *buf, size_t len);
static xqc_int_t xqc_msf_tree_check(const cJSON *node, size_t *count);
static xqc_int_t xqc_msf_read_track(const cJSON *node,
    const char *inherited, xqc_msf_track_t *track);
static xqc_int_t xqc_msf_read_catalog(xqc_msf_catalog_t *catalog);
static cJSON *xqc_msf_write_track(const xqc_msf_track_t *track);

static xqc_int_t
xqc_msf_utf8(const uint8_t *buf, size_t len)
{
    size_t pos = 0;
    while (pos < len) {
        uint32_t ch = buf[pos++], minimum;
        size_t n;
        if (ch < 0x80) {
            if (!ch) {
                return -XQC_EILLEGAL_FRAME;
            }
            continue;
        }
        if (ch >= 0xc2 && ch <= 0xdf) {
            n = 1;
            minimum = 0x80;
            ch &= 0x1f;

        } else if (ch >= 0xe0 && ch <= 0xef) {
            n = 2;
            minimum = 0x800;
            ch &= 0x0f;

        } else if (ch >= 0xf0 && ch <= 0xf4) {
            n = 3;
            minimum = 0x10000;
            ch &= 7;

        } else {
            return -XQC_EILLEGAL_FRAME;
        }
        if (n > len - pos) {
            return -XQC_EILLEGAL_FRAME;
        }
        while (n--) {
            uint8_t next = buf[pos++];
            if ((next & 0xc0) != 0x80) {
                return -XQC_EILLEGAL_FRAME;
            }
            ch = (ch << 6) | (next & 0x3f);
        }
        if (ch < minimum || ch > 0x10ffff
            || (ch >= 0xd800 && ch <= 0xdfff))
        {
            return -XQC_EILLEGAL_FRAME;
        }
    }
    return XQC_OK;
}

static xqc_int_t
xqc_msf_string(const char *str)
{
    if (str == NULL) {
        return XQC_OK;
    }
    size_t len = strnlen(str, XQC_MSF_MAX_STRING + 1);
    if (len > XQC_MSF_MAX_STRING) {
        return -XQC_ELIMIT;
    }
    return xqc_msf_utf8((const uint8_t *)str, len);
}

/* Bound parsing depth before cJSON allocates or recursively parses input. */
static xqc_int_t
xqc_msf_json_check(const uint8_t *buf, size_t len)
{
    if (xqc_msf_utf8(buf, len) != XQC_OK) {
        return -XQC_EILLEGAL_FRAME;
    }
    size_t depth = 0;
    xqc_bool_t quoted = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t ch = buf[i];
        if (quoted) {
            if (ch < 0x20) {
                return -XQC_EILLEGAL_FRAME;
            }
            if (ch == '\\') {
                if (++i == len) {
                    return -XQC_EILLEGAL_FRAME;
                }
                /* C strings cannot represent a decoded embedded NUL. */
                if (buf[i] == 'u' && len - i >= 5
                    && xqc_memcmp(buf + i + 1, "0000", 4) == 0)
                {
                    return -XQC_EILLEGAL_FRAME;
                }

            } else if (ch == '"') {
                quoted = 0;
            }

        } else if (ch == '"') {
            quoted = 1;

        } else if (ch == '{' || ch == '[') {
            if (++depth > XQC_MSF_MAX_DEPTH) {
                return -XQC_ELIMIT;
            }

        } else if (ch == '}' || ch == ']') {
            if (!depth) {
                return -XQC_EILLEGAL_FRAME;
            }
            depth--;

        } else if (ch < 0x20 && ch != '\t' && ch != '\n' && ch != '\r') {
            return -XQC_EILLEGAL_FRAME;

        } else if (ch == '-' || (ch >= '0' && ch <= '9')) {
            size_t p = i + (ch == '-');
            if (p == len || buf[p] < '0' || buf[p] > '9') {
                return -XQC_EILLEGAL_FRAME;
            }
            if (buf[p++] != '0') {
                while (p < len && buf[p] >= '0' && buf[p] <= '9') {
                    p++;
                }
            }
            if (p < len && buf[p] == '.') {
                size_t first = ++p;
                while (p < len && buf[p] >= '0' && buf[p] <= '9') {
                    p++;
                }
                if (first == p) {
                    return -XQC_EILLEGAL_FRAME;
                }
            }
            if (p < len && (buf[p] == 'e' || buf[p] == 'E')) {
                p++;
                if (p < len && (buf[p] == '+' || buf[p] == '-')) {
                    p++;
                }
                size_t first = p;
                while (p < len && buf[p] >= '0' && buf[p] <= '9') {
                    p++;
                }
                if (first == p) {
                    return -XQC_EILLEGAL_FRAME;
                }
            }
            if (p < len && buf[p] != ',' && buf[p] != '}' && buf[p] != ']'
                && buf[p] != ' ' && buf[p] != '\t' && buf[p] != '\n'
                && buf[p] != '\r')
            {
                return -XQC_EILLEGAL_FRAME;
            }
            i = p - 1;
        }
    }
    return quoted || depth ? -XQC_EILLEGAL_FRAME : XQC_OK;
}

static xqc_int_t
xqc_msf_tree_check(const cJSON *node, size_t *count)
{
    if (++*count > XQC_MSF_MAX_NODES) {
        return -XQC_ELIMIT;
    }
    if (xqc_msf_string(node->string) != XQC_OK
        || (cJSON_IsString(node)
            && xqc_msf_string(node->valuestring) != XQC_OK))
    {
        return -XQC_ELIMIT;
    }
    for (const cJSON *child = node->child; child; child = child->next) {
        if (cJSON_IsObject(node)) {
            for (const cJSON *prior = node->child; prior != child;
                 prior = prior->next)
            {
                if (strcmp(prior->string, child->string) == 0) {
                    return -XQC_EILLEGAL_FRAME;
                }
            }
        }
        xqc_int_t ret = xqc_msf_tree_check(child, count);
        if (ret != XQC_OK) {
            return ret;
        }
    }
    return XQC_OK;
}

static xqc_int_t
xqc_msf_read_track(const cJSON *node, const char *inherited,
    xqc_msf_track_t *track)
{
    if (!cJSON_IsObject(node)) {
        return -XQC_EILLEGAL_FRAME;
    }
    /* MSF-01 sections 4.1 and 5.2: explicitly restricted LOC profile. */
    const cJSON *packaging = cJSON_GetObjectItemCaseSensitive(node,
                                                            "packaging");
    const cJSON *live = cJSON_GetObjectItemCaseSensitive(node, "isLive");
    if (!cJSON_IsString(packaging) || !cJSON_IsBool(live)) {
        return -XQC_EILLEGAL_FRAME;
    }
    if (strcmp(packaging->valuestring, "loc") != 0) {
        return -XQC_EPROTO;
    }
    const char *unsupported[] = {"initRef", "parentName", "parentNamespace",
        "depends", "encryptionScheme", "cipherSuite", "keyId", "trackBaseKey"};
    for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
        if (cJSON_GetObjectItemCaseSensitive(node, unsupported[i])) {
            return -XQC_EPROTO;
        }
    }
    xqc_memset(track, 0, sizeof(*track));
    track->is_live = cJSON_IsTrue(live);
    for (size_t i = 0; i < sizeof(xqc_msf_strings) / sizeof(xqc_msf_strings[0]);
         i++)
    {
        const cJSON *value = cJSON_GetObjectItemCaseSensitive(node,
                                                    xqc_msf_strings[i].name);
        if (value && !cJSON_IsString(value)) {
            return -XQC_EILLEGAL_FRAME;
        }
        const char **field = (const char **)((uint8_t *)track
                                             + xqc_msf_strings[i].offset);
        *field = value ? value->valuestring : NULL;
    }
    if (track->name == NULL) {
        return -XQC_EILLEGAL_FRAME;
    }
    if (track->track_namespace == NULL) {
        track->track_namespace = inherited;
    }
    for (size_t i = 0; i < sizeof(xqc_msf_numbers) / sizeof(xqc_msf_numbers[0]);
         i++)
    {
        const cJSON *value = cJSON_GetObjectItemCaseSensitive(node,
                                                    xqc_msf_numbers[i].name);
        if (value == NULL) {
            continue;
        }
        if (!cJSON_IsNumber(value) || !(value->valuedouble >= 1)
            || value->valuedouble > UINT32_MAX
            || (double)(uint32_t)value->valuedouble != value->valuedouble)
        {
            return -XQC_EILLEGAL_FRAME;
        }
        uint32_t *field = (uint32_t *)((uint8_t *)track
                                         + xqc_msf_numbers[i].offset);
        *field = (uint32_t)value->valuedouble;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_msf_read_catalog(xqc_msf_catalog_t *catalog)
{
    const cJSON *root = catalog->root;
    if (!cJSON_IsObject(root)) {
        return -XQC_EILLEGAL_FRAME;
    }
    const cJSON *version = cJSON_GetObjectItemCaseSensitive(root,
                                                          "msfVersion");
    if (!cJSON_IsString(version)) {
        return -XQC_EILLEGAL_FRAME;
    }
    if (strcmp(version->valuestring, XQC_MSF_VERSION) != 0) {
        return -XQC_EPROTO;
    }
    const char *unsupported[] = {"delta", "publishTracks", "initDataList"};
    for (size_t i = 0; i < 3; i++) {
        if (cJSON_GetObjectItemCaseSensitive(root, unsupported[i])) {
            return -XQC_EPROTO;
        }
    }
    const cJSON *tracks = cJSON_GetObjectItemCaseSensitive(root, "tracks");
    if (!cJSON_IsArray(tracks)) {
        return -XQC_EILLEGAL_FRAME;
    }
    if (cJSON_GetArraySize(tracks) > XQC_MSF_MAX_TRACKS) {
        return -XQC_ELIMIT;
    }
    const cJSON *complete = cJSON_GetObjectItemCaseSensitive(root,
                                                           "isComplete");
    if (complete && !cJSON_IsTrue(complete)) {
        return -XQC_EILLEGAL_FRAME;
    }
    const cJSON *generated = cJSON_GetObjectItemCaseSensitive(root,
                                                            "generatedAt");
    if (generated && (!cJSON_IsNumber(generated)
        || !(generated->valuedouble >= 0)
        || generated->valuedouble > 9007199254740991.0))
    {
        return -XQC_EILLEGAL_FRAME;
    }
    for (const cJSON *node = tracks->child; node; node = node->next) {
        xqc_msf_track_t *track = &catalog->tracks[catalog->count];
        xqc_int_t ret = xqc_msf_read_track(node, catalog->inherited, track);
        if (ret != XQC_OK) {
            return ret;
        }
        if (complete && track->is_live) {
            return -XQC_EILLEGAL_FRAME;
        }
        for (size_t i = 0; i < catalog->count; i++) {
            if (strcmp(track->name, catalog->tracks[i].name) == 0
                && strcmp(track->track_namespace,
                          catalog->tracks[i].track_namespace) == 0)
            {
                return -XQC_EILLEGAL_FRAME;
            }
        }
        catalog->count++;
    }
    return XQC_OK;
}

xqc_int_t
xqc_msf_catalog_decode(const uint8_t *buf, size_t len,
    const char *catalog_namespace, xqc_msf_catalog_t **catalog)
{
    if (buf == NULL || !len || catalog == NULL
        || xqc_msf_string(catalog_namespace) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    if (len > XQC_MSF_MAX_JSON) {
        return -XQC_ELIMIT;
    }
    xqc_int_t ret = xqc_msf_json_check(buf, len);
    if (ret != XQC_OK) {
        return ret;
    }
    xqc_msf_catalog_t *result = xqc_calloc(1, sizeof(*result));
    if (result == NULL) {
        return -XQC_EMALLOC;
    }
    if (catalog_namespace) {
        strcpy(result->inherited, catalog_namespace);
    }
    const char *end = NULL;
    result->root = cJSON_ParseWithLengthOpts((const char *)buf, len,
                                            &end, 0);
    if (result->root == NULL) {
        ret = -XQC_EILLEGAL_FRAME;
        goto failed;
    }
    size_t pos = (const uint8_t *)end - buf;
    while (pos < len && (buf[pos] == ' ' || buf[pos] == '\t'
           || buf[pos] == '\r' || buf[pos] == '\n'))
    {
        pos++;
    }
    if (pos != len) {
        ret = -XQC_EILLEGAL_FRAME;
        goto failed;
    }
    size_t count = 0;
    ret = xqc_msf_tree_check(result->root, &count);
    if (ret == XQC_OK) {
        ret = xqc_msf_read_catalog(result);
    }
    if (ret != XQC_OK) {
        goto failed;
    }
    *catalog = result;
    return XQC_OK;

failed:
    xqc_msf_catalog_destroy(result);
    return ret;
}

static cJSON *
xqc_msf_write_track(const xqc_msf_track_t *track)
{
    cJSON *node = cJSON_CreateObject();
    if (node == NULL) {
        return NULL;
    }
    if (!cJSON_AddStringToObject(node, "packaging", "loc")
        || !cJSON_AddBoolToObject(node, "isLive", track->is_live))
    {
        goto failed;
    }
    for (size_t i = 0; i < sizeof(xqc_msf_strings) / sizeof(xqc_msf_strings[0]);
         i++)
    {
        const char *field = *(const char * const *)((const uint8_t *)track
                                                + xqc_msf_strings[i].offset);
        if (field && !cJSON_AddStringToObject(node, xqc_msf_strings[i].name,
                                             field))
        {
            goto failed;
        }
    }
    for (size_t i = 0; i < sizeof(xqc_msf_numbers) / sizeof(xqc_msf_numbers[0]);
         i++)
    {
        uint32_t field = *(const uint32_t *)((const uint8_t *)track
                                                + xqc_msf_numbers[i].offset);
        if (field && !cJSON_AddNumberToObject(node, xqc_msf_numbers[i].name,
                                             field))
        {
            goto failed;
        }
    }
    return node;

failed:
    cJSON_Delete(node);
    return NULL;
}

xqc_int_t
xqc_msf_catalog_encode(const char *catalog_namespace,
    const xqc_msf_track_t *tracks, size_t count, uint8_t *buf, size_t cap)
{
    if ((count && tracks == NULL) || (buf == NULL && cap)
        || xqc_msf_string(catalog_namespace) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    if (count > XQC_MSF_MAX_TRACKS) {
        return -XQC_ELIMIT;
    }
    const char *inherited = catalog_namespace ? catalog_namespace : "";
    for (size_t i = 0; i < count; i++) {
        if (tracks[i].name == NULL
            || (tracks[i].is_live != 0 && tracks[i].is_live != 1))
        {
            return -XQC_EPARAM;
        }
        for (size_t j = 0;
             j < sizeof(xqc_msf_strings) / sizeof(xqc_msf_strings[0]); j++)
        {
            const char *field = *(const char * const *)((const uint8_t *)
                                    &tracks[i] + xqc_msf_strings[j].offset);
            if (xqc_msf_string(field) != XQC_OK) {
                return -XQC_EPARAM;
            }
        }
        const char *ns = tracks[i].track_namespace;
        for (size_t j = 0; j < i; j++) {
            const char *prior = tracks[j].track_namespace;
            if (strcmp(tracks[i].name, tracks[j].name) == 0
                && strcmp(ns ? ns : inherited,
                          prior ? prior : inherited) == 0)
            {
                return -XQC_EPARAM;
            }
        }
    }
    xqc_int_t ret = -XQC_EMALLOC;
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return ret;
    }
    if (!cJSON_AddStringToObject(root, "msfVersion", XQC_MSF_VERSION)) {
        goto done;
    }
    cJSON *array = cJSON_AddArrayToObject(root, "tracks");
    if (array == NULL) {
        goto done;
    }
    for (size_t i = 0; i < count; i++) {
        cJSON *node = xqc_msf_write_track(&tracks[i]);
        if (node == NULL) {
            goto done;
        }
        if (!cJSON_AddItemToArray(array, node)) {
            cJSON_Delete(node);
            goto done;
        }
    }
    char *json = cJSON_PrintUnformatted(root);
    if (json == NULL) {
        goto done;
    }
    size_t len = strlen(json);
    if (len > XQC_MSF_MAX_JSON) {
        ret = -XQC_ELIMIT;

    } else if (buf && cap < len) {
        ret = -XQC_ENOBUF;

    } else {
        if (buf) {
            xqc_memcpy(buf, json, len);
        }
        ret = (xqc_int_t)len;
    }
    cJSON_free(json);

done:
    cJSON_Delete(root);
    return ret;
}

size_t
xqc_msf_catalog_track_count(const xqc_msf_catalog_t *catalog)
{
    return catalog ? catalog->count : 0;
}

xqc_int_t
xqc_msf_catalog_track(const xqc_msf_catalog_t *catalog, size_t index,
    xqc_msf_track_t *track)
{
    if (catalog == NULL || track == NULL || index >= catalog->count) {
        return -XQC_EPARAM;
    }
    *track = catalog->tracks[index];
    return XQC_OK;
}

void
xqc_msf_catalog_destroy(xqc_msf_catalog_t *catalog)
{
    if (catalog) {
        cJSON_Delete(catalog->root);
        xqc_free(catalog);
    }
}
