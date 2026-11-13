/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <stdio.h>
#include <moq/xqc_loc.h>
#include <moq/xqc_msf.h>
#include "xqc_loc_msf_test.h"
#include "moq/moqt/xqc_moqt_codec.h"
#include "src/common/xqc_str.h"

static xqc_int_t xqc_msf_test_parse(const char *json);

/* LOC-05 section 2.3: delta keys, vi64 values, optional public metadata. */
void
xqc_test_loc_properties(void)
{
    const uint8_t wire[] = {8, 100, 1, 1, 0x20, 3, 0x80, 0xff,
        1, 2, 0x01, 0x02, 2, 1, 0x03, 1, 42, 1, 4, 'o', 'p', 'u', 's'};
    xqc_loc_metadata_t metadata;
    CU_ASSERT_EQUAL(xqc_loc_decode(wire, sizeof(wire), &metadata), XQC_OK);
    CU_ASSERT_EQUAL(metadata.present, XQC_LOC_FIELDS);
    CU_ASSERT_EQUAL(metadata.timescale, 100);
    CU_ASSERT_EQUAL(metadata.timestamp, 42);
    CU_ASSERT_EQUAL(metadata.audio_level, 255);
    CU_ASSERT_EQUAL(metadata.video_marking.iov_len, 1);
    CU_ASSERT_EQUAL(metadata.video_config.iov_len, 2);
    CU_ASSERT_EQUAL(metadata.audio_config.iov_len, 1);
    CU_ASSERT_EQUAL(metadata.codec.iov_len, 4);
    CU_ASSERT_PTR_EQUAL(metadata.codec.iov_base, wire + sizeof(wire) - 4);
    uint8_t out[128];
    CU_ASSERT_EQUAL(xqc_loc_encode(&metadata, NULL, 0), sizeof(wire));
    CU_ASSERT_EQUAL(xqc_loc_encode(&metadata, out, sizeof(out)), sizeof(wire));
    CU_ASSERT_EQUAL(xqc_memcmp(wire, out, sizeof(wire)), 0);

    /* Empty properties and unknown even/odd keys do not prefix the payload. */
    CU_ASSERT_EQUAL(xqc_loc_decode(NULL, 0, &metadata), XQC_OK);
    CU_ASSERT_EQUAL(metadata.present, 0);
    CU_ASSERT_EQUAL(metadata.timescale, 1000000);
    CU_ASSERT_EQUAL(xqc_loc_encode(&metadata, NULL, 0), 0);
    const uint8_t unknown[] = {2, 127, 1, 2, 0xff, 0xfe, 13, 1};
    CU_ASSERT_EQUAL(xqc_loc_decode(unknown, sizeof(unknown), &metadata),
                    XQC_OK);
    CU_ASSERT_EQUAL(metadata.present, XQC_LOC_TIMESTAMP);
    CU_ASSERT_EQUAL(metadata.timestamp, 1);

    /* vi64's full uint64 range, not QUIC's 62-bit range. */
    metadata.timestamp = UINT64_MAX;
    xqc_int_t n = xqc_loc_encode(&metadata, out, sizeof(out));
    CU_ASSERT_EQUAL(n, 10);
    CU_ASSERT_EQUAL(out[1], 0xff);
    CU_ASSERT_EQUAL(xqc_loc_decode(out, n, &metadata), XQC_OK);
    CU_ASSERT_EQUAL(metadata.timestamp, UINT64_MAX);
}

void
xqc_test_loc_errors(void)
{
    xqc_loc_metadata_t before = {0}, metadata;
    before.timestamp = 123;
    const uint8_t bad[][6] = {
        {16}, {16, 0x80}, {9, 0}, {9, 5, 1, 2, 3, 4},
        {8, 0}, {16, 1, 0, 2}, {12, 0x81, 0},
    };
    const size_t sizes[] = {1, 2, 2, 6, 2, 4, 3};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        metadata = before;
        CU_ASSERT_EQUAL(xqc_loc_decode(bad[i], sizes[i], &metadata),
                        -XQC_EILLEGAL_FRAME);
        CU_ASSERT_EQUAL(xqc_memcmp(&before, &metadata, sizeof(before)), 0);
    }
    uint8_t many[130];
    for (size_t i = 0; i < sizeof(many); i += 2) {
        many[i] = 0;
        many[i + 1] = 0;
    }
    CU_ASSERT_EQUAL(xqc_loc_decode(many, sizeof(many), &metadata), -XQC_ELIMIT);
    CU_ASSERT_EQUAL(xqc_loc_decode(many, XQC_LOC_MAX_BYTES + 1, &metadata),
                    -XQC_ELIMIT);
    CU_ASSERT_EQUAL(xqc_loc_decode(NULL, 1, &metadata), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_loc_decode(NULL, 0, NULL), -XQC_EPARAM);

    uint8_t out[16], copy[16];
    xqc_memset(out, 0xa5, sizeof(out));
    xqc_memcpy(copy, out, sizeof(out));
    metadata = before;
    metadata.present = XQC_LOC_TIMESTAMP;
    for (size_t i = 0; i < 2; i++) {
        CU_ASSERT_EQUAL(xqc_loc_encode(&metadata, out, i), -XQC_ENOBUF);
        CU_ASSERT_EQUAL(xqc_memcmp(out, copy, sizeof(out)), 0);
    }
    metadata.present = XQC_LOC_VIDEO_MARKING;
    CU_ASSERT_EQUAL(xqc_loc_encode(&metadata, out, sizeof(out)), -XQC_EPARAM);
    metadata.present = XQC_LOC_TIMESCALE;
    CU_ASSERT_EQUAL(xqc_loc_encode(&metadata, out, sizeof(out)), -XQC_EPARAM);
    metadata.present = 0x80;
    CU_ASSERT_EQUAL(xqc_loc_encode(&metadata, out, sizeof(out)), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_loc_encode(NULL, out, sizeof(out)), -XQC_EPARAM);
    metadata.present = XQC_LOC_VIDEO_CONFIG;
    metadata.video_config.iov_len = 1;
    CU_ASSERT_EQUAL(xqc_loc_encode(&metadata, out, sizeof(out)), -XQC_EPARAM);
}

/* MSF-01 sections 5/5.1/5.2: independent, case-sensitive catalog schema. */
void
xqc_test_msf_catalog(void)
{
    const char json[] = "{\"msfVersion\":\"draft-01\",\"generatedAt\":42,"
        "\"custom\":{\"array\":[1,true,null]},\"tracks\":["
        "{\"name\":\"v\\u0069deo\",\"packaging\":\"loc\",\"isLive\":true,"
        "\"codec\":\"avc1.64001f\",\"width\":1280,\"height\":720,"
        "\"role\":\"video\",\"timescale\":90000},"
        "{\"name\":\"audio\",\"namespace\":\"other\",\"packaging\":\"loc\","
        "\"isLive\":false,\"codec\":\"opus\",\"mimeType\":\"audio/opus\","
        "\"samplerate\":48000,\"channelConfig\":\"2\"}]} \n";
    xqc_msf_catalog_t *catalog = NULL;
    CU_ASSERT_EQUAL_FATAL(xqc_msf_catalog_decode((const uint8_t *)json,
        strlen(json), "live/example", &catalog), XQC_OK);
    CU_ASSERT_EQUAL(xqc_msf_catalog_track_count(catalog), 2);
    xqc_msf_track_t tracks[2];
    CU_ASSERT_EQUAL(xqc_msf_catalog_track(catalog, 0, &tracks[0]), XQC_OK);
    CU_ASSERT_STRING_EQUAL(tracks[0].name, "video");
    CU_ASSERT_STRING_EQUAL(tracks[0].track_namespace, "live/example");
    CU_ASSERT_EQUAL(tracks[0].timescale, 90000);
    CU_ASSERT_EQUAL(tracks[0].width, 1280);
    CU_ASSERT_EQUAL(tracks[0].height, 720);
    CU_ASSERT_TRUE(tracks[0].is_live);
    CU_ASSERT_EQUAL(xqc_msf_catalog_track(catalog, 1, &tracks[1]), XQC_OK);
    CU_ASSERT_STRING_EQUAL(tracks[1].track_namespace, "other");
    CU_ASSERT_STRING_EQUAL(tracks[1].mime_type, "audio/opus");
    CU_ASSERT_STRING_EQUAL(tracks[1].channel_config, "2");
    CU_ASSERT_EQUAL(tracks[1].samplerate, 48000);
    CU_ASSERT_FALSE(tracks[1].is_live);

    uint8_t wire[2048];
    xqc_int_t n = xqc_msf_catalog_encode("live/example", tracks, 2, NULL, 0);
    CU_ASSERT_TRUE_FATAL(n > 0);
    CU_ASSERT_EQUAL(xqc_msf_catalog_encode("live/example", tracks, 2,
                    wire, sizeof(wire)), n);
    xqc_msf_catalog_t *copy = NULL;
    CU_ASSERT_EQUAL_FATAL(xqc_msf_catalog_decode(wire, n, "live/example",
                                               &copy), XQC_OK);
    xqc_msf_catalog_destroy(catalog);
    CU_ASSERT_EQUAL(xqc_msf_catalog_track(copy, 0, &tracks[0]), XQC_OK);
    CU_ASSERT_STRING_EQUAL(tracks[0].codec, "avc1.64001f");
    xqc_msf_catalog_destroy(copy);
    xqc_msf_catalog_destroy(NULL);

    const char complete[] = "{\"msfVersion\":\"draft-01\",\"isComplete\":true,"
        "\"tracks\":[{\"name\":\"\",\"packaging\":\"loc\",\"isLive\":false}]}";
    CU_ASSERT_EQUAL_FATAL(xqc_msf_catalog_decode((const uint8_t *)complete,
        strlen(complete), NULL, &catalog), XQC_OK);
    CU_ASSERT_EQUAL(xqc_msf_catalog_track_count(catalog), 1);
    xqc_msf_catalog_destroy(catalog);
    CU_ASSERT_TRUE(xqc_msf_catalog_encode(NULL, NULL, 0, wire,
                                         sizeof(wire)) > 0);

    /* Unknown field names are case-sensitive, including reserved spellings. */
    CU_ASSERT_EQUAL(xqc_msf_test_parse("{\"msfVersion\":\"draft-01\","
        "\"DELTA\":[],\"tracks\":[{\"name\":\"v\",\"packaging\":\"loc\","
        "\"isLive\":true,\"EncryptionScheme\":\"custom\"}]}"), XQC_OK);

    xqc_msf_track_t maximum[XQC_MSF_MAX_TRACKS] = {0};
    char names[XQC_MSF_MAX_TRACKS][8];
    uint8_t large[8192];
    for (size_t i = 0; i < XQC_MSF_MAX_TRACKS; i++) {
        snprintf(names[i], sizeof(names[i]), "t%u", (unsigned)i);
        maximum[i].name = names[i];
    }
    n = xqc_msf_catalog_encode(NULL, maximum, XQC_MSF_MAX_TRACKS, large,
                                sizeof(large));
    CU_ASSERT_TRUE_FATAL(n > 0);
    CU_ASSERT_EQUAL_FATAL(xqc_msf_catalog_decode(large, n, NULL, &catalog),
                          XQC_OK);
    CU_ASSERT_EQUAL(xqc_msf_catalog_track_count(catalog), XQC_MSF_MAX_TRACKS);
    xqc_msf_catalog_destroy(catalog);
}

static xqc_int_t
xqc_msf_test_parse(const char *json)
{
    xqc_msf_catalog_t *catalog = NULL;
    xqc_int_t ret = xqc_msf_catalog_decode((const uint8_t *)json,
                                          strlen(json), "live", &catalog);
    if (ret == XQC_OK) {
        xqc_msf_catalog_destroy(catalog);
    } else {
        CU_ASSERT_PTR_NULL(catalog);
    }
    return ret;
}

void
xqc_test_msf_errors(void)
{
    const char *invalid[] = {
        "{}", "[]", "{\"msfVersion\":1,\"tracks\":[]}",
        "{\"msfVersion\":\"draft-01\",\"tracks\":{}}",
        "{\"msfVersion\":\"draft-01\",\"tracks\":[],\"tracks\":[]}",
        "{\"msfVersion\":\"draft-01\",\"tracks\":[{}]}",
        "{\"msfVersion\":\"draft-01\",\"isComplete\":false,\"tracks\":[]}",
        "{\"msfVersion\":\"draft-01\",\"tracks\":[]}garbage",
        "{\"msfVersion\":\"draft-01\",\"generatedAt\":01,\"tracks\":[]}",
        "{\"msfVersion\":\"draft-01\",\"generatedAt\":1.,\"tracks\":[]}",
        "{\"msfVersion\":\"draft-01\",\"generatedAt\":1e,\"tracks\":[]}",
        "{\"msfVersion\":\"draft-01\",\"unknown\":\"\\u0000\",\"tracks\":[]}",
        "{\"msfVersion\":\"draft-01\",\"unknown\":\"\xc0\x80\",\"tracks\":[]}",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        CU_ASSERT_EQUAL(xqc_msf_test_parse(invalid[i]), -XQC_EILLEGAL_FRAME);
    }
    CU_ASSERT_EQUAL(xqc_msf_test_parse(
        "{\"msfVersion\":\"draft-99\",\"tracks\":[]}"), -XQC_EPROTO);
    CU_ASSERT_EQUAL(xqc_msf_test_parse(
        "{\"msfVersion\":\"draft-01\",\"tracks\":[],\"delta\":[]}"),
        -XQC_EPROTO);
    CU_ASSERT_EQUAL(xqc_msf_test_parse("{\"msfVersion\":\"draft-01\","
        "\"tracks\":[{\"name\":\"v\",\"packaging\":\"cmaf\","
        "\"isLive\":true}]}"),
        -XQC_EPROTO);
    CU_ASSERT_EQUAL(xqc_msf_test_parse("{\"msfVersion\":\"draft-01\","
        "\"tracks\":[{\"name\":\"v\",\"packaging\":\"loc\",\"isLive\":true},"
        "{\"name\":\"v\",\"namespace\":\"live\",\"packaging\":\"loc\","
        "\"isLive\":false}]}"), -XQC_EILLEGAL_FRAME);

    const char *fields[] = {"\"isLive\":1", "\"width\":1.5",
        "\"width\":4294967296", "\"timescale\":0", "\"codec\":true",
        "\"name\":\"duplicate\"", "\"width\":1e999"};
    char json[1024];
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        snprintf(json, sizeof(json), "{\"msfVersion\":\"draft-01\",\"tracks\":["
            "{\"name\":\"v\",\"packaging\":\"loc\",\"isLive\":true,%s}]}",
            fields[i]);
        CU_ASSERT_EQUAL(xqc_msf_test_parse(json), -XQC_EILLEGAL_FRAME);
    }
    const char *unsupported[] = {"\"initRef\":\"id\"", "\"depends\":[\"v\"]",
        "\"parentName\":\"v\"", "\"encryptionScheme\":\"moq-secure-objects\""};
    for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
        snprintf(json, sizeof(json), "{\"msfVersion\":\"draft-01\",\"tracks\":["
            "{\"name\":\"v\",\"packaging\":\"loc\",\"isLive\":true,%s}]}",
            unsupported[i]);
        CU_ASSERT_EQUAL(xqc_msf_test_parse(json), -XQC_EPROTO);
    }
    const char *valid = "{\"msfVersion\":\"draft-01\",\"tracks\":[]}";
    for (size_t n = 1; n < strlen(valid); n++) {
        xqc_msf_catalog_t *catalog = NULL;
        CU_ASSERT_EQUAL(xqc_msf_catalog_decode((const uint8_t *)valid, n,
                        NULL, &catalog), -XQC_EILLEGAL_FRAME);
        CU_ASSERT_PTR_NULL(catalog);
    }
    char deep[64];
    xqc_memset(deep, '[', 17);
    xqc_memset(deep + 17, ']', 17);
    xqc_msf_catalog_t *catalog = NULL;
    CU_ASSERT_EQUAL(xqc_msf_catalog_decode((const uint8_t *)deep, 34,
                    NULL, &catalog), -XQC_ELIMIT);
    CU_ASSERT_EQUAL(xqc_msf_catalog_decode((const uint8_t *)valid,
                    XQC_MSF_MAX_JSON + 1, NULL, &catalog), -XQC_ELIMIT);
    CU_ASSERT_EQUAL(xqc_msf_catalog_decode(NULL, 1, NULL, &catalog),
                    -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_msf_catalog_decode((const uint8_t *)valid,
                    strlen(valid), NULL, NULL), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_msf_catalog_track(NULL, 0, NULL), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_msf_catalog_track_count(NULL), 0);

    xqc_msf_track_t tracks[2] = {{.name = "v", .is_live = 1},
        {.name = "v", .track_namespace = "live", .is_live = 1}};
    CU_ASSERT_EQUAL(xqc_msf_catalog_encode("live", tracks, 2, NULL, 0),
                    -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_msf_catalog_encode(NULL, tracks,
                    XQC_MSF_MAX_TRACKS + 1, NULL, 0), -XQC_ELIMIT);
    uint8_t out[32], before[32];
    xqc_memset(out, 0xa5, sizeof(out));
    xqc_memcpy(before, out, sizeof(out));
    CU_ASSERT_EQUAL(xqc_msf_catalog_encode(NULL, tracks, 1, out, sizeof(out)),
                    -XQC_ENOBUF);
    CU_ASSERT_EQUAL(xqc_memcmp(out, before, sizeof(out)), 0);
    tracks[0].name = NULL;
    CU_ASSERT_EQUAL(xqc_msf_catalog_encode(NULL, tracks, 1, out, sizeof(out)),
                    -XQC_EPARAM);

    char oversized[XQC_MSF_MAX_STRING + 2];
    xqc_memset(oversized, 'x', sizeof(oversized) - 1);
    oversized[sizeof(oversized) - 1] = '\0';
    tracks[0].name = oversized;
    CU_ASSERT_EQUAL(xqc_msf_catalog_encode(NULL, tracks, 1, NULL, 0),
                    -XQC_EPARAM);

    uint8_t excess[4096];
    size_t pos = (size_t)snprintf((char *)excess, sizeof(excess),
        "{\"msfVersion\":\"draft-01\",\"tracks\":[");
    for (size_t i = 0; i <= XQC_MSF_MAX_TRACKS; i++) {
        pos += (size_t)snprintf((char *)excess + pos, sizeof(excess) - pos,
            "%s{\"name\":\"t%u\","
            "\"packaging\":\"loc\",\"isLive\":false}", i ? "," : "",
            (unsigned)i);
    }
    pos += (size_t)snprintf((char *)excess + pos, sizeof(excess) - pos, "]}");
    CU_ASSERT_EQUAL(xqc_msf_catalog_decode(excess, pos, NULL, &catalog),
                    -XQC_ELIMIT);
}

/* LOC-05 section 2.2 and MSF-01 sections 4.1/5: carrier composition. */
void
xqc_test_loc_msf_objects(void)
{
    uint8_t marking = 0x20, properties[64], wire[2048];
    const uint8_t payload[] = {0, 0, 0, 1, 0x65, 0xff};
    xqc_loc_metadata_t metadata = {.present = XQC_LOC_TIMESTAMP
        | XQC_LOC_VIDEO_MARKING, .timestamp = 42,
        .video_marking = {&marking, 1}};
    xqc_int_t n = xqc_loc_encode(&metadata, properties, sizeof(properties));
    CU_ASSERT_TRUE_FATAL(n > 0);
    xqc_moqt_object_t source = {.group_id = 7, .object_id = 0,
        .properties = {properties, n}, .payload = {(void *)payload,
        sizeof(payload)}, .payload_length = sizeof(payload), .priority = 128,
        .datagram = 1};
    xqc_int_t len = xqc_moqt_datagram_encode(3, &source, wire, sizeof(wire));
    CU_ASSERT_TRUE_FATAL(len > 0);
    uint64_t alias, flags;
    xqc_moqt_object_t decoded = {0};
    CU_ASSERT_TRUE(xqc_moqt_datagram_decode(wire, len, &alias, &flags,
                                          &decoded) > 0);
    CU_ASSERT_EQUAL(alias, 3);
    CU_ASSERT_EQUAL(decoded.group_id, 7);
    CU_ASSERT_EQUAL(decoded.payload.iov_len, sizeof(payload));
    CU_ASSERT_EQUAL(xqc_memcmp(decoded.payload.iov_base, payload,
                               sizeof(payload)), 0);
    CU_ASSERT_EQUAL(xqc_loc_decode(decoded.properties.iov_base,
                    decoded.properties.iov_len, &metadata), XQC_OK);
    CU_ASSERT_EQUAL(metadata.timestamp, 42);

    /* Corrupt only LOC metadata: Object framing still decodes, LOC rejects. */
    uint8_t invalid[] = {16, 1, 0, 2};
    source.properties.iov_base = invalid;
    source.properties.iov_len = sizeof(invalid);
    len = xqc_moqt_datagram_encode(3, &source, wire, sizeof(wire));
    CU_ASSERT_TRUE_FATAL(len > 0);
    CU_ASSERT_TRUE(xqc_moqt_datagram_decode(wire, len, &alias, &flags,
                                          &decoded) > 0);
    CU_ASSERT_EQUAL(xqc_loc_decode(decoded.properties.iov_base,
                    decoded.properties.iov_len, &metadata),
                    -XQC_EILLEGAL_FRAME);

    /* MSF-01 section 5: complete catalog at Group start/Subgroup 0/Object 0. */
    xqc_msf_track_t track = {.name = "video", .codec = "avc1.64001f",
                             .is_live = 1};
    uint8_t json[256];
    n = xqc_msf_catalog_encode(NULL, &track, 1, json, sizeof(json));
    CU_ASSERT_TRUE_FATAL(n > 0);
    source.datagram = 0;
    source.subgroup_id = 0;
    source.properties.iov_len = 0;
    source.payload.iov_base = json;
    source.payload.iov_len = source.payload_length = n;
    uint64_t subgroup_flags = XQC_MOQT_SUBGROUP_FIXED_BITS
                              | XQC_MOQT_SUBGROUP_EXPLICIT_ID;
    len = xqc_moqt_subgroup_header_encode(4, subgroup_flags, &source,
                                          wire, sizeof(wire));
    CU_ASSERT_TRUE_FATAL(len > 0);
    CU_ASSERT_EQUAL(xqc_moqt_subgroup_header_decode(wire, len, &alias,
                                                  &flags, &decoded), len);
    CU_ASSERT_EQUAL(alias, 4);
    CU_ASSERT_EQUAL(decoded.subgroup_id, 0);
    len = xqc_moqt_object_header_encode(flags, NULL, &source, wire,
                                        sizeof(wire));
    CU_ASSERT_TRUE_FATAL(len > 0);
    CU_ASSERT_EQUAL(xqc_moqt_object_header_decode(wire, len, flags, NULL,
                                                &decoded), len);
    CU_ASSERT_EQUAL(decoded.object_id, 0);
    CU_ASSERT_EQUAL(decoded.payload_length, n);
    xqc_memcpy(wire + len, json, n);
    xqc_msf_catalog_t *catalog = NULL;
    CU_ASSERT_EQUAL_FATAL(xqc_msf_catalog_decode(wire + len,
        decoded.payload_length, NULL, &catalog), XQC_OK);
    CU_ASSERT_EQUAL(xqc_msf_catalog_track(catalog, 0, &track), XQC_OK);
    CU_ASSERT_STRING_EQUAL(track.name, "video");
    xqc_msf_catalog_destroy(catalog);
}
