#include "moq/moq_media/xqc_moq_catalog.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/cjson/cJSON.h"

static void xqc_moq_catalog_on_create(xqc_moq_track_t *track);
static void xqc_moq_catalog_on_destroy(xqc_moq_track_t *track);
static void xqc_moq_catalog_on_subscribe(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg);
static void xqc_moq_catalog_on_subscribe_ok(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_ok_msg_t *subscribe_ok);
static void xqc_moq_catalog_on_subscribe_error(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_error_msg_t *subscribe_error);
static void xqc_moq_catalog_on_object(xqc_moq_session_t *session, xqc_moq_track_t *track, xqc_moq_object_t *object);

const xqc_moq_track_ops_t xqc_moq_catalog_track_ops = {
    .on_create           = xqc_moq_catalog_on_create,
    .on_destroy          = xqc_moq_catalog_on_destroy,
    .on_subscribe        = xqc_moq_catalog_on_subscribe,
    .on_subscribe_update = NULL,
    .on_subscribe_ok     = xqc_moq_catalog_on_subscribe_ok,
    .on_subscribe_error  = xqc_moq_catalog_on_subscribe_error,
    .on_object           = xqc_moq_catalog_on_object,
};

#define XQC_MOQ_PROCESS_CATALOG_REQUIRED_STRING_FIELD(cstring_ptr, catalog_json, field_name)         \
    do {                                                                                             \
        cJSON *item = cJSON_GetObjectItemCaseSensitive(catalog_json, field_name);                    \
        if (cJSON_IsString(item)) {                                                                  \
            size_t len = strlen((item)->valuestring) + 1;                                            \
            cstring_ptr = (char *)xqc_realloc(cstring_ptr, len);                                     \
            if (cstring_ptr == NULL) {                                                               \
                ret = XQC_MOQ_CATALOG_DECODE_ALLOCATION_ERROR;                                       \
                goto end;                                                                            \
            }                                                                                        \
            xqc_memcpy(cstring_ptr, (item)->valuestring, len);                                       \
        } else {                                                                                     \
            ret = XQC_MOQ_CATALOG_DECODE_FIELD_MISSING;                                              \
            goto end;                                                                                \
        }                                                                                            \
    } while (0)    

#define XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_STRING_FIELD(cstring_ptr, catalog_json, field_name)      \
    do {                                                                                             \
        cJSON *item = cJSON_GetObjectItemCaseSensitive(catalog_json, field_name);                    \
        if (cJSON_IsString(item)) {                                                                  \
            size_t len = strlen((item)->valuestring) + 1;                                            \
            cstring_ptr = (char *)xqc_realloc(cstring_ptr, len);                                     \
            if (cstring_ptr == NULL) {                                                               \
                ret = -XQC_MOQ_CATALOG_DECODE_ALLOCATION_ERROR;                                      \
                goto end;                                                                            \
            }                                                                                        \
            xqc_memcpy(cstring_ptr, (item)->valuestring, len);                                       \
        }                                                                                            \
    } while (0)


#define XQC_MOQ_PROCESS_CATALOG_REQUIRED_INT_FIELD(int_item, catalog_json, field_name)               \
    do {                                                                                             \
        cJSON *item = cJSON_GetObjectItemCaseSensitive(catalog_json, field_name);                    \
        if (cJSON_IsNumber(item)) {                                                                  \
            int_item = item->valueint;                                                               \
        } else {                                                                                     \
            ret = XQC_MOQ_CATALOG_DECODE_FIELD_MISSING;                                              \
            goto end;                                                                                \
        }                                                                                            \
    } while (0)

#define XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_INT_FIELD(int_item, catalog_json, field_name)            \
    do {                                                                                             \
        cJSON *item = cJSON_GetObjectItemCaseSensitive(catalog_json, field_name);                    \
        if (cJSON_IsNumber(item)) {                                                                  \
            int_item = item->valueint;                                                               \
        }                                                                                            \
    } while (0)


#define XQC_MOQ_ADD_REQUIRED_STRING_TO_CATALOG(cstring_ptr, catalog_json, field_name)               \
    do {                                                                                            \
        if (cstring_ptr == NULL) {                                                                  \
            ret = XQC_MOQ_CATALOG_ENCODE_INVALID_STRING;                                            \
            goto end;                                                                               \
        }                                                                                           \
        if (cJSON_AddStringToObject(catalog_json, field_name, cstring_ptr) == NULL) {               \
            ret = XQC_MOQ_CATALOG_ENCODE_ITEMADD_FAIL;                                              \
            goto end;                                                                               \
        }                                                                                           \
    } while (0)


#define XQC_MOQ_ADD_UNNECESSARY_STRING_TO_CATALOG(cstring_ptr, catalog_json, field_name)           \
    do {                                                                                           \
        if (cstring_ptr != NULL) {                                                                 \
            if (cJSON_AddStringToObject(catalog_json, field_name, cstring_ptr) == NULL) {          \
                ret = XQC_MOQ_CATALOG_ENCODE_ITEMADD_FAIL;                                         \
                goto end;                                                                          \
            }                                                                                      \
        }                                                                                          \
    } while (0)

#define XQC_MOQ_ADD_REQUIRED_INT_TO_CATALOG(int_item, catalog_json, field_name)                   \
    do {                                                                                          \
        if (int_item == -1) {                                                                     \
            ret = XQC_MOQ_CATALOG_ENCODE_INVALID_RANGE;                                           \
            goto end;                                                                             \
        }                                                                                         \
        if (cJSON_AddNumberToObject(catalog_json, field_name, int_item) == NULL) {                \
            ret = XQC_MOQ_CATALOG_ENCODE_ITEMADD_FAIL;                                            \
            goto end;                                                                             \
        }                                                                                         \
    } while (0)

#define XQC_MOQ_ADD_UNNECESSARY_INT_TO_CATALOG(int_item, catalog_json, field_name)               \
    do {                                                                                         \
        if (int_item != -1) {                                                                    \
            if (cJSON_AddNumberToObject(catalog_json, field_name, int_item) == NULL) {           \
                ret = XQC_MOQ_CATALOG_ENCODE_ITEMADD_FAIL;                                       \
                goto end;                                                                        \
            }                                                                                    \
        }                                                                                        \
    } while (0)

// xqc moq catalog Field Name
const char kVersion[]                     = "version";
const char kSequence[]                    = "sequence";
const char kStreamingFormat[]             = "streamingFormat";
const char kStreamingFormatVersion[]      = "streamingFormatVersion";
const char kTracks[]                      = "tracks";
const char kCatalogs[]                    = "catalogs";
const char kNamespace[]                   = "namespace";
const char kPackaging[]                   = "packaging";
const char kRole[]                        = "role";
const char kName[]                        = "name";
const char kOperation[]                   = "operation";
const char kLabel[]                       = "label";
const char kRenderGroup[]                 = "renderGroup";
const char kAltGroup[]                    = "altGroup";
const char kInitData[]                    = "initData";
const char kSelectionParams[]             = "selectionParams";
const char kDepends[]                     = "depends";
const char kTemporalId[]                  = "temporalId";
const char kSpatialId[]                   = "spatialId";
const char kMimeType[]                    = "mimeType";
const char kFramerate[]                   = "framerate";
const char kCodec[]                       = "codec";
const char kBitrate[]                     = "bitrate";
const char kWidth[]                       = "width";
const char kHeight[]                      = "height";
const char kDisplayWidth[]                = "displayWidth";
const char kDisplayHeight[]               = "displayHeight";
const char kLang[]                        = "language";
const char kSamplerate[]                  = "samplerate";
const char kChannelConfig[]               = "channelConfig";
const char kCommonTrackFields[]           = "commonTrackFields";


typedef enum xqc_moq_catalog_decode_error_s{
    // No error.
    XQC_MOQ_CATALOG_DECODE_OK,

    // an catalog can not be parsered to json
    XQC_MOQ_CATALOG_DECODE_INVALID_CATALOG,

    // miss the required field
    XQC_MOQ_CATALOG_DECODE_FIELD_MISSING, 
    
    // General error indicating that a supplied parameter is invalid.
    XQC_MOQ_CATALOG_DECODE_INVALID_PARAMETER,

    // string memory allocation error
    XQC_MOQ_CATALOG_DECODE_ALLOCATION_ERROR,

    XQC_MOQ_CATALOG_DECODE_INTERNAL_ERROR,
} xqc_moq_catalog_decode_error_t;


typedef enum xqc_moq_catalog_encode_error_s{
    // No error.
    XQC_MOQ_CATALOG_ENCODE_OK,

    // a string field is required but 'catalog' has a invalid string
    XQC_MOQ_CATALOG_ENCODE_INVALID_STRING,

    // a int field is required but 'catalog' has a invalid range
    XQC_MOQ_CATALOG_ENCODE_INVALID_RANGE,

    // add sub-item to parent catalog json fail
    XQC_MOQ_CATALOG_ENCODE_ITEMADD_FAIL,

    // miss required fileds
    XQC_MOQ_CATALOG_ENCODE_FIELD_MISSING,

    XQC_MOQ_CATALOG_ENCODE_INTERNAL_ERROR,
}xqc_moq_catalog_encode_error_t;


void
xqc_moq_catalog_init(xqc_moq_catalog_t *catalog)
{
    xqc_memset(catalog, 0, sizeof(*catalog));
    catalog->version = -1;
    catalog->sequence = -1;
    catalog->streaming_format = -1;
    catalog->common_track_fields.renderGroup = -1;
    xqc_init_list_head(&catalog->track_list_for_sub);
}


void
xqc_moq_catalog_free_fields(xqc_moq_catalog_t *catalog)
{
    xqc_free(catalog->streaming_format_version);
    catalog->streaming_format_version = NULL;
    xqc_free(catalog->common_track_fields.packaging);
    catalog->common_track_fields.packaging = NULL;
    xqc_free(catalog->common_track_fields.track_namespace);
    catalog->common_track_fields.track_namespace = NULL;

    xqc_list_head_t *pos, *next;
    xqc_moq_track_t *tmp_track;

    xqc_list_for_each_safe(pos, next, &catalog->track_list_for_sub) {
        xqc_list_del(pos);
        tmp_track = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        xqc_moq_track_free_fields(tmp_track);
        xqc_free(tmp_track);
    }

    catalog->track_list_for_pub = NULL;
}


// decode feilds of single track
xqc_moq_catalog_decode_error_t 
xqc_moq_catalog_single_track_decode(cJSON *track_json, xqc_moq_track_t *track, xqc_moq_catalog_t *catalog) 
{
    xqc_moq_catalog_decode_error_t ret = XQC_MOQ_CATALOG_DECODE_OK;
    XQC_MOQ_PROCESS_CATALOG_REQUIRED_STRING_FIELD(track->track_info.track_name, track_json, kName);
    XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_STRING_FIELD(track->track_info.track_namespace, track_json, kNamespace);
    XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_STRING_FIELD(track->packaging, track_json, kPackaging);
    if (track->packaging != NULL && strncmp(track->packaging, XQC_MOQ_CONTAINER_LOC_STR, strlen(track->packaging)) == 0) {
        track->container_format = XQC_MOQ_CONTAINER_LOC;
    } else if (track->packaging != NULL && strncmp(track->packaging, XQC_MOQ_CONTAINER_CMAF_STR, strlen(track->packaging)) == 0) {
        track->container_format = XQC_MOQ_CONTAINER_CMAF;
    }
    cJSON *role_field = cJSON_GetObjectItemCaseSensitive(track_json, kRole);
    if (cJSON_IsString(role_field)) {
        if (strcasecmp(role_field->valuestring, "video") == 0) {
            track->track_info.track_type = XQC_MOQ_TRACK_VIDEO;
        } else if (strcasecmp(role_field->valuestring, "audio") == 0) {
            track->track_info.track_type = XQC_MOQ_TRACK_AUDIO;
        }
    }

    XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_INT_FIELD(track->render_group, track_json, kRenderGroup);

    
    // inherit from catalog->common_track_fields
    if (track->track_info.track_namespace == NULL && catalog->common_track_fields.track_namespace != NULL) {
        size_t str_len = strlen(catalog->common_track_fields.track_namespace) + 1;
        track->track_info.track_namespace = xqc_malloc(str_len);
        xqc_memcpy(track->track_info.track_namespace, catalog->common_track_fields.track_namespace, str_len);
    }
    if (track->packaging == NULL && catalog->common_track_fields.packaging != NULL) {
        size_t str_len = strlen(catalog->common_track_fields.packaging) + 1;
        track->packaging = xqc_malloc(str_len);
        xqc_memcpy(track->packaging, catalog->common_track_fields.packaging, str_len);
    }
    if (track->render_group == -1 && catalog->common_track_fields.renderGroup != -1) {
        track->render_group = catalog->common_track_fields.renderGroup;
    }

    // selectionParams
    cJSON *track_params = cJSON_GetObjectItemCaseSensitive(track_json, kSelectionParams);
    if (cJSON_IsObject(track_params)) {
        XQC_MOQ_PROCESS_CATALOG_REQUIRED_STRING_FIELD(track->track_info.selection_params.codec, track_params, kCodec);

        XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_STRING_FIELD(track->track_info.selection_params.mime_type, track_params, kMimeType);

        XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_INT_FIELD(track->track_info.selection_params.framerate, track_params, kFramerate);

        XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_INT_FIELD(track->track_info.selection_params.bitrate, track_params, kBitrate);

        XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_INT_FIELD(track->track_info.selection_params.width, track_params, kWidth);
        XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_INT_FIELD(track->track_info.selection_params.height, track_params, kHeight);

        XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_INT_FIELD(track->track_info.selection_params.display_width, track_params, kDisplayWidth);
        XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_INT_FIELD(track->track_info.selection_params.display_height, track_params, kDisplayHeight);

        XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_STRING_FIELD(track->track_info.selection_params.lang, track_params, kLang);

        XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_INT_FIELD(track->track_info.selection_params.samplerate, track_params, kSamplerate);
        XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_STRING_FIELD(track->track_info.selection_params.channel_config, track_params, kChannelConfig);
    } else{
        return XQC_MOQ_CATALOG_DECODE_FIELD_MISSING;
    }
end:
    return ret;
}


/**
 * parse feilds of single track
 */
xqc_moq_catalog_encode_error_t 
xqc_moq_catalog_single_track_encode(cJSON *track_json, xqc_moq_track_t *track, xqc_moq_catalog_t *catalog, xqc_bool_t is_first_track)
{
    xqc_moq_catalog_encode_error_t ret = XQC_MOQ_CATALOG_ENCODE_OK;

    // selectionParams
    cJSON *track_params = cJSON_CreateObject();
    if (track_params == NULL) {
        ret = XQC_MOQ_CATALOG_ENCODE_INTERNAL_ERROR;
        goto end;
    }
    XQC_MOQ_ADD_REQUIRED_STRING_TO_CATALOG(track->track_info.track_name, track_json, kName);

    XQC_MOQ_ADD_REQUIRED_STRING_TO_CATALOG(track->track_info.selection_params.codec, track_params, kCodec);

    if (track->track_info.track_type == XQC_MOQ_TRACK_VIDEO) {
        if (cJSON_AddStringToObject(track_json, kRole, "video") == NULL) {
            ret = XQC_MOQ_CATALOG_ENCODE_INTERNAL_ERROR;
            goto end;
        }
    } else if (track->track_info.track_type == XQC_MOQ_TRACK_AUDIO) {
        if (cJSON_AddStringToObject(track_json, kRole, "audio") == NULL) {
            ret = XQC_MOQ_CATALOG_ENCODE_INTERNAL_ERROR;
            goto end;
        }
    }

    /* add field which could be inherited from parent domain, but it's different from ones in parent domain. */
    if (is_first_track) {
        size_t str_field_len;
        catalog->common_track_fields.container_format = track->container_format;

        if (catalog->common_track_fields.track_namespace == NULL) {
            str_field_len = strlen(track->track_info.track_namespace) + 1;
            catalog->common_track_fields.track_namespace = (char *)xqc_malloc(str_field_len);
            xqc_memcpy(catalog->common_track_fields.track_namespace, track->track_info.track_namespace, str_field_len);
        }
        catalog->common_track_fields.renderGroup == track->render_group;
    } else {
        if (catalog->common_track_fields.container_format != track->container_format) {
            if (track->container_format == XQC_MOQ_CONTAINER_LOC) {
                XQC_MOQ_ADD_REQUIRED_STRING_TO_CATALOG(XQC_MOQ_CONTAINER_LOC_STR, track_json, kPackaging);
            } else {
                XQC_MOQ_ADD_REQUIRED_STRING_TO_CATALOG(XQC_MOQ_CONTAINER_CMAF_STR, track_json, kPackaging);
            }
        }

        if(track->packaging != NULL && catalog->common_track_fields.packaging != NULL
                && strcmp(catalog->common_track_fields.packaging, track->packaging) != 0) {
            XQC_MOQ_ADD_REQUIRED_STRING_TO_CATALOG(track->packaging, track_json, kPackaging);
        }
        if(track->track_info.track_namespace != NULL && catalog->common_track_fields.track_namespace != NULL
                && strcmp(catalog->common_track_fields.track_namespace, track->track_info.track_namespace) != 0) {
            XQC_MOQ_ADD_REQUIRED_STRING_TO_CATALOG(track->track_info.track_namespace, track_json, kNamespace);
        }
        if(track->render_group != -1 && catalog->common_track_fields.renderGroup != -1
                && track->render_group != catalog->common_track_fields.renderGroup) {
            XQC_MOQ_ADD_REQUIRED_INT_TO_CATALOG(track->render_group, track_json, kRenderGroup);
        }
    }

    XQC_MOQ_ADD_UNNECESSARY_STRING_TO_CATALOG(track->track_info.selection_params.mime_type, track_params, kMimeType);

    XQC_MOQ_ADD_UNNECESSARY_INT_TO_CATALOG(track->track_info.selection_params.framerate, track_params, kFramerate);

    XQC_MOQ_ADD_UNNECESSARY_INT_TO_CATALOG(track->track_info.selection_params.bitrate, track_params, kBitrate);

    XQC_MOQ_ADD_UNNECESSARY_INT_TO_CATALOG(track->track_info.selection_params.width, track_params, kWidth);
    XQC_MOQ_ADD_UNNECESSARY_INT_TO_CATALOG(track->track_info.selection_params.height, track_params, kHeight);

    XQC_MOQ_ADD_UNNECESSARY_INT_TO_CATALOG(track->track_info.selection_params.display_width, track_params, kDisplayWidth);
    XQC_MOQ_ADD_UNNECESSARY_INT_TO_CATALOG(track->track_info.selection_params.display_height, track_params, kDisplayHeight);

    XQC_MOQ_ADD_UNNECESSARY_STRING_TO_CATALOG(track->track_info.selection_params.lang, track_params, kLang);

    XQC_MOQ_ADD_UNNECESSARY_INT_TO_CATALOG(track->track_info.selection_params.samplerate, track_params, kSamplerate);
    XQC_MOQ_ADD_UNNECESSARY_STRING_TO_CATALOG(track->track_info.selection_params.channel_config, track_params, kChannelConfig);
    if (!cJSON_AddItemToObject(track_json, kSelectionParams, track_params)) {
        ret = XQC_MOQ_CATALOG_ENCODE_ITEMADD_FAIL;
        goto end;
    }
    return ret;
end:
    cJSON_Delete(track_params);
    cJSON_Delete(track_json);
    return ret;
}


xqc_int_t 
xqc_moq_catalog_encode(xqc_moq_catalog_t *catalog, uint8_t *buf, size_t buf_cap, xqc_int_t *encoded_len) 
{
    xqc_moq_catalog_encode_error_t ret = XQC_MOQ_CATALOG_ENCODE_OK;
    cJSON* catalog_json = cJSON_CreateObject();
    // can not create cJSON object, directly return
    if (catalog_json == NULL) {
        return -XQC_MOQ_CATALOG_ENCODE_INTERNAL_ERROR;
    }
    cJSON *common_track_fields_json = cJSON_CreateObject();
    if (common_track_fields_json == NULL) {
        cJSON_Delete(catalog_json);
        return -XQC_MOQ_CATALOG_ENCODE_INTERNAL_ERROR;
    }

    // add the Required Feilds
    XQC_MOQ_ADD_REQUIRED_INT_TO_CATALOG(catalog->version, catalog_json, kVersion);

    XQC_MOQ_ADD_UNNECESSARY_INT_TO_CATALOG(catalog->sequence, catalog_json, kSequence);

    XQC_MOQ_ADD_REQUIRED_INT_TO_CATALOG(catalog->streaming_format, catalog_json, kStreamingFormat);

    XQC_MOQ_ADD_REQUIRED_STRING_TO_CATALOG(catalog->streaming_format_version, catalog_json, kStreamingFormatVersion);


    // encode tracks
    xqc_list_head_t *pos, *next;
    xqc_moq_track_t *catalog_track = NULL;

    if (xqc_list_empty(catalog->track_list_for_pub)) {
        ret = XQC_MOQ_CATALOG_ENCODE_FIELD_MISSING;  
        goto end;
    }

    cJSON *tracks_array = cJSON_CreateArray();
    xqc_bool_t is_first_track = 1;
    xqc_list_for_each_safe(pos, next, catalog->track_list_for_pub) {
        catalog_track = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        if (catalog_track->track_info.track_type != XQC_MOQ_TRACK_VIDEO && catalog_track->track_info.track_type != XQC_MOQ_TRACK_AUDIO) {
            continue;
        }
        cJSON *track_json = cJSON_CreateObject();
        xqc_moq_catalog_encode_error_t track_encode_ret = xqc_moq_catalog_single_track_encode(track_json, catalog_track, catalog, is_first_track);
        is_first_track = 0;
        if (track_encode_ret != XQC_MOQ_CATALOG_ENCODE_OK) {
            ret = track_encode_ret;
            cJSON_Delete(tracks_array);
            goto end;
        }
        if (!cJSON_AddItemToArray(tracks_array, track_json)) {
            cJSON_Delete(tracks_array);
            cJSON_Delete(track_json);
            ret = XQC_MOQ_CATALOG_ENCODE_ITEMADD_FAIL;
            goto end;
        }
    }

    if (!cJSON_AddItemToObject(catalog_json, kTracks, tracks_array)) {
        cJSON_Delete(tracks_array);
        ret = XQC_MOQ_CATALOG_ENCODE_ITEMADD_FAIL;
        goto end;
    }

    // Add common_track_fields to catalog json
    if (catalog->common_track_fields.track_namespace != NULL) {
        if (catalog->common_track_fields.container_format == XQC_MOQ_CONTAINER_LOC) {
            XQC_MOQ_ADD_REQUIRED_STRING_TO_CATALOG(XQC_MOQ_CONTAINER_LOC_STR, common_track_fields_json, kPackaging);
        } else if (catalog->common_track_fields.container_format == XQC_MOQ_CONTAINER_CMAF) {
            XQC_MOQ_ADD_REQUIRED_STRING_TO_CATALOG(XQC_MOQ_CONTAINER_CMAF_STR, common_track_fields_json, kPackaging);
        }
        XQC_MOQ_ADD_REQUIRED_STRING_TO_CATALOG(catalog->common_track_fields.track_namespace, common_track_fields_json, kNamespace);
        XQC_MOQ_ADD_UNNECESSARY_INT_TO_CATALOG(catalog->common_track_fields.renderGroup, common_track_fields_json, kRenderGroup);
        
        if (!cJSON_AddItemToObject(catalog_json, kCommonTrackFields, common_track_fields_json)) {
            ret = XQC_MOQ_CATALOG_ENCODE_ITEMADD_FAIL;
            goto end;
        } else {
            common_track_fields_json = NULL;
        }
    }

    char *catalog_json_string = cJSON_PrintUnformatted(catalog_json);
    size_t catalog_json_str_len = strlen(catalog_json_string) + 1;
    if (catalog_json_str_len > buf_cap) {
        *encoded_len = -1;
        xqc_free(catalog_json_string);
        ret = XQC_MOQ_CATALOG_ENCODE_INTERNAL_ERROR;
        goto end;
    }
    xqc_memcpy(buf, catalog_json_string, catalog_json_str_len);
    *encoded_len = (int32_t) catalog_json_str_len;
    xqc_free(catalog_json_string);

end:
    if (common_track_fields_json != NULL) {
        cJSON_Delete(common_track_fields_json);
    }
    cJSON_Delete(catalog_json);
    return -ret;
}


xqc_int_t 
xqc_moq_catalog_decode(xqc_moq_catalog_t *catalog, uint8_t *buf, size_t buf_len)
{
    xqc_moq_catalog_decode_error_t ret = XQC_MOQ_CATALOG_DECODE_OK;
    char *char_buf = (char *) buf;
    xqc_moq_track_t *tmp_track = NULL;
    // TODO: support "op" = "add" and "remove"

    cJSON *catalog_json = cJSON_ParseWithLength(char_buf, buf_len);
    if (catalog_json == NULL) {
        /*const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            xqc_log(, XQC_LOG_ERROR, "|Catalog cJSON parser error: %s|", error_ptr);
        }*/
        ret = XQC_MOQ_CATALOG_DECODE_INVALID_CATALOG;
        goto end;
    }
    // check the Required Feild Name
    XQC_MOQ_PROCESS_CATALOG_REQUIRED_INT_FIELD(catalog->version, catalog_json, kVersion);

    XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_INT_FIELD(catalog->sequence, catalog_json, kSequence);

    XQC_MOQ_PROCESS_CATALOG_REQUIRED_INT_FIELD(catalog->streaming_format, catalog_json, kStreamingFormat);

    XQC_MOQ_PROCESS_CATALOG_REQUIRED_STRING_FIELD(catalog->streaming_format_version, catalog_json, kStreamingFormatVersion);

    // decode common commonTrackFields
    cJSON *common_field_json = cJSON_GetObjectItemCaseSensitive(catalog_json, kCommonTrackFields);
    if (cJSON_IsObject(common_field_json)) {
        XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_STRING_FIELD(catalog->common_track_fields.packaging, common_field_json, kPackaging);
        XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_STRING_FIELD(catalog->common_track_fields.track_namespace, common_field_json, kNamespace);
        XQC_MOQ_PROCESS_CATALOG_UNNECESSARY_INT_FIELD(catalog->common_track_fields.renderGroup, common_field_json, kRenderGroup);
    }

    // decode tracks
    cJSON *item = cJSON_GetObjectItemCaseSensitive(catalog_json, kTracks);
    if (cJSON_IsArray(item)) {
        cJSON *track = NULL;
        cJSON_ArrayForEach(track, item) {
            if (cJSON_IsObject(track)) {
                tmp_track = xqc_calloc(1, sizeof(xqc_moq_track_t));
                if (tmp_track == NULL) {
                    ret = XQC_MOQ_CATALOG_DECODE_INTERNAL_ERROR;
                    goto end;
                }
                xqc_moq_catalog_decode_error_t track_decode_ret = xqc_moq_catalog_single_track_decode(track, tmp_track, catalog);
                if (track_decode_ret != XQC_MOQ_CATALOG_DECODE_OK) {
                    ret = track_decode_ret;
                    goto end;
                }
                // TODO: support "op" = "add" and "remove"
                if (tmp_track->track_info.track_type != XQC_MOQ_TRACK_VIDEO
                    && tmp_track->track_info.track_type != XQC_MOQ_TRACK_AUDIO) {
                    tmp_track->track_info.track_type = -1;
                    if (tmp_track->track_info.selection_params.mime_type) {
                        if (strncmp(tmp_track->track_info.selection_params.mime_type, "video", strlen("video")) == 0) {
                            tmp_track->track_info.track_type = XQC_MOQ_TRACK_VIDEO;
                        } else if (strncmp(tmp_track->track_info.selection_params.mime_type, "audio", strlen("audio")) == 0) {
                            tmp_track->track_info.track_type = XQC_MOQ_TRACK_AUDIO;
                        }
                    }
                    if (tmp_track->track_info.selection_params.samplerate > 0) {
                        tmp_track->track_info.track_type = XQC_MOQ_TRACK_AUDIO;
                    }
                }
                if (tmp_track->track_info.track_type != XQC_MOQ_TRACK_VIDEO
                    && tmp_track->track_info.track_type != XQC_MOQ_TRACK_AUDIO) {
                    ret = XQC_MOQ_CATALOG_DECODE_FIELD_MISSING;
                    goto end;
                }
                xqc_list_add_tail(&tmp_track->list_member, &catalog->track_list_for_sub);
                tmp_track = NULL;
            } else {
                ret = XQC_MOQ_CATALOG_DECODE_INVALID_PARAMETER;
                goto end;
            }
        }
    } else {
        ret = XQC_MOQ_CATALOG_DECODE_FIELD_MISSING;
        goto end;
    }
end:
    if (ret != XQC_MOQ_CATALOG_DECODE_OK) {
        if (tmp_track != NULL) {
            xqc_moq_track_free_fields(tmp_track);
            xqc_free(tmp_track);
            tmp_track = NULL;
        }
    }
    cJSON_Delete(catalog_json);
    return -ret;
}

xqc_int_t
xqc_moq_build_catalog_param_from_track(xqc_moq_track_t *track, xqc_moq_message_parameter_t *param)
{
    if (track == NULL || param == NULL) {
        return -XQC_EPARAM;
    }

    xqc_moq_catalog_t catalog;
    xqc_moq_catalog_init(&catalog);
    catalog.version = 1;
    catalog.sequence = 0;
    catalog.streaming_format = 1;
    size_t sfv_len = strlen(STREAMING_FORMAT_VERSION) + 1;
    catalog.streaming_format_version = xqc_calloc(1, sfv_len);
    if (catalog.streaming_format_version == NULL) {
        return -XQC_EMALLOC;
    }
    xqc_memcpy(catalog.streaming_format_version, STREAMING_FORMAT_VERSION, sfv_len);

    xqc_list_head_t track_list;
    xqc_init_list_head(&track_list);
    catalog.track_list_for_pub = &track_list;

    xqc_moq_track_t tmp_track;
    xqc_memzero(&tmp_track, sizeof(tmp_track));
    tmp_track.track_info = track->track_info;
    tmp_track.container_format = track->container_format;
    tmp_track.packaging = track->packaging;
    tmp_track.render_group = track->render_group;
    xqc_init_list_head(&tmp_track.list_member);
    xqc_list_add_tail(&tmp_track.list_member, &track_list);

    size_t buf_cap = 2048;
    uint8_t *buf = xqc_malloc(buf_cap);
    if (buf == NULL) {
        xqc_moq_catalog_free_fields(&catalog);
        return -XQC_EMALLOC;
    }

    xqc_int_t encoded_len = 0;
    xqc_int_t ret = xqc_moq_catalog_encode(&catalog, buf, buf_cap, &encoded_len);
    xqc_moq_catalog_free_fields(&catalog);
    if (ret < 0) {
        xqc_free(buf);
        return ret;
    }

    xqc_memzero(param, sizeof(*param));
    param->type = XQC_MOQ_PARAM_AUTHORIZATION_TOKEN;
    param->length = encoded_len;
    param->value = buf;
    param->is_integer = 0;
    param->int_value = 0;

    return XQC_OK;
}

void
xqc_moq_free_catalog_param(xqc_moq_message_parameter_t *param)
{
    if (param == NULL || param->value == NULL) {
        return;
    }
    xqc_free(param->value);
    param->value = NULL;
    param->length = 0;
}


xqc_int_t
xqc_moq_write_catalog(xqc_moq_session_t *session, uint64_t subscribe_id, xqc_moq_track_t *track)
{
    xqc_int_t ret = 0;
    xqc_int_t encoded_len = 0;
    xqc_moq_stream_t *stream;
    xqc_moq_object_stream_msg_t object;
    xqc_moq_catalog_t catalog;
    xqc_moq_catalog_init(&catalog);
    catalog.version = 1;
    catalog.sequence = 0;
    catalog.streaming_format = 1;
    size_t sfv_len = strlen(STREAMING_FORMAT_VERSION) + 1;
    catalog.streaming_format_version = xqc_calloc(1, sfv_len);
    xqc_memcpy(catalog.streaming_format_version, STREAMING_FORMAT_VERSION, sfv_len);
    catalog.track_list_for_pub = &session->track_list_for_pub;
    size_t buf_cap = 4096;
    uint8_t *buf = xqc_malloc(buf_cap);
    ret = xqc_moq_catalog_encode(&catalog, buf, buf_cap, &encoded_len);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|encode catalog error|ret:%d|", ret);
        goto end;
    }

    stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_UNI);
    if (stream == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create moq stream error|");
        ret = -XQC_ECREATE_STREAM;
        goto end;
    }
    stream->write_stream_fin = 1;

    object.subscribe_id = subscribe_id;
    object.track_alias = track->track_alias;
    object.send_order = 0; //TODO
    object.status = XQC_MOQ_OBJ_STATUS_NORMAL;
    object.payload = buf;
    object.payload_len = encoded_len;
    object.group_id = track->cur_group_id;
    object.object_id = track->cur_object_id++;

    ret = xqc_moq_write_object_stream_msg(session, stream, &object);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write_object_stream_msg error|ret:%d|", ret);
        goto end;
    }
end:
    xqc_moq_catalog_free_fields(&catalog);
    xqc_free(buf);
    return ret;
}


xqc_int_t
xqc_moq_subscribe_catalog(xqc_moq_session_t *session)
{
    xqc_int_t ret;

    if (session->role == XQC_MOQ_SUBSCRIBER) {
        xqc_moq_track_create(session, XQC_MOQ_CATALOG_NAMESPACE, XQC_MOQ_CATALOG_NAME,
                             XQC_MOQ_TRACK_CATALOG, NULL, XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_SUB);
    } else if (session->role == XQC_MOQ_PUBLISHER) {
        xqc_moq_track_create(session, XQC_MOQ_CATALOG_NAMESPACE, XQC_MOQ_CATALOG_NAME,
                             XQC_MOQ_TRACK_CATALOG, NULL, XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_PUB);
    } else {
        xqc_moq_track_create(session, XQC_MOQ_CATALOG_NAMESPACE, XQC_MOQ_CATALOG_NAME,
                             XQC_MOQ_TRACK_CATALOG, NULL, XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_SUB);
        xqc_moq_track_create(session, XQC_MOQ_CATALOG_NAMESPACE, XQC_MOQ_CATALOG_NAME,
                             XQC_MOQ_TRACK_CATALOG, NULL, XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_PUB);
    }

    if (session->role == XQC_MOQ_PUBLISHER) {
        return XQC_OK;
    }

    ret = xqc_moq_subscribe_latest(session, XQC_MOQ_CATALOG_NAMESPACE, XQC_MOQ_CATALOG_NAME);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_latest error|ret:%d|", ret);
        return ret;
    }
    return ret;
}

/**
 * Catalog track ops
 */

static void
xqc_moq_catalog_on_create(xqc_moq_track_t *track)
{
    return;
}

static void
xqc_moq_catalog_on_destroy(xqc_moq_track_t *track)
{
    return;
}

static void
xqc_moq_catalog_on_subscribe(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg)
{
    xqc_int_t ret;
    ret = xqc_moq_write_catalog(session, subscribe_id, track);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_write_catalog error|ret:%d|", ret);
        return;
    }
}


static void
xqc_moq_catalog_on_subscribe_ok(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
    return;
}


static void
xqc_moq_catalog_on_subscribe_error(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_error_msg_t *subscribe_error)
{
    return;
}


static void
xqc_moq_catalog_on_object(xqc_moq_session_t *session, xqc_moq_track_t *track, xqc_moq_object_t *object)
{
    xqc_int_t ret;
    xqc_moq_track_info_t **track_info_array = NULL;
    xqc_int_t tracks_num = 0;
    xqc_moq_catalog_t catalog;
    xqc_moq_catalog_init(&catalog);
    ret = xqc_moq_catalog_decode(&catalog, object->payload, object->payload_len);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|decode catalog error|ret:%d|", ret);
        goto end;
    }

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &(catalog.track_list_for_sub)) {
        xqc_moq_track_t *tmp = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        tracks_num++;
        xqc_moq_track_t *new_track = xqc_moq_track_create(session, tmp->track_info.track_namespace, tmp->track_info.track_name,
                                                          tmp->track_info.track_type, &tmp->track_info.selection_params,
                                                          tmp->container_format, XQC_MOQ_TRACK_FOR_SUB);
        if (new_track == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_track_create error|");
            goto end;
        }
    }

    track_info_array = (xqc_moq_track_info_t **)xqc_malloc(tracks_num * sizeof(xqc_moq_track_info_t *));
    xqc_int_t i = 0;
    xqc_list_for_each_safe(pos, next, &(catalog.track_list_for_sub)) {
        xqc_moq_track_t *tmp = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        track_info_array[i] = &tmp->track_info;
        i++;
    }

    xqc_log(session->log, XQC_LOG_INFO, "|on_catalog|tracks_num:%d|", tracks_num);
    session->session_callbacks.on_catalog(session->user_session, track_info_array, tracks_num);

end:
    xqc_free(track_info_array);
    xqc_moq_catalog_free_fields(&catalog);
}
