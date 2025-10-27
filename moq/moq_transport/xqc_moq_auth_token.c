/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 * @file xqc_moq_auth_token.c
 * @brief MOQT Authorization Token parameter handling implementation
 */

#include "xqc_moq_auth_token.h"
#include "xqc_moq_message.h"
#include "../../src/common/utils/vint/xqc_variable_len_int.h"
#include "../../src/common/xqc_malloc.h"
#include "../../src/common/xqc_log.h"
#include "../../include/xquic/xquic.h"
#include "../../include/moq/xqc_moq.h"
#include <string.h>

/* ========== Token Parameter Creation ========== */

static xqc_int_t
xqc_moq_auth_token_encode_len(const xqc_moq_auth_token_t *token)
{
    if (token == NULL) {
        return -1;
    }
    
    xqc_int_t len = 0;
    
    /* Alias Type (varint) */
    len += xqc_put_varint_len(token->alias_type);
    
    switch (token->alias_type) {
        case XQC_MOQ_TOKEN_ALIAS_DELETE:
        case XQC_MOQ_TOKEN_ALIAS_USE_ALIAS:
            /* Token Alias */
            len += xqc_put_varint_len(token->token_alias);
            break;
            
        case XQC_MOQ_TOKEN_ALIAS_REGISTER:
            /* Token Alias + Token Type + Token Value */
            len += xqc_put_varint_len(token->token_alias);
            len += xqc_put_varint_len(token->token_type);
            len += xqc_put_varint_len(token->token_value_len);
            len += token->token_value_len;
            break;
            
        case XQC_MOQ_TOKEN_ALIAS_USE_VALUE:
            /* Token Type + Token Value */
            len += xqc_put_varint_len(token->token_type);
            len += xqc_put_varint_len(token->token_value_len);
            len += token->token_value_len;
            break;
            
        default:
            return -1;
    }
    
    return len;
}

static xqc_int_t
xqc_moq_auth_token_encode(const xqc_moq_auth_token_t *token, uint8_t *buf, size_t buf_cap)
{
    if (token == NULL || buf == NULL) {
        return -1;
    }
    
    uint8_t *pos = buf;
    uint8_t *end = buf + buf_cap;
    
    /* Encode Alias Type */
    if (pos >= end) {
        return -1;
    }
    pos = xqc_put_varint(pos, token->alias_type);
    
    switch (token->alias_type) {
        case XQC_MOQ_TOKEN_ALIAS_DELETE:
        case XQC_MOQ_TOKEN_ALIAS_USE_ALIAS:
            /* Encode Token Alias */
            if (pos >= end) {
                return -1;
            }
            pos = xqc_put_varint(pos, token->token_alias);
            break;
            
        case XQC_MOQ_TOKEN_ALIAS_REGISTER:
            /* Encode Token Alias */
            if (pos >= end) {
                return -1;
            }
            pos = xqc_put_varint(pos, token->token_alias);
            
            /* Encode Token Type */
            if (pos >= end) {
                return -1;
            }
            pos = xqc_put_varint(pos, token->token_type);
            
            /* Encode Token Value Length */
            if (pos >= end) {
                return -1;
            }
            pos = xqc_put_varint(pos, token->token_value_len);
            
            /* Encode Token Value */
            if (pos + token->token_value_len > end) {
                return -1;
            }
            memcpy(pos, token->token_value, token->token_value_len);
            pos += token->token_value_len;
            break;
            
        case XQC_MOQ_TOKEN_ALIAS_USE_VALUE:
            /* Encode Token Type */
            if (pos >= end) {
                return -1;
            }
            pos = xqc_put_varint(pos, token->token_type);
            
            /* Encode Token Value Length */
            if (pos >= end) {
                return -1;
            }
            pos = xqc_put_varint(pos, token->token_value_len);
            
            /* Encode Token Value */
            if (pos + token->token_value_len > end) {
                return -1;
            }
            memcpy(pos, token->token_value, token->token_value_len);
            pos += token->token_value_len;
            break;
            
        default:
            return -1;
    }
    
    return pos - buf;
}

xqc_moq_message_parameter_t *
xqc_moq_create_auth_token_param(xqc_moq_token_alias_type_t alias_type,
                               uint64_t token_alias, uint64_t token_type,
                               const uint8_t *token_value, size_t token_value_len)
{
    /* Create token structure */
    xqc_moq_auth_token_t token = {0};
    token.alias_type = alias_type;
    
    /* Set fields based on alias type */
    switch (alias_type) {
        case XQC_MOQ_TOKEN_ALIAS_DELETE:
        case XQC_MOQ_TOKEN_ALIAS_USE_ALIAS:
            token.token_alias = token_alias;
            token.has_alias = XQC_TRUE;
            break;
            
        case XQC_MOQ_TOKEN_ALIAS_REGISTER:
            token.token_alias = token_alias;
            token.token_type = token_type;
            token.token_value = (uint8_t *)token_value;
            token.token_value_len = token_value_len;
            token.has_alias = XQC_TRUE;
            token.has_type = XQC_TRUE;
            token.has_value = XQC_TRUE;
            break;
            
        case XQC_MOQ_TOKEN_ALIAS_USE_VALUE:
            token.token_type = token_type;
            token.token_value = (uint8_t *)token_value;
            token.token_value_len = token_value_len;
            token.has_type = XQC_TRUE;
            token.has_value = XQC_TRUE;
            break;
            
        default:
            return NULL;
    }
    
    /* Calculate encoded length */
    xqc_int_t encoded_len = xqc_moq_auth_token_encode_len(&token);
    if (encoded_len < 0) {
        return NULL;
    }
    
    /* Create parameter */
    xqc_moq_message_parameter_t *param = xqc_calloc(1, sizeof(xqc_moq_message_parameter_t));
    if (param == NULL) {
        return NULL;
    }
    
    param->type = XQC_MOQ_PARAM_AUTHORIZATION_TOKEN;
    param->length = encoded_len;
    param->value = xqc_malloc(encoded_len);
    if (param->value == NULL) {
        xqc_free(param);
        return NULL;
    }
    
    /* Encode token into parameter value */
    xqc_int_t encoded = xqc_moq_auth_token_encode(&token, param->value, encoded_len);
    if (encoded != encoded_len) {
        xqc_free(param->value);
        xqc_free(param);
        return NULL;
    }
    
    return param;
}

/* ========== Token Parameter Parsing ========== */

xqc_int_t 
xqc_moq_parse_auth_token_param(const xqc_moq_message_parameter_t *param, xqc_moq_auth_token_t *token)
{
    if (param == NULL || token == NULL) {
        return -XQC_EPARAM;
    }
    
    if (param->type != XQC_MOQ_PARAM_AUTHORIZATION_TOKEN) {
        return -XQC_EPARAM;
    }
    
    if (param->value == NULL || param->length == 0) {
        return -XQC_EPARAM;
    }
    
    const uint8_t *pos = param->value;
    const uint8_t *end = param->value + param->length;
    xqc_int_t processed;
    uint64_t val;
    
    /* Initialize token */
    memset(token, 0, sizeof(xqc_moq_auth_token_t));
    
    /* Decode Alias Type */
    processed = xqc_vint_read(pos, end, &val);
    if (processed < 0) {
        return -XQC_EILLEGAL_FRAME;
    }
    token->alias_type = (xqc_moq_token_alias_type_t)val;
    pos += processed;
    
    switch (token->alias_type) {
        case XQC_MOQ_TOKEN_ALIAS_DELETE:
        case XQC_MOQ_TOKEN_ALIAS_USE_ALIAS:
            /* Decode Token Alias */
            processed = xqc_vint_read(pos, end, &token->token_alias);
            if (processed < 0) {
                return -XQC_EILLEGAL_FRAME;
            }
            pos += processed;
            token->has_alias = XQC_TRUE;
            break;
            
        case XQC_MOQ_TOKEN_ALIAS_REGISTER:
            /* Decode Token Alias */
            processed = xqc_vint_read(pos, end, &token->token_alias);
            if (processed < 0) {
                return -XQC_EILLEGAL_FRAME;
            }
            pos += processed;
            token->has_alias = XQC_TRUE;
            
            /* Decode Token Type */
            processed = xqc_vint_read(pos, end, &token->token_type);
            if (processed < 0) {
                return -XQC_EILLEGAL_FRAME;
            }
            pos += processed;
            token->has_type = XQC_TRUE;
            
            /* Decode Token Value Length */
            processed = xqc_vint_read(pos, end, &val);
            if (processed < 0) {
                return -XQC_EILLEGAL_FRAME;
            }
            token->token_value_len = val;
            pos += processed;
            
            /* Decode Token Value */
            if (pos + token->token_value_len > end) {
                return -XQC_EILLEGAL_FRAME;
            }
            token->token_value = (uint8_t *)pos;  /* Point to buffer data */
            pos += token->token_value_len;
            token->has_value = XQC_TRUE;
            break;
            
        case XQC_MOQ_TOKEN_ALIAS_USE_VALUE:
            /* Decode Token Type */
            processed = xqc_vint_read(pos, end, &token->token_type);
            if (processed < 0) {
                return -XQC_EILLEGAL_FRAME;
            }
            pos += processed;
            token->has_type = XQC_TRUE;
            
            /* Decode Token Value Length */
            processed = xqc_vint_read(pos, end, &val);
            if (processed < 0) {
                return -XQC_EILLEGAL_FRAME;
            }
            token->token_value_len = val;
            pos += processed;
            
            /* Decode Token Value */
            if (pos + token->token_value_len > end) {
                return -XQC_EILLEGAL_FRAME;
            }
            token->token_value = (uint8_t *)pos;  /* Point to buffer data */
            pos += token->token_value_len;
            token->has_value = XQC_TRUE;
            break;
            
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    
    return XQC_OK;
}

/* ========== Convenience Functions ========== */

xqc_moq_message_parameter_t *
xqc_moq_create_auth_token_direct(uint64_t token_type, const uint8_t *token_value, size_t token_value_len)
{
    return xqc_moq_create_auth_token_param(XQC_MOQ_TOKEN_ALIAS_USE_VALUE, 0, 
                                          token_type, token_value, token_value_len);
}

xqc_moq_message_parameter_t *
xqc_moq_create_auth_token_register(uint64_t alias, uint64_t token_type,
                                  const uint8_t *token_value, size_t token_value_len)
{
    return xqc_moq_create_auth_token_param(XQC_MOQ_TOKEN_ALIAS_REGISTER, alias,
                                          token_type, token_value, token_value_len);
}

xqc_moq_message_parameter_t *
xqc_moq_create_auth_token_alias(uint64_t alias)
{
    return xqc_moq_create_auth_token_param(XQC_MOQ_TOKEN_ALIAS_USE_ALIAS, alias, 0, NULL, 0);
}

xqc_moq_message_parameter_t *
xqc_moq_create_auth_token_delete(uint64_t alias)
{
    return xqc_moq_create_auth_token_param(XQC_MOQ_TOKEN_ALIAS_DELETE, alias, 0, NULL, 0);
}

/* ========== Validation and Utility Functions ========== */

xqc_bool_t 
xqc_moq_auth_token_is_valid(const xqc_moq_auth_token_t *token)
{
    if (token == NULL) {
        return XQC_FALSE;
    }
    
    switch (token->alias_type) {
        case XQC_MOQ_TOKEN_ALIAS_DELETE:
        case XQC_MOQ_TOKEN_ALIAS_USE_ALIAS:
            return token->has_alias;
            
        case XQC_MOQ_TOKEN_ALIAS_REGISTER:
            return token->has_alias && token->has_type && token->has_value && 
                   token->token_value != NULL && token->token_value_len > 0;
            
        case XQC_MOQ_TOKEN_ALIAS_USE_VALUE:
            return token->has_type && token->has_value && 
                   token->token_value != NULL && token->token_value_len > 0;
            
        default:
            return XQC_FALSE;
    }
}

const char *
xqc_moq_auth_token_alias_type_str(xqc_moq_token_alias_type_t alias_type)
{
    switch (alias_type) {
        case XQC_MOQ_TOKEN_ALIAS_DELETE:
            return "DELETE";
        case XQC_MOQ_TOKEN_ALIAS_REGISTER:
            return "REGISTER";
        case XQC_MOQ_TOKEN_ALIAS_USE_ALIAS:
            return "USE_ALIAS";
        case XQC_MOQ_TOKEN_ALIAS_USE_VALUE:
            return "USE_VALUE";
        default:
            return "UNKNOWN";
    }
}

const char *
xqc_moq_auth_token_type_str(xqc_moq_token_type_t token_type)
{
    switch (token_type) {
        case XQC_MOQ_TOKEN_TYPE_UNSPECIFIED:
            return "UNSPECIFIED";
        case XQC_MOQ_TOKEN_TYPE_JWT:
            return "JWT";
        case XQC_MOQ_TOKEN_TYPE_OPAQUE:
            return "OPAQUE";
        case XQC_MOQ_TOKEN_TYPE_OAUTH_BEARER:
            return "OAUTH_BEARER";
        case XQC_MOQ_TOKEN_TYPE_CUSTOM:
            return "CUSTOM";
        default:
            return "UNKNOWN";
    }
} 