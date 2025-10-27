/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 * @file xqc_moq_auth_token.h
 * @brief MOQT Authorization Token parameter handling
 * 
 * AUTHORIZATION TOKEN supports 4 operation modes embedded as parameters in MOQ messages:
 * - USE_VALUE: Direct token transmission
 * - REGISTER: Register token with alias for future reference  
 * - USE_ALIAS: Reference previously registered token by alias
 * - DELETE: Remove alias and invalidate token
 * 
 * @example Usage Example
 * // Send JWT token in CLIENT_SETUP message
 * const char *jwt = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...";
 * xqc_moq_message_parameter_t *auth_param = 
 *     xqc_moq_create_auth_token_direct(XQC_MOQ_TOKEN_TYPE_JWT, 
 *                                      (uint8_t*)jwt, strlen(jwt));
 * 
 * xqc_moq_message_parameter_t setup_params[] = {
 *     {XQC_MOQ_PARAM_ROLE, 1, (uint8_t*)&session->role},
 *     *auth_param
 * };
 * client_setup.params_num = 2;
 * client_setup.params = setup_params;
 * 
 * // Remember to free memory
 * xqc_free(auth_param->value);
 * xqc_free(auth_param);
 */

#ifndef _XQC_MOQ_AUTH_TOKEN_H_INCLUDED_
#define _XQC_MOQ_AUTH_TOKEN_H_INCLUDED_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
#ifndef XQC_BOOL_DEFINED
#define XQC_BOOL_DEFINED
typedef int xqc_bool_t;
#define XQC_TRUE  1
#define XQC_FALSE 0
#endif

#ifndef XQC_INT_DEFINED
#define XQC_INT_DEFINED
typedef int xqc_int_t;
#endif

// AUTHORIZATION TOKEN Parameter Type (already defined in xqc_moq_message.h)
// #define XQC_MOQ_PARAM_AUTHORIZATION_TOKEN 0x03

// Token Alias Types according to MOQT spec
typedef enum {
    XQC_MOQ_TOKEN_ALIAS_DELETE          = 0x0,  // Delete alias and retire token
    XQC_MOQ_TOKEN_ALIAS_REGISTER        = 0x1,  // Register alias with token
    XQC_MOQ_TOKEN_ALIAS_USE_ALIAS       = 0x2,  // Use previously registered alias
    XQC_MOQ_TOKEN_ALIAS_USE_VALUE       = 0x3,  // Use token value directly
} xqc_moq_token_alias_type_t;

// Token Types (IANA registry - placeholder values)
typedef enum {
    XQC_MOQ_TOKEN_TYPE_UNSPECIFIED      = 0x0,  // Out-of-band negotiated
    XQC_MOQ_TOKEN_TYPE_JWT              = 0x1,  // JSON Web Token
    XQC_MOQ_TOKEN_TYPE_OPAQUE           = 0x2,  // Opaque token
    XQC_MOQ_TOKEN_TYPE_OAUTH_BEARER     = 0x3,  // OAuth Bearer Token
    XQC_MOQ_TOKEN_TYPE_CUSTOM           = 0xFF, // Custom/Application-specific
} xqc_moq_token_type_t;

// Authorization Token Structure (Token field content in parameter value)
typedef struct xqc_moq_auth_token_s {
    xqc_moq_token_alias_type_t  alias_type;
    uint64_t                    token_alias;        // Optional, based on alias_type
    uint64_t                    token_type;         // Optional, based on alias_type
    size_t                      token_value_len;    // Optional, based on alias_type
    uint8_t                     *token_value;       // Optional, based on alias_type
    
    // Internal validation flags
    xqc_bool_t                  has_alias;
    xqc_bool_t                  has_type;
    xqc_bool_t                  has_value;
} xqc_moq_auth_token_t;

// Forward declarations for session and message parameter
struct xqc_moq_session_s;
typedef struct xqc_moq_message_parameter_s xqc_moq_message_parameter_t;

/**
 * Create AUTHORIZATION TOKEN parameter
 * @param alias_type Type of alias operation
 * @param token_alias Token alias (for DELETE, REGISTER, USE_ALIAS)
 * @param token_type Token type (for REGISTER, USE_VALUE)
 * @param token_value Token value data (for REGISTER, USE_VALUE)
 * @param token_value_len Length of token value (for REGISTER, USE_VALUE)
 * @return Created parameter or NULL on failure
 */
xqc_moq_message_parameter_t *xqc_moq_create_auth_token_param(
    xqc_moq_token_alias_type_t alias_type,
    uint64_t token_alias,
    uint64_t token_type,
    const uint8_t *token_value,
    size_t token_value_len);

/**
 * Parse AUTHORIZATION TOKEN parameter value
 * @param param Parameter containing auth token
 * @param token Output token structure
 * @return XQC_OK on success, negative on error
 */
xqc_int_t xqc_moq_parse_auth_token_param(const xqc_moq_message_parameter_t *param,
                                        xqc_moq_auth_token_t *token);

/**
 * Create AUTHORIZATION TOKEN parameter for direct use (USE_VALUE)
 * Direct token transmission, suitable for initial connections or one-time auth
 * 
 * @param token_type Type of token (XQC_MOQ_TOKEN_TYPE_JWT, etc.)
 * @param token_value Token value data (JWT string, OAuth Bearer token, etc.)
 * @param token_value_len Length of token value
 * @return Created parameter or NULL on failure
 */
xqc_moq_message_parameter_t *xqc_moq_create_auth_token_direct(
    uint64_t token_type,
    const uint8_t *token_value,
    size_t token_value_len);

/**
 * Create AUTHORIZATION TOKEN parameter for registration (REGISTER)
 * Register token alias to reduce transmission overhead for long-term sessions
 * 
 * @param alias Token alias to register (recommend incremental IDs like 1,2,3...)
 * @param token_type Type of token (XQC_MOQ_TOKEN_TYPE_JWT, etc.)
 * @param token_value Token value data (complete token data)
 * @param token_value_len Length of token value
 * @return Created parameter or NULL on failure
 */
xqc_moq_message_parameter_t *xqc_moq_create_auth_token_register(
    uint64_t alias,
    uint64_t token_type,
    const uint8_t *token_value,
    size_t token_value_len);

/**
 * Create AUTHORIZATION TOKEN parameter for alias usage (USE_ALIAS)
 * Use registered token alias, efficient and bandwidth-saving for frequent operations
 * 
 * @param alias Token alias to use (must be previously registered via REGISTER)
 * @return Created parameter or NULL on failure
 */
xqc_moq_message_parameter_t *xqc_moq_create_auth_token_alias(uint64_t alias);

/**
 * Create AUTHORIZATION TOKEN parameter for deletion (DELETE)
 * @param alias Token alias to delete
 * @return Created parameter or NULL on failure
 */
xqc_moq_message_parameter_t *xqc_moq_create_auth_token_delete(uint64_t alias);

/**
 * Validate token structure semantics
 * @param token Token to validate
 * @return XQC_TRUE if valid, XQC_FALSE otherwise
 */
xqc_bool_t xqc_moq_auth_token_is_valid(const xqc_moq_auth_token_t *token);

/**
 * Get human-readable description of alias type
 * @param alias_type Alias type
 * @return String description
 */
const char *xqc_moq_auth_token_alias_type_str(xqc_moq_token_alias_type_t alias_type);

/**
 * Get human-readable description of token type
 * @param token_type Token type
 * @return String description
 */
const char *xqc_moq_auth_token_type_str(xqc_moq_token_type_t token_type);

#ifdef __cplusplus
}
#endif

#endif /* _XQC_MOQ_AUTH_TOKEN_H_INCLUDED_ */ 