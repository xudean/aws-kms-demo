#include "nitro_kms_shim.h"

#include <aws/auth/credentials.h>
#include <aws/common/byte_buf.h>
#include <aws/common/error.h>
#include <aws/common/string.h>
#include <aws/io/socket.h>
#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct nkms_client_state {
    struct aws_allocator *allocator;
    struct aws_string *region;
    struct aws_string *access_key_id;
    struct aws_string *secret_access_key;
    struct aws_string *session_token;
    struct aws_credentials *credentials;
    struct aws_nitro_enclaves_kms_client *client;
};

static void set_error(char *error, size_t error_len, const char *message) {
    if (error != NULL && error_len > 0) {
        snprintf(error, error_len, "%s", message != NULL ? message : "unknown Nitro KMS error");
    }
}

static void set_aws_error(char *error, size_t error_len, const char *operation) {
    const int code = aws_last_error();
    const char *detail = aws_error_debug_str(code);
    if (error != NULL && error_len > 0) {
        if (code == AWS_ERROR_SUCCESS) {
            snprintf(error, error_len,
                     "%s failed: Nitro SDK returned AWS_OP_ERR without setting aws_last_error",
                     operation);
        } else {
            snprintf(error, error_len, "%s failed: %s (%d)", operation,
                     detail != NULL ? detail : "unknown", code);
        }
    }
}

static int copy_buffer(const struct aws_byte_buf *source, struct nkms_buffer *target) {
    target->data = NULL;
    target->len = 0;
    if (source->len == 0) {
        return 0;
    }
    target->data = malloc(source->len);
    if (target->data == NULL) {
        return -1;
    }
    memcpy(target->data, source->buffer, source->len);
    target->len = source->len;
    return 0;
}

static void clean_client(struct nkms_client_state *state) {
    if (state->client != NULL) {
        aws_nitro_enclaves_kms_client_destroy(state->client);
    }
    if (state->credentials != NULL) {
        aws_credentials_release(state->credentials);
    }
    aws_string_destroy(state->session_token);
    aws_string_destroy(state->secret_access_key);
    aws_string_destroy(state->access_key_id);
    aws_string_destroy(state->region);
    aws_nitro_enclaves_library_clean_up();
    memset(state, 0, sizeof(*state));
}

static int init_client(
    struct nkms_client_state *state,
    const char *region,
    uint32_t parent_cid,
    uint32_t proxy_port,
    const char *access_key_id,
    const char *secret_access_key,
    const char *session_token,
    char *error,
    size_t error_len) {
    memset(state, 0, sizeof(*state));
    aws_nitro_enclaves_library_init(NULL);
    if (aws_nitro_enclaves_library_seed_entropy(1024) != AWS_OP_SUCCESS) {
        set_aws_error(error, error_len, "seeding enclave entropy");
        clean_client(state);
        return -1;
    }

    state->allocator = aws_nitro_enclaves_get_allocator();
    state->region = aws_string_new_from_c_str(state->allocator, region);
    state->access_key_id = aws_string_new_from_c_str(state->allocator, access_key_id);
    state->secret_access_key = aws_string_new_from_c_str(state->allocator, secret_access_key);
    state->session_token = aws_string_new_from_c_str(state->allocator, session_token != NULL ? session_token : "");
    if (state->region == NULL || state->access_key_id == NULL || state->secret_access_key == NULL ||
        state->session_token == NULL) {
        set_error(error, error_len, "allocating Nitro KMS client strings failed");
        clean_client(state);
        return -1;
    }

    state->credentials = aws_credentials_new(
        state->allocator,
        aws_byte_cursor_from_c_str(access_key_id),
        aws_byte_cursor_from_c_str(secret_access_key),
        aws_byte_cursor_from_c_str(session_token != NULL ? session_token : ""),
        UINT64_MAX);
    if (state->credentials == NULL) {
        set_aws_error(error, error_len, "creating AWS credentials");
        clean_client(state);
        return -1;
    }

    struct aws_socket_endpoint endpoint = {.port = proxy_port};
    snprintf(endpoint.address, sizeof(endpoint.address), "%u", parent_cid);
    struct aws_nitro_enclaves_kms_client_configuration configuration = {
        .allocator = state->allocator,
        .region = state->region,
        .endpoint = &endpoint,
        .domain = AWS_SOCKET_VSOCK,
        .credentials = state->credentials,
    };
    state->client = aws_nitro_enclaves_kms_client_new(&configuration);
    if (state->client == NULL) {
        set_aws_error(error, error_len, "creating Nitro KMS client");
        clean_client(state);
        return -1;
    }
    return 0;
}

int nkms_generate_data_key(
    const char *region,
    uint32_t parent_cid,
    uint32_t proxy_port,
    const char *access_key_id,
    const char *secret_access_key,
    const char *session_token,
    const char *key_id,
    uint32_t key_bits,
    struct nkms_buffer *plaintext,
    struct nkms_buffer *ciphertext,
    char *error,
    size_t error_len) {
    struct nkms_client_state state;
    struct aws_byte_buf plain = {0};
    struct aws_byte_buf encrypted = {0};
    struct aws_string *kms_key_id = NULL;
    int result = -1;

    plaintext->data = NULL;
    plaintext->len = 0;
    ciphertext->data = NULL;
    ciphertext->len = 0;
    if (init_client(&state, region, parent_cid, proxy_port, access_key_id, secret_access_key,
                    session_token, error, error_len) != 0) {
        return -1;
    }

    kms_key_id = aws_string_new_from_c_str(state.allocator, key_id);
    enum aws_key_spec key_spec = key_bits == 128 ? AWS_KS_AES_128 : AWS_KS_AES_256;
    if (kms_key_id == NULL || (key_bits != 128 && key_bits != 256)) {
        set_error(error, error_len, "Nitro KMS supports only AES-128 or AES-256 data keys");
        goto cleanup;
    }
    if (aws_kms_generate_data_key_blocking(state.client, kms_key_id, key_spec, &plain, &encrypted) != AWS_OP_SUCCESS) {
        set_aws_error(error, error_len, "KMS GenerateDataKey");
        goto cleanup;
    }
    if (copy_buffer(&plain, plaintext) != 0 || copy_buffer(&encrypted, ciphertext) != 0) {
        set_error(error, error_len, "copying KMS data key response failed");
        nkms_buffer_free(plaintext);
        nkms_buffer_free(ciphertext);
        goto cleanup;
    }
    result = 0;

cleanup:
    aws_byte_buf_clean_up_secure(&plain);
    aws_byte_buf_clean_up(&encrypted);
    aws_string_destroy(kms_key_id);
    clean_client(&state);
    return result;
}

int nkms_decrypt_data_key(
    const char *region,
    uint32_t parent_cid,
    uint32_t proxy_port,
    const char *access_key_id,
    const char *secret_access_key,
    const char *session_token,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const char *encryption_context_json,
    struct nkms_buffer *plaintext,
    char *error,
    size_t error_len) {
    struct nkms_client_state state;
    struct aws_byte_buf plain = {0};
    struct aws_byte_buf encrypted = aws_byte_buf_from_array(ciphertext, ciphertext_len);
    struct aws_string *context = NULL;
    int result = -1;

    /*
     * GenerateDataKey returns a symmetric KMS ciphertext blob containing its
     * key metadata. The Nitro SDK requires both key_id and
     * encryption_algorithm to be NULL for symmetric ciphertext. Passing a key
     * ID with a NULL algorithm is rejected as "Invalid encryption algorithm".
     */
    plaintext->data = NULL;
    plaintext->len = 0;
    if (init_client(&state, region, parent_cid, proxy_port, access_key_id, secret_access_key,
                    session_token, error, error_len) != 0) {
        return -1;
    }
    int rc;
    if (encryption_context_json != NULL && encryption_context_json[0] != '\0') {
        context = aws_string_new_from_c_str(state.allocator, encryption_context_json);
        if (context == NULL) {
            set_error(error, error_len, "allocating KMS encryption context failed");
            goto cleanup;
        }
        rc = aws_kms_decrypt_blocking_with_context(
            state.client, NULL, NULL, &encrypted, context, &plain);
    } else {
        rc = aws_kms_decrypt_blocking(state.client, NULL, NULL, &encrypted, &plain);
    }
    if (rc != AWS_OP_SUCCESS) {
        set_aws_error(error, error_len, "KMS Decrypt");
        goto cleanup;
    }
    if (copy_buffer(&plain, plaintext) != 0) {
        set_error(error, error_len, "copying decrypted KMS data key failed");
        goto cleanup;
    }
    result = 0;

cleanup:
    aws_byte_buf_clean_up_secure(&plain);
    aws_string_destroy(context);
    clean_client(&state);
    return result;
}

void nkms_buffer_free(struct nkms_buffer *buffer) {
    if (buffer != NULL && buffer->data != NULL) {
        memset(buffer->data, 0, buffer->len);
        free(buffer->data);
        buffer->data = NULL;
        buffer->len = 0;
    }
}
