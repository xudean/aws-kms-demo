#ifndef AWS_KMS_DEMO_NITRO_KMS_SHIM_H
#define AWS_KMS_DEMO_NITRO_KMS_SHIM_H

#include <stddef.h>
#include <stdint.h>

struct nkms_buffer {
    uint8_t *data;
    size_t len;
};

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
    size_t error_len);

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
    size_t error_len);

void nkms_buffer_free(struct nkms_buffer *buffer);

#endif
