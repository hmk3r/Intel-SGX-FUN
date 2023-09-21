#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#define END_COUNTER_VALUE 100
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

char AES_AAD[BUFSIZ] = "lkyorovski-ENCLAVE-2";

sgx_ecc_state_handle_t ecc_hd;
sgx_ec256_private_t pvk;
sgx_ec256_public_t pbk;
sgx_status_t status;

sgx_ec256_dh_shared_t shared_key;
sgx_aes_ctr_128bit_key_t aes_key;

uint8_t i;

uint8_t work_iv[AES_IV_SIZE];
uint8_t iv[AES_IV_SIZE];
uint8_t aes_result[AES_MAX_OUTPUT];

int printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

sgx_status_t setup(uint32_t pbk_data_capacity, uint8_t *pbk_data, uint32_t *pbk_data_size)
{
    status = sgx_ecc256_open_context(&ecc_hd);
    if (status)
        return status;

    // EXERCISE_ANNOTAION: Enclave generates key pair
    status = sgx_ecc256_create_key_pair(&pvk, &pbk, ecc_hd);
    if (status)
        return status;

    if (pbk_data_capacity < (2 * SGX_ECP256_KEY_SIZE))
        return SGX_ERROR_OUT_OF_MEMORY;
    memset(pbk_data, 0, pbk_data_capacity);
    memcpy(pbk_data, pbk.gx, SGX_ECP256_KEY_SIZE);
    memcpy(pbk_data + SGX_ECP256_KEY_SIZE, pbk.gy, SGX_ECP256_KEY_SIZE);

    *pbk_data_size = 2 * SGX_ECP256_KEY_SIZE;

    printf("Created DH keys\n");

    return SGX_SUCCESS;
}

sgx_status_t derive_secret(uint8_t *pbk_data, uint32_t pbk_data_size)
{
    if (pbk_data_size < (2 * SGX_ECP256_KEY_SIZE))
        return SGX_ERROR_OUT_OF_MEMORY;

    sgx_ec256_public_t remote_pbk;
    memcpy(remote_pbk.gx, pbk_data, SGX_ECP256_KEY_SIZE);
    memcpy(remote_pbk.gy, pbk_data + SGX_ECP256_KEY_SIZE, SGX_ECP256_KEY_SIZE);

    // EXERCISE_ANNOTAION: Enclave calculates the shared secret
    status = sgx_ecc256_compute_shared_dhkey(
        &pvk,
        &remote_pbk,
        &shared_key,
        ecc_hd);

    if (status)
        return status;

    memcpy(aes_key, shared_key.s, sizeof(aes_key));

    printf("Computed shared secret\n");

    return SGX_SUCCESS;
}

int increment_counter(
    uint32_t iv_ciphertext_capacity,
    uint8_t *iv_ciphertext,
    uint32_t *iv_ciphertext_size)
{

    // EXERCISE_ANNOTAION: Enclave decrypts the counter
    memset(aes_result, 0, sizeof(aes_result));
    status = sgx_aes_ctr_decrypt(
        &aes_key,
        iv_ciphertext + AES_IV_SIZE,
        *iv_ciphertext_size - AES_IV_SIZE,
        iv_ciphertext,
        AES_IV_SIZE / 2,
        aes_result);
    if (status)
        return status;
    i = aes_result[0];

    if (i == END_COUNTER_VALUE)
    {
        return COUNTER_END_CODE;
    }
    i++;

    /* Random IV */
    status = sgx_read_rand(
        iv,
        sizeof(iv));

    if (status)
        return status;

    memcpy(work_iv, iv, sizeof(work_iv));

    memset(aes_result, 0, sizeof(aes_result));

    // EXERCISE_ANNOTAION: Enclave encrypts the counter
    status = sgx_aes_ctr_encrypt(
        &aes_key,
        &i,
        sizeof(i),
        work_iv,
        AES_IV_SIZE / 2,
        aes_result);

    if (status)
        return status;

    memset(iv_ciphertext, 0, iv_ciphertext_capacity);
    memcpy(iv_ciphertext, iv, sizeof(iv));
    memcpy(
        iv_ciphertext + sizeof(iv),
        aes_result,
        MIN(iv_ciphertext_capacity - sizeof(iv), sizeof(aes_result)));

    *iv_ciphertext_size = static_cast<uint32_t>(
        sizeof(iv) + MIN(iv_ciphertext_capacity - sizeof(iv), sizeof(aes_result))
    );

    return SGX_SUCCESS;
}

/*
Begin Reference
Adapted from "linux-sgx/SampleCode/SealUnseal/Enclave_Seal/Enclave_Seal.cpp"
*/
uint32_t get_sealed_data_size()
{
    return sgx_calc_sealed_data_size((uint32_t)strlen(AES_AAD), (uint32_t)sizeof(i));
}

sgx_status_t seal_data(uint8_t* sealed_blob, uint32_t data_size)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)strlen(AES_AAD), (uint32_t)sizeof(i));
    if (sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (sealed_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;
    
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    // EXERCISE_ANNOTAION: Enclave seals the counter
    sgx_status_t  err = sgx_seal_data(
        (uint32_t)strlen(AES_AAD),
        (const uint8_t *)AES_AAD,
        (uint32_t)sizeof(i),
        &i,
        sealed_data_size,
        (sgx_sealed_data_t *)temp_sealed_buf
    );

    if (err == SGX_SUCCESS)
    {
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
        printf("Sealed counter successfully\n");
    }

    free(temp_sealed_buf);
    return err;
}
/* End reference */

/*
Begin reference

Adapted from linux-sgx/SampleCode/SealUnseal/Enclave_Unseal/Enclave_Unseal.cpp
*/
sgx_status_t unseal_confirm_counter(const uint8_t *sealed_blob, size_t data_size)
{
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    if (mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if(mac_text_len > data_size || decrypt_data_len > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *de_mac_text =(uint8_t *)malloc(mac_text_len);
    if(de_mac_text == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
    if(decrypt_data == NULL)
    {
        free(de_mac_text);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    // EXERCISE_ANNOTAION: Enclave unseals the counter
    sgx_status_t ret = sgx_unseal_data(
        (const sgx_sealed_data_t *)sealed_blob,
        de_mac_text,
        &mac_text_len,
        decrypt_data,
        &decrypt_data_len
    );

    if (ret != SGX_SUCCESS)
    {
        free(de_mac_text);
        free(decrypt_data);
        return ret;
    }

    if (memcmp(de_mac_text, AES_AAD, strlen(AES_AAD)) || *decrypt_data != END_COUNTER_VALUE) {
        free(de_mac_text);
        free(decrypt_data);
        return SGX_ERROR_UNEXPECTED;
    }

    printf("Counter in sealed data matches target value\n");

    free(de_mac_text);
    free(decrypt_data);
    return SGX_SUCCESS;
}
/* End reference */