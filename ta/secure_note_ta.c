#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "secure_note_ta.h"
#include <string.h>

// Insecure key handling for example purposes
#define AES_KEY_SIZE_BITS 128
#define AES_KEY_SIZE_BYTES (AES_KEY_SIZE_BITS / 8)

// AES key for encryption/decryption (for example purposes only, not secure)
static const uint8_t fixed_aes_key[AES_KEY_SIZE_BYTES] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// Maximum number of notes that can be stored
#define MAX_NOTES_IN_TA 5 

typedef struct {
    char id[MAX_NOTE_ID_TA_LEN]; // Null-terminated ID string
    uint8_t encrypted_data_with_iv[MAX_NOTE_STORAGE_BUFFER_TA_LEN];
    uint32_t total_stored_len; // Actual length of (IV + Ciphertext) currently stored
    bool is_used;              // Flag indicating if this slot is in use
} secure_note_entry_t;

static secure_note_entry_t note_storage[MAX_NOTES_IN_TA]; 

// --- Helper: AES Cryptographic Operation with Manual PKCS#7 Padding ---
static TEE_Result do_aes_crypto(TEE_OperationMode mode,        // TEE_MODE_ENCRYPT or TEE_MODE_DECRYPT
                                const uint8_t *key_data,       // Pointer to the AES key
                                uint32_t key_len_bytes,        // Length of the key in bytes
                                const uint8_t *iv_data,        // Pointer to the IV
                                uint32_t iv_len_bytes,         // Length of the IV (must be AES_BLOCK_SIZE)
                                const uint8_t *input_data,     // Pointer to input data (plaintext/ciphertext)
                                uint32_t input_len,            // Length of input data
                                uint8_t *output_data,          // Buffer for output data
                                uint32_t *output_len_ptr) {    // In: size of output_data; Out: actual data written
    TEE_Result res = TEE_ERROR_GENERIC;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
    TEE_Attribute attr;
    uint32_t key_len_bits = key_len_bytes * 8;

    uint8_t *data_to_process = (uint8_t *)input_data; 
    uint32_t len_to_process = input_len;
    uint8_t local_padded_buffer[MAX_PLAINTEXT_CONTENT_CHARS + AES_BLOCK_SIZE];

    // 1. Allocate transient object for the key
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, key_len_bits, &key_handle);
    if (res != TEE_SUCCESS) {
        EMSG("AES: Failed to allocate transient key object: 0x%x", res);
        return res;
    }

    // 2. Populate the key object
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key_data, key_len_bytes);
    res = TEE_PopulateTransientObject(key_handle, &attr, 1);
    if (res != TEE_SUCCESS) {
        EMSG("AES: Failed to populate transient key object: 0x%x", res);
        goto cleanup_crypto;
    }

    // 3. Allocate operation handle for AES-CBC (PKCS#7 padding will be handled manually for NOPAD)
    res = TEE_AllocateOperation(&op_handle, TEE_ALG_AES_CBC_NOPAD, mode, key_len_bits);
    if (res != TEE_SUCCESS) {
        EMSG("AES: Failed to allocate operation handle (TEE_ALG_AES_CBC_NOPAD): 0x%x", res);
        goto cleanup_crypto;
    }

    // 4. Set the key for the operation
    res = TEE_SetOperationKey(op_handle, key_handle);
    if (res != TEE_SUCCESS) {
        EMSG("AES: Failed to set operation key: 0x%x", res);
        goto cleanup_crypto;
    }

    // 5. Initialize the cipher operation with IV
    if (iv_len_bytes != AES_BLOCK_SIZE) { // IV must be 16 bytes for AES
        EMSG("AES: Invalid IV length for CBC: %u, expected %d", iv_len_bytes, AES_BLOCK_SIZE);
        res = TEE_ERROR_BAD_PARAMETERS;
        goto cleanup_crypto;
    }
    TEE_CipherInit(op_handle, iv_data, iv_len_bytes);


    // 6. Manual PKCS#7 Padding for Encryption if using TEE_ALG_AES_CBC_NOPAD
    if (mode == TEE_MODE_ENCRYPT) {
        uint32_t padding_len;
        // If input_len is 0, padding_len will be AES_BLOCK_SIZE.
        // If input_len % AES_BLOCK_SIZE is 0 and input_len > 0, PKCS#7 adds a full block of padding.
        // Otherwise, pad to the next block boundary.
        if (input_len % AES_BLOCK_SIZE == 0) {
             padding_len = AES_BLOCK_SIZE;
        } else {
             padding_len = AES_BLOCK_SIZE - (input_len % AES_BLOCK_SIZE);
        }


        len_to_process = input_len + padding_len;
        DMSG("AES Encrypt: input_len=%u, padding_val/len=%u, len_to_process=%u",
             input_len, padding_len, len_to_process);

        if (len_to_process > sizeof(local_padded_buffer)) {
             EMSG("AES Encrypt: Padded input (%u) too large for local_padded_buffer (%zu)",
                  len_to_process, sizeof(local_padded_buffer));
             res = TEE_ERROR_EXCESS_DATA;
             goto cleanup_crypto;
        }
        TEE_MemMove(local_padded_buffer, input_data, input_len);
        TEE_MemFill(local_padded_buffer + input_len, (uint8_t)padding_len, padding_len);
        data_to_process = local_padded_buffer;
    } else { // TEE_MODE_DECRYPT with NOPAD
        if (input_len == 0 || (input_len % AES_BLOCK_SIZE) != 0) {
            EMSG("AES Decrypt: Ciphertext length %u not a multiple of block size %d", input_len, AES_BLOCK_SIZE);
            res = TEE_ERROR_CIPHERTEXT_INVALID;
            goto cleanup_crypto;
        }
        // len_to_process is input_len, data_to_process is input_data
    }

    // 7. Perform the cryptographic operation
    uint32_t initial_output_buffer_size = *output_len_ptr;
    DMSG("AES: Calling CipherDoFinal: mode=%u, len_to_process=%u, output_buffer_size_in=%u",
         mode, len_to_process, initial_output_buffer_size);

    res = TEE_CipherDoFinal(op_handle, data_to_process, len_to_process,
                            output_data, output_len_ptr); // output_len_ptr is updated here
    if (res != TEE_SUCCESS) {
        EMSG("AES: TEE_CipherDoFinal failed: 0x%x. Output buffer initial size was: %u. After call (if updated for SHORT_BUFFER): %u",
             res, initial_output_buffer_size, *output_len_ptr);
        goto cleanup_crypto;
    }
    DMSG("AES: CipherDoFinal success. Output length (potentially padded for decrypt): %u", *output_len_ptr);


    // 8. Manual PKCS#7 Unpadding for Decryption
    if (mode == TEE_MODE_DECRYPT) {
        if (*output_len_ptr == 0) {
            EMSG("AES Decrypt: Decrypted to zero length before unpadding (was input ciphertext also 0 length?).");
            if (input_len > 0) { // If original ciphertext had data, this is an error.
                 res = TEE_ERROR_CIPHERTEXT_INVALID;
                 goto cleanup_crypto;
            }
        }
        if (*output_len_ptr > MAX_PLAINTEXT_CONTENT_CHARS + AES_BLOCK_SIZE) {
             EMSG("AES Decrypt: Output length %u after decryption is too large (max expected: %u).",
                  *output_len_ptr, (uint32_t)(MAX_PLAINTEXT_CONTENT_CHARS + AES_BLOCK_SIZE));
             res = TEE_ERROR_BAD_STATE;
             goto cleanup_crypto;
        }

        uint32_t padding_val = output_data[*output_len_ptr - 1];
        DMSG("AES Decrypt: Last byte (padding_val) = %u", padding_val);

        if (padding_val == 0 || padding_val > AES_BLOCK_SIZE) {
            EMSG("AES Decrypt: Invalid PKCS#7 padding value: %u (output_len_ptr: %u)", padding_val, *output_len_ptr);
            res = TEE_ERROR_CIPHERTEXT_INVALID;
            goto cleanup_crypto;
        }
        if (padding_val > *output_len_ptr) {
            EMSG("AES Decrypt: Padding value %u greater than decrypted length %u.", padding_val, *output_len_ptr);
            res = TEE_ERROR_CIPHERTEXT_INVALID;
            goto cleanup_crypto;
        }

        // Verify
        for (uint32_t i = 0; i < padding_val; i++) {
            if (output_data[*output_len_ptr - 1 - i] != padding_val) {
                EMSG("AES Decrypt: Invalid PKCS#7 padding byte sequence at offset %u (expected %u, got %u).",
                     *output_len_ptr - 1 - i, padding_val, output_data[*output_len_ptr - 1 - i]);
                res = TEE_ERROR_CIPHERTEXT_INVALID;
                goto cleanup_crypto;
            }
        }
        *output_len_ptr -= padding_val; // Actual length of original plaintext
        DMSG("AES Decrypt: Unpadded output length: %u", *output_len_ptr);
    }

cleanup_crypto:
    if (op_handle != TEE_HANDLE_NULL) TEE_FreeOperation(op_handle);
    if (key_handle != TEE_HANDLE_NULL) TEE_FreeTransientObject(key_handle);
    return res;
}


// --- Helper: Find note slot by ID ---
static int find_note_slot(const char *id_to_find, uint32_t id_len_from_ca, bool find_empty_for_write) {
    size_t cmp_len;
    if (id_len_from_ca == 0) return -1;

    for (int i = 0; i < MAX_NOTES_IN_TA; ++i) {
        if (note_storage[i].is_used) {
            cmp_len = strnlen(id_to_find, id_len_from_ca -1);
            if (cmp_len == strnlen(note_storage[i].id, MAX_NOTE_ID_TA_LEN -1) &&
                strncmp(note_storage[i].id, id_to_find, cmp_len) == 0) {
                DMSG("find_note_slot: Found existing ID '%s' at slot %d", id_to_find, i);
                return i;
            }
        } else if (find_empty_for_write) {
            DMSG("find_note_slot: Found empty slot %d for writing", i);
            return i;
        }
    }
    DMSG("find_note_slot: ID '%s' not found (find_empty_for_write=%d)", id_to_find, find_empty_for_write);
    return -1;
}


TEE_Result TA_CreateEntryPoint(void) {
    DMSG("Secure Note TA (AES): CreateEntryPoint");
    for (int i = 0; i < MAX_NOTES_IN_TA; ++i) {
        note_storage[i].is_used = false;
        TEE_MemFill(note_storage[i].id, 0, MAX_NOTE_ID_TA_LEN);
        TEE_MemFill(note_storage[i].encrypted_data_with_iv, 0, MAX_NOTE_STORAGE_BUFFER_TA_LEN);
        note_storage[i].total_stored_len = 0;
    }
    IMSG("Secure Note TA (AES) initialized. Max notes: %d", MAX_NOTES_IN_TA);
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    DMSG("Secure Note TA (AES): DestroyEntryPoint");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param __maybe_unused params[4], void **session_context) {
    (void)param_types; (void)params; // Correctly use param_types
    *session_context = NULL; // Not using session context in this simple TA
    IMSG("Secure Note TA (AES): Session opened.");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session_context) {
    (void)session_context;
    IMSG("Secure Note TA (AES): Session closed");
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *session_context, uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4]) {
    DMSG("TA (AES): InvokeEntryPoint: cmd_id=0x%x (%u), param_types=0x%x", cmd_id, cmd_id, param_types);
    DMSG("TA: Param0 type: %u, size: %u", TEE_PARAM_TYPE_GET(param_types, 0), params[0].memref.size);
    DMSG("TA: Param1 type: %u, size: %u", TEE_PARAM_TYPE_GET(param_types, 1), params[1].memref.size);

    TEE_Result res = TEE_ERROR_GENERIC;
    char *note_id_from_ca;
    uint32_t note_id_size_from_ca; // Includes null terminator from CA
    char *plaintext_content_from_ca;
    uint32_t plaintext_content_size_from_ca; // Includes null terminator from CA

    uint8_t current_iv[IV_SIZE];
    uint8_t temp_ciphertext_buffer[MAX_CIPHERTEXT_PADDED_LEN]; // Buffer for just ciphertext part
    uint32_t actual_ciphertext_len; // Length of actual ciphertext written by crypto op (padded)

    uint8_t temp_plaintext_buffer[MAX_PLAINTEXT_CONTENT_BUFFER_LEN]; // Sized for content + null
    uint32_t actual_plaintext_len; // Length of actual plaintext after decryption and unpadding

    int slot_index;

    const uint32_t expected_types_store_note = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                                               TEE_PARAM_TYPE_MEMREF_INPUT,
                                                               TEE_PARAM_TYPE_NONE,
                                                               TEE_PARAM_TYPE_NONE);
    const uint32_t expected_types_read_note = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                                              TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                                              TEE_PARAM_TYPE_NONE,
                                                              TEE_PARAM_TYPE_NONE);
    const uint32_t expected_types_clear_note = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                                               TEE_PARAM_TYPE_NONE,
                                                               TEE_PARAM_TYPE_NONE,
                                                               TEE_PARAM_TYPE_NONE);

    switch (cmd_id) {
    case CMD_STORE_NOTE:
        IMSG("TA (AES): Processing CMD_STORE_NOTE");
        if (param_types != expected_types_store_note) {
            EMSG("TA: STORE - Bad param types. Expected 0x%x, Got 0x%x", expected_types_store_note, param_types);
            return TEE_ERROR_BAD_PARAMETERS;
        }

        note_id_from_ca = (char *)params[0].memref.buffer;
        note_id_size_from_ca = params[0].memref.size;
        plaintext_content_from_ca = (char *)params[1].memref.buffer;
        plaintext_content_size_from_ca = params[1].memref.size;

        if (note_id_size_from_ca == 0 || note_id_size_from_ca > MAX_NOTE_ID_TA_LEN ||
            note_id_from_ca[note_id_size_from_ca - 1] != '\0') {
            EMSG("TA: STORE - Invalid ID params (size: %u, max: %d, nullterm: %d)",
                 note_id_size_from_ca, MAX_NOTE_ID_TA_LEN,
                 (note_id_size_from_ca > 0 ? note_id_from_ca[note_id_size_from_ca - 1] == '\0' : 0) );
            return TEE_ERROR_BAD_PARAMETERS;
        }

        uint32_t actual_plaintext_len_for_crypto = (plaintext_content_size_from_ca > 0) ? (plaintext_content_size_from_ca - 1) : 0;
        if (plaintext_content_size_from_ca == 0 ||
            plaintext_content_size_from_ca > MAX_PLAINTEXT_CONTENT_BUFFER_LEN ||
            plaintext_content_from_ca[plaintext_content_size_from_ca - 1] != '\0') {
            EMSG("TA: STORE - Invalid Content params (size: %u, max_buf: %d, actual_len_crypto: %u, nullterm: %d)",
                 plaintext_content_size_from_ca, MAX_PLAINTEXT_CONTENT_BUFFER_LEN, actual_plaintext_len_for_crypto,
                 (plaintext_content_size_from_ca > 0 ? plaintext_content_from_ca[plaintext_content_size_from_ca - 1] == '\0' : 0) );
            return TEE_ERROR_BAD_PARAMETERS;
        }

        slot_index = find_note_slot(note_id_from_ca, note_id_size_from_ca, true);
        if (slot_index == -1) {
            EMSG("TA: STORE - No available slot for ID '%s'", note_id_from_ca);
            return TEE_ERROR_STORAGE_NO_SPACE;
        }
        DMSG("TA: STORE - Using slot %d for ID: %s", slot_index, note_id_from_ca);

        TEE_GenerateRandom(current_iv, sizeof(current_iv));
        DMSG("TA: STORE - Generated IV for slot %d.", slot_index);

        actual_ciphertext_len = sizeof(temp_ciphertext_buffer);
        res = do_aes_crypto(TEE_MODE_ENCRYPT,
                            fixed_aes_key, sizeof(fixed_aes_key),
                            current_iv, sizeof(current_iv),
                            (uint8_t *)plaintext_content_from_ca, actual_plaintext_len_for_crypto,
                            temp_ciphertext_buffer, &actual_ciphertext_len);
        if (res != TEE_SUCCESS) {
            EMSG("TA: STORE - Encryption failed: 0x%x", res);
            return res;
        }
        DMSG("TA: STORE - Encrypted content length (padded): %u", actual_ciphertext_len);

        if (IV_SIZE + actual_ciphertext_len > MAX_NOTE_STORAGE_BUFFER_TA_LEN) {
             EMSG("TA: STORE - IV + Ciphertext (%u) too large for slot buffer (%d)",
                  (IV_SIZE + actual_ciphertext_len), MAX_NOTE_STORAGE_BUFFER_TA_LEN);
             return TEE_ERROR_EXCESS_DATA;
        }

        TEE_MemMove(note_storage[slot_index].encrypted_data_with_iv, current_iv, IV_SIZE);
        TEE_MemMove(note_storage[slot_index].encrypted_data_with_iv + IV_SIZE,
                      temp_ciphertext_buffer, actual_ciphertext_len);
        note_storage[slot_index].total_stored_len = IV_SIZE + actual_ciphertext_len;
        DMSG("TA: STORE - Total stored length (IV+Cipher): %u", note_storage[slot_index].total_stored_len);

        TEE_MemMove(note_storage[slot_index].id, note_id_from_ca, note_id_size_from_ca);
        note_storage[slot_index].is_used = true;

        IMSG("TA (AES): Note '%s' (len %u) stored encrypted in slot %d.",
             note_id_from_ca, actual_plaintext_len_for_crypto, slot_index);
        return TEE_SUCCESS;

    case CMD_READ_NOTE:
        IMSG("TA (AES): Processing CMD_READ_NOTE");
        if (param_types != expected_types_read_note) {
            EMSG("TA: READ - Bad param types. Expected 0x%x, Got 0x%x", expected_types_read_note, param_types);
            return TEE_ERROR_BAD_PARAMETERS;
        }

        note_id_from_ca = (char *)params[0].memref.buffer;
        note_id_size_from_ca = params[0].memref.size;

        if (note_id_size_from_ca == 0 || note_id_size_from_ca > MAX_NOTE_ID_TA_LEN ||
            note_id_from_ca[note_id_size_from_ca - 1] != '\0') {
            EMSG("TA: READ - Invalid ID params"); return TEE_ERROR_BAD_PARAMETERS;
        }

        slot_index = find_note_slot(note_id_from_ca, note_id_size_from_ca, false);
        if (slot_index == -1 || !note_storage[slot_index].is_used) {
            EMSG("TA: READ - Note ID '%s' not found.", note_id_from_ca);
            return TEE_ERROR_ITEM_NOT_FOUND;
        }
        DMSG("TA: READ - Reading from slot %d for ID: '%s'", slot_index, note_id_from_ca);

        if (note_storage[slot_index].total_stored_len < IV_SIZE) {
            EMSG("TA: READ - Stored data in slot %d (len %u) too short (no IV?)",
                 slot_index, note_storage[slot_index].total_stored_len);
            return TEE_ERROR_BAD_STATE;
        }

        TEE_MemMove(current_iv, note_storage[slot_index].encrypted_data_with_iv, IV_SIZE);
        const uint8_t *stored_ciphertext_ptr = note_storage[slot_index].encrypted_data_with_iv + IV_SIZE;
        uint32_t stored_ciphertext_actual_len = note_storage[slot_index].total_stored_len - IV_SIZE;

        DMSG("TA: READ - Extracted IV. Stored ciphertext length: %u", stored_ciphertext_actual_len);

        actual_plaintext_len = MAX_PLAINTEXT_CONTENT_BUFFER_LEN -1;
        res = do_aes_crypto(TEE_MODE_DECRYPT,
                            fixed_aes_key, sizeof(fixed_aes_key),
                            current_iv, sizeof(current_iv),
                            stored_ciphertext_ptr, stored_ciphertext_actual_len,
                            temp_plaintext_buffer, &actual_plaintext_len);
        if (res != TEE_SUCCESS) {
            EMSG("TA: READ - Decryption failed for slot %d: 0x%x", slot_index, res);
            return res;
        }
        DMSG("TA: READ - Decrypted content length (unpadded): %u", actual_plaintext_len);

        temp_plaintext_buffer[actual_plaintext_len] = '\0';
        uint32_t total_plaintext_to_send_to_ca = actual_plaintext_len + 1;

        if (params[1].memref.size < total_plaintext_to_send_to_ca) {
            EMSG("TA: READ - CA output buffer (size %u) too small for decrypted data (need %u).",
                 params[1].memref.size, total_plaintext_to_send_to_ca);
            params[1].memref.size = total_plaintext_to_send_to_ca;
            return TEE_ERROR_SHORT_BUFFER;
        }
        TEE_MemMove(params[1].memref.buffer, temp_plaintext_buffer, total_plaintext_to_send_to_ca);
        params[1].memref.size = total_plaintext_to_send_to_ca;

        IMSG("TA (AES): Note '%s' read securely from slot %d.", note_id_from_ca, slot_index);
        return TEE_SUCCESS;

    case CMD_CLEAR_NOTE:
        IMSG("TA (AES): Processing CMD_CLEAR_NOTE");
        if (param_types != expected_types_clear_note) {
            EMSG("TA: CLEAR - Bad param types. Expected 0x%x, Got 0x%x", expected_types_clear_note, param_types);
            return TEE_ERROR_BAD_PARAMETERS;
        }

        note_id_from_ca = (char *)params[0].memref.buffer;
        note_id_size_from_ca = params[0].memref.size;

        if (note_id_size_from_ca == 0 || note_id_size_from_ca > MAX_NOTE_ID_TA_LEN ||
            note_id_from_ca[note_id_size_from_ca - 1] != '\0') {
            EMSG("TA: CLEAR - Invalid ID params"); return TEE_ERROR_BAD_PARAMETERS;
        }

        slot_index = find_note_slot(note_id_from_ca, note_id_size_from_ca, false);
        if (slot_index == -1 || !note_storage[slot_index].is_used) {
            EMSG("TA: CLEAR - Note ID '%s' not found for deletion.", note_id_from_ca);
            return TEE_ERROR_ITEM_NOT_FOUND;
        }
        DMSG("TA: CLEAR - Clearing slot %d for ID: '%s'", slot_index, note_id_from_ca);

        note_storage[slot_index].is_used = false;
        TEE_MemFill(note_storage[slot_index].id, 0, MAX_NOTE_ID_TA_LEN);
        TEE_MemFill(note_storage[slot_index].encrypted_data_with_iv, 0, MAX_NOTE_STORAGE_BUFFER_TA_LEN);
        note_storage[slot_index].total_stored_len = 0;

        IMSG("TA (AES): Note '%s' in slot %d cleared.", note_id_from_ca, slot_index);
        return TEE_SUCCESS;

    default:
        EMSG("TA (AES): Command ID 0x%x not supported.", cmd_id);
        return TEE_ERROR_NOT_SUPPORTED;
    }
}