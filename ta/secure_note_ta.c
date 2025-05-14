#include <tee_internal_api.h>
// #include <tee_internal_api_extensions.h> // Not needed without AES for now
#include "secure_note_ta.h"
#include <string.h>

#define MAX_NOTES_IN_TA 5

typedef struct {
    char id[MAX_NOTE_ID_TA_LEN]; // Buffer should be large enough for ID + null terminator
    char plaintext_content[MAX_PLAINTEXT_NOTE_TA_LEN]; // Buffer for content + null
    // uint32_t actual_content_len; // If you want to store non-null-terminated data
    bool is_used;
} secure_note_entry_t;

static secure_note_entry_t note_storage[MAX_NOTES_IN_TA];

// Returns slot index if found/empty slot found, or -1 otherwise.
static int find_note_slot(const char *id_to_find, uint32_t id_len, bool find_empty_for_write) {
    // id_len includes the null terminator from CA if present, or is the raw buffer size.
    // We should compare using strncmp with a safe length.
    size_t cmp_len;

    for (int i = 0; i < MAX_NOTES_IN_TA; ++i) {
        if (note_storage[i].is_used) {
            // Compare the ID safely
            // Determine the length to compare, up to MAX_NOTE_ID_TA_LEN - 1
            // Assumes id_to_find is null-terminated or its length is accurately given by id_len
            cmp_len = strnlen(id_to_find, id_len < MAX_NOTE_ID_TA_LEN ? id_len : MAX_NOTE_ID_TA_LEN -1);

            if (strncmp(note_storage[i].id, id_to_find, cmp_len) == 0 && note_storage[i].id[cmp_len] == '\0') {
                DMSG("find_note_slot: Found existing ID '%s' at slot %d", id_to_find, i);
                return i; // Found existing
            }
        } else if (find_empty_for_write) {
            DMSG("find_note_slot: Found empty slot %d for writing", i);
            return i; // Found empty slot for new note
        }
    }
    DMSG("find_note_slot: ID '%s' not found (find_empty_for_write=%d)", id_to_find, find_empty_for_write);
    return -1; // Not found, or no empty slot
}


TEE_Result TA_CreateEntryPoint(void) {
    DMSG("Secure Note TA: CreateEntryPoint");
    // Initialize note_storage
    for (int i = 0; i < MAX_NOTES_IN_TA; ++i) {
        note_storage[i].is_used = false;
        TEE_MemFill(note_storage[i].id, 0, MAX_NOTE_ID_TA_LEN);
        TEE_MemFill(note_storage[i].plaintext_content, 0, MAX_PLAINTEXT_NOTE_TA_LEN);
    }
    IMSG("Secure Note TA initialized. Max notes: %d", MAX_NOTES_IN_TA);
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    DMSG("Secure Note TA: DestroyEntryPoint");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param __maybe_unused params[4], void **session_context) {
    (void)param_types; (void)params;
    DMSG("Secure Note TA: OpenSessionEntryPoint");
    // In a real app with session context:
    // *session_context = TEE_Malloc(sizeof(struct some_session_data), 0);
    // if (!*session_context) return TEE_ERROR_OUT_OF_MEMORY;
    // TEE_MemFill(*session_context, 0, sizeof(struct some_session_data));
    // IMSG("Secure Note TA: Session opened, context allocated (example)");
    // For now, no session context needed:
    *session_context = NULL;
    IMSG("Secure Note TA: Session opened.");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session_context) {
    (void)session_context;
    // if (session_context) TEE_Free(session_context); // If context was allocated
    IMSG("Secure Note TA: Session closed");
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *session_context, uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4]) {
    // DEBUG
    DMSG("TA: InvokeEntryPoint: cmd_id=0x%x (%u), param_types=0x%x", cmd_id, cmd_id, param_types);
    DMSG("TA: Param0 type: %u, size: %u, val_a: 0x%x, val_b: 0x%x", TEE_PARAM_TYPE_GET(param_types, 0), params[0].memref.size, params[0].value.a, params[0].value.b);
    DMSG("TA: Param1 type: %u, size: %u, val_a: 0x%x, val_b: 0x%x", TEE_PARAM_TYPE_GET(param_types, 1), params[1].memref.size, params[1].value.a, params[1].value.b);
    DMSG("TA: Param2 type: %u, size: %u, val_a: 0x%x, val_b: 0x%x", TEE_PARAM_TYPE_GET(param_types, 2), params[2].memref.size, params[2].value.a, params[2].value.b);
    DMSG("TA: Param3 type: %u, size: %u, val_a: 0x%x, val_b: 0x%x", TEE_PARAM_TYPE_GET(param_types, 3), params[3].memref.size, params[3].value.a, params[3].value.b);
    
    char *note_id_from_ca;
    uint32_t note_id_size_from_ca;
    char *plaintext_content_from_ca;
    uint32_t plaintext_content_size_from_ca;
    int slot_index;

    
    const uint32_t expected_types_store_note = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,  // Note ID
                                                               TEE_PARAM_TYPE_MEMREF_INPUT,  // Plaintext Content
                                                               TEE_PARAM_TYPE_NONE,
                                                               TEE_PARAM_TYPE_NONE);

    const uint32_t expected_types_read_note = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, // Note ID
                                                              TEE_PARAM_TYPE_MEMREF_OUTPUT,// Buffer for plaintext
                                                              TEE_PARAM_TYPE_NONE,
                                                              TEE_PARAM_TYPE_NONE);

    const uint32_t expected_types_clear_note = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, // Note ID
                                                               TEE_PARAM_TYPE_NONE,
                                                               TEE_PARAM_TYPE_NONE,
                                                               TEE_PARAM_TYPE_NONE);

    switch (cmd_id) {
    case CMD_STORE_NOTE:
        IMSG("TA: Processing CMD_STORE_NOTE");
        DMSG("TA: STORE - Expected param_types=0x%x, Received param_types=0x%x", expected_types_store_note, param_types);
        if (param_types != expected_types_store_note) {
            EMSG("TA: CMD_STORE_NOTE - Bad parameter types.");
            return TEE_ERROR_BAD_PARAMETERS;
        }

        note_id_from_ca = (char *)params[0].memref.buffer;
        note_id_size_from_ca = params[0].memref.size;
        DMSG("TA: STORE - Received ID size: %u (Max ID buffer: %d)", note_id_size_from_ca, MAX_NOTE_ID_TA_LEN);

        plaintext_content_from_ca = (char *)params[1].memref.buffer;
        plaintext_content_size_from_ca = params[1].memref.size;
        DMSG("TA: STORE - Received Content size: %u (Max Content buffer: %d)", plaintext_content_size_from_ca, MAX_PLAINTEXT_NOTE_TA_LEN);

        // Validate ID size (must have space for at least one char + null terminator if CA sends it)
        // CA sends strlen + 1. Our MAX_NOTE_ID_TA_LEN is the buffer size.
        if (note_id_size_from_ca == 0 || note_id_size_from_ca > MAX_NOTE_ID_TA_LEN) {
            EMSG("TA: CMD_STORE_NOTE - Invalid ID size: %u", note_id_size_from_ca);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        // Ensure CA sent null-terminated string for ID (important for strncmp later)
        if (note_id_from_ca[note_id_size_from_ca - 1] != '\0') {
            EMSG("TA: CMD_STORE_NOTE - Note ID from CA is not null-terminated.");
            return TEE_ERROR_BAD_PARAMETERS; // Or handle by copying and null-terminating if design allows
        }

        // Validate Content size
        if (plaintext_content_size_from_ca == 0 || plaintext_content_size_from_ca > MAX_PLAINTEXT_NOTE_TA_LEN) {
            EMSG("TA: CMD_STORE_NOTE - Invalid content size: %u", plaintext_content_size_from_ca);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        if (plaintext_content_from_ca[plaintext_content_size_from_ca - 1] != '\0') {
            EMSG("TA: CMD_STORE_NOTE - Note content from CA is not null-terminated.");
            return TEE_ERROR_BAD_PARAMETERS;
        }

        // Find a slot (new or existing to overwrite)
        // Pass note_id_size_from_ca to help find_note_slot determine true length if needed
        slot_index = find_note_slot(note_id_from_ca, note_id_size_from_ca, true);
        if (slot_index == -1) {
            EMSG("TA: CMD_STORE_NOTE - No empty slot or ID not found for overwrite. Max notes stored?");
            return TEE_ERROR_STORAGE_NO_SPACE;
        }
        DMSG("TA: CMD_STORE_NOTE - Storing in slot %d for ID: %s", slot_index, note_id_from_ca);

        // Store the ID and plaintext content (NO ENCRYPTION YET)
        // Copy ID, ensuring it fits and is null-terminated in our storage
        TEE_MemMove(note_storage[slot_index].id, note_id_from_ca, note_id_size_from_ca);
        // The CA should send null-terminated, so direct copy of size is fine if size <= MAX_NOTE_ID_TA_LEN.
        // If CA could send non-null terminated up to MAX_NOTE_ID_TA_LEN, then:
        // strncpy(note_storage[slot_index].id, note_id_from_ca, MAX_NOTE_ID_TA_LEN - 1);
        // note_storage[slot_index].id[MAX_NOTE_ID_TA_LEN - 1] = '\0';

        // Copy content
        TEE_MemMove(note_storage[slot_index].plaintext_content, plaintext_content_from_ca, plaintext_content_size_from_ca);
        // Similar null-termination consideration for content if CA might not send it.

        note_storage[slot_index].is_used = true;

        IMSG("TA: CMD_STORE_NOTE - Note '%s' stored (plaintext) in slot %d.", note_id_from_ca, slot_index);
        return TEE_SUCCESS;

    case CMD_READ_NOTE:
        IMSG("TA: Processing CMD_READ_NOTE");
        DMSG("TA: READ - Expected param_types=0x%x, Received param_types=0x%x", expected_types_read_note, param_types);
        if (param_types != expected_types_read_note) {
            EMSG("TA: CMD_READ_NOTE - Bad parameter types.");
            return TEE_ERROR_BAD_PARAMETERS;
        }

        note_id_from_ca = (char *)params[0].memref.buffer;
        note_id_size_from_ca = params[0].memref.size;
        DMSG("TA: READ - Received ID size: %u", note_id_size_from_ca);

        if (note_id_size_from_ca == 0 || note_id_size_from_ca > MAX_NOTE_ID_TA_LEN) {
            EMSG("TA: CMD_READ_NOTE - Invalid ID size: %u", note_id_size_from_ca);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        if (note_id_from_ca[note_id_size_from_ca - 1] != '\0') {
            EMSG("TA: CMD_READ_NOTE - Note ID from CA is not null-terminated.");
            return TEE_ERROR_BAD_PARAMETERS;
        }

        slot_index = find_note_slot(note_id_from_ca, note_id_size_from_ca, false);
        if (slot_index == -1 || !note_storage[slot_index].is_used) {
            EMSG("TA: CMD_READ_NOTE - Note ID '%s' not found.", note_id_from_ca);
            return TEE_ERROR_ITEM_NOT_FOUND;
        }
        DMSG("TA: CMD_READ_NOTE - Reading from slot %d for ID: %s", slot_index, note_id_from_ca);

        // Get length of stored plaintext (it should be null-terminated in our storage)
        size_t stored_content_len = strlen(note_storage[slot_index].plaintext_content);

        // Check if CA's output buffer is large enough
        DMSG("TA: READ - CA output buffer size: %u, Stored content_len+1: %zu", params[1].memref.size, stored_content_len + 1);
        if (params[1].memref.size < stored_content_len + 1) { // +1 for null terminator
            EMSG("TA: CMD_READ_NOTE - CA output buffer too small. Need %zu, got %u.", stored_content_len + 1, params[1].memref.size);
            // Update the required size for the CA if it wants to retry
            params[1].memref.size = stored_content_len + 1;
            return TEE_ERROR_SHORT_BUFFER;
        }

        // Copy plaintext content to CA's buffer
        TEE_MemMove(params[1].memref.buffer, note_storage[slot_index].plaintext_content, stored_content_len + 1);
        params[1].memref.size = stored_content_len + 1; // Inform CA of actual size written (including null)

        IMSG("TA: CMD_READ_NOTE - Note '%s' read (plaintext) from slot %d.", note_id_from_ca, slot_index);
        return TEE_SUCCESS;

    case CMD_CLEAR_NOTE:
        IMSG("TA: Processing CMD_CLEAR_NOTE");
        DMSG("TA: CLEAR - Expected param_types=0x%x, Received param_types=0x%x", expected_types_clear_note, param_types);
        if (param_types != expected_types_clear_note) {
             EMSG("TA: CMD_CLEAR_NOTE - Bad parameter types.");
            return TEE_ERROR_BAD_PARAMETERS;
        }

        note_id_from_ca = (char *)params[0].memref.buffer;
        note_id_size_from_ca = params[0].memref.size;
        DMSG("TA: CLEAR - Received ID size: %u", note_id_size_from_ca);


        if (note_id_size_from_ca == 0 || note_id_size_from_ca > MAX_NOTE_ID_TA_LEN) {
            EMSG("TA: CMD_CLEAR_NOTE - Invalid ID size: %u", note_id_size_from_ca);
            return TEE_ERROR_BAD_PARAMETERS;
        }
         if (note_id_from_ca[note_id_size_from_ca - 1] != '\0') {
            EMSG("TA: CMD_CLEAR_NOTE - Note ID from CA is not null-terminated.");
            return TEE_ERROR_BAD_PARAMETERS;
        }


        slot_index = find_note_slot(note_id_from_ca, note_id_size_from_ca, false);
        if (slot_index == -1 || !note_storage[slot_index].is_used) {
            EMSG("TA: CMD_CLEAR_NOTE - Note ID '%s' not found for deletion.", note_id_from_ca);
            return TEE_ERROR_ITEM_NOT_FOUND; // Or TEE_SUCCESS if "delete non-existent" is fine
        }
        DMSG("TA: CMD_CLEAR_NOTE - Clearing slot %d for ID: %s", slot_index, note_id_from_ca);


        // Clear the slot
        note_storage[slot_index].is_used = false;
        TEE_MemFill(note_storage[slot_index].id, 0, MAX_NOTE_ID_TA_LEN);
        TEE_MemFill(note_storage[slot_index].plaintext_content, 0, MAX_PLAINTEXT_NOTE_TA_LEN);

        IMSG("TA: CMD_CLEAR_NOTE - Note in slot %d ('%s') cleared.", slot_index, note_id_from_ca);
        return TEE_SUCCESS;

    default:
        EMSG("TA: Command ID 0x%x not supported.", cmd_id);
        return TEE_ERROR_NOT_SUPPORTED;
    }
}