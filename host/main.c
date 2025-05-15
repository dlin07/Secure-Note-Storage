#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>    

#include <tee_client_api.h>
#include "secure_note_ta.h" 

#define MAX_USER_CHOICE_LEN 10 // For menu choice input
#define CA_NOTE_ID_BUFFER_LEN (MAX_NOTE_ID_TA_LEN) // Buffer for ID input (matches TA's buffer def)
#define CA_NOTE_CONTENT_BUFFER_LEN (MAX_PLAINTEXT_CONTENT_BUFFER_LEN) // Buffer for content input

// Helper stuff
void initialize_tee_session(TEEC_Context *ctx, TEEC_Session *sess, const TEEC_UUID *uuid);
void terminate_tee_session(TEEC_Context *ctx, TEEC_Session *sess);
int get_user_input(const char *prompt, char *buffer, size_t buffer_size);
void handle_store_note(TEEC_Session *sess);
void handle_read_note(TEEC_Session *sess);
void handle_clear_note(TEEC_Session *sess);
void display_menu(void);

TEEC_Context teec_ctx;
TEEC_Session teec_sess;
const TEEC_UUID ta_uuid = TA_SECURE_NOTE_UUID;


void initialize_tee_session(TEEC_Context *ctx, TEEC_Session *sess, const TEEC_UUID *uuid) {
    TEEC_Result res;
    uint32_t err_origin;

    printf("Initializing TEE context...\n");
    res = TEEC_InitializeContext(NULL, ctx);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
    }

    printf("Opening session with TA UUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
           uuid->timeLow, uuid->timeMid, uuid->timeHiAndVersion,
           uuid->clockSeqAndNode[0], uuid->clockSeqAndNode[1],
           uuid->clockSeqAndNode[2], uuid->clockSeqAndNode[3],
           uuid->clockSeqAndNode[4], uuid->clockSeqAndNode[5],
           uuid->clockSeqAndNode[6], uuid->clockSeqAndNode[7]);

    res = TEEC_OpenSession(ctx, sess, uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        TEEC_FinalizeContext(ctx);
        errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x", res, err_origin);
    }
    printf("Session opened successfully.\n");
}

void terminate_tee_session(TEEC_Context *ctx, TEEC_Session *sess) {
    printf("Closing session...\n");
    TEEC_CloseSession(sess);
    printf("Finalizing TEE context...\n");
    TEEC_FinalizeContext(ctx);
}

int get_user_input(const char *prompt, char *buffer, size_t buffer_size) {
    char *ret_fgets;
    if (prompt) printf("%s", prompt);
    fflush(stdout);
    ret_fgets = fgets(buffer, buffer_size, stdin);
    if (ret_fgets == NULL) {
        if (feof(stdin)) {
            printf("\nEOF detected. Exiting.\n"); // Add newline for cleaner exit
            return -1;
        } else {
            perror("fgets failed");
            return -1;
        }
    }
    buffer[strcspn(buffer, "\n")] = 0; // Remove trailing newline
    // Check for overflow if newline wasn't read (buffer full)
    if (strchr(buffer, '\0') == &buffer[buffer_size - 1] && buffer[buffer_size -1] != '\0') {
        printf("Warning: Input too long and was truncated. Please try again with shorter input.\n");
        int c;
        while ((c = getchar()) != '\n' && c != EOF); // Clear rest of stdin line
        buffer[0] = '\0'; // Mark buffer as empty to force re-entry typically
        return 0; // Indicate truncation but allow retry
    }
    return 0;
}

void handle_store_note(TEEC_Session *sess) {
    char note_id[CA_NOTE_ID_BUFFER_LEN];
    char note_content[CA_NOTE_CONTENT_BUFFER_LEN];
    TEEC_Operation op = {0};
    TEEC_Result res;
    uint32_t err_origin;

    printf("Enter note ID (max %d chars): ", MAX_NOTE_ID_CHARS);
    if (get_user_input("", note_id, sizeof(note_id)) != 0) return;
    if (strlen(note_id) > MAX_NOTE_ID_CHARS) {
        printf("Error: Note ID too long. Max %d characters allowed.\n", MAX_NOTE_ID_CHARS);
        return;
    }
    if (strlen(note_id) == 0) {
        printf("Error: Note ID cannot be empty.\n");
        return;
    }

    printf("Enter note content (max %d chars): ", MAX_PLAINTEXT_CONTENT_CHARS);
    if (get_user_input("", note_content, sizeof(note_content)) != 0) return;
    if (strlen(note_content) > MAX_PLAINTEXT_CONTENT_CHARS) {
        printf("Error: Note content too long. Max %d characters allowed.\n", MAX_PLAINTEXT_CONTENT_CHARS);
        return;
    }
    // Storing an empty content string "" is allowed by the TA.

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, // Note ID
                                     TEEC_MEMREF_TEMP_INPUT, // Note Content
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = note_id;
    op.params[0].tmpref.size = strlen(note_id) + 1; // Send null-terminated string
    op.params[1].tmpref.buffer = note_content;
    op.params[1].tmpref.size = strlen(note_content) + 1; // Send null-terminated string

    printf("CA: Invoking CMD_STORE_NOTE for ID: '%s', Content len: %zu\n",
           note_id, strlen(note_content));
    res = TEEC_InvokeCommand(sess, CMD_STORE_NOTE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "CA: TEEC_InvokeCommand(CMD_STORE_NOTE) failed with code 0x%x origin 0x%x\n", res, err_origin);
    } else {
        printf("CA: Note '%s' store command sent successfully.\n", note_id);
    }
}

void handle_read_note(TEEC_Session *sess) {
    char note_id[CA_NOTE_ID_BUFFER_LEN];
    char received_plaintext[CA_NOTE_CONTENT_BUFFER_LEN]; // Buffer to receive plaintext
    TEEC_Operation op = {0};
    TEEC_Result res;
    uint32_t err_origin;

    printf("Enter note ID to read (max %d chars): ", MAX_NOTE_ID_CHARS);
    if (get_user_input("", note_id, sizeof(note_id)) != 0) return;
    if (strlen(note_id) > MAX_NOTE_ID_CHARS) {
        printf("Error: Note ID too long.\n");
        return;
    }
    if (strlen(note_id) == 0) {
        printf("Error: Note ID cannot be empty.\n");
        return;
    }

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,  // Note ID to read
                                     TEEC_MEMREF_TEMP_OUTPUT, // Buffer for note content
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = note_id;
    op.params[0].tmpref.size = strlen(note_id) + 1;
    op.params[1].tmpref.buffer = received_plaintext;
    op.params[1].tmpref.size = sizeof(received_plaintext); // CA tells TA max size it can receive

    printf("CA: Invoking CMD_READ_NOTE for ID: '%s'\n", note_id);
    res = TEEC_InvokeCommand(sess, CMD_READ_NOTE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "CA: TEEC_InvokeCommand(CMD_READ_NOTE) failed with code 0x%x origin 0x%x\n", res, err_origin);
        if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
             printf("CA: Note ID '%s' not found in secure storage.\n", note_id);
        } else if (res == TEEC_ERROR_SHORT_BUFFER) {
            fprintf(stderr, "CA: Buffer to receive note too small. TA requires buffer of size %u\n", op.params[1].tmpref.size);
        }
    } else {
        printf("CA: Secure Note (ID: '%s'): %s\n", note_id, received_plaintext);
    }
}

void handle_clear_note(TEEC_Session *sess) {
    char note_id[CA_NOTE_ID_BUFFER_LEN];
    TEEC_Operation op = {0};
    TEEC_Result res;
    uint32_t err_origin;

    printf("Enter note ID to delete (max %d chars): ", MAX_NOTE_ID_CHARS);
    if (get_user_input("", note_id, sizeof(note_id)) != 0) return;
    if (strlen(note_id) > MAX_NOTE_ID_CHARS) {
        printf("Error: Note ID too long.\n");
        return;
    }
    if (strlen(note_id) == 0) {
        printf("Error: Note ID cannot be empty.\n");
        return;
    }

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, // Note ID to delete
                                     TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = note_id;
    op.params[0].tmpref.size = strlen(note_id) + 1;

    printf("CA: Invoking CMD_CLEAR_NOTE for ID: '%s'\n", note_id);
    res = TEEC_InvokeCommand(sess, CMD_CLEAR_NOTE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "CA: TEEC_InvokeCommand(CMD_CLEAR_NOTE) failed with code 0x%x origin 0x%x\n", res, err_origin);
         if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
             printf("CA: Note ID '%s' not found for deletion.\n", note_id);
        }
    } else {
        printf("CA: Note '%s' delete command sent successfully.\n", note_id);
    }
}

void display_menu(void) {
    printf("\n--- Secure Note Storage Menu (AES Encrypted) ---\n");
    printf("1. Store a new note\n");
    printf("2. Read a note\n");
    printf("3. Delete a note\n");
    printf("4. Exit\n");
    printf("-----------------------------------------------\n");
}

int main(void) {
    char choice_buffer[MAX_USER_CHOICE_LEN];
    int choice = 0;

    initialize_tee_session(&teec_ctx, &teec_sess, &ta_uuid);

    while (1) {
        display_menu();
        if (get_user_input("Enter your choice: ", choice_buffer, sizeof(choice_buffer)) != 0) {
            break; // EOF or error
        }

        if (strlen(choice_buffer) == 1 && choice_buffer[0] >= '1' && choice_buffer[0] <= '4') {
            choice = atoi(choice_buffer); // Convert char to int
        } else {
            printf("Invalid choice '%s'. Please enter a number between 1 and 4.\n", choice_buffer);
            choice = 0; // Reset choice
            continue;
        }

        switch (choice) {
            case 1:
                handle_store_note(&teec_sess);
                break;
            case 2:
                handle_read_note(&teec_sess);
                break;
            case 3:
                handle_clear_note(&teec_sess);
                break;
            case 4:
                printf("Exiting...\n");
                terminate_tee_session(&teec_ctx, &teec_sess);
                return 0;
            default:
                // Should not be reached if input validation is correct
                printf("Invalid choice. Please try again.\n");
        }
        printf("\nPress Enter to continue...");
        get_user_input("", choice_buffer, sizeof(choice_buffer)); // Wait for user
    }

    terminate_tee_session(&teec_ctx, &teec_sess);
    printf("Program terminated.\n");
    return 0;
}