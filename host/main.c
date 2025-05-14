#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>

#include <tee_client_api.h>
#include "secure_note_ta.h"

// Define a maximum size for notes and IDs for buffer safety
#define MAX_USER_INPUT_LEN 256
#define MAX_NOTE_ID_LEN 32
#define MAX_NOTE_CONTENT_LEN 200

void initialize_tee_session(TEEC_Context *ctx, TEEC_Session *sess, const TEEC_UUID *uuid);
void terminate_tee_session(TEEC_Context *ctx, TEEC_Session *sess);
void handle_store_note(TEEC_Session *sess);
void handle_read_note(TEEC_Session *sess);
void handle_clear_note(TEEC_Session *sess);
void display_menu(void);
// int handle_authenticate_pin(TEEC_Session *sess);

TEEC_Context teec_ctx;
TEEC_Session teec_sess;
const TEEC_UUID ta_uuid = TA_SECURE_NOTE_UUID;
// bool is_authenticated = false;


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
        // Clean up context if session open fails
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

// Gets a line of input from the user, handling potential overflows.
// Returns 0 on success, -1 on error or EOF.
int get_user_input(const char *prompt, char *buffer, size_t buffer_size) {
    char *ret_fgets;
    printf("%s", prompt);
    fflush(stdout);
    ret_fgets = fgets(buffer, buffer_size, stdin);
    if (ret_fgets == NULL) {
        if (feof(stdin)) {
            printf("EOF detected. Exiting.\n");
            return -1; // EOF
        } else {
            perror("fgets failed");
            return -1; // Error
        }
    }

    // Remove trailing newline, if any
    buffer[strcspn(buffer, "\n")] = 0;

    // Check for overflow if newline was not read
    if (strchr(buffer, '\n') == NULL && strlen(buffer) == buffer_size - 1) {
        printf("Warning: Input too long and was truncated.\n");
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
    }
    return 0;
}


void handle_store_note(TEEC_Session *sess) {
    char note_id[MAX_NOTE_ID_LEN];
    char note_content[MAX_NOTE_CONTENT_LEN];
    TEEC_Operation op = {0};
    TEEC_Result res;
    uint32_t err_origin;

    if (get_user_input("Enter note ID (max 31 chars): ", note_id, sizeof(note_id)) != 0) return;
    if (get_user_input("Enter note content (max 199 chars): ", note_content, sizeof(note_content)) != 0) return;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = note_id;
    op.params[0].tmpref.size = strlen(note_id) + 1;
    op.params[1].tmpref.buffer = note_content;
    op.params[1].tmpref.size = strlen(note_content) + 1;

    printf("Invoking CMD_STORE_NOTE for ID: %s\n", note_id);
    res = TEEC_InvokeCommand(sess, CMD_STORE_NOTE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TEEC_InvokeCommand(CMD_STORE_NOTE) failed with code 0x%x origin 0x%x\n", res, err_origin);
    } else {
        printf("Note '%s' store command sent.\n", note_id);
    }
}

void handle_read_note(TEEC_Session *sess) {
    char note_id[MAX_NOTE_ID_LEN];
    char received_content[MAX_NOTE_CONTENT_LEN + 64];
    TEEC_Operation op = {0};
    TEEC_Result res;
    uint32_t err_origin;

    if (get_user_input("Enter note ID to read: ", note_id, sizeof(note_id)) != 0) return;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = note_id;
    op.params[0].tmpref.size = strlen(note_id) + 1;
    op.params[1].tmpref.buffer = received_content;
    op.params[1].tmpref.size = sizeof(received_content);

    printf("Invoking CMD_READ_NOTE for ID: %s\n", note_id);
    res = TEEC_InvokeCommand(sess, CMD_READ_NOTE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TEEC_InvokeCommand(CMD_READ_NOTE) failed with code 0x%x origin 0x%x\n", res, err_origin);
        if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
             printf("Note ID '%s' not found in secure storage.\n", note_id);
        }
    } else {
        // op.params[1].tmpref.size will contain the actual size written by TA
        received_content[op.params[1].tmpref.size] = '\0';
        printf("Secure Note (ID: %s): %s\n", note_id, received_content);
    }
}

void handle_clear_note(TEEC_Session *sess) {
    char note_id[MAX_NOTE_ID_LEN];
    TEEC_Operation op = {0};
    TEEC_Result res;
    uint32_t err_origin;

    if (get_user_input("Enter note ID to delete: ", note_id, sizeof(note_id)) != 0) return;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = note_id;
    op.params[0].tmpref.size = strlen(note_id) + 1;

    printf("Invoking CMD_CLEAR_NOTE for ID: %s\n", note_id);
    res = TEEC_InvokeCommand(sess, CMD_CLEAR_NOTE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TEEC_InvokeCommand(CMD_CLEAR_NOTE) failed with code 0x%x origin 0x%x\n", res, err_origin);
    } else {
        printf("Note '%s' delete command sent.\n", note_id);
    }
}

void display_menu(void) {
    printf("\n--- Secure Note Storage Menu ---\n");
    // if (!is_authenticated) {
    //     printf("P. Enter PIN\n");
    // } else {
        printf("1. Store a new note\n");
        printf("2. Read a note\n");
        printf("3. Delete a note\n");
    // }
    printf("4. Exit\n");
    printf("---------------------------------\n");
    printf("Enter your choice: ");
}


int main(void) {
    char choice_buffer[MAX_USER_INPUT_LEN];
    int choice = 0;

    initialize_tee_session(&teec_ctx, &teec_sess, &ta_uuid);

    // is_authenticated = handle_authenticate_pin(&teec_sess);
    // if (!is_authenticated) {
    //     printf("Authentication failed. Exiting.\n");
    //     terminate_tee_session(&teec_ctx, &teec_sess);
    //     return 1;
    // }
    // printf("PIN Authentication successful.\n");


    while (1) {
        display_menu();
        if (get_user_input("", choice_buffer, sizeof(choice_buffer)) != 0) {
            // EOF or error from get_user_input
            break;
        }

        // Basic input validation for choice
        if (strlen(choice_buffer) == 1 && choice_buffer[0] >= '1' && choice_buffer[0] <= '4') {
            choice = choice_buffer[0] - '0';
        } else {
            // Could also handle 'P' for PIN if implementing that menu option
            printf("Invalid choice. Please try again.\n");
            continue;
        }

        // if (!is_authenticated && choice != 'P' - '0' && choice != 4) {
        //     printf("Please authenticate with PIN first.\n");
        //     continue;
        // }

        switch (choice) {
            // case 'P' - '0': // If using 'P' for PIN
            //     is_authenticated = handle_authenticate_pin(&teec_sess);
            //     if (is_authenticated) printf("PIN Authentication successful.\n");
            //     else printf("PIN Authentication failed.\n");
            //     break;
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
                printf("Invalid choice. Please try again.\n");
        }
    }

    terminate_tee_session(&teec_ctx, &teec_sess);
    return 0;
}
