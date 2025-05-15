/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef SECURE_NOTE_TA_H
#define SECURE_NOTE_TA_H

#define TA_SECURE_NOTE_UUID \
    { 0x12345678, 0x1234, 0x1234, \
      { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef } }

#define CMD_STORE_NOTE       0
#define CMD_READ_NOTE        1
#define CMD_CLEAR_NOTE       2

/* Maximum length of a note ID string (excluding null terminator) */
#define MAX_NOTE_ID_CHARS 31
/* Buffer size in TA for ID (MAX_NOTE_ID_CHARS + 1 for null terminator) */
#define MAX_NOTE_ID_TA_LEN (MAX_NOTE_ID_CHARS + 1)

/* Maximum length of PLAINTEXT note content (excluding null terminator) */
#define MAX_PLAINTEXT_CONTENT_CHARS 200
/* Buffer size in TA/CA for plaintext content (MAX_PLAINTEXT_CONTENT_CHARS + 1 for null) */
#define MAX_PLAINTEXT_CONTENT_BUFFER_LEN (MAX_PLAINTEXT_CONTENT_CHARS + 1)

/* AES Configuration (relevant for TA's internal storage calculations) */
#define AES_BLOCK_SIZE 16  /* Bytes */
#define IV_SIZE AES_BLOCK_SIZE /* Bytes */

/* Max length of ciphertext after PKCS#7 padding.
 * Plaintext can expand by up to (AES_BLOCK_SIZE - 1) bytes, or by AES_BLOCK_SIZE if already block aligned.
 */
#define MAX_CIPHERTEXT_PADDED_LEN (MAX_PLAINTEXT_CONTENT_CHARS + AES_BLOCK_SIZE)

/* Total buffer size in TA to store [IV (16 bytes)][Padded Ciphertext] */
#define MAX_NOTE_STORAGE_BUFFER_TA_LEN (IV_SIZE + MAX_CIPHERTEXT_PADDED_LEN)

#endif