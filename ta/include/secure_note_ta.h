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

// Define max SIZES for buffers in TA (including space for null terminator)
#define MAX_NOTE_ID_TA_LEN 32       // Allows for IDs up to 31 chars + null
#define MAX_PLAINTEXT_NOTE_TA_LEN 201 // Allows for content up to 200 chars + null

#endif /* SECURE_NOTE_TA_H */
