/*
 * Copyright (c) 2001-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MBEDTLS_SHA1_ALT_H
#define MBEDTLS_SHA1_ALT_H

#include <stddef.h>
#include <stdint.h>

#include "cc_hash_defs_proj.h"

#include "mbedtls/build_info.h"

#define MBEDTLS_ERR_SHA1_HW_ACCEL_FAILED                  -0x0035  /**< SHA-1 hardware accelerator failed */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SHA-1 context structure
 */
typedef struct mbedtls_sha1_context {
        /*! Internal buffer */
        uint32_t buff[CC_HASH_USER_CTX_SIZE_IN_WORDS]; // defined in cc_hash_defs_proj.h
} mbedtls_sha1_context;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_SHA1_ALT_H */
