/*
 *  PSA crypto driver wrapper function declarations
 */
/*  Copyright (C) 2020, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef PSA_CRYPTO_DRIVER_WRAPPERS_H
#define PSA_CRYPTO_DRIVER_WRAPPERS_H

#include "psa/crypto_driver_common.h"

psa_status_t psa_driver_wrapper_sign_hash( psa_key_slot_t *slot,
                                           psa_algorithm_t alg,
                                           const uint8_t *hash,
                                           size_t hash_length,
                                           uint8_t *signature,
                                           size_t signature_size,
                                           size_t *signature_length );

#endif /* PSA_CRYPTO_DRIVER_WRAPPERS_H */
