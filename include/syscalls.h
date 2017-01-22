/*******************************************************************************
*   Ledger Blue - Secure firmware
*   (c) 2016, 2017 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

/* MACHINE GENERATED: DO NOT MODIFY */
#ifndef SYSCALL_DEFS_H
#define SYSCALL_DEFS_H

#define EXC_RETURN_THREAD_PSP 0xFFFFFFFD
#define EXC_RETURN_THREAD_MSP 0xFFFFFFF9
#define EXC_RETURN_HANDLER_MSP 0xFFFFFFF1

// called when entering the SVC Handler C
void syscall_enter(unsigned int syscall_id, unsigned int entry_lr);
void syscall_exit(void);

unsigned int syscall_check_app_address(unsigned int *parameters,
                                       unsigned int checked_idx,
                                       unsigned int checked_length);
unsigned int syscall_check_app_flags(unsigned int flags);

void os_sched_hold_r4_r11(void);
void os_sched_restore_r4_r11(void);
void os_sched_task_save_current(void);

#define SYSCALL_check_api_level_ID_IN 0x60000137UL
#define SYSCALL_check_api_level_ID_OUT 0x900001c6UL
void check_api_level(unsigned int apiLevel);

#define SYSCALL_reset_ID_IN 0x60000200UL
#define SYSCALL_reset_ID_OUT 0x900002f1UL
void reset(void);

#define SYSCALL_nvm_write_ID_IN 0x6000037fUL
#define SYSCALL_nvm_write_ID_OUT 0x900003bcUL
void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len);

#define SYSCALL_cx_rng_u8_ID_IN 0x600004c0UL
#define SYSCALL_cx_rng_u8_ID_OUT 0x90000425UL
unsigned char cx_rng_u8(void);

#define SYSCALL_cx_rng_ID_IN 0x6000052cUL
#define SYSCALL_cx_rng_ID_OUT 0x90000567UL
unsigned char *cx_rng(unsigned char *buffer, unsigned int len);

#define SYSCALL_cx_ripemd160_init_ID_IN 0x6000067fUL
#define SYSCALL_cx_ripemd160_init_ID_OUT 0x900006f8UL
int cx_ripemd160_init(cx_ripemd160_t *hash);

#define SYSCALL_cx_sha224_init_ID_IN 0x6000075bUL
#define SYSCALL_cx_sha224_init_ID_OUT 0x9000071dUL
int cx_sha224_init(cx_sha256_t *hash);

#define SYSCALL_cx_sha256_init_ID_IN 0x600008dbUL
#define SYSCALL_cx_sha256_init_ID_OUT 0x90000864UL
int cx_sha256_init(cx_sha256_t *hash);

#define SYSCALL_cx_sha384_init_ID_IN 0x6000092bUL
#define SYSCALL_cx_sha384_init_ID_OUT 0x900009afUL
int cx_sha384_init(cx_sha512_t *hash);

#define SYSCALL_cx_sha512_init_ID_IN 0x60000ac1UL
#define SYSCALL_cx_sha512_init_ID_OUT 0x90000aeeUL
int cx_sha512_init(cx_sha512_t *hash);

#define SYSCALL_cx_sha3_init_ID_IN 0x60000b0eUL
#define SYSCALL_cx_sha3_init_ID_OUT 0x90000b59UL
int cx_sha3_init(cx_sha3_t *hash, int size);

#define SYSCALL_cx_keccak_init_ID_IN 0x60000c3cUL
#define SYSCALL_cx_keccak_init_ID_OUT 0x90000c39UL
int cx_keccak_init(cx_sha3_t *hash, int size);

#define SYSCALL_cx_sha3_xof_init_ID_IN 0x60000d40UL
#define SYSCALL_cx_sha3_xof_init_ID_OUT 0x90000de0UL
int cx_sha3_xof_init(cx_sha3_t *hash, unsigned int size,
                     unsigned int out_length);

#define SYSCALL_cx_hash_ID_IN 0x60000ea6UL
#define SYSCALL_cx_hash_ID_OUT 0x90000e46UL
int cx_hash(cx_hash_t *hash, int mode, unsigned char *in, unsigned int len,
            unsigned char *out);

#define SYSCALL_cx_hash_sha256_ID_IN 0x60000f27UL
#define SYSCALL_cx_hash_sha256_ID_OUT 0x90000f1eUL
int cx_hash_sha256(unsigned char *in, unsigned int len, unsigned char *out);

#define SYSCALL_cx_hash_sha512_ID_IN 0x6000108bUL
#define SYSCALL_cx_hash_sha512_ID_OUT 0x900010dfUL
int cx_hash_sha512(unsigned char *in, unsigned int len, unsigned char *out);

#define SYSCALL_cx_hmac_ripemd160_init_ID_IN 0x600011c2UL
#define SYSCALL_cx_hmac_ripemd160_init_ID_OUT 0x90001158UL
int cx_hmac_ripemd160_init(cx_hmac_ripemd160_t *hmac, unsigned char *key,
                           unsigned int key_len);

#define SYSCALL_cx_hmac_sha256_init_ID_IN 0x6000128bUL
#define SYSCALL_cx_hmac_sha256_init_ID_OUT 0x900012ceUL
int cx_hmac_sha256_init(cx_hmac_sha256_t *hmac, unsigned char *key,
                        unsigned int key_len);

#define SYSCALL_cx_hmac_sha512_init_ID_IN 0x600013fcUL
#define SYSCALL_cx_hmac_sha512_init_ID_OUT 0x9000130eUL
int cx_hmac_sha512_init(cx_hmac_sha512_t *hmac, unsigned char *key,
                        unsigned int key_len);

#define SYSCALL_cx_hmac_ID_IN 0x60001477UL
#define SYSCALL_cx_hmac_ID_OUT 0x9000146cUL
int cx_hmac(cx_hmac_t *hmac, int mode, unsigned char *in, unsigned int len,
            unsigned char *mac);

#define SYSCALL_cx_hmac_sha512_ID_IN 0x6000151bUL
#define SYSCALL_cx_hmac_sha512_ID_OUT 0x900015ecUL
int cx_hmac_sha512(unsigned char *key, unsigned int key_len, unsigned char *in,
                   unsigned int len, unsigned char *out);

#define SYSCALL_cx_hmac_sha256_ID_IN 0x60001668UL
#define SYSCALL_cx_hmac_sha256_ID_OUT 0x90001621UL
int cx_hmac_sha256(unsigned char *key, unsigned int key_len, unsigned char *in,
                   unsigned int len, unsigned char *out);

#define SYSCALL_cx_pbkdf2_sha512_ID_IN 0x60001790UL
#define SYSCALL_cx_pbkdf2_sha512_ID_OUT 0x9000179dUL
void cx_pbkdf2_sha512(unsigned char *password, unsigned short passwordlen,
                      unsigned char *salt, unsigned short saltlen,
                      unsigned int iterations, unsigned char *out,
                      unsigned int outLength);

#define SYSCALL_cx_des_init_key_ID_IN 0x600018c3UL
#define SYSCALL_cx_des_init_key_ID_OUT 0x900018efUL
int cx_des_init_key(unsigned char *rawkey, unsigned int key_len,
                    cx_des_key_t *key);

#define SYSCALL_cx_des_iv_ID_IN 0x60001901UL
#define SYSCALL_cx_des_iv_ID_OUT 0x900019b7UL
int cx_des_iv(cx_des_key_t *key, int mode, unsigned char *iv, unsigned char *in,
              unsigned int len, unsigned char *out);

#define SYSCALL_cx_des_ID_IN 0x60001a34UL
#define SYSCALL_cx_des_ID_OUT 0x90001acdUL
int cx_des(cx_des_key_t *key, int mode, unsigned char *in, unsigned int len,
           unsigned char *out);

#define SYSCALL_cx_aes_init_key_ID_IN 0x60001b66UL
#define SYSCALL_cx_aes_init_key_ID_OUT 0x90001b26UL
int cx_aes_init_key(unsigned char *rawkey, unsigned int key_len,
                    cx_aes_key_t *key);

#define SYSCALL_cx_aes_iv_ID_IN 0x60001cabUL
#define SYSCALL_cx_aes_iv_ID_OUT 0x90001c0bUL
int cx_aes_iv(cx_aes_key_t *key, int mode, unsigned char *iv, unsigned char *in,
              unsigned int len, unsigned char *out);

#define SYSCALL_cx_aes_ID_IN 0x60001d21UL
#define SYSCALL_cx_aes_ID_OUT 0x90001d6aUL
int cx_aes(cx_aes_key_t *key, int mode, unsigned char *in, unsigned int len,
           unsigned char *out);

#define SYSCALL_cx_rsa_init_public_key_ID_IN 0x60001e0fUL
#define SYSCALL_cx_rsa_init_public_key_ID_OUT 0x90001e7aUL
int cx_rsa_init_public_key(unsigned char *exponent, unsigned char *modulus,
                           unsigned int modulus_len, cx_rsa_public_key_t *key);

#define SYSCALL_cx_rsa_init_private_key_ID_IN 0x60001f12UL
#define SYSCALL_cx_rsa_init_private_key_ID_OUT 0x90001fb0UL
int cx_rsa_init_private_key(unsigned char *exponent, unsigned char *modulus,
                            unsigned int modulus_len,
                            cx_rsa_private_key_t *key);

#define SYSCALL_cx_rsa_generate_pair_ID_IN 0x60002062UL
#define SYSCALL_cx_rsa_generate_pair_ID_OUT 0x90002076UL
int cx_rsa_generate_pair(unsigned int modulus_len,
                         cx_rsa_public_key_t *public_key,
                         cx_rsa_private_key_t *private_key,
                         unsigned long int pub_exponent,
                         unsigned char *externalPQ);

#define SYSCALL_cx_rsa_sign_ID_IN 0x6000212dUL
#define SYSCALL_cx_rsa_sign_ID_OUT 0x900021c8UL
int cx_rsa_sign(cx_rsa_private_key_t *key, int mode, cx_md_t hashID,
                unsigned char *hash, unsigned int hash_len, unsigned char *sig,
                unsigned int sig_len);

#define SYSCALL_cx_rsa_verify_ID_IN 0x60002210UL
#define SYSCALL_cx_rsa_verify_ID_OUT 0x9000228cUL
int cx_rsa_verify(cx_rsa_public_key_t *key, int mode, cx_md_t hashID,
                  unsigned char *hash, unsigned int hash_len,
                  unsigned char *sig, unsigned int sig_len);

#define SYSCALL_cx_rsa_encrypt_ID_IN 0x60002328UL
#define SYSCALL_cx_rsa_encrypt_ID_OUT 0x90002392UL
int cx_rsa_encrypt(cx_rsa_public_key_t *key, int mode, cx_md_t hashID,
                   unsigned char *mesg, unsigned int mesg_len,
                   unsigned char *enc, unsigned int enc_len);

#define SYSCALL_cx_rsa_decrypt_ID_IN 0x60002426UL
#define SYSCALL_cx_rsa_decrypt_ID_OUT 0x900024a1UL
int cx_rsa_decrypt(cx_rsa_private_key_t *key, int mode, cx_md_t hashID,
                   unsigned char *mesg, unsigned int mesg_len,
                   unsigned char *dec, unsigned int dec_len);

#define SYSCALL_cx_ecfp_is_valid_point_ID_IN 0x60002510UL
#define SYSCALL_cx_ecfp_is_valid_point_ID_OUT 0x90002555UL
int cx_ecfp_is_valid_point(cx_curve_t curve, unsigned char *point);

#define SYSCALL_cx_ecfp_add_point_ID_IN 0x6000262aUL
#define SYSCALL_cx_ecfp_add_point_ID_OUT 0x9000261bUL
int cx_ecfp_add_point(cx_curve_t curve, unsigned char *R, unsigned char *P,
                      unsigned char *Q);

#define SYSCALL_cx_ecfp_scalar_mult_ID_IN 0x6000277bUL
#define SYSCALL_cx_ecfp_scalar_mult_ID_OUT 0x9000273fUL
int cx_ecfp_scalar_mult(cx_curve_t curve, unsigned char *P, unsigned char *k,
                        unsigned int k_len);

#define SYSCALL_cx_ecfp_init_public_key_ID_IN 0x60002835UL
#define SYSCALL_cx_ecfp_init_public_key_ID_OUT 0x900028f0UL
int cx_ecfp_init_public_key(cx_curve_t curve, unsigned char *rawkey,
                            unsigned int key_len, cx_ecfp_public_key_t *key);

#define SYSCALL_cx_ecfp_init_private_key_ID_IN 0x600029edUL
#define SYSCALL_cx_ecfp_init_private_key_ID_OUT 0x900029aeUL
int cx_ecfp_init_private_key(cx_curve_t curve, unsigned char *rawkey,
                             unsigned int key_len, cx_ecfp_private_key_t *key);

#define SYSCALL_cx_ecfp_generate_pair_ID_IN 0x60002a2eUL
#define SYSCALL_cx_ecfp_generate_pair_ID_OUT 0x90002a74UL
int cx_ecfp_generate_pair(cx_curve_t curve, cx_ecfp_public_key_t *pubkey,
                          cx_ecfp_private_key_t *privkey, int keepprivate);

#define SYSCALL_cx_borromean_sign_ID_IN 0x60002b17UL
#define SYSCALL_cx_borromean_sign_ID_OUT 0x90002bffUL
int cx_borromean_sign(cx_ecfp_private_key_t **privkeys,
                      cx_ecfp_public_key_t **pubkeys, unsigned int *rsizes,
                      unsigned int *pv_keys_index, unsigned int rcount,
                      unsigned int mode, cx_md_t hashID, unsigned char *msg,
                      unsigned int msg_len, unsigned char *sig);

#define SYSCALL_cx_borromean_verify_ID_IN 0x60002c08UL
#define SYSCALL_cx_borromean_verify_ID_OUT 0x90002c44UL
int cx_borromean_verify(cx_ecfp_public_key_t **pubkeys, unsigned int *rsizes,
                        unsigned int rcount, int mode, cx_md_t hashID,
                        unsigned char *msg, unsigned int msg_len,
                        unsigned char *sig, unsigned int sig_len);

#define SYSCALL_cx_ecschnorr_sign_ID_IN 0x60002d5eUL
#define SYSCALL_cx_ecschnorr_sign_ID_OUT 0x90002dcbUL
int cx_ecschnorr_sign(cx_ecfp_private_key_t *pvkey, int mode, cx_md_t hashID,
                      unsigned char *msg, unsigned int msg_len,
                      unsigned char *sig);

#define SYSCALL_cx_ecschnorr_verify_ID_IN 0x60002ef2UL
#define SYSCALL_cx_ecschnorr_verify_ID_OUT 0x90002e73UL
int cx_ecschnorr_verify(cx_ecfp_public_key_t *pukey, int mode, cx_md_t hashID,
                        unsigned char *msg, unsigned int msg_len,
                        unsigned char *sig, unsigned int sig_len);

#define SYSCALL_cx_edward_compress_point_ID_IN 0x60002fecUL
#define SYSCALL_cx_edward_compress_point_ID_OUT 0x90002f26UL
void cx_edward_compress_point(cx_curve_t curve, unsigned char *P);

#define SYSCALL_cx_edward_decompress_point_ID_IN 0x6000308eUL
#define SYSCALL_cx_edward_decompress_point_ID_OUT 0x9000307dUL
void cx_edward_decompress_point(cx_curve_t curve, unsigned char *P);

#define SYSCALL_cx_eddsa_sign_ID_IN 0x6000315dUL
#define SYSCALL_cx_eddsa_sign_ID_OUT 0x9000315eUL
int cx_eddsa_sign(cx_ecfp_private_key_t *pvkey, cx_ecfp_public_key_t *pukey,
                  int mode, cx_md_t hashID, unsigned char *hash,
                  unsigned int hash_len, unsigned char *sig);

#define SYSCALL_cx_eddsa_verify_ID_IN 0x6000329dUL
#define SYSCALL_cx_eddsa_verify_ID_OUT 0x900032bbUL
int cx_eddsa_verify(cx_ecfp_public_key_t *key, int mode, cx_md_t hashID,
                    unsigned char *hash, unsigned int hash_len,
                    unsigned char *sig, unsigned int sig_len);

#define SYSCALL_cx_ecdsa_sign_ID_IN 0x60003301UL
#define SYSCALL_cx_ecdsa_sign_ID_OUT 0x900033f3UL
int cx_ecdsa_sign(cx_ecfp_private_key_t *key, int mode, cx_md_t hashID,
                  unsigned char *hash, unsigned int hash_len,
                  unsigned char *sig);

#define SYSCALL_cx_ecdsa_verify_ID_IN 0x6000343eUL
#define SYSCALL_cx_ecdsa_verify_ID_OUT 0x9000348fUL
int cx_ecdsa_verify(cx_ecfp_public_key_t *key, int mode, cx_md_t hashID,
                    unsigned char *hash, unsigned int hash_len,
                    unsigned char *sig, unsigned int sig_len);

#define SYSCALL_cx_ecdh_ID_IN 0x60003516UL
#define SYSCALL_cx_ecdh_ID_OUT 0x90003561UL
int cx_ecdh(cx_ecfp_private_key_t *key, int mode, unsigned char *public_point,
            unsigned char *secret);

#define SYSCALL_cx_crc16_ID_IN 0x60003637UL
#define SYSCALL_cx_crc16_ID_OUT 0x90003695UL
unsigned short cx_crc16(void *buffer, unsigned int len);

#define SYSCALL_cx_crc16_update_ID_IN 0x600037f4UL
#define SYSCALL_cx_crc16_update_ID_OUT 0x9000377fUL
unsigned short cx_crc16_update(unsigned short crc, void *buffer,
                               unsigned int len);

#define SYSCALL_cx_math_cmp_ID_IN 0x60003873UL
#define SYSCALL_cx_math_cmp_ID_OUT 0x9000388aUL
int cx_math_cmp(unsigned char *a, unsigned char *b, unsigned int len);

#define SYSCALL_cx_math_is_zero_ID_IN 0x60003991UL
#define SYSCALL_cx_math_is_zero_ID_OUT 0x90003923UL
int cx_math_is_zero(unsigned char *a, unsigned int len);

#define SYSCALL_cx_math_add_ID_IN 0x60003a50UL
#define SYSCALL_cx_math_add_ID_OUT 0x90003a68UL
int cx_math_add(unsigned char *r, unsigned char *a, unsigned char *b,
                unsigned int len);

#define SYSCALL_cx_math_sub_ID_IN 0x60003b37UL
#define SYSCALL_cx_math_sub_ID_OUT 0x90003bf2UL
int cx_math_sub(unsigned char *r, unsigned char *a, unsigned char *b,
                unsigned int len);

#define SYSCALL_cx_math_mult_ID_IN 0x60003ce1UL
#define SYSCALL_cx_math_mult_ID_OUT 0x90003c67UL
void cx_math_mult(unsigned char *r, unsigned char *a, unsigned char *b,
                  unsigned int len);

#define SYSCALL_cx_math_addm_ID_IN 0x60003dddUL
#define SYSCALL_cx_math_addm_ID_OUT 0x90003d05UL
void cx_math_addm(unsigned char *r, unsigned char *a, unsigned char *b,
                  unsigned char *m, unsigned int len);

#define SYSCALL_cx_math_subm_ID_IN 0x60003e32UL
#define SYSCALL_cx_math_subm_ID_OUT 0x90003e69UL
void cx_math_subm(unsigned char *r, unsigned char *a, unsigned char *b,
                  unsigned char *m, unsigned int len);

#define SYSCALL_cx_math_multm_ID_IN 0x60003f24UL
#define SYSCALL_cx_math_multm_ID_OUT 0x90003fc2UL
void cx_math_multm(unsigned char *r, unsigned char *a, unsigned char *b,
                   unsigned char *m, unsigned int len);

#define SYSCALL_cx_math_powm_ID_IN 0x600040adUL
#define SYSCALL_cx_math_powm_ID_OUT 0x90004064UL
void cx_math_powm(unsigned char *r, unsigned char *a, unsigned char *e,
                  unsigned int len_e, unsigned char *m, unsigned int len);

#define SYSCALL_cx_math_modm_ID_IN 0x600041b0UL
#define SYSCALL_cx_math_modm_ID_OUT 0x9000419cUL
void cx_math_modm(unsigned char *v, unsigned int len_v, unsigned char *m,
                  unsigned int len_m);

#define SYSCALL_cx_math_invprimem_ID_IN 0x6000425dUL
#define SYSCALL_cx_math_invprimem_ID_OUT 0x90004278UL
void cx_math_invprimem(unsigned char *r, unsigned char *a, unsigned char *m,
                       unsigned int len);

#define SYSCALL_cx_math_invintm_ID_IN 0x600043ebUL
#define SYSCALL_cx_math_invintm_ID_OUT 0x900043c1UL
void cx_math_invintm(unsigned char *r, unsigned long int a, unsigned char *m,
                     unsigned int len);

#define SYSCALL_cx_math_is_prime_ID_IN 0x60004495UL
#define SYSCALL_cx_math_is_prime_ID_OUT 0x9000445eUL
int cx_math_is_prime(unsigned char *p, unsigned int len);

#define SYSCALL_cx_math_next_prime_ID_IN 0x600045a4UL
#define SYSCALL_cx_math_next_prime_ID_OUT 0x900045cbUL
void cx_math_next_prime(unsigned char *n, unsigned int len);

#define SYSCALL_os_perso_wipe_ID_IN 0x6000462aUL
#define SYSCALL_os_perso_wipe_ID_OUT 0x90004645UL
void os_perso_wipe(void);

#define SYSCALL_os_perso_set_pin_ID_IN 0x600047ccUL
#define SYSCALL_os_perso_set_pin_ID_OUT 0x900047dfUL
void os_perso_set_pin(unsigned char *pin, unsigned int length);

#define SYSCALL_os_perso_set_seed_ID_IN 0x60004829UL
#define SYSCALL_os_perso_set_seed_ID_OUT 0x90004840UL
void os_perso_set_seed(unsigned int algorithm, unsigned char *seed,
                       unsigned int length);

#define SYSCALL_os_perso_set_alternate_pin_ID_IN 0x600049e2UL
#define SYSCALL_os_perso_set_alternate_pin_ID_OUT 0x90004987UL
void os_perso_set_alternate_pin(unsigned char *pin, unsigned int pinLength);

#define SYSCALL_os_perso_set_alternate_seed_ID_IN 0x60004a8fUL
#define SYSCALL_os_perso_set_alternate_seed_ID_OUT 0x90004aa8UL
void os_perso_set_alternate_seed(unsigned char *seed, unsigned int seedLength);

#define SYSCALL_os_perso_set_words_ID_IN 0x60004b3dUL
#define SYSCALL_os_perso_set_words_ID_OUT 0x90004b8cUL
void os_perso_set_words(unsigned char *words, unsigned int length);

#define SYSCALL_os_perso_set_devname_ID_IN 0x60004c7bUL
#define SYSCALL_os_perso_set_devname_ID_OUT 0x90004cbeUL
void os_perso_set_devname(unsigned char *devname, unsigned int length);

#define SYSCALL_os_perso_finalize_ID_IN 0x60004d80UL
#define SYSCALL_os_perso_finalize_ID_OUT 0x90004d54UL
void os_perso_finalize(void);

#define SYSCALL_os_perso_isonboarded_ID_IN 0x60004e9aUL
#define SYSCALL_os_perso_isonboarded_ID_OUT 0x90004ed5UL
unsigned int os_perso_isonboarded(void);

#define SYSCALL_os_perso_get_devname_ID_IN 0x60004f22UL
#define SYSCALL_os_perso_get_devname_ID_OUT 0x90004fc8UL
unsigned int os_perso_get_devname(unsigned char *devname, unsigned int length);

#define SYSCALL_os_perso_derive_node_bip32_ID_IN 0x6000502bUL
#define SYSCALL_os_perso_derive_node_bip32_ID_OUT 0x9000507fUL
void os_perso_derive_node_bip32(cx_curve_t curve, unsigned int *path,
                                unsigned int pathLength,
                                unsigned char *privateKey,
                                unsigned char *chain);

#define SYSCALL_os_endorsement_get_code_hash_ID_IN 0x6000510fUL
#define SYSCALL_os_endorsement_get_code_hash_ID_OUT 0x900051a1UL
unsigned int os_endorsement_get_code_hash(unsigned char *buffer);

#define SYSCALL_os_endorsement_get_public_key_ID_IN 0x600052f3UL
#define SYSCALL_os_endorsement_get_public_key_ID_OUT 0x90005299UL
unsigned int os_endorsement_get_public_key(unsigned char index,
                                           unsigned char *buffer);

#define SYSCALL_os_endorsement_get_public_key_certificate_ID_IN 0x6000534cUL
#define SYSCALL_os_endorsement_get_public_key_certificate_ID_OUT 0x9000537fUL
unsigned int os_endorsement_get_public_key_certificate(unsigned char index,
                                                       unsigned char *buffer);

#define SYSCALL_os_endorsement_key1_get_app_secret_ID_IN 0x6000545cUL
#define SYSCALL_os_endorsement_key1_get_app_secret_ID_OUT 0x90005460UL
unsigned int os_endorsement_key1_get_app_secret(unsigned char *buffer);

#define SYSCALL_os_endorsement_key1_sign_data_ID_IN 0x600055d8UL
#define SYSCALL_os_endorsement_key1_sign_data_ID_OUT 0x9000552bUL
unsigned int os_endorsement_key1_sign_data(unsigned char *src,
                                           unsigned int srcLength,
                                           unsigned char *signature);

#define SYSCALL_os_endorsement_key2_derive_sign_data_ID_IN 0x6000564aUL
#define SYSCALL_os_endorsement_key2_derive_sign_data_ID_OUT 0x9000563eUL
unsigned int os_endorsement_key2_derive_sign_data(unsigned char *src,
                                                  unsigned int srcLength,
                                                  unsigned char *signature);

#define SYSCALL_os_global_pin_is_validated_ID_IN 0x60005789UL
#define SYSCALL_os_global_pin_is_validated_ID_OUT 0x90005745UL
unsigned int os_global_pin_is_validated(void);

#define SYSCALL_os_global_pin_check_ID_IN 0x6000586fUL
#define SYSCALL_os_global_pin_check_ID_OUT 0x9000581eUL
unsigned int os_global_pin_check(unsigned char *pin_buffer,
                                 unsigned char pin_length);

#define SYSCALL_os_global_pin_invalidate_ID_IN 0x600059d0UL
#define SYSCALL_os_global_pin_invalidate_ID_OUT 0x900059fbUL
void os_global_pin_invalidate(void);

#define SYSCALL_os_global_pin_retries_ID_IN 0x60005a59UL
#define SYSCALL_os_global_pin_retries_ID_OUT 0x90005a18UL
unsigned int os_global_pin_retries(void);

#define SYSCALL_os_registry_count_ID_IN 0x60005b40UL
#define SYSCALL_os_registry_count_ID_OUT 0x90005b06UL
unsigned int os_registry_count(void);

#define SYSCALL_os_registry_get_ID_IN 0x60005c65UL
#define SYSCALL_os_registry_get_ID_OUT 0x90005cb2UL
void os_registry_get(unsigned int index, application_t *out_application_entry);

#define SYSCALL_os_sched_exec_ID_IN 0x60005d14UL
#define SYSCALL_os_sched_exec_ID_OUT 0x90005d9fUL
unsigned int os_sched_exec(unsigned int application_index);

#define SYSCALL_os_sched_exit_ID_IN 0x60005ee1UL
#define SYSCALL_os_sched_exit_ID_OUT 0x90005e6fUL
void os_sched_exit(unsigned int exit_code);

#define SYSCALL_os_ux_register_ID_IN 0x60005f15UL
#define SYSCALL_os_ux_register_ID_OUT 0x90005fb9UL
void os_ux_register(bolos_ux_params_t *parameter_ram_pointer);

#define SYSCALL_os_ux_ID_IN 0x60006058UL
#define SYSCALL_os_ux_ID_OUT 0x9000601fUL
unsigned int os_ux(bolos_ux_params_t *params);

#define SYSCALL_os_flags_ID_IN 0x6000616eUL
#define SYSCALL_os_flags_ID_OUT 0x9000617fUL
unsigned int os_flags(void);

#define SYSCALL_os_version_ID_IN 0x600062b8UL
#define SYSCALL_os_version_ID_OUT 0x900062c4UL
unsigned int os_version(unsigned char *version, unsigned int maxlength);

#define SYSCALL_os_seph_features_ID_IN 0x600063d6UL
#define SYSCALL_os_seph_features_ID_OUT 0x90006344UL
unsigned int os_seph_features(void);

#define SYSCALL_os_seph_version_ID_IN 0x600064acUL
#define SYSCALL_os_seph_version_ID_OUT 0x9000645dUL
unsigned int os_seph_version(unsigned char *version, unsigned int maxlength);

#define SYSCALL_os_setting_get_ID_IN 0x60006597UL
#define SYSCALL_os_setting_get_ID_OUT 0x90006503UL
unsigned int os_setting_get(unsigned int setting_id);

#define SYSCALL_os_setting_set_ID_IN 0x60006667UL
#define SYSCALL_os_setting_set_ID_OUT 0x9000668dUL
void os_setting_set(unsigned int setting_id, unsigned int value);

#define SYSCALL_os_get_memory_info_ID_IN 0x60006763UL
#define SYSCALL_os_get_memory_info_ID_OUT 0x900067cbUL
void os_get_memory_info(meminfo_t *meminfo);

#define SYSCALL_os_registry_get_icon_ID_IN 0x600068f1UL
#define SYSCALL_os_registry_get_icon_ID_OUT 0x9000681eUL
unsigned int os_registry_get_icon(unsigned int appidx, unsigned int offset,
                                  unsigned char *buffer,
                                  unsigned int maxlength);

#define SYSCALL_io_seproxyhal_spi_send_ID_IN 0x6000691cUL
#define SYSCALL_io_seproxyhal_spi_send_ID_OUT 0x900069f3UL
void io_seproxyhal_spi_send(const unsigned char *buffer, unsigned short length);

#define SYSCALL_io_seproxyhal_spi_is_status_sent_ID_IN 0x60006acfUL
#define SYSCALL_io_seproxyhal_spi_is_status_sent_ID_OUT 0x90006a7fUL
unsigned int io_seproxyhal_spi_is_status_sent(void);

#define SYSCALL_io_seproxyhal_spi_recv_ID_IN 0x60006bd1UL
#define SYSCALL_io_seproxyhal_spi_recv_ID_OUT 0x90006b2bUL
unsigned short io_seproxyhal_spi_recv(unsigned char *buffer,
                                      unsigned short maxlength,
                                      unsigned int flags);

#endif // SYSCALL_DEFS_H
