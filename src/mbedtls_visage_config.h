/* src/mbedtls_visage_config.h
 *
 * visage's mbedTLS 3.6.x configuration — minimal TLS 1.2 client (+ test
 * server) for opportunistic STARTTLS relaying. Selected by compiling every
 * TU (ours and mbedTLS's) with
 *     -DMBEDTLS_CONFIG_FILE='"mbedtls_visage_config.h"' -I src
 * which makes mbedtls/build_info.h include this file instead of upstream
 * mbedtls/mbedtls_config.h — ONLY the macros below are enabled; everything
 * unlisted is OFF (PSA, TLS1.3, AESNI/CE, PADLOCK, NET, TIMING, THREADING,
 * MD5, DHM, ECJPAKE, HMAC_DRBG, tickets, cookies, DTLS, renegotiation).
 */
#ifndef MBEDTLS_VISAGE_CONFIG_H
#define MBEDTLS_VISAGE_CONFIG_H

/* System: cosmopolitan provides time()/gmtime_r (libc spike verified). */
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE

#define MBEDTLS_VERSION_C        /* selfcheck asserts "Mbed TLS 3.6.7"    */
#define MBEDTLS_ERROR_C          /* mbedtls_strerror for TLS diagnostics  */
#define MBEDTLS_FS_IO            /* x509_crt_parse_file / pk_parse_keyfile */

/* Crypto primitives. */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_MD_C
#define MBEDTLS_SHA1_C           /* TLS 1.2 PRF/interop                  */
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CONSTANT_TIME_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C        /* /dev/urandom via entropy_poll.c      */

/* PK / X.509. */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_OID_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECDSA_C           /* verify ECDSA-signed relay certs      */
#define MBEDTLS_ECDH_C            /* ECDHE key exchange                   */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C

/* TLS. */
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_SRV_C        /* test server in tests/tls_selfcheck.c */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE /* assert peer cert CN          */

/* TLS 1.2 key exchanges (check_config.h requires >=1; ECDHE-RSA/ECDSA are
 * what the ECDHE AES-GCM ciphersuites use, matching the selfcheck). */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

#endif /* MBEDTLS_VISAGE_CONFIG_H */
