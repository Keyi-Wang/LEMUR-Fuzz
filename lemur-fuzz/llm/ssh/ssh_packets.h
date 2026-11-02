// ssh_packets.h
// Compact, self-contained SSH packet model for fuzzing
// C11 portable, fixed-size inline buffers only

#ifndef SSH_PACKETS_H
#define SSH_PACKETS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Limits (kept small enough for AFL memory use)
#define SSH_MAX_BANNER_LEN            255u
#define SSH_MAX_WIRE_PACKET_BYTES     35000u
#define SSH_MAX_PADDING_BYTES         255u
#define SSH_MAX_NAMELIST_BYTES        4096u
#define SSH_MAX_MPINT_BYTES           4096u
#define SSH_MAX_SERVICE_NAME_BYTES    256u
#define SSH_MAX_OPAQUE_BYTES          35000u
#define SSH_MAX_TYPED_PAYLOAD_BYTES   35000u
#define SSH_MAX_TYPED_FIELD_BYTES     32768u
#define SSH_MAX_TYPED_STRING_FIELDS   16u
#define SSH_MAX_TYPED_UINT32_FIELDS   8u
#define SSH_MAX_TYPED_BOOL_FIELDS     4u

// SSH message numbers from RFC 4253, RFC 4252 and RFC 4254.
#define SSH_MSG_DISCONNECT                 1u
#define SSH_MSG_IGNORE                     2u
#define SSH_MSG_UNIMPLEMENTED              3u
#define SSH_MSG_DEBUG                      4u
#define SSH_MSG_SERVICE_REQUEST            5u
#define SSH_MSG_SERVICE_ACCEPT             6u
#define SSH_MSG_KEXINIT                    20u
#define SSH_MSG_NEWKEYS                    21u
#define SSH_MSG_KEXDH_INIT                 30u
#define SSH_MSG_KEXDH_REPLY                31u
#define SSH_MSG_KEX_DH_GEX_INIT            32u
#define SSH_MSG_KEX_DH_GEX_REQUEST         34u
#define SSH_MSG_USERAUTH_REQUEST           50u
#define SSH_MSG_USERAUTH_FAILURE           51u
#define SSH_MSG_USERAUTH_SUCCESS           52u
#define SSH_MSG_USERAUTH_BANNER            53u
#define SSH_MSG_USERAUTH_PK_OK             60u
#define SSH_MSG_USERAUTH_PASSWD_CHANGEREQ  60u
#define SSH_MSG_USERAUTH_METHOD_REPLY      SSH_MSG_USERAUTH_PK_OK
#define SSH_MSG_USERAUTH_INFO_RESPONSE     61u
#define SSH_MSG_GLOBAL_REQUEST             80u
#define SSH_MSG_REQUEST_SUCCESS            81u
#define SSH_MSG_REQUEST_FAILURE            82u
#define SSH_MSG_CHANNEL_OPEN               90u
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION  91u
#define SSH_MSG_CHANNEL_OPEN_FAILURE       92u
#define SSH_MSG_CHANNEL_WINDOW_ADJUST      93u
#define SSH_MSG_CHANNEL_DATA               94u
#define SSH_MSG_CHANNEL_EXTENDED_DATA      95u
#define SSH_MSG_CHANNEL_EOF                96u
#define SSH_MSG_CHANNEL_CLOSE              97u
#define SSH_MSG_CHANNEL_REQUEST            98u
#define SSH_MSG_CHANNEL_SUCCESS            99u
#define SSH_MSG_CHANNEL_FAILURE            100u

// Packet type classification for this model
typedef enum {
    SSH_BANNER = 0,
    SSH_TRANSPORT_PACKET = 1,
    SSH_KEXINIT = 2,
    SSH_KEXDH_INIT = 3,
    SSH_SERVICE_REQUEST = 4,
    SSH_NEWKEYS = 5,
    SSH_OPAQUE = 6,
    SSH_DISCONNECT = 7,
    SSH_IGNORE = 8,
    SSH_UNIMPLEMENTED = 9,
    SSH_DEBUG = 10,
    SSH_SERVICE_ACCEPT = 11,
    SSH_KEXDH_REPLY = 12,
    SSH_USERAUTH_REQUEST = 13,
    SSH_USERAUTH_FAILURE = 14,
    SSH_USERAUTH_SUCCESS = 15,
    SSH_USERAUTH_BANNER = 16,
    SSH_USERAUTH_METHOD_REPLY = 17,
    SSH_GLOBAL_REQUEST = 18,
    SSH_REQUEST_SUCCESS = 19,
    SSH_REQUEST_FAILURE = 20,
    SSH_CHANNEL_OPEN = 21,
    SSH_CHANNEL_OPEN_CONFIRMATION = 22,
    SSH_CHANNEL_OPEN_FAILURE = 23,
    SSH_CHANNEL_WINDOW_ADJUST = 24,
    SSH_CHANNEL_DATA = 25,
    SSH_CHANNEL_EXTENDED_DATA = 26,
    SSH_CHANNEL_EOF = 27,
    SSH_CHANNEL_CLOSE = 28,
    SSH_CHANNEL_REQUEST = 29,
    SSH_CHANNEL_SUCCESS = 30,
    SSH_CHANNEL_FAILURE = 31,
    SSH_KEX_DH_GEX_INIT = 32,
    SSH_KEX_DH_GEX_REQUEST = 33,
    SSH_USERAUTH_INFO_RESPONSE = 34
} ssh_packet_type_t;

// SSH identification banner (ASCII), ending with CRLF
// Format per RFC 4253: "SSH-2.0-" software [SP comments] CR LF
typedef struct {
    // High-level components
    char proto_id[4];                   /* Fixed */   // "SSH"
    char dash1;                         /* Fixed */   // '-'
    char protoversion[4];               /* Fixed */   // "2.0"
    char dash2;                         /* Fixed */   // '-'

    // Variable parts
    char software[SSH_MAX_BANNER_LEN];                // softwareversion string (ASCII)
    uint16_t software_len;

    uint8_t has_comments;                              /* Optional */
    char comments[SSH_MAX_BANNER_LEN];                 /* Optional */
    uint16_t comments_len;                             /* Optional */

    // Terminator
    char cr;                              /* Fixed */   // '\r'
    char lf;                              /* Fixed */   // '\n'

    // Raw bytes as seen on wire for reassembly convenience (without trailing NUL)
    uint16_t raw_len;                                   // total banner bytes including CRLF
    unsigned char raw[SSH_MAX_BANNER_LEN];
} ssh_banner_t;

// Generic SSH transport packet record (binary packet protocol, without MAC)
// uint32 packet_length; byte padding_length; byte[n1] payload; byte[n2] padding
typedef struct {
    uint32_t packet_length;                           // on-wire packet_length
    uint8_t padding_length;                           // on-wire padding_length

    uint32_t payload_len;                             // n1 = packet_length - padding_length - 1
    unsigned char payload[SSH_MAX_WIRE_PACKET_BYTES]; // payload bytes (bounded)

    uint8_t padding[SSH_MAX_PADDING_BYTES];           // random padding bytes

    // Convenience: first byte of payload when present
    uint8_t has_message_code;                         /* Optional */
    uint8_t message_code;                             /* Optional */
} ssh_transport_packet_t;

// SSH_MSG_KEXINIT payload structure
typedef struct {
    uint8_t message_code;                 /* Fixed */   // SSH_MSG_KEXINIT (20)
    uint8_t cookie[16];                                  // 16 random bytes

    // name-list fields, each is: uint32 length; byte[length] list (comma-separated names)
    uint32_t kex_algorithms_len;
    unsigned char kex_algorithms[SSH_MAX_NAMELIST_BYTES];              /* Optional */

    uint32_t server_host_key_algorithms_len;
    unsigned char server_host_key_algorithms[SSH_MAX_NAMELIST_BYTES];  /* Optional */

    uint32_t encryption_algorithms_client_to_server_len;
    unsigned char encryption_algorithms_client_to_server[SSH_MAX_NAMELIST_BYTES]; /* Optional */

    uint32_t encryption_algorithms_server_to_client_len;
    unsigned char encryption_algorithms_server_to_client[SSH_MAX_NAMELIST_BYTES]; /* Optional */

    uint32_t mac_algorithms_client_to_server_len;
    unsigned char mac_algorithms_client_to_server[SSH_MAX_NAMELIST_BYTES]; /* Optional */

    uint32_t mac_algorithms_server_to_client_len;
    unsigned char mac_algorithms_server_to_client[SSH_MAX_NAMELIST_BYTES]; /* Optional */

    uint32_t compression_algorithms_client_to_server_len;
    unsigned char compression_algorithms_client_to_server[SSH_MAX_NAMELIST_BYTES]; /* Optional */

    uint32_t compression_algorithms_server_to_client_len;
    unsigned char compression_algorithms_server_to_client[SSH_MAX_NAMELIST_BYTES]; /* Optional */

    uint32_t languages_client_to_server_len;
    unsigned char languages_client_to_server[SSH_MAX_NAMELIST_BYTES];  /* Optional */

    uint32_t languages_server_to_client_len;
    unsigned char languages_server_to_client[SSH_MAX_NAMELIST_BYTES];  /* Optional */

    uint8_t first_kex_packet_follows;                                       // boolean
    uint32_t reserved_zero;                           /* Fixed */          // must be 0
} ssh_kexinit_t;

// SSH_MSG_KEXDH_INIT
typedef struct {
    uint8_t message_code;                 /* Fixed */   // SSH_MSG_KEXDH_INIT (30)
    uint32_t e_len;                                      // mpint length (bytes)
    unsigned char e[SSH_MAX_MPINT_BYTES];                // mpint bytes
} ssh_kexdh_init_t;

// SSH_MSG_SERVICE_REQUEST
typedef struct {
    uint8_t message_code;                 /* Fixed */   // SSH_MSG_SERVICE_REQUEST (5)
    uint32_t service_name_len;
    unsigned char service_name[SSH_MAX_SERVICE_NAME_BYTES];
} ssh_service_request_t;

// SSH_MSG_NEWKEYS
typedef struct {
    uint8_t message_code;                 /* Fixed */   // SSH_MSG_NEWKEYS (21)
} ssh_newkeys_t;

// Generic typed SSH payload. message_code is the first payload byte; payload
// stores the message-specific bytes after message_code. This lets Lemur cover
// RFC-defined SSH messages without needing a full deep parser for every body.
typedef struct {
    uint32_t len;
    unsigned char bytes[SSH_MAX_TYPED_FIELD_BYTES];
} ssh_string_field_t;

typedef struct {
    uint8_t message_code;
    uint32_t payload_len;
    unsigned char payload[SSH_MAX_TYPED_PAYLOAD_BYTES];

    // Structured RFC 4251 string/boolean/uint32 template for message bodies
    // that do not have a dedicated packet type above. field_schema is the
    // SSH_MSG_* value when these fields are populated. For RFC 4252
    // USERAUTH_REQUEST, strings[0..2] are user/service/method; method-specific
    // fields follow: publickey -> boolean_value, algorithm, key blob, signature;
    // password -> boolean_value, password, optional new password; hostbased ->
    // algorithm, key blob, client host, client user, signature.
    uint8_t field_schema;
    uint8_t boolean_value;
    uint8_t boolean_count;
    uint8_t boolean_values[SSH_MAX_TYPED_BOOL_FIELDS];
    uint8_t uint32_count;
    uint32_t uint32_values[SSH_MAX_TYPED_UINT32_FIELDS];
    uint8_t string_count;
    ssh_string_field_t strings[SSH_MAX_TYPED_STRING_FIELDS];
    ssh_string_field_t trailing_payload;
} ssh_typed_payload_t;

// Opaque packet bytes (unknown or encrypted)
typedef struct {
    uint32_t len;
    unsigned char bytes[SSH_MAX_OPAQUE_BYTES];
    const uint8_t *overflow; /* Borrowed input beyond bytes[], valid until input is released. */
    uint32_t overflow_len;
} ssh_opaque_t;

// Unified packet container
typedef struct {
    ssh_packet_type_t type;
    /* Non-owning parser input slice. Mutators must clear wire_len after
     * changing the structured representation. */
    const uint8_t *wire;
    uint32_t wire_len;
    /* RFC4253 §6: retain original random padding independently of payload. */
    uint8_t has_transport_padding;
    uint8_t transport_padding_length;
    uint8_t transport_padding[SSH_MAX_PADDING_BYTES];
    uint32_t transport_payload_length;
    union {
        ssh_banner_t              banner;
        ssh_transport_packet_t    transport;
        ssh_kexinit_t             kexinit;
        ssh_kexdh_init_t          kexdh_init;
        ssh_service_request_t     service_request;
        ssh_newkeys_t             newkeys;
        ssh_typed_payload_t       typed;
        ssh_opaque_t              opaque;
    } u;
} ssh_packet_t;

// API
ssh_packet_t* generate_ssh_packets(int count);
void print_ssh_packets(const ssh_packet_t *packets, int count);

#ifdef __cplusplus
}
#endif

#endif // SSH_PACKETS_H
