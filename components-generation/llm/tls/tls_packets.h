// File: ./llm/tls/tls_packets.h
#ifndef TLS_PACKETS_H
#define TLS_PACKETS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// From RFC 5246 (TLS 1.2): ContentType values
// enum { change_cipher_spec(20), alert(21), handshake(22), application_data(23), (255) } ContentType;

typedef enum {
    TLS_CONTENTTYPE_CHANGE_CIPHER_SPEC = 20, /* Fixed */
    TLS_CONTENTTYPE_ALERT              = 21, /* Fixed */
    TLS_CONTENTTYPE_HANDSHAKE          = 22, /* Fixed */
    TLS_CONTENTTYPE_APPLICATION_DATA   = 23  /* Fixed */
} tls_content_type_t;

// ProtocolVersion
// struct { uint8 major; uint8 minor; } ProtocolVersion;

typedef struct {
    uint8_t major;
    uint8_t minor;
} tls_protocol_version_t;

// TLSPlaintext record structure per RFC 5246 Section 6.2
// struct { ContentType type; ProtocolVersion version; uint16 length; opaque fragment[TLSPlaintext.length]; } TLSPlaintext;

typedef struct {
    uint8_t type;                      /* Fixed */
    tls_protocol_version_t version;    
    uint16_t length;                   
    // The fragment content depends on type. We model separate packet bodies below.
} tls_record_header_t;

// ChangeCipherSpec message per RFC 5246 Section 7.1 / Appendix A.2
// struct { enum { change_cipher_spec(1), (255) } type; } ChangeCipherSpec;

typedef struct {
    uint8_t type; /* Fixed: value 1 */
} tls_change_cipher_spec_msg_t;

// Alert message per RFC 5246 Section 7.2 / Appendix A.3
// struct { AlertLevel level; AlertDescription description; } Alert;

typedef enum {
    TLS_ALERT_LEVEL_WARNING = 1,
    TLS_ALERT_LEVEL_FATAL   = 2
} tls_alert_level_t;

typedef enum {
    TLS_ALERT_CLOSE_NOTIFY                 = 0,
    TLS_ALERT_UNEXPECTED_MESSAGE           = 10,
    TLS_ALERT_BAD_RECORD_MAC               = 20,
    TLS_ALERT_DECRYPTION_FAILED_RESERVED   = 21,
    TLS_ALERT_RECORD_OVERFLOW              = 22,
    TLS_ALERT_DECOMPRESSION_FAILURE        = 30,
    TLS_ALERT_HANDSHAKE_FAILURE            = 40,
    TLS_ALERT_NO_CERTIFICATE_RESERVED      = 41,
    TLS_ALERT_BAD_CERTIFICATE              = 42,
    TLS_ALERT_UNSUPPORTED_CERTIFICATE      = 43,
    TLS_ALERT_CERTIFICATE_REVOKED          = 44,
    TLS_ALERT_CERTIFICATE_EXPIRED          = 45,
    TLS_ALERT_CERTIFICATE_UNKNOWN          = 46,
    TLS_ALERT_ILLEGAL_PARAMETER            = 47,
    TLS_ALERT_UNKNOWN_CA                   = 48,
    TLS_ALERT_ACCESS_DENIED                = 49,
    TLS_ALERT_DECODE_ERROR                 = 50,
    TLS_ALERT_DECRYPT_ERROR                = 51,
    TLS_ALERT_EXPORT_RESTRICTION_RESERVED  = 60,
    TLS_ALERT_PROTOCOL_VERSION             = 70,
    TLS_ALERT_INSUFFICIENT_SECURITY        = 71,
    TLS_ALERT_INTERNAL_ERROR               = 80,
    TLS_ALERT_USER_CANCELED                = 90,
    TLS_ALERT_NO_RENEGOTIATION             = 100,
    TLS_ALERT_MISSING_EXTENSION            = 109,
    TLS_ALERT_UNSUPPORTED_EXTENSION        = 110,
    TLS_ALERT_UNRECOGNIZED_NAME            = 112,
    TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 113,
    TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE   = 114,
    TLS_ALERT_UNKNOWN_PSK_IDENTITY         = 115,
    TLS_ALERT_CERTIFICATE_REQUIRED         = 116,
    TLS_ALERT_NO_APPLICATION_PROTOCOL      = 120
} tls_alert_description_t;

typedef struct {
    uint8_t level;        // AlertLevel
    uint8_t description;  // AlertDescription
} tls_alert_msg_t;

// Handshake message header per RFC 5246 Section 7.4
// struct { HandshakeType msg_type; uint24 length; body } Handshake;

typedef enum {
    TLS_HANDSHAKE_HELLO_REQUEST        = 0,
    TLS_HANDSHAKE_CLIENT_HELLO         = 1,
    TLS_HANDSHAKE_SERVER_HELLO         = 2,
    TLS_HANDSHAKE_HELLO_VERIFY_REQUEST = 3,   /* DTLS, harmless for TLS corpus mutation */
    TLS_HANDSHAKE_NEW_SESSION_TICKET   = 4,
    TLS_HANDSHAKE_END_OF_EARLY_DATA    = 5,
    TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS = 8,
    TLS_HANDSHAKE_CERTIFICATE          = 11,
    TLS_HANDSHAKE_SERVER_KEY_EXCHANGE  = 12,
    TLS_HANDSHAKE_CERTIFICATE_REQUEST  = 13,
    TLS_HANDSHAKE_SERVER_HELLO_DONE    = 14,
    TLS_HANDSHAKE_CERTIFICATE_VERIFY   = 15,
    TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE  = 16,
    TLS_HANDSHAKE_FINISHED             = 20,
    TLS_HANDSHAKE_CERTIFICATE_URL      = 21,
    TLS_HANDSHAKE_CERTIFICATE_STATUS   = 22,
    TLS_HANDSHAKE_SUPPLEMENTAL_DATA    = 23,
    TLS_HANDSHAKE_KEY_UPDATE           = 24,
    TLS_HANDSHAKE_MESSAGE_HASH         = 254
} tls_handshake_type_t;

// Represent uint24 as 3 bytes

typedef struct {
    uint8_t b0;
    uint8_t b1;
    uint8_t b2;
} tls_uint24_t;

#define TLS_MAX_SESSION_ID_LEN          32u
#define TLS_MAX_CIPHER_SUITES_BYTES     1024u
#define TLS_MAX_COMPRESSION_METHODS     32u
#define TLS_MAX_EXTENSIONS_BYTES        4096u
#define TLS_MAX_EXTENSION_ITEMS          32u
#define TLS_MAX_EXTENSION_DATA_BYTES     4096u
#define TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES      4096u
#define TLS_MAX_CERTIFICATE_ITEMS         16u
#define TLS_MAX_CERTIFICATE_BYTES         2048u
#define TLS_MAX_CERTIFICATE_EXTENSION_BYTES 1024u
#define TLS_MAX_COALESCED_HANDSHAKES      16u

typedef struct {
    uint16_t extension_type;
    uint16_t extension_data_len;
    uint8_t extension_data[TLS_MAX_EXTENSION_DATA_BYTES];
} tls_extension_t;

// Structured view of a ClientHello body. Other handshake messages remain
// available through the generic handshake body.
typedef struct {
    tls_protocol_version_t client_version;
    uint8_t random[32];

    uint8_t session_id_len;
    uint8_t session_id[TLS_MAX_SESSION_ID_LEN];

    uint16_t cipher_suites_len;
    uint8_t cipher_suites[TLS_MAX_CIPHER_SUITES_BYTES];

    uint8_t compression_methods_len;
    uint8_t compression_methods[TLS_MAX_COMPRESSION_METHODS];

    uint8_t extensions_present; /* Optional vector: omitted differs from present/empty. */
    uint16_t extensions_len;
    uint8_t extensions[TLS_MAX_EXTENSIONS_BYTES];
    uint8_t extension_count;
    tls_extension_t extension_items[TLS_MAX_EXTENSION_ITEMS]; /* Optional, Repeatable */
} tls_client_hello_t;


typedef enum {
    TLS_HANDSHAKE_BODY_NONE = 0,
    TLS_HANDSHAKE_BODY_CLIENT_HELLO = 1,
    TLS_HANDSHAKE_BODY_CERTIFICATE = 2,
    TLS_HANDSHAKE_BODY_CLIENT_KEY_EXCHANGE = 3,
    TLS_HANDSHAKE_BODY_CERTIFICATE_VERIFY = 4,
    TLS_HANDSHAKE_BODY_FINISHED = 5,
    TLS_HANDSHAKE_BODY_CERTIFICATE_URL = 6,
    TLS_HANDSHAKE_BODY_END_OF_EARLY_DATA = 7,
    TLS_HANDSHAKE_BODY_KEY_UPDATE = 8
} tls_handshake_body_schema_t;

typedef struct {
    uint8_t tls13_layout;
    uint8_t request_context_len;
    uint8_t request_context[255];
    uint32_t certificate_list_len;
    uint8_t certificate_count;
    uint32_t certificate_len[TLS_MAX_CERTIFICATE_ITEMS];
    uint16_t certificate_extensions_len[TLS_MAX_CERTIFICATE_ITEMS];
    uint8_t certificate_extensions[TLS_MAX_CERTIFICATE_ITEMS][TLS_MAX_CERTIFICATE_EXTENSION_BYTES];
    uint8_t certificate_bytes[TLS_MAX_CERTIFICATE_ITEMS][TLS_MAX_CERTIFICATE_BYTES];
} tls_certificate_body_t;

typedef struct {
    uint8_t length_prefixed;
    uint16_t exchange_len;
    uint8_t exchange[TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES];
} tls_client_key_exchange_body_t;

typedef struct {
    uint8_t length_prefixed;
    uint16_t signature_scheme;
    uint16_t signature_len;
    uint8_t signature[TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES];
} tls_certificate_verify_body_t;

typedef struct {
    uint16_t verify_data_len;
    uint8_t verify_data[TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES];
} tls_finished_body_t;

typedef struct {
    uint8_t chain_type;
    uint16_t url_and_hash_list_len;
    uint8_t url_and_hash_list[TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES];
} tls_certificate_url_body_t;

typedef struct {
    uint8_t request_update;
} tls_key_update_body_t;

typedef struct {
    uint8_t msg_type;
    tls_uint24_t length;
    const uint8_t *wire;
    uint32_t wire_len;
} tls_coalesced_handshake_t;

typedef struct {
    uint8_t msg_type;      // HandshakeType
    tls_uint24_t length;       // uint24 length
    uint8_t *body;         /* Optional */
    uint32_t body_len;
} tls_handshake_msg_t;

// Application Data has no inner header fields at TLS layer other than being carried as record fragment.
// We define a trivial payload holder to fit the requested structure style.

typedef struct {
    uint8_t *data;         /* Optional, Repeatable */
    uint16_t data_len;
} tls_application_data_t;

// Composite packet structures mapping ContentType -> specific message structures

typedef struct {
    tls_record_header_t record;
    tls_change_cipher_spec_msg_t ccs;
} tls_change_cipher_spec_packet_t;

typedef struct {
    tls_record_header_t record;
    tls_alert_msg_t alert;
} tls_alert_packet_t;

typedef struct {
    tls_record_header_t record;
    tls_handshake_msg_t handshake;
    uint8_t has_client_hello;
    tls_client_hello_t client_hello;
    uint8_t body_schema;
    uint8_t fragmented_body_schema;
    union {
        tls_certificate_body_t certificate;
        tls_client_key_exchange_body_t client_key_exchange;
        tls_certificate_verify_body_t certificate_verify;
        tls_finished_body_t finished;
        tls_certificate_url_body_t certificate_url;
        tls_key_update_body_t key_update;
    } body;
    /* RFC5246 §6.2.1: a record need not contain exactly one whole handshake.
     * Fragment bytes are explicit; this is not a cross-record handshake decoder. */
    uint8_t is_fragment;
    uint8_t fragment_decoded;
    const uint8_t *fragment;
    uint16_t fragment_len;
    const uint8_t *following_handshakes;
    uint16_t following_handshakes_len;
    uint8_t following_handshake_count;
    tls_coalesced_handshake_t following[TLS_MAX_COALESCED_HANDSHAKES];
} tls_handshake_packet_t;

typedef struct {
    tls_record_header_t record;
    tls_application_data_t app_data;
} tls_application_data_packet_t;

// Enum to identify packet types

typedef enum {
    TLS_PACKET_CHANGE_CIPHER_SPEC,
    TLS_PACKET_ALERT,
    TLS_PACKET_HANDSHAKE,
    TLS_PACKET_APPLICATION_DATA,
    TLS_PACKET_UNKNOWN
} tls_packet_type_t;

// Union of all packet types

typedef struct {
    tls_packet_type_t type;
    /* Non-owning parser input slice used to preserve exact legal records. */
    const uint8_t *wire;
    uint32_t wire_len;
    union {
        tls_change_cipher_spec_packet_t change_cipher_spec;
        tls_alert_packet_t              alert;
        tls_handshake_packet_t          handshake;
        tls_application_data_packet_t   application_data;
        tls_application_data_packet_t   opaque_record; /* Record header + uninterpreted fragment. */
    } u;
} tls_packet_t;

// API functions

tls_packet_t* generate_tls_packets(int count);
void print_tls_packets(const tls_packet_t *packets, int count);

#ifdef __cplusplus
}
#endif

#endif // TLS_PACKETS_H
