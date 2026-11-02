// dns_packets.h
// Self-contained DNS packet structures and helpers for fuzzing
// Supports DNS over UDP messages per RFC 1035 and EDNS(0) per RFC 6891.

#ifndef DNS_PACKETS_H
#define DNS_PACKETS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Limits to keep AFL memory usage bounded
#define DNS_MAX_WIRE 65535
#define DNS_MAX_LABELS 128
#define DNS_MAX_NAME_LEN 255
#define DNS_MAX_QUESTIONS 32
#define DNS_MAX_RRS 64
#define DNS_MAX_RDATA 4096
#define DNS_MAX_OPT_RDATA 4096
#define DNS_MAX_DSO_TLVS 16
#define DNS_MAX_DSO_DATA 2048
#define DNS_MAX_RDATA_NAMES 4
#define DNS_MAX_RDATA_U16S 8
#define DNS_MAX_RDATA_U32S 8
#define DNS_MAX_RDATA_STRINGS 16
#define DNS_MAX_EDNS_OPTIONS 16
#define DNS_MAX_TSIG_MAC 512
#define DNS_MAX_TSIG_OTHER 512
#define DNS_MAX_MSGS 32

// Packet type tags (Fixed for each struct instance type)
#define DNS_MESSAGE            1
#define DNS_HEADER             2
#define DNS_QUESTION           3
#define DNS_RESOURCE_RECORD    4
#define DNS_OPT_RECORD         5
#define DNS_OPAQUE_RDATA       6

// DNS header flags breakdown for convenience

typedef struct {
    uint8_t packet_type; /* Fixed */

    // Header fields per RFC 1035 4.1.1
    uint16_t id;
    // Flags and codes
    uint8_t qr;    // query/response
    uint8_t opcode; // 4 bits effective
    uint8_t aa;
    uint8_t tc;
    uint8_t rd;
    uint8_t ra;
    uint8_t z;     // 3 bits (reserved)
    uint8_t rcode; // 4 bits

    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

// Domain name storage (wire format) preserved inline for exact round-trip.
// Stores either uncompressed or compressed names exactly as seen.

typedef struct {
    uint8_t packet_type; /* Fixed */

    // Encoded QNAME bytes as they appeared on the wire
    uint16_t name_len;
    uint8_t name[DNS_MAX_NAME_LEN];

    uint16_t qtype;
    uint16_t qclass;

    // Helper flags
    uint8_t present; /* Optional */
} dns_question_t;

// Opaque RDATA holder to preserve unknown formats

typedef struct {
    uint8_t packet_type; /* Fixed */

    uint16_t rdlength;
    uint16_t rdata_len; // duplicate for safety (should equal rdlength)
    uint8_t rdata[DNS_MAX_RDATA];
} dns_opaque_rdata_t;

// Generic Resource Record (Answer/Authority/Additional). For OPT (EDNS), a
// dedicated dns_opt_record_t is provided, but generic RR can still store it.

typedef struct {
    uint8_t packet_type; /* Fixed */

    // NAME as exact wire bytes (may include compression pointers)
    uint16_t name_len;
    uint8_t name[DNS_MAX_NAME_LEN];

    uint16_t type;
    uint16_t class_code;
    uint32_t ttl;

    uint16_t rdlength; // per header

    // Opaque RDATA storage
    uint16_t rdata_len; // mirrors rdlength
    uint8_t rdata[DNS_MAX_RDATA];
    const uint8_t *rdata_overflow;
    uint16_t rdata_overflow_len;

    uint16_t rdata_schema; /* 0=opaque, otherwise DNS RR TYPE with decoded fields. */
    uint8_t address_len; /* 4 for A/WKS, 16 for AAAA */
    uint8_t address[16];
    uint8_t protocol; /* WKS */
    uint16_t bitmap_len; /* WKS bitmap bytes retained in bitmap[] prefix of rdata */
    uint8_t name_count;
    struct {
        uint16_t len;
        uint8_t wire[DNS_MAX_NAME_LEN];
    } names[DNS_MAX_RDATA_NAMES];
    uint8_t u16_count;
    uint16_t u16_values[DNS_MAX_RDATA_U16S];
    uint8_t u32_count;
    uint32_t u32_values[DNS_MAX_RDATA_U32S];
    uint8_t string_count;
    struct {
        uint16_t len;
        uint8_t data[255];
    } strings[DNS_MAX_RDATA_STRINGS];

    /* RFC 2845 TSIG RDATA typed view: NAME algorithm, uint48 time, uint16 fields, opaque MAC/other data. */
    uint8_t has_tsig;
    uint16_t tsig_algorithm_name_len;
    uint8_t tsig_algorithm_name[DNS_MAX_NAME_LEN];
    uint64_t tsig_time_signed;
    uint16_t tsig_fudge;
    uint16_t tsig_mac_len;
    uint8_t tsig_mac[DNS_MAX_TSIG_MAC];
    uint16_t tsig_original_id;
    uint16_t tsig_error;
    uint16_t tsig_other_len;
    uint8_t tsig_other_data[DNS_MAX_TSIG_OTHER];

    // Flags
    uint8_t present; /* Optional */
} dns_resource_record_t;

typedef struct {
    uint16_t option_code;
    uint16_t option_length;
    uint16_t data_len;
    uint8_t data[DNS_MAX_OPT_RDATA];
    uint8_t present; /* Optional */
} dns_edns_option_t;

// EDNS(0) OPT RR specific view (TYPE=41), with decoded fields.
// Still preserves full RDATA in opaque buffer.

typedef struct {
    uint8_t packet_type; /* Fixed */

    // NAME must be 0 length (root). Preserve exact encoding length (should be 1 zero byte)
    uint16_t name_len;
    uint8_t name[DNS_MAX_NAME_LEN];

    uint16_t type;             // should be 41 for OPT
    uint16_t udp_payload_size; // stored in CLASS
    // TTL decomposed as per RFC 6891: extended RCODE, version, flags (Z)
    uint8_t ext_rcode;    // upper 8 bits of extended RCODE
    uint8_t edns_version; // 8 bits
    uint16_t edns_flags;  // 16 bits; DO bit is 0x8000

    uint16_t rdlength;
    uint16_t rdata_len; // mirrors rdlength
    uint8_t rdata[DNS_MAX_OPT_RDATA];
    const uint8_t *rdata_overflow;
    uint16_t rdata_overflow_len;
    dns_edns_option_t options[DNS_MAX_EDNS_OPTIONS]; /* Repeatable */
    uint16_t option_count;

    uint8_t present; /* Optional */
} dns_opt_record_t;

typedef struct {
    uint16_t tlv_type;
    uint16_t tlv_length;
    uint16_t data_len;
    uint8_t data[DNS_MAX_DSO_DATA];
    uint8_t has_keepalive; /* Optional: TLV type 1, length 8 */
    uint32_t inactivity_timeout;
    uint32_t keepalive_interval;
    uint8_t present; /* Optional */
} dns_dso_tlv_t;

/* Borrowed overflow fields refer to the parser input; keep it alive through
 * reassembly. Array capacities bound editable projections, not wire limits. */
typedef struct {
    const uint8_t *data;
    uint32_t len;
    uint16_t count;
} dns_section_tail_t;

// DNS Message encapsulating header and sections.

typedef struct {
    uint8_t packet_type; /* Fixed */

    dns_header_t header;

    // Questions
    dns_question_t questions[DNS_MAX_QUESTIONS]; /* Repeatable */
    uint16_t question_count;

    // RRs
    dns_resource_record_t answers[DNS_MAX_RRS]; /* Repeatable */
    uint16_t answer_count;

    dns_resource_record_t authorities[DNS_MAX_RRS]; /* Repeatable */
    uint16_t authority_count;

    // Additional: generic RRs and at most one OPT explicitly decoded
    dns_resource_record_t additionals[DNS_MAX_RRS]; /* Repeatable */
    uint16_t additional_count;

    // Track whether we extracted an OPT (EDNS) RR separately
    dns_opt_record_t opt_rr; /* Optional */
    uint8_t has_opt;         /* Optional */
    uint8_t has_opt_position;
    uint16_t opt_position; /* Original index among additional records, RFC6891 §6.1.1. */

    dns_dso_tlv_t dso_tlvs[DNS_MAX_DSO_TLVS]; /* Repeatable, RFC8490 DSO TLVs */
    uint16_t dso_tlv_count;

    dns_section_tail_t section_tails[4]; /* question, answer, authority, additional */
    dns_section_tail_t dso_tail;
    uint8_t capacity_exceeded; /* Some fields require borrowed overflow slices. */

    // Preserve original wire slice for exact round-trip
    uint16_t wire_len;
    uint8_t wire[DNS_MAX_WIRE];
} dns_message_t;

// Union-like top-level packet. For Lemur fuzzer by-value mutation, keep fixed-size structs.

typedef struct {
    uint8_t type; /* Fixed */
    union {
        dns_message_t      dns_message;
        dns_header_t       dns_header;
        dns_question_t     dns_question;
        dns_resource_record_t dns_rr;
        dns_opt_record_t   dns_opt;
        dns_opaque_rdata_t dns_opaque;
    } u;
} dns_packet_t;

// API

dns_packet_t* generate_dns_packets(int count);
void print_dns_packets(const dns_packet_t *packets, int count);

#ifdef __cplusplus
}
#endif

#endif // DNS_PACKETS_H
