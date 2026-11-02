// File: ./llm/tls/tls_packets.c
#include "tls_packets.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_uint24(tls_uint24_t u24) {
    unsigned int val = (u24.b0 << 16) | (u24.b1 << 8) | (u24.b2);
    printf("%u", val);
}

static void print_record_header(const tls_record_header_t *hdr) {
    printf("  record.type=%u\n", (unsigned)hdr->type);
    printf("  record.version.major=%u\n", (unsigned)hdr->version.major);
    printf("  record.version.minor=%u\n", (unsigned)hdr->version.minor);
    printf("  record.length=%u\n", (unsigned)hdr->length);
}

static void print_change_cipher_spec(const tls_change_cipher_spec_msg_t *ccs) {
    printf("  ccs.type=%u\n", (unsigned)ccs->type);
}

static void print_alert(const tls_alert_msg_t *alert) {
    printf("  alert.level=%u\n", (unsigned)alert->level);
    printf("  alert.description=%u\n", (unsigned)alert->description);
}

static void print_handshake(const tls_handshake_msg_t *hs) {
    printf("  handshake.msg_type=%u\n", (unsigned)hs->msg_type);
    printf("  handshake.length=");
    print_uint24(hs->length);
    printf("\n");
}

static void print_app_data(const tls_application_data_t *ad) {
    printf("  app_data.data_len=%u\n", (unsigned)ad->data_len);
    if (ad->data && ad->data_len) {
        printf("  app_data.data (hex): ");
        for (unsigned i = 0; i < ad->data_len; ++i) {
            printf("%02X", ad->data[i]);
        }
        printf("\n");
    }
}

static void init_record_header(tls_record_header_t *hdr, uint8_t type) {
    hdr->type = type; // Fixed for each packet type
    hdr->version.major = 3; // TLS 1.2 default example
    hdr->version.minor = 3; // TLS 1.2 default example
    hdr->length = 0;
}

static tls_packet_t make_empty_packet(tls_packet_type_t t) {
    tls_packet_t p;
    memset(&p, 0, sizeof(p));
    p.type = t;
    switch (t) {
        case TLS_PACKET_CHANGE_CIPHER_SPEC:
            init_record_header(&p.u.change_cipher_spec.record, TLS_CONTENTTYPE_CHANGE_CIPHER_SPEC);
            p.u.change_cipher_spec.ccs.type = 1; // Fixed value per RFC
            break;
        case TLS_PACKET_ALERT:
            init_record_header(&p.u.alert.record, TLS_CONTENTTYPE_ALERT);
            p.u.alert.alert.level = TLS_ALERT_LEVEL_WARNING;
            p.u.alert.alert.description = TLS_ALERT_CLOSE_NOTIFY;
            break;
        case TLS_PACKET_HANDSHAKE:
            init_record_header(&p.u.handshake.record, TLS_CONTENTTYPE_HANDSHAKE);
            p.u.handshake.handshake.msg_type = TLS_HANDSHAKE_HELLO_REQUEST;
            p.u.handshake.handshake.length.b0 = 0;
            p.u.handshake.handshake.length.b1 = 0;
            p.u.handshake.handshake.length.b2 = 0;
            break;
        case TLS_PACKET_APPLICATION_DATA:
            init_record_header(&p.u.application_data.record, TLS_CONTENTTYPE_APPLICATION_DATA);
            p.u.application_data.app_data.data = NULL;
            p.u.application_data.app_data.data_len = 0;
            break;
        default:
            break;
    }
    return p;
}

// Allocate and zero-initialize a list of empty packets
// Caller should free the returned pointer with free().
tls_packet_t* generate_tls_packets(int count) {
    if (count <= 0) return NULL;
    tls_packet_t *packets = (tls_packet_t *)malloc(sizeof(tls_packet_t) * count);
    if (!packets) return NULL;
    memset(packets, 0, sizeof(tls_packet_t) * count);

    // Populate with a repeating sequence of the four TLS packet types for demonstration
    for (int i = 0; i < count; ++i) {
        tls_packet_type_t t;
        switch (i % 4) {
            case 0: t = TLS_PACKET_CHANGE_CIPHER_SPEC; break;
            case 1: t = TLS_PACKET_ALERT; break;
            case 2: t = TLS_PACKET_HANDSHAKE; break;
            default: t = TLS_PACKET_APPLICATION_DATA; break;
        }
        packets[i] = make_empty_packet(t);
    }

    return packets;
}

void print_tls_packets(const tls_packet_t *packets, int count) {
    if (!packets || count <= 0) return;
    for (int i = 0; i < count; ++i) {
        printf("Packet %d:\n", i);
        switch (packets[i].type) {
            case TLS_PACKET_CHANGE_CIPHER_SPEC:
                printf(" type=CHANGE_CIPHER_SPEC\n");
                print_record_header(&packets[i].u.change_cipher_spec.record);
                print_change_cipher_spec(&packets[i].u.change_cipher_spec.ccs);
                break;
            case TLS_PACKET_ALERT:
                printf(" type=ALERT\n");
                print_record_header(&packets[i].u.alert.record);
                print_alert(&packets[i].u.alert.alert);
                break;
            case TLS_PACKET_HANDSHAKE:
                printf(" type=HANDSHAKE\n");
                print_record_header(&packets[i].u.handshake.record);
                print_handshake(&packets[i].u.handshake.handshake);
                break;
            case TLS_PACKET_APPLICATION_DATA:
                printf(" type=APPLICATION_DATA\n");
                print_record_header(&packets[i].u.application_data.record);
                print_app_data(&packets[i].u.application_data.app_data);
                break;
            default:
                printf(" type=UNKNOWN\n");
                break;
        }
    }
}
