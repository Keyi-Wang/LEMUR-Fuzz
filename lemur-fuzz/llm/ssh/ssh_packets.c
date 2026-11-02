// ssh_packets.c
#include "ssh_packets.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

ssh_packet_t* generate_ssh_packets(int count) {
    if (count <= 0) return NULL;
    ssh_packet_t *packets = (ssh_packet_t *)malloc(sizeof(ssh_packet_t) * (size_t)count);
    if (!packets) return NULL;
    memset(packets, 0, sizeof(ssh_packet_t) * (size_t)count);

    // Initialize fixed fields for banner defaults
    for (int i = 0; i < count; ++i) {
        packets[i].type = SSH_OPAQUE;
        packets[i].u.banner.proto_id[0] = 'S';
        packets[i].u.banner.proto_id[1] = 'S';
        packets[i].u.banner.proto_id[2] = 'H';
        packets[i].u.banner.proto_id[3] = '\0'; // not on wire; convenience
        packets[i].u.banner.dash1 = '-';
        packets[i].u.banner.protoversion[0] = '2';
        packets[i].u.banner.protoversion[1] = '.';
        packets[i].u.banner.protoversion[2] = '0';
        packets[i].u.banner.protoversion[3] = '\0';
        packets[i].u.banner.dash2 = '-';
        packets[i].u.banner.cr = '\r';
        packets[i].u.banner.lf = '\n';

        // transport convenience
        packets[i].u.transport.has_message_code = 0;
        packets[i].u.transport.message_code = 0;

        // fixed message codes
        packets[i].u.kexinit.message_code = SSH_MSG_KEXINIT;
        packets[i].u.kexinit.reserved_zero = 0;
        packets[i].u.kexdh_init.message_code = SSH_MSG_KEXDH_INIT;
        packets[i].u.service_request.message_code = SSH_MSG_SERVICE_REQUEST;
        packets[i].u.newkeys.message_code = SSH_MSG_NEWKEYS;
        packets[i].u.typed.message_code = 0;
        packets[i].u.typed.payload_len = 0;
    }

    return packets;
}


static const char *ssh_type_name(ssh_packet_type_t type) {
    switch (type) {
        case SSH_DISCONNECT: return "SSH_DISCONNECT";
        case SSH_IGNORE: return "SSH_IGNORE";
        case SSH_UNIMPLEMENTED: return "SSH_UNIMPLEMENTED";
        case SSH_DEBUG: return "SSH_DEBUG";
        case SSH_SERVICE_ACCEPT: return "SSH_SERVICE_ACCEPT";
        case SSH_KEXDH_REPLY: return "SSH_KEXDH_REPLY";
        case SSH_USERAUTH_REQUEST: return "SSH_USERAUTH_REQUEST";
        case SSH_USERAUTH_FAILURE: return "SSH_USERAUTH_FAILURE";
        case SSH_USERAUTH_SUCCESS: return "SSH_USERAUTH_SUCCESS";
        case SSH_USERAUTH_BANNER: return "SSH_USERAUTH_BANNER";
        case SSH_USERAUTH_METHOD_REPLY: return "SSH_USERAUTH_METHOD_REPLY";
        case SSH_GLOBAL_REQUEST: return "SSH_GLOBAL_REQUEST";
        case SSH_REQUEST_SUCCESS: return "SSH_REQUEST_SUCCESS";
        case SSH_REQUEST_FAILURE: return "SSH_REQUEST_FAILURE";
        case SSH_CHANNEL_OPEN: return "SSH_CHANNEL_OPEN";
        case SSH_CHANNEL_OPEN_CONFIRMATION: return "SSH_CHANNEL_OPEN_CONFIRMATION";
        case SSH_CHANNEL_OPEN_FAILURE: return "SSH_CHANNEL_OPEN_FAILURE";
        case SSH_CHANNEL_WINDOW_ADJUST: return "SSH_CHANNEL_WINDOW_ADJUST";
        case SSH_CHANNEL_DATA: return "SSH_CHANNEL_DATA";
        case SSH_CHANNEL_EXTENDED_DATA: return "SSH_CHANNEL_EXTENDED_DATA";
        case SSH_CHANNEL_EOF: return "SSH_CHANNEL_EOF";
        case SSH_CHANNEL_CLOSE: return "SSH_CHANNEL_CLOSE";
        case SSH_CHANNEL_REQUEST: return "SSH_CHANNEL_REQUEST";
        case SSH_CHANNEL_SUCCESS: return "SSH_CHANNEL_SUCCESS";
        case SSH_CHANNEL_FAILURE: return "SSH_CHANNEL_FAILURE";
        default: return NULL;
    }
}

static void print_bytes(const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = b[i];
        if (c >= 32 && c <= 126) {
            putchar(c);
        } else {
            printf("<%02X>", (unsigned)c);
        }
    }
}

void print_ssh_packets(const ssh_packet_t *packets, int count) {
    if (!packets || count <= 0) return;
    for (int i = 0; i < count; ++i) {
        printf("Packet %d:\n", i);
        switch (packets[i].type) {
            case SSH_BANNER: {
                const ssh_banner_t *b = &packets[i].u.banner;
                printf("  type: SSH_BANNER\n");
                printf("  proto_id (Fixed): %s\n", b->proto_id);
                printf("  dash1 (Fixed): %c\n", b->dash1);
                printf("  protoversion (Fixed): %s\n", b->protoversion);
                printf("  dash2 (Fixed): %c\n", b->dash2);
                printf("  software_len: %u\n", (unsigned)b->software_len);
                printf("  software: "); print_bytes((const unsigned char*)b->software, b->software_len); printf("\n");
                printf("  has_comments (Optional): %u\n", (unsigned)b->has_comments);
                printf("  comments_len (Optional): %u\n", (unsigned)b->comments_len);
                if (b->has_comments) { printf("  comments: "); print_bytes((const unsigned char*)b->comments, b->comments_len); printf("\n"); }
                printf("  cr (Fixed): %d lf (Fixed): %d\n", (int)b->cr, (int)b->lf);
                printf("  raw_len: %u\n", (unsigned)b->raw_len);
                printf("  raw: "); print_bytes((const unsigned char*)b->raw, b->raw_len); printf("\n");
                break;
            }
            case SSH_TRANSPORT_PACKET: {
                const ssh_transport_packet_t *t = &packets[i].u.transport;
                printf("  type: SSH_TRANSPORT_PACKET\n");
                printf("  packet_length: %u\n", (unsigned)t->packet_length);
                printf("  padding_length: %u\n", (unsigned)t->padding_length);
                printf("  payload_len: %u\n", (unsigned)t->payload_len);
                printf("  has_message_code (Optional): %u\n", (unsigned)t->has_message_code);
                printf("  message_code (Optional): %u\n", (unsigned)t->message_code);
                printf("  payload: "); print_bytes((const unsigned char*)t->payload, t->payload_len); printf("\n");
                printf("  padding (%u bytes): ", (unsigned)t->padding_length);
                print_bytes((const unsigned char*)t->padding, t->padding_length);
                printf("\n");
                break;
            }
            case SSH_KEXINIT: {
                const ssh_kexinit_t *k = &packets[i].u.kexinit;
                printf("  type: SSH_KEXINIT\n");
                printf("  message_code (Fixed): %u\n", (unsigned)k->message_code);
                printf("  cookie: "); print_bytes(k->cookie, 16); printf("\n");
                printf("  kex_algorithms_len: %u\n", (unsigned)k->kex_algorithms_len);
                printf("  kex_algorithms: "); print_bytes(k->kex_algorithms, k->kex_algorithms_len); printf("\n");
                printf("  server_host_key_algorithms_len: %u\n", (unsigned)k->server_host_key_algorithms_len);
                printf("  server_host_key_algorithms: "); print_bytes(k->server_host_key_algorithms, k->server_host_key_algorithms_len); printf("\n");
                printf("  enc c->s len: %u\n", (unsigned)k->encryption_algorithms_client_to_server_len);
                printf("  enc c->s: "); print_bytes(k->encryption_algorithms_client_to_server, k->encryption_algorithms_client_to_server_len); printf("\n");
                printf("  enc s->c len: %u\n", (unsigned)k->encryption_algorithms_server_to_client_len);
                printf("  enc s->c: "); print_bytes(k->encryption_algorithms_server_to_client, k->encryption_algorithms_server_to_client_len); printf("\n");
                printf("  mac c->s len: %u\n", (unsigned)k->mac_algorithms_client_to_server_len);
                printf("  mac c->s: "); print_bytes(k->mac_algorithms_client_to_server, k->mac_algorithms_client_to_server_len); printf("\n");
                printf("  mac s->c len: %u\n", (unsigned)k->mac_algorithms_server_to_client_len);
                printf("  mac s->c: "); print_bytes(k->mac_algorithms_server_to_client, k->mac_algorithms_server_to_client_len); printf("\n");
                printf("  comp c->s len: %u\n", (unsigned)k->compression_algorithms_client_to_server_len);
                printf("  comp c->s: "); print_bytes(k->compression_algorithms_client_to_server, k->compression_algorithms_client_to_server_len); printf("\n");
                printf("  comp s->c len: %u\n", (unsigned)k->compression_algorithms_server_to_client_len);
                printf("  comp s->c: "); print_bytes(k->compression_algorithms_server_to_client, k->compression_algorithms_server_to_client_len); printf("\n");
                printf("  lang c->s len: %u\n", (unsigned)k->languages_client_to_server_len);
                printf("  lang c->s: "); print_bytes(k->languages_client_to_server, k->languages_client_to_server_len); printf("\n");
                printf("  lang s->c len: %u\n", (unsigned)k->languages_server_to_client_len);
                printf("  lang s->c: "); print_bytes(k->languages_server_to_client, k->languages_server_to_client_len); printf("\n");
                printf("  first_kex_packet_follows: %u\n", (unsigned)k->first_kex_packet_follows);
                printf("  reserved_zero (Fixed): %u\n", (unsigned)k->reserved_zero);
                break;
            }
            case SSH_KEXDH_INIT: {
                const ssh_kexdh_init_t *d = &packets[i].u.kexdh_init;
                printf("  type: SSH_KEXDH_INIT\n");
                printf("  message_code (Fixed): %u\n", (unsigned)d->message_code);
                printf("  e_len: %u\n", (unsigned)d->e_len);
                printf("  e: "); print_bytes(d->e, d->e_len); printf("\n");
                break;
            }
            case SSH_SERVICE_REQUEST: {
                const ssh_service_request_t *s = &packets[i].u.service_request;
                printf("  type: SSH_SERVICE_REQUEST\n");
                printf("  message_code (Fixed): %u\n", (unsigned)s->message_code);
                printf("  service_name_len: %u\n", (unsigned)s->service_name_len);
                printf("  service_name: "); print_bytes(s->service_name, s->service_name_len); printf("\n");
                break;
            }
            case SSH_NEWKEYS: {
                const ssh_newkeys_t *n = &packets[i].u.newkeys;
                printf("  type: SSH_NEWKEYS\n");
                printf("  message_code (Fixed): %u\n", (unsigned)n->message_code);
                break;
            }
            case SSH_OPAQUE: {
                const ssh_opaque_t *o = &packets[i].u.opaque;
                printf("  type: SSH_OPAQUE\n");
                printf("  len: %u\n", (unsigned)o->len);
                printf("  bytes: "); print_bytes(o->bytes, o->len); printf("\n");
                break;
            }
            default: {
                const char *tn = ssh_type_name(packets[i].type);
                if (tn) {
                    const ssh_typed_payload_t *tp = &packets[i].u.typed;
                    printf("  type: %s\n", tn);
                    printf("  message_code: %u\n", (unsigned)tp->message_code);
                    printf("  payload_len: %u\n", (unsigned)tp->payload_len);
                    printf("  payload: "); print_bytes(tp->payload, tp->payload_len); printf("\n");
                } else {
                    printf("  type: (unknown enum %d)\n", packets[i].type);
                }
                break;
            }
        }
    }
}
