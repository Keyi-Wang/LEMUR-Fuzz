#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "tls.h"
#include "../../llm/tls/tls_fixers.c"

static int test_change_cipher_spec(void) {
    tls_packet_t p;
    memset(&p, 0, sizeof(p));
    p.type = TLS_PACKET_CHANGE_CIPHER_SPEC;
    p.u.change_cipher_spec.record.type = 99;
    p.u.change_cipher_spec.record.version.major = 9;
    p.u.change_cipher_spec.record.version.minor = 9;
    p.u.change_cipher_spec.record.length = 9;
    p.u.change_cipher_spec.ccs.type = 9;
    fix_change_cipher_spec_type(&p, 1);
    return p.u.change_cipher_spec.record.type == TLS_CONTENTTYPE_CHANGE_CIPHER_SPEC &&
           p.u.change_cipher_spec.record.version.major == 3 &&
           p.u.change_cipher_spec.record.version.minor == 3 &&
           p.u.change_cipher_spec.record.length == 1 &&
           p.u.change_cipher_spec.ccs.type == 1;
}

static int test_alert(void) {
    tls_packet_t p;
    memset(&p, 0, sizeof(p));
    p.type = TLS_PACKET_ALERT;
    p.u.alert.record.type = 99;
    p.u.alert.record.version.major = 4;
    p.u.alert.record.version.minor = 99;
    p.u.alert.record.length = 99;
    p.u.alert.alert.level = 99;
    fix_alert_record(&p, 1);
    return p.u.alert.record.type == TLS_CONTENTTYPE_ALERT &&
           p.u.alert.record.version.major == 3 &&
           p.u.alert.record.version.minor == 3 &&
           p.u.alert.record.length == 2 &&
           p.u.alert.alert.level == TLS_ALERT_LEVEL_FATAL;
}

static int test_handshake(void) {
    tls_packet_t p;
    memset(&p, 0, sizeof(p));
    uint8_t body[9] = { TLS_HANDSHAKE_CLIENT_HELLO, 0xff, 0xff, 0xff, 1, 2, 3, 4, 5 };
    p.type = TLS_PACKET_HANDSHAKE;
    p.u.handshake.record.type = 1;
    p.u.handshake.record.version.major = 3;
    p.u.handshake.record.version.minor = 9;
    p.u.handshake.record.length = 0xffff;
    p.u.handshake.handshake.msg_type = TLS_HANDSHAKE_CLIENT_HELLO;
    p.u.handshake.handshake.length.b0 = 0xff;
    p.u.handshake.handshake.length.b1 = 0xff;
    p.u.handshake.handshake.length.b2 = 0xff;
    p.u.handshake.handshake.body = body;
    p.u.handshake.handshake.body_len = sizeof(body);
    fix_handshake_record(&p, 1);
    return p.u.handshake.record.type == TLS_CONTENTTYPE_HANDSHAKE &&
           p.u.handshake.record.length == 9 &&
           p.u.handshake.handshake.length.b0 == 0 &&
           p.u.handshake.handshake.length.b1 == 0 &&
           p.u.handshake.handshake.length.b2 == 5 &&
           p.u.handshake.handshake.body[0] == TLS_HANDSHAKE_CLIENT_HELLO;
}

static int test_application_data(void) {
    tls_packet_t p;
    memset(&p, 0, sizeof(p));
    p.type = TLS_PACKET_APPLICATION_DATA;
    p.u.application_data.record.type = 1;
    p.u.application_data.record.version.major = 3;
    p.u.application_data.record.version.minor = 9;
    p.u.application_data.record.length = 0xffff;
    p.u.application_data.app_data.data = NULL;
    p.u.application_data.app_data.data_len = 8;
    fix_application_data_record(&p, 1);
    int ok = p.u.application_data.record.type == TLS_CONTENTTYPE_APPLICATION_DATA &&
             p.u.application_data.record.version.minor == 3 &&
             p.u.application_data.record.length == 8 &&
             p.u.application_data.app_data.data != NULL;
    free(p.u.application_data.app_data.data);
    return ok;
}

int main(void) {
    int passed = 0, failed = 0;
    if (test_change_cipher_spec()) { puts("[PASS] fix_change_cipher_spec_type"); passed++; } else { puts("[FAIL] fix_change_cipher_spec_type"); failed++; }
    if (test_alert()) { puts("[PASS] fix_alert_record"); passed++; } else { puts("[FAIL] fix_alert_record"); failed++; }
    if (test_handshake()) { puts("[PASS] fix_handshake_record"); passed++; } else { puts("[FAIL] fix_handshake_record"); failed++; }
    if (test_application_data()) { puts("[PASS] fix_application_data_record"); passed++; } else { puts("[FAIL] fix_application_data_record"); failed++; }
    printf("%s passed=%d failed=%d total=%d\n", failed ? "[FAIL]" : "[PASS]", passed, failed, passed + failed);
    return failed ? 1 : 0;
}
