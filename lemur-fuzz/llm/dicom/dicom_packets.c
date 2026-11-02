// ./llm/dicom/dicom_packets.c
#include "dicom_packets.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_bytes(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (i && (i % 16 == 0)) printf("\n");
        printf("%02X ", buf[i]);
    }
    if (len) printf("\n");
}

static void print_str(const char *label, const dicom_str_t *s) {
    printf("%s.length=%u\n", label, (unsigned)s->length);
    printf("%s.value=", label);
    if (s->length) {
        for (uint16_t i = 0; i < s->length && s->value[i]; ++i) putchar(s->value[i]);
    }
    printf("\n");
}

static void print_app_context(const dicom_app_context_item_t *ac) {
    printf("  Application Context Item:\n");
    printf("    item_type=0x%02X /* Fixed */\n", ac->item_type);
    printf("    reserved1=0x%02X /* Fixed */\n", ac->reserved1);
    printf("    item_length=%u\n", ac->item_length);
    print_str("    application_context_name", &ac->application_context_name);
}

static void print_abs_syntax(const dicom_abstract_syntax_item_t *as) {
    printf("    Abstract Syntax Item:\n");
    printf("      item_type=0x%02X /* Fixed */\n", as->item_type);
    printf("      reserved1=0x%02X /* Fixed */\n", as->reserved1);
    printf("      item_length=%u\n", as->item_length);
    print_str("      abstract_syntax_name", &as->abstract_syntax_name);
}

static void print_xfer_syntax(const dicom_transfer_syntax_item_t *ts) {
    printf("      Transfer Syntax Item:\n");
    printf("        item_type=0x%02X /* Fixed */\n", ts->item_type);
    printf("        reserved1=0x%02X /* Fixed */\n", ts->reserved1);
    printf("        item_length=%u\n", ts->item_length);
    print_str("        transfer_syntax_name", &ts->transfer_syntax_name);
}

static void print_pc_item(const dicom_presentation_context_item_t *pc) {
    printf("  Presentation Context Item:\n");
    printf("    item_type=0x%02X /* Fixed */\n", pc->item_type);
    printf("    reserved1=0x%02X /* Fixed */\n", pc->reserved1);
    printf("    item_length=%u\n", pc->item_length);
    printf("    presentation_context_id=%u\n", pc->presentation_context_id);
    printf("    reserved2[0..2]=%02X %02X %02X /* Fixed */\n", pc->reserved2[0], pc->reserved2[1], pc->reserved2[2]);
    print_abs_syntax(&pc->abstract_syntax);
    printf("    transfer_syntax_count=%u\n", pc->transfer_syntax_count);
    for (uint8_t i = 0; i < pc->transfer_syntax_count && i < DICOM_MAX_TRANSFER_SYNTAXES; ++i) {
        print_xfer_syntax(&pc->transfer_syntaxes[i]);
    }
}

static void print_user_info_item(const dicom_user_info_item_t *ui) {
    printf("  User Information Item:\n");
    printf("    item_type=0x%02X /* Fixed */\n", ui->item_type);
    printf("    reserved1=0x%02X /* Fixed */\n", ui->reserved1);
    printf("    item_length=%u\n", ui->item_length);
    printf("    has_user_data=%u /* Optional */\n", ui->has_user_data);
    printf("    user_data_length=%u\n", (unsigned)ui->user_data_length);
    if (ui->has_user_data && ui->user_data_length) {
        print_bytes(ui->user_data, ui->user_data_length);
    }
}

static void print_a_associate_rq(const dicom_a_associate_rq_pdu_t *p) {
    printf("A-ASSOCIATE-RQ PDU:\n");
    printf("  pdu_type=0x%02X /* Fixed */\n", p->pdu_type);
    printf("  reserved1=0x%02X /* Fixed */\n", p->reserved1);
    printf("  pdu_length=%u\n", p->pdu_length);
    printf("  protocol_version=0x%04X\n", p->protocol_version);
    printf("  reserved2=0x%04X /* Fixed */\n", p->reserved2);
    printf("  called_ae_title='%.*s'\n", 16, p->called_ae_title);
    printf("  calling_ae_title='%.*s'\n", 16, p->calling_ae_title);
    printf("  reserved3[32] /* Fixed */\n");
    print_app_context(&p->application_context);
    printf("  presentation_context_count=%u\n", p->presentation_context_count);
    for (uint8_t i = 0; i < p->presentation_context_count && i < DICOM_MAX_PRESENTATION_CONTEXTS; ++i) {
        print_pc_item(&p->presentation_contexts[i]);
    }
    printf("  has_user_info=%u /* Optional */\n", p->has_user_info);
    if (p->has_user_info) {
        print_user_info_item(&p->user_info);
    }
}

static void print_pdv(const dicom_pdv_item_t *pdv) {
    printf("  PDV Item:\n");
    printf("    pdv_length=%u\n", pdv->pdv_length);
    printf("    presentation_context_id=%u\n", pdv->presentation_context_id);
    printf("    control_header=0x%02X\n", pdv->control_header);
    printf("    data_length=%u\n", pdv->data_length);
    if (pdv->data_length) print_bytes(pdv->data, pdv->data_length);
}


static void print_a_associate_ac(const dicom_a_associate_ac_pdu_t *p) {
    printf("A-ASSOCIATE-AC PDU:\n");
    printf("  pdu_type=0x%02X /* Fixed */\n", p->pdu_type);
    printf("  reserved1=0x%02X /* Fixed */\n", p->reserved1);
    printf("  pdu_length=%u\n", p->pdu_length);
    printf("  protocol_version=0x%04X\n", p->protocol_version);
    printf("  called_ae_title='%.*s'\n", 16, p->called_ae_title);
    printf("  calling_ae_title='%.*s'\n", 16, p->calling_ae_title);
    printf("  raw_items_length=%u\n", (unsigned)p->raw_items_length);
}

static void print_a_associate_rj(const dicom_a_associate_rj_pdu_t *p) {
    printf("A-ASSOCIATE-RJ PDU:\n");
    printf("  pdu_type=0x%02X /* Fixed */\n", p->pdu_type);
    printf("  pdu_length=%u /* Fixed */\n", p->pdu_length);
    printf("  result=0x%02X source=0x%02X reason_diag=0x%02X\n", p->result, p->source, p->reason_diag);
}

static void print_p_data_tf(const dicom_p_data_tf_pdu_t *p) {
    printf("P-DATA-TF PDU:\n");
    printf("  pdu_type=0x%02X /* Fixed */\n", p->pdu_type);
    printf("  reserved1=0x%02X /* Fixed */\n", p->reserved1);
    printf("  pdu_length=%u\n", p->pdu_length);
    printf("  pdv_count=%u\n", p->pdv_count);
    for (uint16_t i = 0; i < p->pdv_count && i < DICOM_MAX_PDV_ITEMS; ++i) {
        print_pdv(&p->pdvs[i]);
    }
}

static void print_a_release_rq(const dicom_a_release_rq_pdu_t *p) {
    printf("A-RELEASE-RQ PDU:\n");
    printf("  pdu_type=0x%02X /* Fixed */\n", p->pdu_type);
    printf("  reserved1=0x%02X /* Fixed */\n", p->reserved1);
    printf("  pdu_length=%u /* Fixed */\n", p->pdu_length);
    printf("  reserved2=0x%04X /* Fixed */\n", p->reserved2);
    printf("  reserved3=0x%04X /* Fixed */\n", p->reserved3);
}


static void print_a_release_rp(const dicom_a_release_rp_pdu_t *p) {
    printf("A-RELEASE-RP PDU:\n");
    printf("  pdu_type=0x%02X /* Fixed */\n", p->pdu_type);
    printf("  reserved1=0x%02X /* Fixed */\n", p->reserved1);
    printf("  pdu_length=%u /* Fixed */\n", p->pdu_length);
    printf("  reserved2=0x%04X /* Fixed */\n", p->reserved2);
    printf("  reserved3=0x%04X /* Fixed */\n", p->reserved3);
}

static void print_a_abort(const dicom_a_abort_pdu_t *p) {
    printf("A-ABORT PDU:\n");
    printf("  pdu_type=0x%02X /* Fixed */\n", p->pdu_type);
    printf("  reserved1=0x%02X /* Fixed */\n", p->reserved1);
    printf("  pdu_length=%u /* Fixed */\n", p->pdu_length);
    printf("  reserved2=0x%02X /* Fixed */\n", p->reserved2);
    printf("  reserved3=0x%02X /* Fixed */\n", p->reserved3);
    printf("  source=0x%02X\n", p->source);
    printf("  reason_diag=0x%02X\n", p->reason_diag);
}

void print_dicom_packets(const dicom_packet_t *packets, int count) {
    if (!packets || count <= 0) return;
    for (int i = 0; i < count; ++i) {
        printf("Packet #%d type=%d\n", i, packets[i].type);
        switch (packets[i].type) {
            case DICOM_PKT_A_ASSOCIATE_RQ:
                print_a_associate_rq(&packets[i].u.a_associate_rq);
                break;
            case DICOM_PKT_A_ASSOCIATE_AC:
                print_a_associate_ac(&packets[i].u.a_associate_ac);
                break;
            case DICOM_PKT_A_ASSOCIATE_RJ:
                print_a_associate_rj(&packets[i].u.a_associate_rj);
                break;
            case DICOM_PKT_P_DATA_TF:
                print_p_data_tf(&packets[i].u.p_data_tf);
                break;
            case DICOM_PKT_A_RELEASE_RQ:
                print_a_release_rq(&packets[i].u.a_release_rq);
                break;
            case DICOM_PKT_A_RELEASE_RP:
                print_a_release_rp(&packets[i].u.a_release_rp);
                break;
            case DICOM_PKT_A_ABORT:
                print_a_abort(&packets[i].u.a_abort);
                break;
            default:
                printf("Unknown packet type\n");
                break;
        }
    }
}

dicom_packet_t* generate_dicom_packets(int count) {
    if (count <= 0) return NULL;
    dicom_packet_t *packets = (dicom_packet_t *)malloc(sizeof(dicom_packet_t) * count);
    if (!packets) return NULL;
    memset(packets, 0, sizeof(dicom_packet_t) * count);
    for (int i = 0; i < count; ++i) {
        packets[i].type = DICOM_PKT_UNKNOWN;
    }
    return packets;
}
