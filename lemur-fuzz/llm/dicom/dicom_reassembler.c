// ./llm/dicom/dicom_reassembler.c
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "dicom_packets.h"

static int wr_u8(uint8_t *buf, uint32_t maxlen, uint32_t *off, uint8_t v) {
    if (*off + 1 > maxlen) return 0;
    buf[*off] = v;
    (*off)++;
    return 1;
}
static int wr_u16_be(uint8_t *buf, uint32_t maxlen, uint32_t *off, uint16_t v) {
    if (*off + 2 > maxlen) return 0;
    buf[*off] = (uint8_t)(v >> 8);
    buf[*off + 1] = (uint8_t)(v & 0xFF);
    *off += 2;
    return 1;
}
static int wr_u32_be(uint8_t *buf, uint32_t maxlen, uint32_t *off, uint32_t v) {
    if (*off + 4 > maxlen) return 0;
    buf[*off] = (uint8_t)(v >> 24);
    buf[*off + 1] = (uint8_t)((v >> 16) & 0xFF);
    buf[*off + 2] = (uint8_t)((v >> 8) & 0xFF);
    buf[*off + 3] = (uint8_t)(v & 0xFF);
    *off += 4;
    return 1;
}
static int wr_u16_le(uint8_t *buf, uint32_t maxlen, uint32_t *off, uint16_t v) {
    if (*off + 2 > maxlen) return 0;
    buf[*off] = (uint8_t)(v & 0xFF);
    buf[*off + 1] = (uint8_t)(v >> 8);
    *off += 2;
    return 1;
}
static int wr_u32_le(uint8_t *buf, uint32_t maxlen, uint32_t *off, uint32_t v) {
    if (*off + 4 > maxlen) return 0;
    buf[*off] = (uint8_t)(v & 0xFF);
    buf[*off + 1] = (uint8_t)((v >> 8) & 0xFF);
    buf[*off + 2] = (uint8_t)((v >> 16) & 0xFF);
    buf[*off + 3] = (uint8_t)(v >> 24);
    *off += 4;
    return 1;
}
static int wr_bytes(uint8_t *buf, uint32_t maxlen, uint32_t *off, const uint8_t *src, uint32_t n) {
    if (*off > maxlen || n > maxlen - *off || (n && !src)) return 0;
    if (n && src) memcpy(buf + *off, src, n);
    *off += n;
    return 1;
}

static int dimse_add_elem_header(uint8_t *buf, uint32_t maxlen, uint32_t *off,
                                 uint16_t elem, uint32_t vlen) {
    if (!wr_u16_le(buf, maxlen, off, 0x0000)) return 0;
    if (!wr_u16_le(buf, maxlen, off, elem)) return 0;
    if (!wr_u32_le(buf, maxlen, off, vlen)) return 0;
    return 1;
}

static int dimse_add_u16(uint8_t *buf, uint32_t maxlen, uint32_t *off,
                         uint16_t elem, uint16_t value) {
    if (!dimse_add_elem_header(buf, maxlen, off, elem, 2)) return 0;
    if (!wr_u16_le(buf, maxlen, off, value)) return 0;
    return 1;
}

static int dimse_add_bytes(uint8_t *buf, uint32_t maxlen, uint32_t *off,
                           uint16_t elem, const uint8_t *value, uint32_t len) {
    if (!value || len == 0) return 1;
    if (!dimse_add_elem_header(buf, maxlen, off, elem, len)) return 0;
    if (!wr_bytes(buf, maxlen, off, value, len)) return 0;
    return 1;
}

static uint16_t dimse_uid_len_bound(uint16_t len) {
    return len > DICOM_MAX_DIMSE_UID_LEN ? DICOM_MAX_DIMSE_UID_LEN : len;
}

static uint16_t dimse_ae_len_bound(uint16_t len) {
    return len > DICOM_MAX_DIMSE_AE_LEN ? DICOM_MAX_DIMSE_AE_LEN : len;
}

static uint16_t dimse_attr_len_bound(uint16_t len) {
    return len > DICOM_MAX_DIMSE_ATTR_LIST_LEN ? DICOM_MAX_DIMSE_ATTR_LIST_LEN : len;
}

static int dimse_add_uid(uint8_t *buf, uint32_t maxlen, uint32_t *off,
                         uint16_t elem, const uint8_t *value, uint32_t len) {
    if (!value || len == 0) return 1;
    uint32_t padded = len + (len & 1U);
    if (!dimse_add_elem_header(buf, maxlen, off, elem, padded)) return 0;
    if (!wr_bytes(buf, maxlen, off, value, len)) return 0;
    if (padded != len && !wr_u8(buf, maxlen, off, 0)) return 0;
    return 1;
}

static int dimse_requires_no_dataset(uint16_t cmd) {
    return cmd == DICOM_DIMSE_C_ECHO_RQ ||
           cmd == DICOM_DIMSE_C_CANCEL_RQ ||
           cmd == DICOM_DIMSE_N_GET_RQ ||
           cmd == DICOM_DIMSE_N_DELETE_RQ;
}

static uint32_t build_dimse_command_data(const dicom_pdv_item_t *pdv,
                                         uint8_t *buf, uint32_t maxlen) {
    if (!pdv || !buf) return 0;
    uint32_t off = 0;
    uint32_t present = pdv->dimse_fields_present;
    if (!dimse_add_elem_header(buf, maxlen, &off, 0x0000, 4)) return 0;
    uint32_t group_length_pos = off;
    if (!wr_u32_le(buf, maxlen, &off, 0)) return 0;
    uint16_t cmd = pdv->dimse_command_field ? pdv->dimse_command_field : DICOM_DIMSE_C_ECHO_RQ;
    uint16_t msg_id = pdv->dimse_message_id;
    uint16_t dataset_type = pdv->dimse_command_data_set_type;
    if (!present && dimse_requires_no_dataset(cmd)) dataset_type = 0x0101;

    if (dimse_uid_len_bound(pdv->dimse_affected_sop_class_uid_len)) {
        if (!dimse_add_uid(buf, maxlen, &off, 0x0002,
                           (const uint8_t*)pdv->dimse_affected_sop_class_uid,
                           dimse_uid_len_bound(pdv->dimse_affected_sop_class_uid_len))) return 0;
    }
    if (dimse_uid_len_bound(pdv->dimse_requested_sop_class_uid_len)) {
        if (!dimse_add_uid(buf, maxlen, &off, 0x0003,
                           (const uint8_t*)pdv->dimse_requested_sop_class_uid,
                           dimse_uid_len_bound(pdv->dimse_requested_sop_class_uid_len))) return 0;
    }
    if (!dimse_add_u16(buf, maxlen, &off, 0x0100, cmd)) return 0;
    if ((present & DICOM_DIMSE_PRESENT_MESSAGE_ID) || (!present && cmd != DICOM_DIMSE_C_CANCEL_RQ))
        if (!dimse_add_u16(buf, maxlen, &off, 0x0110, msg_id)) return 0;
    if ((present & DICOM_DIMSE_PRESENT_RESPONDED_TO) || pdv->dimse_message_id_responded_to || (!present && cmd == DICOM_DIMSE_C_CANCEL_RQ)) {
        if (!dimse_add_u16(buf, maxlen, &off, 0x0120, pdv->dimse_message_id_responded_to)) return 0;
    }
    if (dimse_ae_len_bound(pdv->dimse_move_destination_len)) {
        if (!dimse_add_bytes(buf, maxlen, &off, 0x0600,
                             (const uint8_t*)pdv->dimse_move_destination,
                             dimse_ae_len_bound(pdv->dimse_move_destination_len))) return 0;
    }
    if ((present & DICOM_DIMSE_PRESENT_PRIORITY) || (!present && (cmd == DICOM_DIMSE_C_STORE_RQ || cmd == DICOM_DIMSE_C_GET_RQ || cmd == DICOM_DIMSE_C_FIND_RQ || cmd == DICOM_DIMSE_C_MOVE_RQ)))
        if (!dimse_add_u16(buf, maxlen, &off, 0x0700, pdv->dimse_priority)) return 0;
    if (!dimse_add_u16(buf, maxlen, &off, 0x0800, dataset_type)) return 0;
    if ((present & DICOM_DIMSE_PRESENT_STATUS) || pdv->dimse_status) {
        if (!dimse_add_u16(buf, maxlen, &off, 0x0900, pdv->dimse_status)) return 0;
    }
    if (dimse_uid_len_bound(pdv->dimse_affected_sop_instance_uid_len)) {
        if (!dimse_add_uid(buf, maxlen, &off, 0x1000,
                           (const uint8_t*)pdv->dimse_affected_sop_instance_uid,
                           dimse_uid_len_bound(pdv->dimse_affected_sop_instance_uid_len))) return 0;
    }
    if (dimse_uid_len_bound(pdv->dimse_requested_sop_instance_uid_len)) {
        if (!dimse_add_uid(buf, maxlen, &off, 0x1001,
                           (const uint8_t*)pdv->dimse_requested_sop_instance_uid,
                           dimse_uid_len_bound(pdv->dimse_requested_sop_instance_uid_len))) return 0;
    }
    if ((present & DICOM_DIMSE_PRESENT_EVENT_TYPE) || pdv->dimse_event_type_id) {
        if (!dimse_add_u16(buf, maxlen, &off, 0x1002, pdv->dimse_event_type_id)) return 0;
    }
    if (dimse_attr_len_bound(pdv->dimse_attribute_identifier_list_len)) {
        if (!dimse_add_bytes(buf, maxlen, &off, 0x1005,
                             pdv->dimse_attribute_identifier_list,
                             dimse_attr_len_bound(pdv->dimse_attribute_identifier_list_len))) return 0;
    }
    if ((present & DICOM_DIMSE_PRESENT_ACTION_TYPE) || pdv->dimse_action_type_id) {
        if (!dimse_add_u16(buf, maxlen, &off, 0x1008, pdv->dimse_action_type_id)) return 0;
    }
    if (dimse_ae_len_bound(pdv->dimse_move_originator_ae_title_len)) {
        if (!dimse_add_bytes(buf, maxlen, &off, 0x1030,
                             (const uint8_t*)pdv->dimse_move_originator_ae_title,
                             dimse_ae_len_bound(pdv->dimse_move_originator_ae_title_len))) return 0;
    }
    if ((present & DICOM_DIMSE_PRESENT_ORIGINATOR_ID) || pdv->dimse_move_originator_message_id) {
        if (!dimse_add_u16(buf, maxlen, &off, 0x1031, pdv->dimse_move_originator_message_id)) return 0;
    }
    uint32_t group_length = off >= 12 ? off - 12U : 0;
    buf[group_length_pos] = (uint8_t)(group_length & 0xff);
    buf[group_length_pos + 1] = (uint8_t)((group_length >> 8) & 0xff);
    buf[group_length_pos + 2] = (uint8_t)((group_length >> 16) & 0xff);
    buf[group_length_pos + 3] = (uint8_t)((group_length >> 24) & 0xff);
    return off;
}

static uint16_t dicom_str_len_bound(const dicom_str_t *s);

static int reassemble_application_context(uint8_t *buf, uint32_t maxlen, uint32_t *off, const dicom_app_context_item_t *ac) {
    if (!wr_u8(buf, maxlen, off, 0x10)) return 0;
    if (!wr_u8(buf, maxlen, off, ac->reserved1)) return 0;
    uint16_t n = dicom_str_len_bound(&ac->application_context_name);
    if (!wr_u16_be(buf, maxlen, off, n)) return 0;
    if (!wr_bytes(buf, maxlen, off, (const uint8_t*)ac->application_context_name.value, n)) return 0;
    return 1;
}

static int reassemble_abstract_syntax(uint8_t *buf, uint32_t maxlen, uint32_t *off, const dicom_abstract_syntax_item_t *as) {
    if (!wr_u8(buf, maxlen, off, 0x30)) return 0;
    if (!wr_u8(buf, maxlen, off, as->reserved1)) return 0;
    uint16_t n = dicom_str_len_bound(&as->abstract_syntax_name);
    if (!wr_u16_be(buf, maxlen, off, n)) return 0;
    if (!wr_bytes(buf, maxlen, off, (const uint8_t*)as->abstract_syntax_name.value, n)) return 0;
    return 1;
}

static int reassemble_transfer_syntax(uint8_t *buf, uint32_t maxlen, uint32_t *off, const dicom_transfer_syntax_item_t *ts) {
    if (!wr_u8(buf, maxlen, off, 0x40)) return 0;
    if (!wr_u8(buf, maxlen, off, ts->reserved1)) return 0;
    uint16_t n = dicom_str_len_bound(&ts->transfer_syntax_name);
    if (!wr_u16_be(buf, maxlen, off, n)) return 0;
    if (!wr_bytes(buf, maxlen, off, (const uint8_t*)ts->transfer_syntax_name.value, n)) return 0;
    return 1;
}

static uint16_t dicom_str_len_bound(const dicom_str_t *s) {
    if (!s) return 0;
    return s->length > DICOM_MAX_UID_LEN ? DICOM_MAX_UID_LEN : s->length;
}

static int reassemble_user_info_subitem_str(uint8_t *buf, uint32_t maxlen, uint32_t *off, uint8_t item_type, const dicom_str_t *s) {
    uint16_t n = dicom_str_len_bound(s);
    if (!wr_u8(buf, maxlen, off, item_type)) return 0;
    if (!wr_u8(buf, maxlen, off, 0)) return 0;
    if (!wr_u16_be(buf, maxlen, off, n)) return 0;
    if (!wr_bytes(buf, maxlen, off, (const uint8_t*)s->value, n)) return 0;
    return 1;
}

static int reassemble_user_info(uint8_t *buf, uint32_t maxlen, uint32_t *off, const dicom_user_info_item_t *ui) {
    if (!wr_u8(buf, maxlen, off, 0x50)) return 0;
    if (!wr_u8(buf, maxlen, off, ui->reserved1)) return 0;
    uint32_t len_pos = *off;
    if (!wr_u16_be(buf, maxlen, off, 0)) return 0;
    if (ui->has_maximum_length) {
        if (!wr_u8(buf, maxlen, off, 0x51)) return 0;
        if (!wr_u8(buf, maxlen, off, 0)) return 0;
        if (!wr_u16_be(buf, maxlen, off, 4)) return 0;
        if (!wr_u32_be(buf, maxlen, off, ui->maximum_length_received)) return 0;
    }
    if (ui->has_implementation_class_uid) {
        if (!reassemble_user_info_subitem_str(buf, maxlen, off, 0x52, &ui->implementation_class_uid)) return 0;
    }
    if (ui->has_async_ops_window) {
        if (!wr_u8(buf, maxlen, off, 0x53)) return 0;
        if (!wr_u8(buf, maxlen, off, 0)) return 0;
        if (!wr_u16_be(buf, maxlen, off, 4)) return 0;
        if (!wr_u16_be(buf, maxlen, off, ui->max_ops_invoked)) return 0;
        if (!wr_u16_be(buf, maxlen, off, ui->max_ops_performed)) return 0;
    }
    uint8_t roles = ui->role_selection_count;
    if (roles > DICOM_MAX_ROLE_SELECTIONS) roles = DICOM_MAX_ROLE_SELECTIONS;
    for (uint8_t i = 0; i < roles; i++) {
        uint16_t uid_len = dicom_str_len_bound(&ui->role_selections[i].sop_class_uid);
        if (!wr_u8(buf, maxlen, off, 0x54)) return 0;
        if (!wr_u8(buf, maxlen, off, 0)) return 0;
        if (!wr_u16_be(buf, maxlen, off, (uint16_t)(4 + uid_len))) return 0;
        if (!wr_u16_be(buf, maxlen, off, uid_len)) return 0;
        if (!wr_bytes(buf, maxlen, off, (const uint8_t*)ui->role_selections[i].sop_class_uid.value, uid_len)) return 0;
        if (!wr_u8(buf, maxlen, off, ui->role_selections[i].scu_role ? 1 : 0)) return 0;
        if (!wr_u8(buf, maxlen, off, ui->role_selections[i].scp_role ? 1 : 0)) return 0;
    }
    if (ui->has_implementation_version_name) {
        if (!reassemble_user_info_subitem_str(buf, maxlen, off, 0x55, &ui->implementation_version_name)) return 0;
    }
    if (ui->has_sop_class_extended_negotiation) {
        uint16_t uid_len = dicom_str_len_bound(&ui->sop_class_extended_uid);
        uint16_t info_len = ui->sop_class_extended_info_len > DICOM_MAX_USER_INFO_BYTES ? DICOM_MAX_USER_INFO_BYTES : ui->sop_class_extended_info_len;
        if (!wr_u8(buf, maxlen, off, 0x56)) return 0;
        if (!wr_u8(buf, maxlen, off, 0)) return 0;
        if (!wr_u16_be(buf, maxlen, off, (uint16_t)(2u + uid_len + info_len))) return 0;
        if (!wr_u16_be(buf, maxlen, off, uid_len)) return 0;
        if (!wr_bytes(buf, maxlen, off, (const uint8_t*)ui->sop_class_extended_uid.value, uid_len)) return 0;
        if (!wr_bytes(buf, maxlen, off, ui->sop_class_extended_info, info_len)) return 0;
    }
    if (ui->has_sop_class_common_extended_negotiation) {
        uint16_t sop_len = dicom_str_len_bound(&ui->sop_class_common_sop_uid);
        uint16_t svc_len = dicom_str_len_bound(&ui->sop_class_common_service_class_uid);
        uint32_t item_len = 2u + sop_len + 2u + svc_len + 2u;
        uint8_t rel_count = ui->related_general_sop_class_uid_count;
        if (rel_count > DICOM_MAX_RELATED_SOP_CLASSES) rel_count = DICOM_MAX_RELATED_SOP_CLASSES;
        for (uint8_t i = 0; i < rel_count; i++) item_len += 2u + dicom_str_len_bound(&ui->related_general_sop_class_uids[i]);
        if (item_len > 0xffffU) return 0;
        if (!wr_u8(buf, maxlen, off, 0x57)) return 0;
        if (!wr_u8(buf, maxlen, off, 0)) return 0;
        if (!wr_u16_be(buf, maxlen, off, (uint16_t)item_len)) return 0;
        if (!wr_u16_be(buf, maxlen, off, sop_len)) return 0;
        if (!wr_bytes(buf, maxlen, off, (const uint8_t*)ui->sop_class_common_sop_uid.value, sop_len)) return 0;
        if (!wr_u16_be(buf, maxlen, off, svc_len)) return 0;
        if (!wr_bytes(buf, maxlen, off, (const uint8_t*)ui->sop_class_common_service_class_uid.value, svc_len)) return 0;
        if (!wr_u16_be(buf, maxlen, off, (uint16_t)(item_len - 6u - sop_len - svc_len))) return 0;
        for (uint8_t i = 0; i < rel_count; i++) {
            uint16_t rel_len = dicom_str_len_bound(&ui->related_general_sop_class_uids[i]);
            if (!wr_u16_be(buf, maxlen, off, rel_len)) return 0;
            if (!wr_bytes(buf, maxlen, off, (const uint8_t*)ui->related_general_sop_class_uids[i].value, rel_len)) return 0;
        }
    }
    if (ui->has_user_identity_negotiation) {
        uint16_t primary_len = ui->user_identity_primary_field_len > DICOM_MAX_USER_INFO_BYTES ? DICOM_MAX_USER_INFO_BYTES : ui->user_identity_primary_field_len;
        uint16_t secondary_len = ui->user_identity_secondary_field_len > DICOM_MAX_USER_INFO_BYTES ? DICOM_MAX_USER_INFO_BYTES : ui->user_identity_secondary_field_len;
        if (!wr_u8(buf, maxlen, off, 0x58)) return 0;
        if (!wr_u8(buf, maxlen, off, 0)) return 0;
        if (!wr_u16_be(buf, maxlen, off, (uint16_t)(6u + primary_len + secondary_len))) return 0;
        if (!wr_u8(buf, maxlen, off, ui->user_identity_type)) return 0;
        if (!wr_u8(buf, maxlen, off, ui->user_identity_positive_response_requested ? 1 : 0)) return 0;
        if (!wr_u16_be(buf, maxlen, off, primary_len)) return 0;
        if (!wr_bytes(buf, maxlen, off, ui->user_identity_primary_field, primary_len)) return 0;
        if (!wr_u16_be(buf, maxlen, off, secondary_len)) return 0;
        if (!wr_bytes(buf, maxlen, off, ui->user_identity_secondary_field, secondary_len)) return 0;
    }
    if (ui->has_user_data && ui->user_data_length) {
        uint32_t raw = ui->user_data_length;
        if (raw > DICOM_MAX_USER_INFO_BYTES) raw = DICOM_MAX_USER_INFO_BYTES;
        if (!wr_bytes(buf, maxlen, off, ui->user_data, raw)) return 0;
    }
    uint32_t item_len = *off - (len_pos + 2);
    if (item_len > 0xffffU) return 0;
    buf[len_pos] = (uint8_t)(item_len >> 8);
    buf[len_pos + 1] = (uint8_t)(item_len & 0xff);
    return 1;
}

static int reassemble_presentation_context(uint8_t *buf, uint32_t maxlen, uint32_t *off, const dicom_presentation_context_item_t *pc) {
    uint32_t start = *off;
    (void)start;
    if (!wr_u8(buf, maxlen, off, 0x20)) return 0;
    if (!wr_u8(buf, maxlen, off, pc->reserved1)) return 0;
    uint32_t len_pos = *off;
    if (!wr_u16_be(buf, maxlen, off, 0)) return 0;
    if (!wr_u8(buf, maxlen, off, pc->presentation_context_id)) return 0;
    if (!wr_bytes(buf, maxlen, off, pc->reserved2, 3)) return 0;
    if (!reassemble_abstract_syntax(buf, maxlen, off, &pc->abstract_syntax)) return 0;
    uint8_t ts_count = pc->transfer_syntax_count;
    if (ts_count > DICOM_MAX_TRANSFER_SYNTAXES) ts_count = DICOM_MAX_TRANSFER_SYNTAXES;
    for (uint8_t i = 0; i < ts_count; ++i) {
        if (!reassemble_transfer_syntax(buf, maxlen, off, &pc->transfer_syntaxes[i])) return 0;
    }
    uint32_t item_len = (uint32_t)(*off - (len_pos + 2));
    buf[len_pos] = (uint8_t)(item_len >> 8);
    buf[len_pos + 1] = (uint8_t)(item_len & 0xFF);
    return 1;
}


static int reassemble_presentation_context_ac(uint8_t *buf, uint32_t maxlen, uint32_t *off, const dicom_presentation_context_ac_item_t *pc) {
    if (!wr_u8(buf, maxlen, off, 0x21)) return 0;
    if (!wr_u8(buf, maxlen, off, pc->reserved1)) return 0;
    uint32_t len_pos = *off;
    if (!wr_u16_be(buf, maxlen, off, 0)) return 0;
    if (!wr_u8(buf, maxlen, off, pc->presentation_context_id)) return 0;
    if (!wr_u8(buf, maxlen, off, pc->reserved2)) return 0;
    if (!wr_u8(buf, maxlen, off, pc->result_reason)) return 0;
    if (!wr_u8(buf, maxlen, off, pc->reserved3)) return 0;
    if (pc->has_transfer_syntax) {
        if (!reassemble_transfer_syntax(buf, maxlen, off, &pc->transfer_syntax)) return 0;
    }
    uint32_t item_len = *off - (len_pos + 2);
    if (item_len > 0xffffU) return 0;
    buf[len_pos] = (uint8_t)(item_len >> 8);
    buf[len_pos + 1] = (uint8_t)item_len;
    return 1;
}

static int reassemble_a_associate_rq(uint8_t *buf, uint32_t maxlen, uint32_t *off, const dicom_a_associate_rq_pdu_t *p) {
    uint32_t start = *off;
    (void)start;
    if (!wr_u8(buf, maxlen, off, DICOM_PDU_A_ASSOCIATE_RQ)) return 0;
    if (!wr_u8(buf, maxlen, off, p->reserved1)) return 0;
    uint32_t len_pos = *off;
    if (!wr_u32_be(buf, maxlen, off, 0)) return 0;
    if (!wr_u16_be(buf, maxlen, off, p->protocol_version)) return 0;
    if (!wr_u16_be(buf, maxlen, off, p->reserved2)) return 0;
    if (!wr_bytes(buf, maxlen, off, (const uint8_t*)p->called_ae_title, 16)) return 0;
    if (!wr_bytes(buf, maxlen, off, (const uint8_t*)p->calling_ae_title, 16)) return 0;
    if (!wr_bytes(buf, maxlen, off, p->reserved3, 32)) return 0;
    if (!reassemble_application_context(buf, maxlen, off, &p->application_context)) return 0;
    uint8_t pc_count = p->presentation_context_count;
    if (pc_count > DICOM_MAX_PRESENTATION_CONTEXTS) pc_count = DICOM_MAX_PRESENTATION_CONTEXTS;
    for (uint8_t i = 0; i < pc_count; ++i) {
        if (!reassemble_presentation_context(buf, maxlen, off, &p->presentation_contexts[i])) return 0;
    }
    if (p->has_user_info) {
        if (!reassemble_user_info(buf, maxlen, off, &p->user_info)) return 0;
    }
    uint32_t pdu_len = (uint32_t)(*off - (len_pos + 4));
    buf[len_pos] = (uint8_t)(pdu_len >> 24);
    buf[len_pos + 1] = (uint8_t)((pdu_len >> 16) & 0xFF);
    buf[len_pos + 2] = (uint8_t)((pdu_len >> 8) & 0xFF);
    buf[len_pos + 3] = (uint8_t)(pdu_len & 0xFF);
    return 1;
}


static int reassemble_a_associate_ac(uint8_t *buf, uint32_t maxlen, uint32_t *off, const dicom_a_associate_ac_pdu_t *p) {
    uint32_t start = *off;
    if (!wr_u8(buf, maxlen, off, DICOM_PDU_A_ASSOCIATE_AC)) return 0;
    if (!wr_u8(buf, maxlen, off, p->reserved1)) return 0;
    uint32_t len_pos = *off;
    if (!wr_u32_be(buf, maxlen, off, 0)) return 0;
    if (!wr_u16_be(buf, maxlen, off, p->protocol_version ? p->protocol_version : 1)) return 0;
    if (!wr_u16_be(buf, maxlen, off, p->reserved2)) return 0;
    if (!wr_bytes(buf, maxlen, off, (const uint8_t*)p->called_ae_title, 16)) return 0;
    if (!wr_bytes(buf, maxlen, off, (const uint8_t*)p->calling_ae_title, 16)) return 0;
    if (!wr_bytes(buf, maxlen, off, p->reserved3, 32)) return 0;
    if (p->has_application_context) {
        if (!reassemble_application_context(buf, maxlen, off, &p->application_context)) return 0;
    }
    uint8_t pc_count = p->presentation_context_count;
    if (pc_count > DICOM_MAX_PRESENTATION_CONTEXTS) pc_count = DICOM_MAX_PRESENTATION_CONTEXTS;
    for (uint8_t i = 0; i < pc_count; i++) {
        if (!reassemble_presentation_context_ac(buf, maxlen, off, &p->presentation_contexts[i])) return 0;
    }
    if (p->has_user_info) {
        if (!reassemble_user_info(buf, maxlen, off, &p->user_info)) return 0;
    }
    uint32_t raw_len = p->raw_items_length;
    if (raw_len > DICOM_MAX_UNKNOWN_PDU_LEN) raw_len = DICOM_MAX_UNKNOWN_PDU_LEN;
    if (raw_len && !wr_bytes(buf, maxlen, off, p->raw_items, raw_len)) return 0;
    uint32_t pdu_len = (uint32_t)(*off - (len_pos + 4));
    buf[len_pos] = (uint8_t)(pdu_len >> 24);
    buf[len_pos + 1] = (uint8_t)((pdu_len >> 16) & 0xFF);
    buf[len_pos + 2] = (uint8_t)((pdu_len >> 8) & 0xFF);
    buf[len_pos + 3] = (uint8_t)(pdu_len & 0xFF);
    (void)start;
    return 1;
}

static int reassemble_a_associate_rj(uint8_t *buf, uint32_t maxlen, uint32_t *off, const dicom_a_associate_rj_pdu_t *p) {
    if (!wr_u8(buf, maxlen, off, DICOM_PDU_A_ASSOCIATE_RJ)) return 0;
    if (!wr_u8(buf, maxlen, off, p->reserved1)) return 0;
    if (!wr_u32_be(buf, maxlen, off, 4)) return 0;
    if (!wr_u8(buf, maxlen, off, 0)) return 0;
    if (!wr_u8(buf, maxlen, off, p->result ? p->result : 1)) return 0;
    if (!wr_u8(buf, maxlen, off, p->source ? p->source : 1)) return 0;
    if (!wr_u8(buf, maxlen, off, p->reason_diag ? p->reason_diag : 1)) return 0;
    return 1;
}

static int reassemble_pdv_item(uint8_t *buf, uint32_t maxlen, uint32_t *off, const dicom_pdv_item_t *pdv) {
    uint8_t dimse_data[DICOM_MAX_PDV_DATA_LEN];
    const uint8_t *data = pdv->data;
    uint32_t data_len = pdv->data_length;
    if (pdv->has_dimse_command) {
        uint32_t built = build_dimse_command_data(pdv, dimse_data, sizeof(dimse_data));
        if (built > 0) {
            data = dimse_data;
            data_len = built;
        }
    }
    if (data_len > DICOM_MAX_PDV_DATA_LEN) data_len = DICOM_MAX_PDV_DATA_LEN;
    uint32_t tail_len = pdv->has_dimse_command ? 0 : pdv->data_tail_length;
    if (tail_len > UINT32_MAX - data_len - 2) return 0;
    uint32_t pdv_len = data_len + tail_len + 2;
    if (!wr_u32_be(buf, maxlen, off, pdv_len)) return 0;
    if (!wr_u8(buf, maxlen, off, pdv->presentation_context_id)) return 0;
    if (!wr_u8(buf, maxlen, off, pdv->control_header)) return 0;
    if (!wr_bytes(buf, maxlen, off, data, data_len)) return 0;
    if (!wr_bytes(buf, maxlen, off, pdv->data_tail, tail_len)) return 0;
    return 1;
}

static int reassemble_p_data_tf(uint8_t *buf, uint32_t maxlen, uint32_t *off, const dicom_p_data_tf_pdu_t *p) {
    uint32_t start = *off;
    (void)start;
    if (!wr_u8(buf, maxlen, off, DICOM_PDU_P_DATA_TF)) return 0;
    if (!wr_u8(buf, maxlen, off, p->reserved1)) return 0;
    uint32_t len_pos = *off;
    if (!wr_u32_be(buf, maxlen, off, 0)) return 0;
    uint16_t pdv_count = p->pdv_count;
    if (pdv_count > DICOM_MAX_PDV_ITEMS) pdv_count = DICOM_MAX_PDV_ITEMS;
    uint8_t skip_fragment[DICOM_MAX_PDV_ITEMS];
    uint8_t rebuild_model[DICOM_MAX_PDV_ITEMS];
    memset(skip_fragment, 0, sizeof(skip_fragment));
    memset(rebuild_model, 0, sizeof(rebuild_model));
    /* Mark only prefixes that are followed by a complete modeled command and
     * whose repaired model differs from the original concatenated fragments.
     * This preserves exact parser/reassembler identity for untouched seeds. */
    for (uint16_t i = 0; i < pdv_count; ++i) {
        const dicom_pdv_item_t *pdv = &p->pdvs[i];
        uint8_t ctrl = pdv->control_header & (DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT);
        if ((!pdv->has_dimse_command_fields && !pdv->has_dimse_command) ||
            (ctrl & (DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT)) !=
            (DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT)) continue;
        int first = (int)i;
        while (first > 0) {
            uint8_t prev = p->pdvs[first - 1].control_header & (DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT);
            if (!(prev & DICOM_PDV_FLAG_COMMAND) || (prev & DICOM_PDV_FLAG_LAST_FRAGMENT)) break;
            --first;
        }
        if (first == (int)i) continue; /* not a fragmented command */
        uint8_t original[DICOM_MAX_PDV_DATA_LEN];
        uint32_t original_len = 0;
        int representable = 1;
        for (int j = first; j <= (int)i; ++j) {
            const dicom_pdv_item_t *part = &p->pdvs[j];
            if (part->data_length > DICOM_MAX_PDV_DATA_LEN - original_len) { representable = 0; break; }
            memcpy(original + original_len, part->data, part->data_length);
            original_len += part->data_length;
        }
        uint8_t modeled[DICOM_MAX_PDV_DATA_LEN];
        uint32_t modeled_len = build_dimse_command_data(pdv, modeled, sizeof(modeled));
        if (representable && modeled_len == original_len &&
            memcmp(modeled, original, original_len) == 0) continue;
        rebuild_model[i] = 1;
        for (int j = first; j < (int)i; ++j) skip_fragment[j] = 1;
    }
    for (uint16_t i = 0; i < pdv_count; ++i) {
        const dicom_pdv_item_t *pdv = &p->pdvs[i];
        if (skip_fragment[i]) continue;
        if (rebuild_model[i] && !pdv->has_dimse_command) {
            dicom_pdv_item_t modeled = *pdv;
            modeled.has_dimse_command = 1;
            modeled.has_dimse_command_fields = 0;
            if (!reassemble_pdv_item(buf, maxlen, off, &modeled)) return 0;
        } else if (!reassemble_pdv_item(buf, maxlen, off, pdv)) return 0;
    }
    uint32_t tail_len = p->pdv_tail_length;
    if (!wr_bytes(buf, maxlen, off, p->pdv_tail, tail_len)) return 0;
    uint32_t pdu_len = (uint32_t)(*off - (len_pos + 4));
    buf[len_pos] = (uint8_t)(pdu_len >> 24);
    buf[len_pos + 1] = (uint8_t)((pdu_len >> 16) & 0xFF);
    buf[len_pos + 2] = (uint8_t)((pdu_len >> 8) & 0xFF);
    buf[len_pos + 3] = (uint8_t)(pdu_len & 0xFF);
    return 1;
}

static int reassemble_a_release_rq(uint8_t *buf, uint32_t maxlen, uint32_t *off, const dicom_a_release_rq_pdu_t *p) {
    if (!wr_u8(buf, maxlen, off, DICOM_PDU_A_RELEASE_RQ)) return 0;
    if (!wr_u8(buf, maxlen, off, p->reserved1)) return 0;
    if (!wr_u32_be(buf, maxlen, off, 4)) return 0;
    if (!wr_u16_be(buf, maxlen, off, p->reserved2)) return 0;
    if (!wr_u16_be(buf, maxlen, off, p->reserved3)) return 0;
    return 1;
}


static int reassemble_a_release_rp(uint8_t *buf, uint32_t maxlen, uint32_t *off, const dicom_a_release_rp_pdu_t *p) {
    if (!wr_u8(buf, maxlen, off, DICOM_PDU_A_RELEASE_RP)) return 0;
    if (!wr_u8(buf, maxlen, off, p->reserved1)) return 0;
    if (!wr_u32_be(buf, maxlen, off, 4)) return 0;
    if (!wr_u16_be(buf, maxlen, off, p->reserved2)) return 0;
    if (!wr_u16_be(buf, maxlen, off, p->reserved3)) return 0;
    return 1;
}

static int reassemble_a_abort(uint8_t *buf, uint32_t maxlen, uint32_t *off, const dicom_a_abort_pdu_t *p) {
    if (!wr_u8(buf, maxlen, off, DICOM_PDU_A_ABORT)) return 0;
    if (!wr_u8(buf, maxlen, off, p->reserved1)) return 0;
    if (!wr_u32_be(buf, maxlen, off, 4)) return 0;
    if (!wr_u8(buf, maxlen, off, p->reserved2)) return 0;
    if (!wr_u8(buf, maxlen, off, p->reserved3)) return 0;
    if (!wr_u8(buf, maxlen, off, p->source)) return 0;
    if (!wr_u8(buf, maxlen, off, p->reason_diag)) return 0;
    return 1;
}

int reassemble_dicom_msgs(const dicom_packet_t *packets, uint32_t num_packets, uint8_t *output_buf, uint32_t *out_len) {
    if (!packets || !output_buf || !out_len) return -1;
    uint32_t off = 0;
    uint32_t maxlen = *out_len;
    for (uint32_t i = 0; i < num_packets; ++i) {
        /* Parser-originated packets retain the exact PDU. Use it for the
         * identity path so reserved bytes and unknown extensions survive a
         * parse/reassemble round trip. Mutators update raw_data directly. */
        if (packets[i].raw_length > 0) {
            if (packets[i].raw_length > DICOM_MAX_UNKNOWN_PDU_LEN ||
                packets[i].raw_length > maxlen - off) return -7;
            memcpy(output_buf + off, packets[i].raw_data, packets[i].raw_length);
            off += packets[i].raw_length;
            if (!wr_bytes(output_buf, maxlen, &off, packets[i].raw_tail, packets[i].raw_tail_length)) return -7;
            continue;
        }
        switch (packets[i].type) {
            case DICOM_PKT_A_ASSOCIATE_RQ:
                if (!reassemble_a_associate_rq(output_buf, maxlen, &off, &packets[i].u.a_associate_rq)) return -2;
                break;
            case DICOM_PKT_A_ASSOCIATE_AC:
                if (!reassemble_a_associate_ac(output_buf, maxlen, &off, &packets[i].u.a_associate_ac)) return -8;
                break;
            case DICOM_PKT_A_ASSOCIATE_RJ:
                if (!reassemble_a_associate_rj(output_buf, maxlen, &off, &packets[i].u.a_associate_rj)) return -9;
                break;
            case DICOM_PKT_P_DATA_TF:
                if (!reassemble_p_data_tf(output_buf, maxlen, &off, &packets[i].u.p_data_tf)) return -3;
                break;
            case DICOM_PKT_A_RELEASE_RQ:
                if (!reassemble_a_release_rq(output_buf, maxlen, &off, &packets[i].u.a_release_rq)) return -4;
                break;
            case DICOM_PKT_A_RELEASE_RP:
                if (!reassemble_a_release_rp(output_buf, maxlen, &off, &packets[i].u.a_release_rp)) return -10;
                break;
            case DICOM_PKT_A_ABORT:
                if (!reassemble_a_abort(output_buf, maxlen, &off, &packets[i].u.a_abort)) return -5;
                break;
            default:
                return -6;
        }
    }
    *out_len = off;
    return 0;
}
