// ./llm/dicom/dicom_parser.c
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "dicom_packets.h"

// Helpers for big-endian network byte order reads
static int rd_u8(const uint8_t *buf, uint32_t len, uint32_t *off, uint8_t *out) {
    if (*off + 1 > len) return 0;
    *out = buf[*off];
    (*off)++;
    return 1;
}
static int rd_u16_be(const uint8_t *buf, uint32_t len, uint32_t *off, uint16_t *out) {
    if (*off + 2 > len) return 0;
    *out = ((uint16_t)buf[*off] << 8) | (uint16_t)buf[*off + 1];
    *off += 2;
    return 1;
}
static int rd_u32_be(const uint8_t *buf, uint32_t len, uint32_t *off, uint32_t *out) {
    if (*off + 4 > len) return 0;
    *out = ((uint32_t)buf[*off] << 24) | ((uint32_t)buf[*off + 1] << 16) |
           ((uint32_t)buf[*off + 2] << 8) | (uint32_t)buf[*off + 3];
    *off += 4;
    return 1;
}
static int rd_bytes(const uint8_t *buf, uint32_t len, uint32_t *off, uint8_t *dst, uint32_t n) {
    if (*off + n > len) return 0;
    if (dst) memcpy(dst, buf + *off, n);
    *off += n;
    return 1;
}

static uint16_t rd_le16_raw(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd_le32_raw(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void copy_dimse_text(char *dst, uint16_t *dst_len, uint32_t max_len, const uint8_t *src, uint32_t len) {
    if (!dst || !dst_len || !src || max_len == 0) return;
    uint32_t copy = len;
    if (copy > max_len) copy = max_len;
    memcpy(dst, src, copy);
    if (copy < max_len) memset(dst + copy, 0, max_len - copy);
    *dst_len = (uint16_t)copy;
}

static int is_dimse_request_command(uint16_t cmd) {
    return cmd == DICOM_DIMSE_C_STORE_RQ ||
           cmd == DICOM_DIMSE_C_GET_RQ ||
           cmd == DICOM_DIMSE_C_FIND_RQ ||
           cmd == DICOM_DIMSE_C_MOVE_RQ ||
           cmd == DICOM_DIMSE_C_ECHO_RQ ||
           cmd == DICOM_DIMSE_N_EVENT_REPORT_RQ ||
           cmd == DICOM_DIMSE_N_GET_RQ ||
           cmd == DICOM_DIMSE_N_SET_RQ ||
           cmd == DICOM_DIMSE_N_ACTION_RQ ||
           cmd == DICOM_DIMSE_N_CREATE_RQ ||
           cmd == DICOM_DIMSE_N_DELETE_RQ ||
           cmd == DICOM_DIMSE_C_CANCEL_RQ;
}

static void parse_dimse_command_data(dicom_pdv_item_t *pdv) {
    if (!pdv) return;
    pdv->has_dimse_command = 0;
    pdv->has_dimse_command_fields = 0;
    pdv->dimse_fields_present = 0;
    pdv->dimse_command_field = 0;
    pdv->dimse_message_id = 0;
    pdv->dimse_message_id_responded_to = 0;
    pdv->dimse_priority = 0;
    pdv->dimse_command_data_set_type = 0;
    pdv->dimse_status = 0;
    pdv->dimse_event_type_id = 0;
    pdv->dimse_action_type_id = 0;
    pdv->dimse_move_originator_message_id = 0;
    pdv->dimse_affected_sop_class_uid_len = 0;
    pdv->dimse_requested_sop_class_uid_len = 0;
    pdv->dimse_affected_sop_instance_uid_len = 0;
    pdv->dimse_requested_sop_instance_uid_len = 0;
    pdv->dimse_move_destination_len = 0;
    pdv->dimse_move_originator_ae_title_len = 0;
    pdv->dimse_attribute_identifier_list_len = 0;

    if ((pdv->control_header & (DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT)) !=
        (DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT)) return;
    uint32_t len = pdv->data_length;
    if (len > DICOM_MAX_PDV_DATA_LEN) len = DICOM_MAX_PDV_DATA_LEN;
    uint32_t off = 0;
    while (off + 8 <= len) {
        uint16_t group = rd_le16_raw(pdv->data + off);
        uint16_t elem = rd_le16_raw(pdv->data + off + 2);
        uint32_t vlen = rd_le32_raw(pdv->data + off + 4);
        off += 8;
        if (group != 0x0000 || vlen > len - off) return;
        const uint8_t *val = pdv->data + off;
        static const uint16_t tags[] = {0x0000,0x0002,0x0003,0x0100,0x0110,0x0120,0x0600,0x0700,0x0800,0x0900,0x1000,0x1001,0x1002,0x1005,0x1008,0x1030,0x1031};
        unsigned ti;
        for (ti=0; ti<sizeof(tags)/sizeof(tags[0]); ti++) if (tags[ti]==elem) break;
        if (ti==sizeof(tags)/sizeof(tags[0]) || (pdv->dimse_fields_present & (1u<<ti))) return;
        pdv->dimse_fields_present |= 1u<<ti;
        switch (elem) {
            case 0x0002:
                copy_dimse_text(pdv->dimse_affected_sop_class_uid,
                                &pdv->dimse_affected_sop_class_uid_len,
                                DICOM_MAX_DIMSE_UID_LEN, val, vlen);
                break;
            case 0x0003:
                copy_dimse_text(pdv->dimse_requested_sop_class_uid,
                                &pdv->dimse_requested_sop_class_uid_len,
                                DICOM_MAX_DIMSE_UID_LEN, val, vlen);
                break;
            case 0x0100:
                if (vlen >= 2) pdv->dimse_command_field = rd_le16_raw(val);
                break;
            case 0x0110:
                if (vlen >= 2) pdv->dimse_message_id = rd_le16_raw(val);
                break;
            case 0x0120:
                if (vlen >= 2) pdv->dimse_message_id_responded_to = rd_le16_raw(val);
                break;
            case 0x0600:
                copy_dimse_text(pdv->dimse_move_destination,
                                &pdv->dimse_move_destination_len,
                                DICOM_MAX_DIMSE_AE_LEN, val, vlen);
                break;
            case 0x0700:
                if (vlen >= 2) pdv->dimse_priority = rd_le16_raw(val);
                break;
            case 0x0800:
                if (vlen >= 2) pdv->dimse_command_data_set_type = rd_le16_raw(val);
                break;
            case 0x0900:
                if (vlen >= 2) pdv->dimse_status = rd_le16_raw(val);
                break;
            case 0x1000:
                copy_dimse_text(pdv->dimse_affected_sop_instance_uid,
                                &pdv->dimse_affected_sop_instance_uid_len,
                                DICOM_MAX_DIMSE_UID_LEN, val, vlen);
                break;
            case 0x1001:
                copy_dimse_text(pdv->dimse_requested_sop_instance_uid,
                                &pdv->dimse_requested_sop_instance_uid_len,
                                DICOM_MAX_DIMSE_UID_LEN, val, vlen);
                break;
            case 0x1002:
                if (vlen >= 2) pdv->dimse_event_type_id = rd_le16_raw(val);
                break;
            case 0x1005: {
                uint32_t copy = vlen;
                if (copy > DICOM_MAX_DIMSE_ATTR_LIST_LEN) copy = DICOM_MAX_DIMSE_ATTR_LIST_LEN;
                if (copy) memcpy(pdv->dimse_attribute_identifier_list, val, copy);
                pdv->dimse_attribute_identifier_list_len = (uint16_t)copy;
                break;
            }
            case 0x1008:
                if (vlen >= 2) pdv->dimse_action_type_id = rd_le16_raw(val);
                break;
            case 0x1030:
                copy_dimse_text(pdv->dimse_move_originator_ae_title,
                                &pdv->dimse_move_originator_ae_title_len,
                                DICOM_MAX_DIMSE_AE_LEN, val, vlen);
                break;
            case 0x1031:
                if (vlen >= 2) pdv->dimse_move_originator_message_id = rd_le16_raw(val);
                break;
            default:
                break;
        }
        off += vlen;
    }
    if (off == len && (pdv->dimse_fields_present & DICOM_DIMSE_PRESENT_GROUP_LENGTH) &&
        (pdv->dimse_fields_present & DICOM_DIMSE_PRESENT_COMMAND) &&
        (pdv->dimse_fields_present & DICOM_DIMSE_PRESENT_DATASET_TYPE) &&
        is_dimse_request_command(pdv->dimse_command_field)) {
        pdv->has_dimse_command = 1;
        pdv->has_dimse_command_fields = 1;
    }
}


static void copy_dimse_fields(dicom_pdv_item_t *dst, const dicom_pdv_item_t *src) {
    if (!dst || !src) return;
    /* Keep has_dimse_command tied to bytes physically present in this PDV.
     * Fragmented commands are represented by has_dimse_command_fields on the
     * final fragment; the reassembler compares the repaired model with the
     * original fragment sequence before deciding to collapse it. */
    dst->has_dimse_command_fields = src->has_dimse_command_fields;
    dst->dimse_fields_present = src->dimse_fields_present;
    dst->dimse_command_field = src->dimse_command_field;
    dst->dimse_message_id = src->dimse_message_id;
    dst->dimse_message_id_responded_to = src->dimse_message_id_responded_to;
    dst->dimse_priority = src->dimse_priority;
    dst->dimse_command_data_set_type = src->dimse_command_data_set_type;
    dst->dimse_status = src->dimse_status;
    dst->dimse_event_type_id = src->dimse_event_type_id;
    dst->dimse_action_type_id = src->dimse_action_type_id;
    dst->dimse_move_originator_message_id = src->dimse_move_originator_message_id;
    dst->dimse_affected_sop_class_uid_len = src->dimse_affected_sop_class_uid_len;
    memcpy(dst->dimse_affected_sop_class_uid, src->dimse_affected_sop_class_uid, sizeof(dst->dimse_affected_sop_class_uid));
    dst->dimse_requested_sop_class_uid_len = src->dimse_requested_sop_class_uid_len;
    memcpy(dst->dimse_requested_sop_class_uid, src->dimse_requested_sop_class_uid, sizeof(dst->dimse_requested_sop_class_uid));
    dst->dimse_affected_sop_instance_uid_len = src->dimse_affected_sop_instance_uid_len;
    memcpy(dst->dimse_affected_sop_instance_uid, src->dimse_affected_sop_instance_uid, sizeof(dst->dimse_affected_sop_instance_uid));
    dst->dimse_requested_sop_instance_uid_len = src->dimse_requested_sop_instance_uid_len;
    memcpy(dst->dimse_requested_sop_instance_uid, src->dimse_requested_sop_instance_uid, sizeof(dst->dimse_requested_sop_instance_uid));
    dst->dimse_move_destination_len = src->dimse_move_destination_len;
    memcpy(dst->dimse_move_destination, src->dimse_move_destination, sizeof(dst->dimse_move_destination));
    dst->dimse_move_originator_ae_title_len = src->dimse_move_originator_ae_title_len;
    memcpy(dst->dimse_move_originator_ae_title, src->dimse_move_originator_ae_title, sizeof(dst->dimse_move_originator_ae_title));
    dst->dimse_attribute_identifier_list_len = src->dimse_attribute_identifier_list_len;
    memcpy(dst->dimse_attribute_identifier_list, src->dimse_attribute_identifier_list, sizeof(dst->dimse_attribute_identifier_list));
}

static void annotate_dimse_fragments(dicom_packet_t *packets, uint32_t count) {
    uint8_t command_buf[DICOM_MAX_PDV_DATA_LEN];
    uint32_t command_len = 0;
    int active = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (packets[i].type != DICOM_PKT_P_DATA_TF) continue;
        dicom_p_data_tf_pdu_t *p = &packets[i].u.p_data_tf;
        for (uint16_t k = 0; k < p->pdv_count; k++) {
            dicom_pdv_item_t *pdv = &p->pdvs[k];
            if (!(pdv->control_header & DICOM_PDV_FLAG_COMMAND)) continue;
            if (!active) { command_len = 0; active = 1; }
            uint32_t copy = pdv->data_length;
            if (copy > DICOM_MAX_PDV_DATA_LEN) copy = DICOM_MAX_PDV_DATA_LEN;
            if (command_len + copy <= DICOM_MAX_PDV_DATA_LEN) {
                memcpy(command_buf + command_len, pdv->data, copy);
                command_len += copy;
            } else {
                active = 0;
                command_len = 0;
            }
            if (pdv->control_header & DICOM_PDV_FLAG_LAST_FRAGMENT) {
                if (active && command_len) {
                    dicom_pdv_item_t tmp;
                    memset(&tmp, 0, sizeof(tmp));
                    tmp.control_header = DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT;
                    tmp.data_length = command_len;
                    memcpy(tmp.data, command_buf, command_len);
                    parse_dimse_command_data(&tmp);
                    if (tmp.has_dimse_command_fields) {
                        if (!pdv->has_dimse_command) copy_dimse_fields(pdv, &tmp);
                    }
                }
                active = 0;
                command_len = 0;
            }
        }
    }
}

// Parse helper for dicom_str_t (UID-like strings)
static int rd_dicom_str(const uint8_t *buf, uint32_t len, uint32_t *off, uint16_t field_len, dicom_str_t *out) {
    out->length = field_len;
    uint32_t copy = field_len;
    if (copy > DICOM_MAX_UID_LEN) copy = DICOM_MAX_UID_LEN;
    if (*off + field_len > len) return 0;
    memset(out->value, 0, sizeof(out->value));
    memcpy(out->value, buf + *off, copy);
    *off += field_len;
    return 1;
}

// Forward decls for packet-specific parsers

static int parse_a_associate_rq(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_packet_t *out);
static int parse_a_associate_ac(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_packet_t *out);
static int parse_a_associate_rj(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_packet_t *out);
static int parse_p_data_tf(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_packet_t *out);
static int parse_a_release_rq(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_packet_t *out);
static int parse_a_release_rp(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_packet_t *out);
static int parse_a_abort(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_packet_t *out);

// Parse Item headers common: item_type(1), reserved(1), item_length(2)
static int rd_item_header(const uint8_t *buf, uint32_t len, uint32_t *off, uint8_t *item_type, uint8_t *reserved, uint16_t *item_length) {
    if (!rd_u8(buf, len, off, item_type)) return 0;
    if (!rd_u8(buf, len, off, reserved)) return 0;
    if (!rd_u16_be(buf, len, off, item_length)) return 0;
    return 1;
}

static int parse_application_context(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_app_context_item_t *ac) {
    if (!rd_item_header(buf, len, off, &ac->item_type, &ac->reserved1, &ac->item_length)) return 0;
    if (ac->item_type != 0x10) return 0;
    if (!rd_dicom_str(buf, len, off, ac->item_length, &ac->application_context_name)) return 0;
    return 1;
}

static void user_info_append_raw(dicom_user_info_item_t *ui, const uint8_t *src, uint32_t n) {
    if (!ui || !src || n == 0) return;
    uint32_t room = DICOM_MAX_USER_INFO_BYTES - ui->user_data_length;
    uint32_t copy = n < room ? n : room;
    if (copy) {
        memcpy(ui->user_data + ui->user_data_length, src, copy);
        ui->user_data_length += copy;
        ui->has_user_data = 1;
    }
}

static int parse_user_info(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_user_info_item_t *ui) {
    if (!rd_item_header(buf, len, off, &ui->item_type, &ui->reserved1, &ui->item_length)) return 0;
    if (ui->item_type != 0x50) return 0;
    ui->has_user_data = 0;
    ui->user_data_length = 0;
    ui->has_maximum_length = 0;
    ui->maximum_length_received = 0;
    ui->has_implementation_class_uid = 0;
    ui->has_async_ops_window = 0;
    ui->role_selection_count = 0;
    ui->has_implementation_version_name = 0;
    ui->has_sop_class_extended_negotiation = 0;
    ui->sop_class_extended_info_len = 0;
    ui->has_sop_class_common_extended_negotiation = 0;
    ui->related_general_sop_class_uid_count = 0;
    ui->has_user_identity_negotiation = 0;
    ui->user_identity_primary_field_len = 0;
    ui->user_identity_secondary_field_len = 0;
    uint32_t item_start = *off;
    uint32_t item_end = item_start + ui->item_length;
    if (item_end < item_start || item_end > len) return 0;
    while (*off < item_end) {
        uint32_t sub_start = *off;
        uint8_t item_type = 0, reserved = 0;
        uint16_t item_len = 0;
        if (item_end - *off < 4) return 0;
        if (!rd_item_header(buf, len, off, &item_type, &reserved, &item_len)) return 0;
        uint32_t value_off = *off;
        uint32_t sub_end = value_off + item_len;
        if (sub_end < value_off || sub_end > item_end) return 0;
        if (item_type == 0x51 && item_len == 4) {
            uint32_t max_len = 0;
            if (!rd_u32_be(buf, len, off, &max_len)) return 0;
            ui->has_maximum_length = 1;
            ui->maximum_length_received = max_len;
        } else if (item_type == 0x52) {
            if (!rd_dicom_str(buf, len, off, item_len, &ui->implementation_class_uid)) return 0;
            ui->has_implementation_class_uid = 1;
        } else if (item_type == 0x53 && item_len == 4) {
            if (!rd_u16_be(buf, len, off, &ui->max_ops_invoked)) return 0;
            if (!rd_u16_be(buf, len, off, &ui->max_ops_performed)) return 0;
            ui->has_async_ops_window = 1;
        } else if (item_type == 0x54 && item_len >= 4) {
            uint16_t uid_len = 0;
            if (!rd_u16_be(buf, len, off, &uid_len)) return 0;
            if ((uint32_t)uid_len + 4u > item_len) return 0;
            if (ui->role_selection_count < DICOM_MAX_ROLE_SELECTIONS) {
                uint8_t idx = ui->role_selection_count++;
                if (!rd_dicom_str(buf, len, off, uid_len, &ui->role_selections[idx].sop_class_uid)) return 0;
                if (!rd_u8(buf, len, off, &ui->role_selections[idx].scu_role)) return 0;
                if (!rd_u8(buf, len, off, &ui->role_selections[idx].scp_role)) return 0;
            } else {
                *off = sub_end;
            }
        } else if (item_type == 0x55) {
            if (!rd_dicom_str(buf, len, off, item_len, &ui->implementation_version_name)) return 0;
            ui->has_implementation_version_name = 1;
        } else if (item_type == 0x56 && item_len >= 2) {
            uint16_t uid_len = 0;
            if (!rd_u16_be(buf, len, off, &uid_len)) return 0;
            if ((uint32_t)uid_len + 2u > item_len) return 0;
            if (!rd_dicom_str(buf, len, off, uid_len, &ui->sop_class_extended_uid)) return 0;
            uint32_t info_len = item_len - 2u - uid_len;
            uint32_t copy = info_len > DICOM_MAX_USER_INFO_BYTES ? DICOM_MAX_USER_INFO_BYTES : info_len;
            if (copy && !rd_bytes(buf, len, off, ui->sop_class_extended_info, copy)) return 0;
            *off += info_len - copy;
            ui->sop_class_extended_info_len = (uint16_t)copy;
            ui->has_sop_class_extended_negotiation = 1;
        } else if (item_type == 0x57 && item_len >= 6) {
            uint16_t uid_len = 0;
            if (!rd_u16_be(buf, len, off, &uid_len)) return 0;
            if ((uint32_t)uid_len + 4u > item_len) return 0;
            if (!rd_dicom_str(buf, len, off, uid_len, &ui->sop_class_common_sop_uid)) return 0;
            uint16_t svc_len = 0;
            if (!rd_u16_be(buf, len, off, &svc_len)) return 0;
            if ((uint32_t)uid_len + 4u + svc_len > item_len) return 0;
            if (!rd_dicom_str(buf, len, off, svc_len, &ui->sop_class_common_service_class_uid)) return 0;
            uint16_t related_len = 0;
            if (!rd_u16_be(buf, sub_end, off, &related_len)) return 0;
            if (related_len != sub_end - *off) return 0;
            while (*off + 2 <= sub_end && ui->related_general_sop_class_uid_count < DICOM_MAX_RELATED_SOP_CLASSES) {
                uint16_t rel_len = 0;
                if (!rd_u16_be(buf, len, off, &rel_len)) return 0;
                if (*off + rel_len > sub_end) return 0;
                if (!rd_dicom_str(buf, len, off, rel_len, &ui->related_general_sop_class_uids[ui->related_general_sop_class_uid_count])) return 0;
                ui->related_general_sop_class_uid_count++;
            }
            ui->has_sop_class_common_extended_negotiation = 1;
        } else if (item_type == 0x58 && item_len >= 6) {
            if (!rd_u8(buf, len, off, &ui->user_identity_type)) return 0;
            if (!rd_u8(buf, len, off, &ui->user_identity_positive_response_requested)) return 0;
            uint16_t primary_len = 0, secondary_len = 0;
            if (!rd_u16_be(buf, len, off, &primary_len)) return 0;
            if ((uint32_t)primary_len + 6u > item_len) return 0;
            uint32_t copy = primary_len > DICOM_MAX_USER_INFO_BYTES ? DICOM_MAX_USER_INFO_BYTES : primary_len;
            if (copy && !rd_bytes(buf, len, off, ui->user_identity_primary_field, copy)) return 0;
            *off += primary_len - copy;
            if (!rd_u16_be(buf, len, off, &secondary_len)) return 0;
            if ((uint32_t)primary_len + secondary_len + 6u > item_len) return 0;
            copy = secondary_len > DICOM_MAX_USER_INFO_BYTES ? DICOM_MAX_USER_INFO_BYTES : secondary_len;
            if (copy && !rd_bytes(buf, len, off, ui->user_identity_secondary_field, copy)) return 0;
            *off += secondary_len - copy;
            ui->user_identity_primary_field_len = primary_len > DICOM_MAX_USER_INFO_BYTES ? DICOM_MAX_USER_INFO_BYTES : primary_len;
            ui->user_identity_secondary_field_len = secondary_len > DICOM_MAX_USER_INFO_BYTES ? DICOM_MAX_USER_INFO_BYTES : secondary_len;
            ui->has_user_identity_negotiation = 1;
        } else {
            user_info_append_raw(ui, buf + sub_start, 4u + item_len);
            *off = sub_end;
        }
        if (*off != sub_end) *off = sub_end;
        (void)reserved;
    }
    return (*off == item_end);
}

static int parse_presentation_context(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_presentation_context_item_t *pc) {
    if (!rd_item_header(buf, len, off, &pc->item_type, &pc->reserved1, &pc->item_length)) return 0;
    if (pc->item_type != 0x20) return 0;
    uint32_t item_body_start = *off;
    uint32_t item_end = item_body_start + pc->item_length;
    if (item_end < item_body_start || item_end > len) return 0;
    if (pc->item_length < 4) return 0;
    if (!rd_u8(buf, len, off, &pc->presentation_context_id)) return 0;
    if (!rd_bytes(buf, len, off, pc->reserved2, 3)) return 0; // reserved
    pc->transfer_syntax_count = 0;

    // item_length includes PCID and the three reserved bytes; parse sub-items
    // only until the absolute end of this presentation context item.
    while (*off < item_end) {
        uint8_t peek_type = 0, rsv = 0; uint16_t sub_len = 0;
        if (item_end - *off < 4) return 0;
        if (!rd_item_header(buf, len, off, &peek_type, &rsv, &sub_len)) return 0;
        uint32_t content_off = *off;
        uint32_t sub_end = content_off + sub_len;
        if (sub_end < content_off || sub_end > item_end) return 0;
        if (peek_type == 0x30) {
            if (!rd_dicom_str(buf, len, off, sub_len, &pc->abstract_syntax.abstract_syntax_name)) return 0;
            pc->abstract_syntax.item_type = peek_type;
            pc->abstract_syntax.reserved1 = rsv;
            pc->abstract_syntax.item_length = sub_len;
        } else if (peek_type == 0x40) {
            if (pc->transfer_syntax_count < DICOM_MAX_TRANSFER_SYNTAXES) {
                dicom_transfer_syntax_item_t *ts = &pc->transfer_syntaxes[pc->transfer_syntax_count++];
                ts->item_type = peek_type;
                ts->reserved1 = rsv;
                ts->item_length = sub_len;
                if (!rd_dicom_str(buf, len, off, sub_len, &ts->transfer_syntax_name)) return 0;
            } else {
                *off = sub_end;
            }
        } else {
            *off = sub_end;
        }
    }
    if (pc->abstract_syntax.item_type == 0) pc->abstract_syntax.item_type = 0x30;
    return (*off == item_end);
}


static int parse_presentation_context_ac(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_presentation_context_ac_item_t *pc) {
    if (!rd_item_header(buf, len, off, &pc->item_type, &pc->reserved1, &pc->item_length)) return 0;
    if (pc->item_type != 0x21) return 0;
    uint32_t item_start = *off;
    uint32_t item_end = item_start + pc->item_length;
    if (item_end < item_start || item_end > len || pc->item_length < 4) return 0;
    if (!rd_u8(buf, len, off, &pc->presentation_context_id)) return 0;
    if (!rd_u8(buf, len, off, &pc->reserved2)) return 0;
    if (!rd_u8(buf, len, off, &pc->result_reason)) return 0;
    if (!rd_u8(buf, len, off, &pc->reserved3)) return 0;
    pc->has_transfer_syntax = 0;
    while (*off < item_end) {
        uint8_t typ = 0, rsv = 0; uint16_t slen = 0;
        if (item_end - *off < 4) return 0;
        if (!rd_item_header(buf, len, off, &typ, &rsv, &slen)) return 0;
        uint32_t sub_end = *off + slen;
        if (sub_end < *off || sub_end > item_end) return 0;
        if (typ == 0x40 && !pc->has_transfer_syntax) {
            pc->transfer_syntax.item_type = typ;
            pc->transfer_syntax.reserved1 = rsv;
            pc->transfer_syntax.item_length = slen;
            if (!rd_dicom_str(buf, len, off, slen, &pc->transfer_syntax.transfer_syntax_name)) return 0;
            pc->has_transfer_syntax = 1;
        }
        *off = sub_end;
    }
    return *off == item_end;
}

static int parse_a_associate_rq(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_packet_t *out) {
    dicom_a_associate_rq_pdu_t *p = &out->u.a_associate_rq;
    out->type = DICOM_PKT_A_ASSOCIATE_RQ;
    if (!rd_u8(buf, len, off, &p->pdu_type)) return 0;
    if (p->pdu_type != DICOM_PDU_A_ASSOCIATE_RQ) return 0;
    if (!rd_u8(buf, len, off, &p->reserved1)) return 0;
    if (!rd_u32_be(buf, len, off, &p->pdu_length)) return 0;
    uint32_t pdu_start = *off;

    if (!rd_u16_be(buf, len, off, &p->protocol_version)) return 0;
    if (!rd_u16_be(buf, len, off, &p->reserved2)) return 0; // must be 0x0000

    if (!rd_bytes(buf, len, off, (uint8_t*)p->called_ae_title, 16)) return 0;
    if (!rd_bytes(buf, len, off, (uint8_t*)p->calling_ae_title, 16)) return 0;
    if (!rd_bytes(buf, len, off, p->reserved3, 32)) return 0; // reserved

    // Items follow: Application Context (0x10), one or more Presentation Context (0x20), User Info (0x50)
    // Application Context
    if (!parse_application_context(buf, len, off, &p->application_context)) return 0;

    // Parse remaining items until pdu_length consumed
    p->presentation_context_count = 0;
    p->has_user_info = 0;

    while ((*off - pdu_start) < p->pdu_length) {
        if (*off + 4 > len) return 0;
        uint8_t item_type = buf[*off];
        // Don't advance here; delegate parsers will consume headers.
        if (item_type == 0x20) {
            if (p->presentation_context_count >= DICOM_MAX_PRESENTATION_CONTEXTS) return 0;
            if (!parse_presentation_context(buf, len, off, &p->presentation_contexts[p->presentation_context_count])) return 0;
            p->presentation_context_count++;
        } else if (item_type == 0x50) {
            if (!parse_user_info(buf, len, off, &p->user_info)) return 0;
            p->has_user_info = 1;
        } else if (item_type == 0x10) {
            // Multiple Application Context is not expected; parse and overwrite
            if (!parse_application_context(buf, len, off, &p->application_context)) return 0;
        } else {
            // Unknown item in A-ASSOCIATE-RQ, skip conservatively
            uint8_t rsv; uint16_t ilen;
            uint8_t dummy;
            if (!rd_item_header(buf, len, off, &dummy, &rsv, &ilen)) return 0;
            if (*off + ilen > len) return 0;
            *off += ilen;
        }
    }

    return ((*off - pdu_start) == p->pdu_length);
}


static int parse_a_associate_ac(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_packet_t *out) {
    dicom_a_associate_ac_pdu_t *p = &out->u.a_associate_ac;
    out->type = DICOM_PKT_A_ASSOCIATE_AC;
    if (!rd_u8(buf, len, off, &p->pdu_type)) return 0;
    if (p->pdu_type != DICOM_PDU_A_ASSOCIATE_AC) return 0;
    if (!rd_u8(buf, len, off, &p->reserved1)) return 0;
    if (!rd_u32_be(buf, len, off, &p->pdu_length)) return 0;
    uint32_t pdu_start = *off;
    if (p->pdu_length < 68) return 0;
    if (!rd_u16_be(buf, len, off, &p->protocol_version)) return 0;
    if (!rd_u16_be(buf, len, off, &p->reserved2)) return 0;
    if (!rd_bytes(buf, len, off, (uint8_t*)p->called_ae_title, 16)) return 0;
    if (!rd_bytes(buf, len, off, (uint8_t*)p->calling_ae_title, 16)) return 0;
    if (!rd_bytes(buf, len, off, p->reserved3, 32)) return 0;
    p->has_application_context = 0;
    p->presentation_context_count = 0;
    p->has_user_info = 0;
    p->raw_items_length = 0;
    while ((*off - pdu_start) < p->pdu_length) {
        if (*off + 4 > len) return 0;
        uint32_t item_start = *off;
        uint8_t item_type = buf[*off];
        if (item_type == 0x10) {
            if (!parse_application_context(buf, len, off, &p->application_context)) return 0;
            p->has_application_context = 1;
        } else if (item_type == 0x21) {
            if (p->presentation_context_count >= DICOM_MAX_PRESENTATION_CONTEXTS) return 0;
            if (!parse_presentation_context_ac(buf, len, off, &p->presentation_contexts[p->presentation_context_count])) return 0;
            p->presentation_context_count++;
        } else if (item_type == 0x50) {
            if (!parse_user_info(buf, len, off, &p->user_info)) return 0;
            p->has_user_info = 1;
        } else {
            uint8_t typ = 0, rsv = 0; uint16_t ilen = 0;
            if (!rd_item_header(buf, len, off, &typ, &rsv, &ilen)) return 0;
            if (*off + ilen > len) return 0;
            uint32_t total = 4u + ilen;
            uint32_t room = DICOM_MAX_UNKNOWN_PDU_LEN - p->raw_items_length;
            uint32_t copy = total < room ? total : room;
            if (copy) memcpy(p->raw_items + p->raw_items_length, buf + item_start, copy);
            p->raw_items_length += copy;
            *off += ilen;
        }
    }
    return ((*off - pdu_start) == p->pdu_length);
}

static int parse_a_associate_rj(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_packet_t *out) {
    dicom_a_associate_rj_pdu_t *p = &out->u.a_associate_rj;
    out->type = DICOM_PKT_A_ASSOCIATE_RJ;
    if (!rd_u8(buf, len, off, &p->pdu_type)) return 0;
    if (p->pdu_type != DICOM_PDU_A_ASSOCIATE_RJ) return 0;
    if (!rd_u8(buf, len, off, &p->reserved1)) return 0;
    if (!rd_u32_be(buf, len, off, &p->pdu_length)) return 0;
    if (p->pdu_length != 4) return 0;
    if (!rd_u8(buf, len, off, &p->reserved2)) return 0;
    if (!rd_u8(buf, len, off, &p->result)) return 0;
    if (!rd_u8(buf, len, off, &p->source)) return 0;
    if (!rd_u8(buf, len, off, &p->reason_diag)) return 0;
    return 1;
}

static int parse_pdv_item(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_pdv_item_t *pdv) {
    uint32_t pdv_len = 0;
    if (!rd_u32_be(buf, len, off, &pdv_len)) return 0;
    pdv->pdv_length = pdv_len;
    if (pdv_len < 2 || pdv_len > len - *off) return 0; // must include context id and control header
    if (!rd_u8(buf, len, off, &pdv->presentation_context_id)) return 0;
    if (!rd_u8(buf, len, off, &pdv->control_header)) return 0;
    uint32_t data_len = pdv_len - 2;
    pdv->data_length = data_len;
    uint32_t copy = data_len;
    if (copy > DICOM_MAX_PDV_DATA_LEN) copy = DICOM_MAX_PDV_DATA_LEN;
    if (!rd_bytes(buf, len, off, pdv->data, copy)) return 0;
    // If we truncated, skip the remainder of this PDV
    uint32_t remaining = data_len - copy;
    if (*off > len || remaining > len - *off) return 0;
    if (remaining) { pdv->data_tail = buf + *off; pdv->data_tail_length = remaining; }
    *off += remaining;
    parse_dimse_command_data(pdv);
    return 1;
}

static int parse_p_data_tf(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_packet_t *out) {
    dicom_p_data_tf_pdu_t *p = &out->u.p_data_tf;
    out->type = DICOM_PKT_P_DATA_TF;
    if (!rd_u8(buf, len, off, &p->pdu_type)) return 0;
    if (p->pdu_type != DICOM_PDU_P_DATA_TF) return 0;
    if (!rd_u8(buf, len, off, &p->reserved1)) return 0;
    if (!rd_u32_be(buf, len, off, &p->pdu_length)) return 0;
    uint32_t pdu_start = *off;

    p->pdv_count = 0;
    while ((*off - pdu_start) < p->pdu_length) {
        if (p->pdv_count >= DICOM_MAX_PDV_ITEMS) {
            // skip remaining PDVs
            uint32_t remaining = p->pdu_length - (uint32_t)(*off - pdu_start);
            if (*off > len || remaining > len - *off) return 0;
            p->pdv_tail = buf + *off;
            p->pdv_tail_length = remaining;
            *off += remaining;
            break;
        }
        if (!parse_pdv_item(buf, len, off, &p->pdvs[p->pdv_count])) return 0;
        p->pdv_count++;
    }
    return ((*off - pdu_start) == p->pdu_length);
}

static int parse_a_release_rq(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_packet_t *out) {
    dicom_a_release_rq_pdu_t *p = &out->u.a_release_rq;
    out->type = DICOM_PKT_A_RELEASE_RQ;
    if (!rd_u8(buf, len, off, &p->pdu_type)) return 0;
    if (p->pdu_type != DICOM_PDU_A_RELEASE_RQ) return 0;
    if (!rd_u8(buf, len, off, &p->reserved1)) return 0;
    if (!rd_u32_be(buf, len, off, &p->pdu_length)) return 0;
    if (p->pdu_length != 4) {
        // Still attempt to parse two reserved fields but enforce expected
    }
    if (!rd_u16_be(buf, len, off, &p->reserved2)) return 0;
    if (!rd_u16_be(buf, len, off, &p->reserved3)) return 0;
    return 1;
}


static int parse_a_release_rp(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_packet_t *out) {
    dicom_a_release_rp_pdu_t *p = &out->u.a_release_rp;
    out->type = DICOM_PKT_A_RELEASE_RP;
    if (!rd_u8(buf, len, off, &p->pdu_type)) return 0;
    if (p->pdu_type != DICOM_PDU_A_RELEASE_RP) return 0;
    if (!rd_u8(buf, len, off, &p->reserved1)) return 0;
    if (!rd_u32_be(buf, len, off, &p->pdu_length)) return 0;
    if (p->pdu_length != 4) return 0;
    if (!rd_u16_be(buf, len, off, &p->reserved2)) return 0;
    if (!rd_u16_be(buf, len, off, &p->reserved3)) return 0;
    return 1;
}

static int parse_a_abort(const uint8_t *buf, uint32_t len, uint32_t *off, dicom_packet_t *out) {
    dicom_a_abort_pdu_t *p = &out->u.a_abort;
    out->type = DICOM_PKT_A_ABORT;
    if (!rd_u8(buf, len, off, &p->pdu_type)) return 0;
    if (p->pdu_type != DICOM_PDU_A_ABORT) return 0;
    if (!rd_u8(buf, len, off, &p->reserved1)) return 0;
    if (!rd_u32_be(buf, len, off, &p->pdu_length)) return 0;
    if (p->pdu_length != 4) {
        // proceed but enforce reading exactly 4 bytes next
    }
    if (!rd_u8(buf, len, off, &p->reserved2)) return 0;
    if (!rd_u8(buf, len, off, &p->reserved3)) return 0;
    if (!rd_u8(buf, len, off, &p->source)) return 0;
    if (!rd_u8(buf, len, off, &p->reason_diag)) return 0;
    return 1;
}

size_t parse_dicom_msg(const uint8_t *buf, uint32_t buf_len, dicom_packet_t *out_packets, uint32_t max_count) {
    if (!buf || !out_packets || max_count == 0) return 0;
    uint32_t off = 0;
    uint32_t count = 0;

    while (off < buf_len && count < max_count) {
        if (buf_len - off < 6) break;
        uint32_t pdu_start = off;
        uint8_t pdu_type = buf[off];
        uint32_t pdu_len = ((uint32_t)buf[off + 2] << 24) | ((uint32_t)buf[off + 3] << 16) |
                           ((uint32_t)buf[off + 4] << 8) | (uint32_t)buf[off + 5];
        if (pdu_len > buf_len - off - 6U) return 0;
        uint32_t total_len = 6U + pdu_len;


        uint32_t tmp_off = pdu_start;
        dicom_packet_t tmp_pkt;
        memset(&tmp_pkt, 0, sizeof(tmp_pkt));
        int ok = 0;
        switch (pdu_type) {
            case DICOM_PDU_A_ASSOCIATE_RQ:
                ok = parse_a_associate_rq(buf, pdu_start + total_len, &tmp_off, &tmp_pkt);
                break;
            case DICOM_PDU_A_ASSOCIATE_AC:
                ok = parse_a_associate_ac(buf, pdu_start + total_len, &tmp_off, &tmp_pkt);
                break;
            case DICOM_PDU_A_ASSOCIATE_RJ:
                ok = parse_a_associate_rj(buf, pdu_start + total_len, &tmp_off, &tmp_pkt);
                break;
            case DICOM_PDU_P_DATA_TF:
                ok = parse_p_data_tf(buf, pdu_start + total_len, &tmp_off, &tmp_pkt);
                break;
            case DICOM_PDU_A_RELEASE_RQ:
                ok = parse_a_release_rq(buf, pdu_start + total_len, &tmp_off, &tmp_pkt);
                break;
            case DICOM_PDU_A_RELEASE_RP:
                ok = parse_a_release_rp(buf, pdu_start + total_len, &tmp_off, &tmp_pkt);
                break;
            case DICOM_PDU_A_ABORT:
                ok = parse_a_abort(buf, pdu_start + total_len, &tmp_off, &tmp_pkt);
                break;
            default:
                tmp_pkt.type = DICOM_PKT_UNKNOWN;
                tmp_pkt.u.unknown.pdu_type = pdu_type;
                tmp_pkt.u.unknown.reserved1 = buf[pdu_start + 1];
                tmp_pkt.u.unknown.pdu_length = pdu_len;
                tmp_pkt.u.unknown.data_length = pdu_len;
                if (pdu_len) memcpy(tmp_pkt.u.unknown.data, buf + pdu_start + 6,
                    pdu_len > DICOM_MAX_UNKNOWN_PDU_LEN ? DICOM_MAX_UNKNOWN_PDU_LEN : pdu_len);
                tmp_off = pdu_start + total_len;
                ok = 1;
                break;
        }
        if (!ok || tmp_off != pdu_start + total_len) {
            memset(&tmp_pkt, 0, sizeof(tmp_pkt));
            tmp_pkt.type = DICOM_PKT_UNKNOWN;
            tmp_pkt.u.unknown.pdu_type = pdu_type;
            tmp_pkt.u.unknown.reserved1 = buf[pdu_start + 1];
            tmp_pkt.u.unknown.pdu_length = pdu_len;
            tmp_pkt.u.unknown.data_length = pdu_len;
            if (pdu_len) memcpy(tmp_pkt.u.unknown.data, buf + pdu_start + 6,
                    pdu_len > DICOM_MAX_UNKNOWN_PDU_LEN ? DICOM_MAX_UNKNOWN_PDU_LEN : pdu_len);
        }
        tmp_pkt.raw_length = total_len > DICOM_MAX_UNKNOWN_PDU_LEN ? DICOM_MAX_UNKNOWN_PDU_LEN : total_len;
        memcpy(tmp_pkt.raw_data, buf + pdu_start, tmp_pkt.raw_length);
        if (total_len > tmp_pkt.raw_length) {
            tmp_pkt.raw_tail = buf + pdu_start + tmp_pkt.raw_length;
            tmp_pkt.raw_tail_length = total_len - tmp_pkt.raw_length;
        }
        out_packets[count++] = tmp_pkt;
        off = pdu_start + total_len;
    }

    annotate_dimse_fragments(out_packets, count);
    return off == buf_len ? count : 0;
}
