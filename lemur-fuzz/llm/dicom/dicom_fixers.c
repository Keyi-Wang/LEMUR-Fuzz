#include <stdint.h>
#include <string.h>
#include "dicom_packets.h"

static uint32_t rd32(const uint8_t *p){ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static void wr32(uint8_t *p, uint32_t v){ p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v; }
static uint16_t rd16le(const uint8_t *p){ return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8)); }
static uint32_t rd32le(const uint8_t *p){ return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }
static void wr16le(uint8_t *p, uint16_t v){ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }

static void set_dicom_str(dicom_str_t *s, const char *v){
    if(!s || !v) return;
    size_t n = strlen(v);
    if(n > DICOM_MAX_UID_LEN) n = DICOM_MAX_UID_LEN;
    s->length = (uint16_t)n;
    memset(s->value, 0, sizeof(s->value));
    memcpy(s->value, v, n);
}

static void set_dimse_uid(char *dst, uint16_t *dst_len, uint32_t max_len, const char *v){
    if(!dst || !dst_len || !v || max_len == 0) return;
    size_t n = strlen(v);
    if(n > max_len) n = max_len;
    memset(dst, 0, max_len);
    memcpy(dst, v, n);
    *dst_len = (uint16_t)n;
}

/* PS3.5 UID values are at most 64 characters (including components), and
 * contain only digits and dots.  Keep the field model usable after mutation
 * instead of allowing an overlong/non-UID value to poison association
 * negotiation or a DIMSE command. */
static void normalize_uid_buf(char *s, uint16_t *len, uint32_t cap, const char *fallback){
    if(!s || !len || cap == 0) return;
    uint32_t n = *len;
    if(n > cap) n = cap;
    if(n > 64U) n = 64U;
    uint32_t w = 0;
    for(uint32_t i=0; i<n && w<64U; i++){
        unsigned char c = (unsigned char)s[i];
        if((c >= '0' && c <= '9') || c == '.') s[w++] = (char)c;
    }
    while(w && s[w-1] == '.') w--;
    if(w == 0 && fallback){
        size_t fn = strlen(fallback); if(fn > cap) fn = cap; if(fn > 64U) fn = 64U;
        memcpy(s, fallback, fn); w = (uint32_t)fn;
    }
    *len = (uint16_t)w;
    if(w < cap) memset(s + w, 0, cap - w);
}

static void normalize_ae_title(char s[16], int preserve_value){
    if(!s) return;
    char tmp[16]; memset(tmp, ' ', sizeof(tmp));
    if(preserve_value){
        int w = 0;
        for(int i=0;i<16 && w<16;i++){
            unsigned char c=(unsigned char)s[i];
            if(c == 0) break;
            /* AE titles are ASCII, padded with spaces; reject control bytes. */
            if(c >= 0x20 && c <= 0x7e) tmp[w++] = (char)c;
        }
    }
    memcpy(s, tmp, sizeof(tmp));
}

static uint8_t normalize_pcid(uint8_t pcid);
static void fix_dimse_semantic_fields(dicom_pdv_item_t *p);

static uint16_t trim_uid_len(const char *s, uint16_t n){
    while(n > 0 && (s[n - 1] == '\0' || s[n - 1] == ' ')) n--;
    return n;
}

static int uid_equals_buf(const dicom_str_t *a, const char *b, uint16_t b_len){
    if(!a || !b) return 0;
    uint16_t alen = trim_uid_len(a->value, a->length);
    uint16_t blen = trim_uid_len(b, b_len);
    return alen == blen && memcmp(a->value, b, alen) == 0;
}

static const char *default_sop_for_command(uint16_t cmd){
    switch(cmd){
        case DICOM_DIMSE_C_STORE_RQ: return "1.2.840.10008.5.1.4.1.1.2";
        case DICOM_DIMSE_C_FIND_RQ:  return "1.2.840.10008.5.1.4.1.2.1.1";
        case DICOM_DIMSE_C_GET_RQ:   return "1.2.840.10008.5.1.4.1.2.1.3";
        case DICOM_DIMSE_C_MOVE_RQ:  return "1.2.840.10008.5.1.4.1.2.1.2";
        default: return "1.2.840.10008.1.1";
    }
}

static void pdv_command_sop(const dicom_pdv_item_t *pdv, const char **literal, const char **buf, uint16_t *len){
    if(literal) *literal = 0;
    if(buf) *buf = 0;
    if(len) *len = 0;
    if(!pdv) return;
    if(pdv->dimse_affected_sop_class_uid_len){
        if(buf) *buf = pdv->dimse_affected_sop_class_uid;
        if(len) *len = pdv->dimse_affected_sop_class_uid_len;
        return;
    }
    if(pdv->dimse_requested_sop_class_uid_len){
        if(buf) *buf = pdv->dimse_requested_sop_class_uid;
        if(len) *len = pdv->dimse_requested_sop_class_uid_len;
        return;
    }
    if(literal) *literal = default_sop_for_command(pdv->dimse_command_field);
}

static int pcid_exists(dicom_packet_t *pkts, int num_packets, uint8_t pcid){
    pcid = normalize_pcid(pcid);
    for(int i=0;i<num_packets;i++){
        if(pkts[i].type != DICOM_PKT_A_ASSOCIATE_RQ) continue;
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        for(uint8_t j=0;j<rq->presentation_context_count && j<DICOM_MAX_PRESENTATION_CONTEXTS;j++)
            if(normalize_pcid(rq->presentation_contexts[j].presentation_context_id) == pcid) return 1;
    }
    return 0;
}

static uint8_t find_pcid_for_uid(dicom_packet_t *pkts, int num_packets, const char *uid, uint16_t uid_len){
    if(!uid || uid_len == 0) return 0;
    for(int i=0;i<num_packets;i++){
        if(pkts[i].type != DICOM_PKT_A_ASSOCIATE_RQ) continue;
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        for(uint8_t j=0;j<rq->presentation_context_count && j<DICOM_MAX_PRESENTATION_CONTEXTS;j++){
            dicom_presentation_context_item_t *pc = &rq->presentation_contexts[j];
            if(uid_equals_buf(&pc->abstract_syntax.abstract_syntax_name, uid, uid_len))
                return normalize_pcid(pc->presentation_context_id);
        }
    }
    return 0;
}

static void set_pc_abstract_for_pcid(dicom_packet_t *pkts, int num_packets, uint8_t pcid, const char *uid, uint16_t uid_len){
    if(!uid || uid_len == 0) return;
    pcid = normalize_pcid(pcid);
    for(int i=0;i<num_packets;i++){
        if(pkts[i].type != DICOM_PKT_A_ASSOCIATE_RQ) continue;
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        if(rq->presentation_context_count == 0) rq->presentation_context_count = 1;
        if(rq->presentation_context_count > DICOM_MAX_PRESENTATION_CONTEXTS) rq->presentation_context_count = DICOM_MAX_PRESENTATION_CONTEXTS;
        dicom_presentation_context_item_t *fallback = &rq->presentation_contexts[0];
        dicom_presentation_context_item_t *target = fallback;
        for(uint8_t j=0;j<rq->presentation_context_count;j++){
            if(normalize_pcid(rq->presentation_contexts[j].presentation_context_id) == pcid){
                target = &rq->presentation_contexts[j];
                break;
            }
        }
        pkts[i].raw_length = 0;
        target->item_type = 0x20;
        target->reserved1 = 0;
        target->presentation_context_id = pcid;
        memset(target->reserved2, 0, sizeof(target->reserved2));
        target->abstract_syntax.item_type = 0x30;
        target->abstract_syntax.reserved1 = 0;
        uint16_t n = trim_uid_len(uid, uid_len);
        if(n > DICOM_MAX_UID_LEN) n = DICOM_MAX_UID_LEN;
        target->abstract_syntax.abstract_syntax_name.length = n;
        memset(target->abstract_syntax.abstract_syntax_name.value, 0, DICOM_MAX_UID_LEN);
        memcpy(target->abstract_syntax.abstract_syntax_name.value, uid, n);
        if(target->transfer_syntax_count == 0) target->transfer_syntax_count = 1;
        target->transfer_syntaxes[0].item_type = 0x40;
        target->transfer_syntaxes[0].reserved1 = 0;
        if(target->transfer_syntaxes[0].transfer_syntax_name.length == 0)
            set_dicom_str(&target->transfer_syntaxes[0].transfer_syntax_name, "1.2.840.10008.1.2");
    }
}

static uint8_t normalize_pcid(uint8_t pcid){
    if(pcid == 0) pcid = 1;
    /* All odd IDs through 255 are legal (PS3.8). */
    if(pcid == 0) pcid = 1;
    if((pcid & 1u) == 0) pcid++;
    return pcid;
}

static uint8_t preferred_pcid(dicom_packet_t *pkts, int num_packets){
    if(!pkts || num_packets <= 0) return 1;
    for(int i=0;i<num_packets;i++){
        if(pkts[i].type != DICOM_PKT_A_ASSOCIATE_RQ) continue;
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        for(uint8_t j=0;j<rq->presentation_context_count && j<DICOM_MAX_PRESENTATION_CONTEXTS;j++){
            uint8_t pcid = rq->presentation_contexts[j].presentation_context_id;
            if(pcid) return normalize_pcid(pcid);
        }
    }
    return 1;
}

static int looks_like_dimse_command(const uint8_t *data, uint32_t len){
    uint32_t off = 0;
    while(data && off + 8 <= len){
        uint16_t group = rd16le(data + off);
        uint16_t elem = rd16le(data + off + 2);
        uint32_t vlen = rd32le(data + off + 4);
        off += 8;
        if(group != 0x0000 || off + vlen > len) return 0;
        if(elem == 0x0100 && vlen >= 2) return 1;
        off += vlen;
    }
    return 0;
}

static int pdv_has_dimse(const dicom_pdv_item_t *pdv){
    if(!pdv) return 0;
    /* A command can span several PDVs.  The command bit identifies every
     * fragment, while the semantic model belongs only to the final fragment
     * (or to a PDV explicitly synthesized by a mutator).  Treating an
     * intermediate fragment as a complete DIMSE message makes the cross-PDV
     * fixer reset its dataset state and causes the reassembler to emit one
     * command per fragment. */
    if(pdv->has_dimse_command || pdv->has_dimse_command_fields) return 1;
    return (pdv->control_header & (DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT)) ==
           (DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT) &&
           pdv->data_length >= 8;
}

static int valid_dimse_request(uint16_t cmd){
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

static int dimse_request_has_no_dataset(uint16_t cmd){
    return cmd == DICOM_DIMSE_C_ECHO_RQ ||
           cmd == DICOM_DIMSE_C_CANCEL_RQ ||
           cmd == DICOM_DIMSE_N_GET_RQ ||
           cmd == DICOM_DIMSE_N_DELETE_RQ;
}

static void fix_dicom_str_len(dicom_str_t *s){
    if(!s) return;
    if(s->length > DICOM_MAX_UID_LEN) s->length = DICOM_MAX_UID_LEN;
}

static uint32_t presentation_context_item_len(dicom_presentation_context_item_t *pc){
    if(!pc) return 0;
    fix_dicom_str_len(&pc->abstract_syntax.abstract_syntax_name);
    pc->abstract_syntax.item_length = pc->abstract_syntax.abstract_syntax_name.length;
    uint32_t len = 4U + 4U + pc->abstract_syntax.item_length;
    if(pc->transfer_syntax_count > DICOM_MAX_TRANSFER_SYNTAXES)
        pc->transfer_syntax_count = DICOM_MAX_TRANSFER_SYNTAXES;
    for(uint8_t k=0;k<pc->transfer_syntax_count;k++){
        fix_dicom_str_len(&pc->transfer_syntaxes[k].transfer_syntax_name);
        pc->transfer_syntaxes[k].item_length = pc->transfer_syntaxes[k].transfer_syntax_name.length;
        len += 4U + pc->transfer_syntaxes[k].item_length;
    }
    if(len > 0xffffU) len = 0xffffU;
    pc->item_length = (uint16_t)len;
    return 4U + pc->item_length;
}

static uint32_t user_info_item_value_len(dicom_user_info_item_t *ui){
    if(!ui) return 0;
    uint32_t len = 0;
    if(ui->has_maximum_length) len += 8U;
    if(ui->has_implementation_class_uid){
        normalize_uid_buf(ui->implementation_class_uid.value, &ui->implementation_class_uid.length,
                          sizeof(ui->implementation_class_uid.value), "1.2.826.0.1.3680043.2.1125.lemur");
        fix_dicom_str_len(&ui->implementation_class_uid);
        len += 4U + ui->implementation_class_uid.length;
    }
    if(ui->has_async_ops_window) len += 8U;
    if(ui->role_selection_count > DICOM_MAX_ROLE_SELECTIONS)
        ui->role_selection_count = DICOM_MAX_ROLE_SELECTIONS;
    for(uint8_t i=0;i<ui->role_selection_count;i++){
        normalize_uid_buf(ui->role_selections[i].sop_class_uid.value,
                          &ui->role_selections[i].sop_class_uid.length,
                          sizeof(ui->role_selections[i].sop_class_uid.value),
                          "1.2.840.10008.1.1");
        fix_dicom_str_len(&ui->role_selections[i].sop_class_uid);
        ui->role_selections[i].scu_role = ui->role_selections[i].scu_role ? 1 : 0;
        ui->role_selections[i].scp_role = ui->role_selections[i].scp_role ? 1 : 0;
        len += 8U + ui->role_selections[i].sop_class_uid.length;
    }
    if(ui->has_implementation_version_name){
        fix_dicom_str_len(&ui->implementation_version_name);
        len += 4U + ui->implementation_version_name.length;
    }
    if(ui->has_sop_class_extended_negotiation){
        normalize_uid_buf(ui->sop_class_extended_uid.value, &ui->sop_class_extended_uid.length,
                          sizeof(ui->sop_class_extended_uid.value), "1.2.840.10008.1.1");
        fix_dicom_str_len(&ui->sop_class_extended_uid);
        if(ui->sop_class_extended_info_len > DICOM_MAX_USER_INFO_BYTES)
            ui->sop_class_extended_info_len = DICOM_MAX_USER_INFO_BYTES;
        len += 6U + ui->sop_class_extended_uid.length + ui->sop_class_extended_info_len;
    }
    if(ui->has_sop_class_common_extended_negotiation){
        normalize_uid_buf(ui->sop_class_common_sop_uid.value, &ui->sop_class_common_sop_uid.length,
                          sizeof(ui->sop_class_common_sop_uid.value), "1.2.840.10008.1.1");
        normalize_uid_buf(ui->sop_class_common_service_class_uid.value, &ui->sop_class_common_service_class_uid.length,
                          sizeof(ui->sop_class_common_service_class_uid.value), "1.2.840.10008.4.1");
        fix_dicom_str_len(&ui->sop_class_common_sop_uid);
        fix_dicom_str_len(&ui->sop_class_common_service_class_uid);
        if(ui->related_general_sop_class_uid_count > DICOM_MAX_RELATED_SOP_CLASSES)
            ui->related_general_sop_class_uid_count = DICOM_MAX_RELATED_SOP_CLASSES;
        len += 10U + ui->sop_class_common_sop_uid.length + ui->sop_class_common_service_class_uid.length;
        for(uint8_t i=0;i<ui->related_general_sop_class_uid_count;i++){
            normalize_uid_buf(ui->related_general_sop_class_uids[i].value,
                              &ui->related_general_sop_class_uids[i].length,
                              sizeof(ui->related_general_sop_class_uids[i].value),
                              "1.2.840.10008.1.1");
            fix_dicom_str_len(&ui->related_general_sop_class_uids[i]);
            len += 2U + ui->related_general_sop_class_uids[i].length;
        }
    }
    if(ui->has_user_identity_negotiation){
        ui->user_identity_type = (ui->user_identity_type >= 1 && ui->user_identity_type <= 5) ? ui->user_identity_type : 1;
        ui->user_identity_positive_response_requested = ui->user_identity_positive_response_requested ? 1 : 0;
        if(ui->user_identity_primary_field_len > DICOM_MAX_USER_INFO_BYTES)
            ui->user_identity_primary_field_len = DICOM_MAX_USER_INFO_BYTES;
        if(ui->user_identity_secondary_field_len > DICOM_MAX_USER_INFO_BYTES)
            ui->user_identity_secondary_field_len = DICOM_MAX_USER_INFO_BYTES;
        /* Type 2 is the only defined form with a secondary field.  For the
         * other forms retaining arbitrary secondary bytes makes peers reject
         * the User Identity sub-item. */
        if(ui->user_identity_type != 2) ui->user_identity_secondary_field_len = 0;
        if(ui->user_identity_type == 2 && ui->user_identity_primary_field_len == 0)
            ui->user_identity_primary_field_len = 1, ui->user_identity_primary_field[0] = 'u';
        len += 10U + ui->user_identity_primary_field_len + ui->user_identity_secondary_field_len;
    }
    if(ui->has_user_data){
        if(ui->user_data_length > DICOM_MAX_USER_INFO_BYTES) ui->user_data_length = DICOM_MAX_USER_INFO_BYTES;
        len += ui->user_data_length;
    } else {
        ui->user_data_length = 0;
    }
    if(len > 0xffffU) len = 0xffffU;
    ui->item_length = (uint16_t)len;
    return len;
}

static void ensure_required_user_info(dicom_user_info_item_t *ui){
    if(!ui) return;
    ui->item_type = 0x50;
    ui->reserved1 = 0;
    if(!ui->has_maximum_length || ui->maximum_length_received == 0){
        ui->has_maximum_length = 1;
        ui->maximum_length_received = 16384;
    }
    if(!ui->has_implementation_class_uid || ui->implementation_class_uid.length == 0){
        ui->has_implementation_class_uid = 1;
        set_dicom_str(&ui->implementation_class_uid, "1.2.826.0.1.3680043.2.1125.lemur");
    }
    if(!ui->has_implementation_version_name || ui->implementation_version_name.length == 0){
        ui->has_implementation_version_name = 1;
        set_dicom_str(&ui->implementation_version_name, "LEMUR_1");
    }
    user_info_item_value_len(ui);
}

static uint32_t fix_associate_rq_item_lengths(dicom_a_associate_rq_pdu_t *rq){
    if(!rq) return 0;
    fix_dicom_str_len(&rq->application_context.application_context_name);
    rq->application_context.item_length = rq->application_context.application_context_name.length;
    uint32_t pdu_len = 68U + 4U + rq->application_context.item_length;
    if(rq->presentation_context_count > DICOM_MAX_PRESENTATION_CONTEXTS)
        rq->presentation_context_count = DICOM_MAX_PRESENTATION_CONTEXTS;
    for(uint8_t j=0;j<rq->presentation_context_count;j++)
        pdu_len += presentation_context_item_len(&rq->presentation_contexts[j]);
    if(rq->has_user_info){
        ensure_required_user_info(&rq->user_info);
        pdu_len += 4U + rq->user_info.item_length;
    }
    rq->pdu_length = pdu_len;
    return pdu_len;
}


static uint32_t presentation_context_ac_item_len(dicom_presentation_context_ac_item_t *pc){
    if(!pc) return 0;
    pc->item_type = 0x21;
    pc->reserved1 = 0;
    pc->presentation_context_id = normalize_pcid(pc->presentation_context_id);
    pc->reserved2 = 0;
    pc->reserved3 = 0;
    if(pc->result_reason > 4) pc->result_reason = 2;
    /* Result 0 means an accepted context and therefore requires exactly one
     * transfer syntax; rejected contexts carry no transfer-syntax sub-item. */
    if(pc->result_reason != 0) pc->has_transfer_syntax = 0;
    if(pc->result_reason == 0) pc->has_transfer_syntax = 1;
    uint32_t len = 4U;
    if(pc->has_transfer_syntax){
        pc->transfer_syntax.item_type = 0x40;
        pc->transfer_syntax.reserved1 = 0;
        if(pc->transfer_syntax.transfer_syntax_name.length == 0)
            set_dicom_str(&pc->transfer_syntax.transfer_syntax_name, "1.2.840.10008.1.2");
        fix_dicom_str_len(&pc->transfer_syntax.transfer_syntax_name);
        pc->transfer_syntax.item_length = pc->transfer_syntax.transfer_syntax_name.length;
        len += 4U + pc->transfer_syntax.item_length;
    }
    if(len > 0xffffU) len = 0xffffU;
    pc->item_length = (uint16_t)len;
    return 4U + pc->item_length;
}

static uint32_t fix_associate_ac_item_lengths(dicom_a_associate_ac_pdu_t *ac){
    if(!ac) return 0;
    uint32_t pdu_len = 68U;
    if(ac->has_application_context){
        fix_dicom_str_len(&ac->application_context.application_context_name);
        ac->application_context.item_type = 0x10;
        ac->application_context.reserved1 = 0;
        ac->application_context.item_length = ac->application_context.application_context_name.length;
        pdu_len += 4U + ac->application_context.item_length;
    }
    if(ac->presentation_context_count > DICOM_MAX_PRESENTATION_CONTEXTS)
        ac->presentation_context_count = DICOM_MAX_PRESENTATION_CONTEXTS;
    for(uint8_t j=0;j<ac->presentation_context_count;j++)
        pdu_len += presentation_context_ac_item_len(&ac->presentation_contexts[j]);
    if(ac->has_user_info){
        ensure_required_user_info(&ac->user_info);
        pdu_len += 4U + ac->user_info.item_length;
    }
    if(ac->raw_items_length > DICOM_MAX_UNKNOWN_PDU_LEN)
        ac->raw_items_length = DICOM_MAX_UNKNOWN_PDU_LEN;
    pdu_len += ac->raw_items_length;
    ac->pdu_length = pdu_len;
    return pdu_len;
}

static int valid_rj_reason(uint8_t source, uint8_t reason){
    if(source == 1) return reason == 1 || reason == 2 || reason == 3 || reason == 7;
    if(source == 2) return reason == 1 || reason == 2;
    if(source == 3) return reason == 1 || reason == 2;
    return 0;
}

static uint8_t default_rj_reason(uint8_t source){
    (void)source;
    return 1;
}

static int valid_abort_reason(uint8_t source, uint8_t reason){
    if(source == 0) return reason == 0;
    if(source == 2) return reason == 0 || reason == 1 || reason == 2 || reason == 4 || reason == 5 || reason == 6;
    return 0;
}

static void fix_dimse_command_bytes(uint8_t *data, uint32_t len){
    if(!data) return;
    uint16_t command_field = 0;
    uint32_t off = 0;
    while(off + 8 <= len){
        uint16_t group = rd16le(data + off);
        uint16_t elem = rd16le(data + off + 2);
        uint32_t vlen = rd32le(data + off + 4);
        off += 8;
        if(group != 0x0000 || off + vlen > len) break;
        uint8_t *val = data + off;
        if(elem == 0x0100 && vlen >= 2){
            command_field = rd16le(val);
            if(!valid_dimse_request(command_field)){
                command_field = DICOM_DIMSE_C_ECHO_RQ;
                wr16le(val, command_field);
            }
        } else if((elem == 0x0110 || elem == 0x0120) && vlen >= 2){
            if(rd16le(val) == 0) wr16le(val, 1);
        } else if(elem == 0x0700 && vlen >= 2){
            uint16_t prio = rd16le(val);
            if(prio > 2) wr16le(val, 2);
        } else if(elem == 0x0800 && vlen >= 2){
            uint16_t ds = rd16le(val);
            if(dimse_request_has_no_dataset(command_field)){
                wr16le(val, 0x0101);
            } else if(ds == 0xffff){
                wr16le(val, 0x0101);
            }
        } else if((elem == 0x1002 || elem == 0x1008 || elem == 0x1031) && vlen >= 2){
            if(rd16le(val) == 0) wr16le(val, 1);
        }
        off += vlen;
    }
}

void fix_dicom_pdu_header_lengths(dicom_packet_t *pkts, int num_packets){
    if(!pkts || num_packets<=0) return;
    for(int i=0;i<num_packets;i++){
        /* A split cache is immutable input. Edit the field model for known
         * oversized PDUs instead of treating its prefix as the whole PDU. */
        if (pkts[i].raw_tail_length && pkts[i].type != DICOM_PKT_UNKNOWN)
            pkts[i].raw_length = 0;
        if(pkts[i].raw_length >= 6){
            uint32_t len = pkts[i].raw_length - 6U + pkts[i].raw_tail_length;
            wr32(pkts[i].raw_data + 2, len);
            if(pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) pkts[i].raw_data[0] = DICOM_PDU_A_ASSOCIATE_RQ;
            else if(pkts[i].type == DICOM_PKT_A_ASSOCIATE_AC) pkts[i].raw_data[0] = DICOM_PDU_A_ASSOCIATE_AC;
            else if(pkts[i].type == DICOM_PKT_A_ASSOCIATE_RJ) pkts[i].raw_data[0] = DICOM_PDU_A_ASSOCIATE_RJ;
            else if(pkts[i].type == DICOM_PKT_P_DATA_TF) pkts[i].raw_data[0] = DICOM_PDU_P_DATA_TF;
            else if(pkts[i].type == DICOM_PKT_A_RELEASE_RQ) pkts[i].raw_data[0] = DICOM_PDU_A_RELEASE_RQ;
            else if(pkts[i].type == DICOM_PKT_A_RELEASE_RP) pkts[i].raw_data[0] = DICOM_PDU_A_RELEASE_RP;
            else if(pkts[i].type == DICOM_PKT_A_ABORT) pkts[i].raw_data[0] = DICOM_PDU_A_ABORT;
            pkts[i].raw_data[1] = 0;
        }
        if(pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
            pkts[i].u.a_associate_rq.pdu_type = DICOM_PDU_A_ASSOCIATE_RQ;
            pkts[i].u.a_associate_rq.reserved1 = 0;
        } else if(pkts[i].type == DICOM_PKT_A_ASSOCIATE_AC) {
            pkts[i].u.a_associate_ac.pdu_type = DICOM_PDU_A_ASSOCIATE_AC;
            pkts[i].u.a_associate_ac.reserved1 = 0;
        } else if(pkts[i].type == DICOM_PKT_A_ASSOCIATE_RJ) {
            pkts[i].u.a_associate_rj.pdu_type = DICOM_PDU_A_ASSOCIATE_RJ;
            pkts[i].u.a_associate_rj.reserved1 = 0;
            pkts[i].u.a_associate_rj.pdu_length = 4;
        } else if(pkts[i].type == DICOM_PKT_P_DATA_TF) {
            pkts[i].u.p_data_tf.pdu_type = DICOM_PDU_P_DATA_TF;
            pkts[i].u.p_data_tf.reserved1 = 0;
        } else if(pkts[i].type == DICOM_PKT_A_RELEASE_RQ) {
            pkts[i].u.a_release_rq.pdu_type = DICOM_PDU_A_RELEASE_RQ;
            pkts[i].u.a_release_rq.reserved1 = 0;
            pkts[i].u.a_release_rq.pdu_length = 4;
        } else if(pkts[i].type == DICOM_PKT_A_RELEASE_RP) {
            pkts[i].u.a_release_rp.pdu_type = DICOM_PDU_A_RELEASE_RP;
            pkts[i].u.a_release_rp.reserved1 = 0;
            pkts[i].u.a_release_rp.pdu_length = 4;
        } else if(pkts[i].type == DICOM_PKT_A_ABORT) {
            pkts[i].u.a_abort.pdu_type = DICOM_PDU_A_ABORT;
            pkts[i].u.a_abort.reserved1 = 0;
            pkts[i].u.a_abort.pdu_length = 4;
        }
    }
}

void fix_associate_rq_constraints(dicom_packet_t *pkts, int num_packets){
    if(!pkts || num_packets<=0) return;
    for(int i=0;i<num_packets;i++){
        if(pkts[i].type != DICOM_PKT_A_ASSOCIATE_RQ) continue;
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        rq->protocol_version = 1;
        rq->reserved1 = 0;
        rq->reserved2 = 0;
        memset(rq->reserved3, 0, sizeof(rq->reserved3));
        normalize_ae_title(rq->called_ae_title, 1);
        normalize_ae_title(rq->calling_ae_title, 1);
        if(rq->application_context.application_context_name.length == 0)
            set_dicom_str(&rq->application_context.application_context_name, "1.2.840.10008.3.1.1.1");
        rq->application_context.item_type = 0x10;
        rq->application_context.reserved1 = 0;
        if(rq->presentation_context_count == 0)
            rq->presentation_context_count = 1;
        if(rq->presentation_context_count > DICOM_MAX_PRESENTATION_CONTEXTS)
            rq->presentation_context_count = DICOM_MAX_PRESENTATION_CONTEXTS;
        for(uint8_t j=0;j<rq->presentation_context_count;j++){
            dicom_presentation_context_item_t *pc = &rq->presentation_contexts[j];
            pc->item_type = 0x20;
            pc->reserved1 = 0;
            pc->presentation_context_id = normalize_pcid(pc->presentation_context_id ? pc->presentation_context_id : (uint8_t)(1 + 2*j));
            for(uint8_t k=0;k<j;k++) if(rq->presentation_contexts[k].presentation_context_id == pc->presentation_context_id){
                uint16_t candidate = (uint16_t)pc->presentation_context_id + 2U;
                while(candidate <= 255U){ int used=0; for(uint8_t q=0;q<j;q++) if(rq->presentation_contexts[q].presentation_context_id==(uint8_t)candidate) used=1; if(!used) break; candidate+=2U; }
                pc->presentation_context_id = (uint8_t)(candidate <= 255U ? candidate : (1U + 2U*j));
            }
            memset(pc->reserved2, 0, sizeof(pc->reserved2));
            pc->abstract_syntax.item_type = 0x30;
            pc->abstract_syntax.reserved1 = 0;
            normalize_uid_buf(pc->abstract_syntax.abstract_syntax_name.value,
                              &pc->abstract_syntax.abstract_syntax_name.length,
                              sizeof(pc->abstract_syntax.abstract_syntax_name.value), "1.2.840.10008.1.1");
            if(pc->abstract_syntax.abstract_syntax_name.length == 0)
                set_dicom_str(&pc->abstract_syntax.abstract_syntax_name, "1.2.840.10008.1.1");
            if(pc->transfer_syntax_count == 0)
                pc->transfer_syntax_count = 1;
            if(pc->transfer_syntax_count > DICOM_MAX_TRANSFER_SYNTAXES)
                pc->transfer_syntax_count = DICOM_MAX_TRANSFER_SYNTAXES;
            for(uint8_t k=0;k<pc->transfer_syntax_count;k++){
                pc->transfer_syntaxes[k].item_type = 0x40;
                pc->transfer_syntaxes[k].reserved1 = 0;
                normalize_uid_buf(pc->transfer_syntaxes[k].transfer_syntax_name.value,
                                  &pc->transfer_syntaxes[k].transfer_syntax_name.length,
                                  sizeof(pc->transfer_syntaxes[k].transfer_syntax_name.value), "1.2.840.10008.1.2");
                if(pc->transfer_syntaxes[k].transfer_syntax_name.length == 0)
                    set_dicom_str(&pc->transfer_syntaxes[k].transfer_syntax_name, "1.2.840.10008.1.2");
            }
        }
        /* Do not synthesize an entire User Information item for a mutated
         * association that did not carry one.  It changes negotiation state
         * and masks the server's optional-item paths.  Repair the item only
         * when the input actually contained it. */
        if(rq->has_user_info) ensure_required_user_info(&rq->user_info);
        fix_associate_rq_item_lengths(rq);
        /* The parser may retain the original PDU as a lossless cache.  Once
         * any modeled field is normalized/synthesized, that cache is stale. */
        pkts[i].raw_length = 0;
        if(pkts[i].raw_length >= 74){
            pkts[i].raw_data[6]=0; pkts[i].raw_data[7]=1;
            pkts[i].raw_data[8]=0; pkts[i].raw_data[9]=0;
            memset(pkts[i].raw_data + 42, 0, 32);
        }
    }
}

void fix_associate_ac_constraints(dicom_packet_t *pkts, int num_packets){
    if(!pkts || num_packets<=0) return;
    for(int i=0;i<num_packets;i++){
        if(pkts[i].type != DICOM_PKT_A_ASSOCIATE_AC) continue;
        dicom_a_associate_ac_pdu_t *ac = &pkts[i].u.a_associate_ac;
        ac->pdu_type = DICOM_PDU_A_ASSOCIATE_AC;
        ac->reserved1 = 0;
        ac->protocol_version = 1;
        ac->reserved2 = 0;
        memset(ac->reserved3, 0, sizeof(ac->reserved3));
        normalize_ae_title(ac->called_ae_title, 1);
        normalize_ae_title(ac->calling_ae_title, 1);
        /* Application Context and User Information are optional in the model
         * until the peer actually supplied them.  Do not add negotiation
         * items merely because a semantic mutation touched another field. */
        if(ac->has_application_context && ac->application_context.application_context_name.length == 0)
            set_dicom_str(&ac->application_context.application_context_name, "1.2.840.10008.3.1.1.1");
        if(ac->presentation_context_count > DICOM_MAX_PRESENTATION_CONTEXTS)
            ac->presentation_context_count = DICOM_MAX_PRESENTATION_CONTEXTS;
        for(uint8_t j=0;j<ac->presentation_context_count;j++){
            ac->presentation_contexts[j].presentation_context_id = normalize_pcid(ac->presentation_contexts[j].presentation_context_id);
            for(uint8_t k=0;k<j;k++) if(ac->presentation_contexts[k].presentation_context_id == ac->presentation_contexts[j].presentation_context_id){
                uint16_t candidate=(uint16_t)ac->presentation_contexts[j].presentation_context_id+2U;
                while(candidate<=255U){ int used=0; for(uint8_t q=0;q<j;q++) if(ac->presentation_contexts[q].presentation_context_id==(uint8_t)candidate) used=1; if(!used) break; candidate+=2U; }
                ac->presentation_contexts[j].presentation_context_id=(uint8_t)(candidate<=255U?candidate:(1U+2U*j));
            }
        }
        if(ac->has_user_info) ensure_required_user_info(&ac->user_info);
        fix_associate_ac_item_lengths(ac);
        pkts[i].raw_length = 0;
        if(pkts[i].raw_length >= 74){
            pkts[i].raw_data[0] = DICOM_PDU_A_ASSOCIATE_AC;
            pkts[i].raw_data[1] = 0;
            wr32(pkts[i].raw_data + 2, pkts[i].raw_length - 6U);
            pkts[i].raw_data[6] = 0; pkts[i].raw_data[7] = 1;
            pkts[i].raw_data[8] = 0; pkts[i].raw_data[9] = 0;
            memset(pkts[i].raw_data + 42, 0, 32);
        }
    }
}

void fix_p_data_tf_constraints(dicom_packet_t *pkts, int num_packets){
    if(!pkts || num_packets<=0) return;
    uint8_t pcid = preferred_pcid(pkts, num_packets);
    for(int i=0;i<num_packets;i++){
        if(pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        if(pkts[i].raw_length >= 6){
            uint32_t body_len = pkts[i].raw_length - 6U;
            wr32(pkts[i].raw_data + 2, body_len);
            uint32_t off = 6;
            while(off + 6 <= pkts[i].raw_length){
                uint32_t pdv_len = rd32(pkts[i].raw_data + off);
                if(pdv_len < 2 || off + 4 + pdv_len > pkts[i].raw_length) {
                    uint32_t rest = pkts[i].raw_length - off - 4;
                    if(rest >= 2) wr32(pkts[i].raw_data + off, rest);
                    break;
                }
                pkts[i].raw_data[off + 4] = pcid;
                /* Preserve the command-fragment boundary.  Earlier code
                 * forced LAST_FRAGMENT on every PDV, splitting a fragmented
                 * DIMSE command into several independent commands. */
                uint8_t ctrl = (uint8_t)(pkts[i].raw_data[off + 5] &
                                         (DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT));
                if ((ctrl & (DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT)) ==
                    (DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT) &&
                    looks_like_dimse_command(pkts[i].raw_data + off + 6, pdv_len - 2))
                    ctrl |= DICOM_PDV_FLAG_COMMAND;
                pkts[i].raw_data[off + 5] = ctrl;
                off += 4 + pdv_len;
            }
        }
        dicom_p_data_tf_pdu_t *pt = &pkts[i].u.p_data_tf;
        pt->pdu_type = DICOM_PDU_P_DATA_TF;
        pt->reserved1 = 0;
        if(pt->pdv_count == 0) pt->pdv_count = 1;
        if(pt->pdv_count > DICOM_MAX_PDV_ITEMS) pt->pdv_count = DICOM_MAX_PDV_ITEMS;
        pt->pdu_length = 0;
        for(uint16_t j=0;j<pt->pdv_count && j<DICOM_MAX_PDV_ITEMS;j++){
            dicom_pdv_item_t *pdv=&pt->pdvs[j];
            const char *lit = 0, *uid = 0;
            uint16_t uid_len = 0;
            pdv_command_sop(pdv, &lit, &uid, &uid_len);
            uint8_t current_pcid = normalize_pcid(pdv->presentation_context_id ? pdv->presentation_context_id : pcid);
            /* Preserve a valid context selected by the seed.  Retargeting all
             * PDVs to the first context made C-GET/C-STORE datasets negotiate
             * under the wrong SOP class and was the main fixer-induced loss of
             * DICOM coverage. */
            if(!pdv->presentation_context_id || !pcid_exists(pkts, num_packets, current_pcid)){
                if(uid && uid_len) current_pcid = find_pcid_for_uid(pkts, num_packets, uid, uid_len);
                else if(lit) current_pcid = find_pcid_for_uid(pkts, num_packets, lit, (uint16_t)strlen(lit));
                if(!current_pcid) current_pcid = pcid;
            }
            pdv->presentation_context_id = normalize_pcid(current_pcid);
            if(pdv->data_length > DICOM_MAX_PDV_DATA_LEN)
                pdv->data_length = DICOM_MAX_PDV_DATA_LEN;
            if(pdv->data_tail_length > DICOM_MAX_PDV_DATA_LEN - pdv->data_length)
                pdv->data_tail_length = DICOM_MAX_PDV_DATA_LEN - pdv->data_length;
            pdv->control_header &= (DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT);
            if(pdv->has_dimse_command)
                pdv->control_header |= DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT;
            else if (pt->pdv_count == 1)
                pdv->control_header |= DICOM_PDV_FLAG_LAST_FRAGMENT;
            /* Keep an intermediate command fragment intermediate.  For a
             * newly synthesized PDV, add_pdvs() already supplies the final
             * flag; the fixer must not turn every item into a final fragment. */
            pdv->pdv_length = pdv->data_length + pdv->data_tail_length + 2U;
            pt->pdu_length += 4U + pdv->pdv_length;
        }
        if(pt->pdu_length >= DICOM_MAX_UNKNOWN_PDU_LEN)
            pt->pdv_tail_length = 0;
        else if(pt->pdv_tail_length > DICOM_MAX_UNKNOWN_PDU_LEN - pt->pdu_length)
            pt->pdv_tail_length = DICOM_MAX_UNKNOWN_PDU_LEN - pt->pdu_length;
        pt->pdu_length += pt->pdv_tail_length;
        /* Reassembly must use the repaired structured representation rather
         * than the stale raw PDU cached by the parser. */
        pkts[i].raw_length = 0;
        pkts[i].raw_tail_length = 0;
    }
}

void fix_dimse_command_constraints(dicom_packet_t *pkts, int num_packets){
    if(!pkts || num_packets<=0) return;
    for(int i=0;i<num_packets;i++){
        if(pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        if(pkts[i].raw_length >= 12){
            uint32_t body_len = pkts[i].raw_length - 6U;
            uint32_t off = 6;
            while(off + 6 <= pkts[i].raw_length){
                uint32_t pdv_len = rd32(pkts[i].raw_data + off);
                if(pdv_len < 2 || off + 4 + pdv_len > pkts[i].raw_length) break;
                if(pkts[i].raw_data[off + 5] & DICOM_PDV_FLAG_COMMAND)
                    fix_dimse_command_bytes(pkts[i].raw_data + off + 6, pdv_len - 2);
                off += 4 + pdv_len;
                if(off - 6 >= body_len) break;
            }
        }
        for(uint16_t j=0;j<pkts[i].u.p_data_tf.pdv_count && j<DICOM_MAX_PDV_ITEMS;j++){
            dicom_pdv_item_t *pdv=&pkts[i].u.p_data_tf.pdvs[j];
            if(pdv->has_dimse_command || pdv->has_dimse_command_fields){
                /* has_dimse_command_fields also describes a command that was
                 * reconstructed across several PDVs.  Keep it fragmented;
                 * setting has_dimse_command here caused the reassembler to
                 * replace the whole fragment sequence with one synthetic
                 * command and discarded the dataset boundary. */
                int modeled_command = pdv->has_dimse_command;
                if(!valid_dimse_request(pdv->dimse_command_field))
                    pdv->dimse_command_field = DICOM_DIMSE_C_ECHO_RQ;

                /* PS3.7 §9.3.2.3: C-CANCEL-RQ requires Responded To, not
                 * Message ID. Preserve the referenced request, including zero. */
                if (pdv->dimse_command_field != DICOM_DIMSE_C_CANCEL_RQ) {
                    pdv->dimse_message_id_responded_to = 0;
                    pdv->dimse_fields_present &= ~DICOM_DIMSE_PRESENT_RESPONDED_TO;
                } else {
                    pdv->dimse_fields_present &= ~DICOM_DIMSE_PRESENT_MESSAGE_ID;
                    pdv->dimse_fields_present |= DICOM_DIMSE_PRESENT_RESPONDED_TO;
                }
                pdv->dimse_status = 0;
                pdv->dimse_fields_present &= ~DICOM_DIMSE_PRESENT_STATUS;
                if(pdv->dimse_priority > 2) pdv->dimse_priority = 2;
                if(dimse_request_has_no_dataset(pdv->dimse_command_field))
                    pdv->dimse_command_data_set_type = 0x0101;
                else if(pdv->dimse_command_data_set_type != 0x0000 &&
                        pdv->dimse_command_data_set_type != 0x0101)
                    pdv->dimse_command_data_set_type = 0x0101;

                if(pdv->dimse_affected_sop_class_uid_len > DICOM_MAX_DIMSE_UID_LEN)
                    pdv->dimse_affected_sop_class_uid_len = DICOM_MAX_DIMSE_UID_LEN;
                if(pdv->dimse_requested_sop_class_uid_len > DICOM_MAX_DIMSE_UID_LEN)
                    pdv->dimse_requested_sop_class_uid_len = DICOM_MAX_DIMSE_UID_LEN;
                if(pdv->dimse_affected_sop_instance_uid_len > DICOM_MAX_DIMSE_UID_LEN)
                    pdv->dimse_affected_sop_instance_uid_len = DICOM_MAX_DIMSE_UID_LEN;
                if(pdv->dimse_requested_sop_instance_uid_len > DICOM_MAX_DIMSE_UID_LEN)
                    pdv->dimse_requested_sop_instance_uid_len = DICOM_MAX_DIMSE_UID_LEN;
                if(pdv->dimse_move_destination_len > DICOM_MAX_DIMSE_AE_LEN)
                    pdv->dimse_move_destination_len = DICOM_MAX_DIMSE_AE_LEN;
                if(pdv->dimse_move_originator_ae_title_len > DICOM_MAX_DIMSE_AE_LEN)
                    pdv->dimse_move_originator_ae_title_len = DICOM_MAX_DIMSE_AE_LEN;
                if(pdv->dimse_attribute_identifier_list_len > DICOM_MAX_DIMSE_ATTR_LIST_LEN)
                    pdv->dimse_attribute_identifier_list_len = DICOM_MAX_DIMSE_ATTR_LIST_LEN;
                pdv->dimse_attribute_identifier_list_len = (uint16_t)(pdv->dimse_attribute_identifier_list_len & ~3U);
                if((pdv->dimse_command_field == DICOM_DIMSE_C_ECHO_RQ ||
                    pdv->dimse_command_field == DICOM_DIMSE_C_STORE_RQ ||
                    pdv->dimse_command_field == DICOM_DIMSE_C_FIND_RQ ||
                    pdv->dimse_command_field == DICOM_DIMSE_C_GET_RQ ||
                    pdv->dimse_command_field == DICOM_DIMSE_C_MOVE_RQ) &&
                   pdv->dimse_affected_sop_class_uid_len == 0)
                    set_dimse_uid(pdv->dimse_affected_sop_class_uid,
                                  &pdv->dimse_affected_sop_class_uid_len,
                                  DICOM_MAX_DIMSE_UID_LEN, default_sop_for_command(pdv->dimse_command_field));
                if(pdv->dimse_command_field == DICOM_DIMSE_C_STORE_RQ &&
                   pdv->dimse_affected_sop_instance_uid_len == 0)
                    set_dimse_uid(pdv->dimse_affected_sop_instance_uid,
                                  &pdv->dimse_affected_sop_instance_uid_len,
                                  DICOM_MAX_DIMSE_UID_LEN, "1.2.826.0.1.3680043.2.1125.1");
                if(pdv->dimse_command_field == DICOM_DIMSE_N_CREATE_RQ &&
                   pdv->dimse_affected_sop_class_uid_len == 0)
                    set_dimse_uid(pdv->dimse_affected_sop_class_uid,
                                  &pdv->dimse_affected_sop_class_uid_len,
                                  DICOM_MAX_DIMSE_UID_LEN, "1.2.840.10008.1.1");
                if((pdv->dimse_command_field == DICOM_DIMSE_N_EVENT_REPORT_RQ ||
                    pdv->dimse_command_field == DICOM_DIMSE_N_GET_RQ ||
                    pdv->dimse_command_field == DICOM_DIMSE_N_SET_RQ ||
                    pdv->dimse_command_field == DICOM_DIMSE_N_ACTION_RQ ||
                    pdv->dimse_command_field == DICOM_DIMSE_N_DELETE_RQ) &&
                   pdv->dimse_requested_sop_class_uid_len == 0)
                    set_dimse_uid(pdv->dimse_requested_sop_class_uid,
                                  &pdv->dimse_requested_sop_class_uid_len,
                                  DICOM_MAX_DIMSE_UID_LEN, "1.2.840.10008.1.1");
                if((pdv->dimse_command_field == DICOM_DIMSE_N_EVENT_REPORT_RQ ||
                    pdv->dimse_command_field == DICOM_DIMSE_N_GET_RQ ||
                    pdv->dimse_command_field == DICOM_DIMSE_N_SET_RQ ||
                    pdv->dimse_command_field == DICOM_DIMSE_N_ACTION_RQ ||
                    pdv->dimse_command_field == DICOM_DIMSE_N_DELETE_RQ) &&
                   pdv->dimse_requested_sop_instance_uid_len == 0)
                    set_dimse_uid(pdv->dimse_requested_sop_instance_uid,
                                  &pdv->dimse_requested_sop_instance_uid_len,
                                  DICOM_MAX_DIMSE_UID_LEN, "1.2.826.0.1.3680043.2.1125.9");
                if((pdv->dimse_command_field == DICOM_DIMSE_N_EVENT_REPORT_RQ) && pdv->dimse_event_type_id == 0)
                    pdv->dimse_event_type_id = 1;
                if((pdv->dimse_command_field == DICOM_DIMSE_N_ACTION_RQ) && pdv->dimse_action_type_id == 0)
                    pdv->dimse_action_type_id = 1;
                if(pdv->dimse_command_field == DICOM_DIMSE_C_MOVE_RQ && pdv->dimse_move_destination_len == 0){
                    memcpy(pdv->dimse_move_destination, "STORESCP", 8);
                    pdv->dimse_move_destination_len = 8;
                }
                fix_dimse_semantic_fields(pdv);
                if(!modeled_command) pdv->has_dimse_command = 0;
            }
        }
    }
}

/* Command Set fields constrain the following P-DATA stream.  In particular,
 * Command Data Set Type must agree with whether a dataset PDV follows, and a
 * C-CANCEL-RQ must refer to a request message ID from the same association.
 * These are cross-PDV/message constraints; fixing the individual 16-bit
 * fields alone cannot enforce them. */
static __attribute__((unused)) int dimse_command_allows_dataset(uint16_t cmd){
    return cmd == DICOM_DIMSE_C_STORE_RQ || cmd == DICOM_DIMSE_C_FIND_RQ ||
           cmd == DICOM_DIMSE_C_GET_RQ || cmd == DICOM_DIMSE_C_MOVE_RQ ||
           cmd == DICOM_DIMSE_N_EVENT_REPORT_RQ || cmd == DICOM_DIMSE_N_SET_RQ ||
           cmd == DICOM_DIMSE_N_ACTION_RQ || cmd == DICOM_DIMSE_N_CREATE_RQ;
}

static void fix_dimse_semantic_fields(dicom_pdv_item_t *p){
    if(!p) return;
    uint16_t c = p->dimse_command_field;
    normalize_uid_buf(p->dimse_affected_sop_class_uid, &p->dimse_affected_sop_class_uid_len,
                      sizeof(p->dimse_affected_sop_class_uid), NULL);
    normalize_uid_buf(p->dimse_requested_sop_class_uid, &p->dimse_requested_sop_class_uid_len,
                      sizeof(p->dimse_requested_sop_class_uid), NULL);
    normalize_uid_buf(p->dimse_affected_sop_instance_uid, &p->dimse_affected_sop_instance_uid_len,
                      sizeof(p->dimse_affected_sop_instance_uid), NULL);
    normalize_uid_buf(p->dimse_requested_sop_instance_uid, &p->dimse_requested_sop_instance_uid_len,
                      sizeof(p->dimse_requested_sop_instance_uid), NULL);
    if(c != DICOM_DIMSE_C_CANCEL_RQ && p->dimse_message_id == 0) p->dimse_message_id = 1;
    if(c == DICOM_DIMSE_C_FIND_RQ || c == DICOM_DIMSE_C_GET_RQ || c == DICOM_DIMSE_C_MOVE_RQ){
        if(p->dimse_requested_sop_class_uid_len == 0)
            set_dimse_uid(p->dimse_requested_sop_class_uid, &p->dimse_requested_sop_class_uid_len,
                          DICOM_MAX_DIMSE_UID_LEN, default_sop_for_command(c));
        p->dimse_affected_sop_class_uid_len = 0;
    } else if(c == DICOM_DIMSE_C_ECHO_RQ || c == DICOM_DIMSE_C_STORE_RQ){
        if(p->dimse_affected_sop_class_uid_len == 0)
            set_dimse_uid(p->dimse_affected_sop_class_uid, &p->dimse_affected_sop_class_uid_len,
                          DICOM_MAX_DIMSE_UID_LEN, default_sop_for_command(c));
        p->dimse_requested_sop_class_uid_len = 0;
    }
    if(c == DICOM_DIMSE_C_STORE_RQ && p->dimse_affected_sop_instance_uid_len == 0)
        set_dimse_uid(p->dimse_affected_sop_instance_uid, &p->dimse_affected_sop_instance_uid_len,
                      DICOM_MAX_DIMSE_UID_LEN, "1.2.826.0.1.3680043.2.1125.1");
    if(c == DICOM_DIMSE_C_MOVE_RQ && p->dimse_move_destination_len == 0){
        memcpy(p->dimse_move_destination, "STORESCP", 8); p->dimse_move_destination_len = 8;
    }
    if(c == DICOM_DIMSE_N_EVENT_REPORT_RQ || c == DICOM_DIMSE_N_GET_RQ || c == DICOM_DIMSE_N_SET_RQ ||
       c == DICOM_DIMSE_N_ACTION_RQ || c == DICOM_DIMSE_N_DELETE_RQ){
        if(p->dimse_requested_sop_class_uid_len == 0)
            set_dimse_uid(p->dimse_requested_sop_class_uid, &p->dimse_requested_sop_class_uid_len,
                          DICOM_MAX_DIMSE_UID_LEN, "1.2.840.10008.1.1");
        if(p->dimse_requested_sop_instance_uid_len == 0)
            set_dimse_uid(p->dimse_requested_sop_instance_uid, &p->dimse_requested_sop_instance_uid_len,
                          DICOM_MAX_DIMSE_UID_LEN, "1.2.826.0.1.3680043.2.1125.9");
    }
    if(c == DICOM_DIMSE_N_CREATE_RQ && p->dimse_affected_sop_class_uid_len == 0)
        set_dimse_uid(p->dimse_affected_sop_class_uid, &p->dimse_affected_sop_class_uid_len,
                      DICOM_MAX_DIMSE_UID_LEN, "1.2.840.10008.1.1");
}

static __attribute__((unused)) int dataset_follows_command(dicom_packet_t *pkts, int n, int pi, int pj){
    for(int i=pi;i<n;i++){
        if(pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        dicom_p_data_tf_pdu_t *pt = &pkts[i].u.p_data_tf;
        uint16_t start = (i == pi) ? (uint16_t)(pj + 1) : 0;
        for(uint16_t j=start;j<pt->pdv_count && j<DICOM_MAX_PDV_ITEMS;j++){
            dicom_pdv_item_t *q = &pt->pdvs[j];
            if(pdv_has_dimse(q)) return 0; /* next command starts a new DIMSE */
            if(!(q->control_header & DICOM_PDV_FLAG_COMMAND) && q->data_length)
                return 1;
        }
    }
    return 0;
}

static __attribute__((unused)) void fix_dimse_cross_message_constraints(dicom_packet_t *pkts, int n){
    if(!pkts || n <= 0) return;
    uint16_t last_request_id = 1;
    for(int i=0;i<n;i++){
        if(pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        dicom_p_data_tf_pdu_t *pt = &pkts[i].u.p_data_tf;
        for(uint16_t j=0;j<pt->pdv_count && j<DICOM_MAX_PDV_ITEMS;j++){
            dicom_pdv_item_t *pdv = &pt->pdvs[j];
            if(!pdv->has_dimse_command && !pdv->has_dimse_command_fields) continue;
            uint16_t cmd = pdv->dimse_command_field;
            if(cmd == DICOM_DIMSE_C_CANCEL_RQ){
                pdv->dimse_message_id_responded_to = last_request_id;
                pdv->dimse_fields_present &= ~DICOM_DIMSE_PRESENT_MESSAGE_ID;
                pdv->dimse_fields_present |= DICOM_DIMSE_PRESENT_RESPONDED_TO;
                pdv->dimse_command_data_set_type = 0x0101;
            } else {
                if(pdv->dimse_message_id == 0) pdv->dimse_message_id = 1;
                last_request_id = pdv->dimse_message_id;
                if(!dimse_command_allows_dataset(cmd))
                    pdv->dimse_command_data_set_type = 0x0101;
                else
                    pdv->dimse_command_data_set_type = dataset_follows_command(pkts, n, i, j) ? 0x0000 : 0x0101;
            }
        }
    }
}

/* PS3.8 requires the AC to acknowledge the same application context and AE
 * titles proposed by the RQ.  Keeping these values linked prevents a mutated
 * AC from being rejected before DIMSE processing starts. */
static __attribute__((unused)) void fix_association_cross_message_constraints(dicom_packet_t *pkts, int n){
    if(!pkts || n <= 0) return;
    int rq_i = -1;
    for(int i=0;i<n;i++) if(pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ){ rq_i = i; break; }
    if(rq_i < 0) return;
    dicom_a_associate_rq_pdu_t *rq = &pkts[rq_i].u.a_associate_rq;
    for(int i=0;i<n;i++){
        if(pkts[i].type != DICOM_PKT_A_ASSOCIATE_AC) continue;
        dicom_a_associate_ac_pdu_t *ac = &pkts[i].u.a_associate_ac;
        memcpy(ac->called_ae_title, rq->called_ae_title, sizeof(ac->called_ae_title));
        memcpy(ac->calling_ae_title, rq->calling_ae_title, sizeof(ac->calling_ae_title));
        ac->has_application_context = 1;
        ac->application_context.application_context_name = rq->application_context.application_context_name;
        pkts[i].raw_length = 0;
    }
}

void fix_dicom_association_dimse_alignment(dicom_packet_t *pkts, int num_packets){
    if(!pkts || num_packets <= 0) return;
    for(int i=0;i<num_packets;i++){
        if(pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        dicom_p_data_tf_pdu_t *pt = &pkts[i].u.p_data_tf;
        for(uint16_t j=0;j<pt->pdv_count && j<DICOM_MAX_PDV_ITEMS;j++){
            dicom_pdv_item_t *pdv = &pt->pdvs[j];
            if(!pdv->has_dimse_command && !(pdv->control_header & DICOM_PDV_FLAG_COMMAND)) continue;
            const char *lit = 0, *uid = 0;
            uint16_t uid_len = 0;
            pdv_command_sop(pdv, &lit, &uid, &uid_len);
            uint8_t pcid = normalize_pcid(pdv->presentation_context_id ? pdv->presentation_context_id : preferred_pcid(pkts, num_packets));
            /* Preserve rich seed association tables whenever the selected
             * presentation context already exists. Rewriting an existing PCID's
             * abstract syntax based on one mutated DIMSE command can make later
             * C-GET/C-STORE datasets negotiate under the wrong service class.
             * Only synthesize/retarget the association if the PCID is missing. */
            uint8_t matching_pcid = 0;
            if(uid && uid_len) matching_pcid = find_pcid_for_uid(pkts, num_packets, uid, uid_len);
            else if(lit) matching_pcid = find_pcid_for_uid(pkts, num_packets, lit, (uint16_t)strlen(lit));
            if(matching_pcid) pcid = matching_pcid;
            if(!pcid_exists(pkts, num_packets, pcid)) {
                if(uid && uid_len) set_pc_abstract_for_pcid(pkts, num_packets, pcid, uid, uid_len);
                else if(lit) set_pc_abstract_for_pcid(pkts, num_packets, pcid, lit, (uint16_t)strlen(lit));
            }
            pdv->presentation_context_id = pcid;
        }
    }
}

void fix_release_abort_constraints(dicom_packet_t *pkts, int num_packets){
    if(!pkts || num_packets<=0) return;
    for(int i=0;i<num_packets;i++){
        if(pkts[i].type == DICOM_PKT_A_RELEASE_RQ){
            pkts[i].u.a_release_rq.pdu_length = 4;
            pkts[i].u.a_release_rq.reserved2 = 0;
            pkts[i].u.a_release_rq.reserved3 = 0;
            if(pkts[i].raw_length >= 10){ pkts[i].raw_data[0]=DICOM_PDU_A_RELEASE_RQ; pkts[i].raw_data[1]=0; wr32(pkts[i].raw_data+2,4); memset(pkts[i].raw_data+6,0,4); pkts[i].raw_length=10; }
        } else if(pkts[i].type == DICOM_PKT_A_RELEASE_RP){
            pkts[i].u.a_release_rp.pdu_length = 4;
            pkts[i].u.a_release_rp.reserved2 = 0;
            pkts[i].u.a_release_rp.reserved3 = 0;
            if(pkts[i].raw_length >= 10){ pkts[i].raw_data[0]=DICOM_PDU_A_RELEASE_RP; pkts[i].raw_data[1]=0; wr32(pkts[i].raw_data+2,4); memset(pkts[i].raw_data+6,0,4); pkts[i].raw_length=10; }
        } else if(pkts[i].type == DICOM_PKT_A_ASSOCIATE_RJ){
            dicom_a_associate_rj_pdu_t *rj = &pkts[i].u.a_associate_rj;
            rj->pdu_type = DICOM_PDU_A_ASSOCIATE_RJ;
            rj->reserved1 = 0;
            rj->pdu_length = 4;
            rj->reserved2 = 0;
            if(rj->result != 1 && rj->result != 2) rj->result = 1;
            if(rj->source < 1 || rj->source > 3) rj->source = 1;
            if(!valid_rj_reason(rj->source, rj->reason_diag)) rj->reason_diag = default_rj_reason(rj->source);
            if(pkts[i].raw_length >= 10){ pkts[i].raw_data[0]=DICOM_PDU_A_ASSOCIATE_RJ; pkts[i].raw_data[1]=0; wr32(pkts[i].raw_data+2,4); pkts[i].raw_data[6]=0; pkts[i].raw_data[7]=rj->result; pkts[i].raw_data[8]=rj->source; pkts[i].raw_data[9]=rj->reason_diag; pkts[i].raw_length=10; }
        } else if(pkts[i].type == DICOM_PKT_A_ABORT){
            dicom_a_abort_pdu_t *ab = &pkts[i].u.a_abort;
            ab->pdu_type = DICOM_PDU_A_ABORT;
            ab->reserved1 = 0;
            ab->pdu_length = 4;
            ab->reserved2 = 0;
            ab->reserved3 = 0;
            if(!(ab->source == 0 || ab->source == 2)) ab->source = 2;
            if(!valid_abort_reason(ab->source, ab->reason_diag)) ab->reason_diag = (ab->source == 0) ? 0 : 2;
            if(pkts[i].raw_length >= 10){ pkts[i].raw_data[0]=DICOM_PDU_A_ABORT; pkts[i].raw_data[1]=0; wr32(pkts[i].raw_data+2,4); pkts[i].raw_data[6]=0; pkts[i].raw_data[7]=0; pkts[i].raw_data[8]=ab->source; pkts[i].raw_data[9]=ab->reason_diag; pkts[i].raw_length=10; }
        }
    }
}

void fix_DICOM_PS3_8_9_3_2_associate_rq_items(dicom_packet_t *pkt, int num_packets){ fix_associate_rq_constraints(pkt, num_packets); }
void fix_DICOM_PS3_8_9_3_3_associate_ac_items(dicom_packet_t *pkt, int num_packets){ fix_associate_ac_constraints(pkt, num_packets); }
void fix_DICOM_PS3_8_9_3_5_pdata_pdv_items(dicom_packet_t *pkt, int num_packets){ fix_p_data_tf_constraints(pkt, num_packets); }
void fix_DICOM_PS3_7_DIMSE_request_command_set(dicom_packet_t *pkt, int num_packets){ fix_dimse_command_constraints(pkt, num_packets); }
void fix_DICOM_PS3_8_9_3_4_6_7_8_fixed_length_pdus(dicom_packet_t *pkt, int num_packets){ fix_release_abort_constraints(pkt, num_packets); }

void fix_dicom(dicom_packet_t *pkt, int num_packets){
    fix_dicom_pdu_header_lengths(pkt, num_packets);
    fix_DICOM_PS3_7_DIMSE_request_command_set(pkt, num_packets);
    fix_DICOM_PS3_8_9_3_2_associate_rq_items(pkt, num_packets);
    fix_dicom_association_dimse_alignment(pkt, num_packets);
    fix_DICOM_PS3_8_9_3_3_associate_ac_items(pkt, num_packets);
    fix_DICOM_PS3_8_9_3_5_pdata_pdv_items(pkt, num_packets);
    /* Cross-message repair is deliberately left out of the hot path.  It
     * rewrites a valid mutated command/data relationship using a global
     * guess, and on C-FIND/C-GET/C-STORE transcripts this was both expensive
     * and more destructive than useful.  The per-PDU checks above already
     * enforce wire-level legality while preserving the seed's service state. */
    fix_DICOM_PS3_8_9_3_4_6_7_8_fixed_length_pdus(pkt, num_packets);
}
