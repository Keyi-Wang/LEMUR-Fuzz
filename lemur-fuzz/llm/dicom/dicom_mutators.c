#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dicom_packets.h"

static int dicom_rng_init = 0;
static void dicom_seed(void)
{
    if (!dicom_rng_init)
    {
        srand((unsigned)time(NULL));
        dicom_rng_init = 1;
    }
}
static uint8_t rnd8(void)
{
    dicom_seed();
    return (uint8_t)(rand() & 0xff);
}
static int rndn(int n)
{
    dicom_seed();
    return n > 0 ? rand() % n : 0;
}
static uint32_t rd32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static uint16_t rd16le(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8)); }
static uint32_t rd32le(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void wr16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}
static void wr32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}
static int each_raw_pdu(dicom_packet_t *p, uint8_t **body, uint32_t *body_len);
static void fill_ae(char *dst, const char *s)
{
    size_t n = strlen(s);
    memset(dst, ' ', 16);
    if (n > 16)
        n = 16;
    memcpy(dst, s, n);
}

typedef void (*dimse_elem_cb_t)(uint16_t elem, uint8_t *val, uint32_t len, void *arg);

static void walk_dimse_command_elements(uint8_t *data, uint32_t len, dimse_elem_cb_t cb, void *arg)
{
    if (!data || !cb) return;
    uint32_t off = 0;
    while (off + 8 <= len)
    {
        uint16_t group = rd16le(data + off);
        uint16_t elem = rd16le(data + off + 2);
        uint32_t vlen = rd32le(data + off + 4);
        off += 8;
        if (group != 0x0000 || off + vlen > len) break;
        cb(elem, data + off, vlen, arg);
        off += vlen;
    }
}

typedef struct {
    uint16_t elem;
    uint16_t value;
    int changed;
} dimse_us_update_t;

static void update_us_elem_cb(uint16_t elem, uint8_t *val, uint32_t len, void *arg)
{
    dimse_us_update_t *u = (dimse_us_update_t *)arg;
    if (!u || elem != u->elem || len < 2) return;
    wr16le(val, u->value);
    u->changed = 1;
}

typedef struct {
    uint16_t elem;
    const char *value;
    int changed;
} dimse_text_update_t;

static void update_text_elem_cb(uint16_t elem, uint8_t *val, uint32_t len, void *arg)
{
    dimse_text_update_t *u = (dimse_text_update_t *)arg;
    if (!u || elem != u->elem || !u->value || len == 0) return;
    size_t n = strlen(u->value);
    if (n > len) n = len;
    memset(val, 0, len);
    memcpy(val, u->value, n);
    u->changed = 1;
}

static void mutate_dimse_raw_us(dicom_packet_t *pkt, uint16_t elem, uint16_t value)
{
    if (!pkt || pkt->type != DICOM_PKT_P_DATA_TF || pkt->raw_length < 12) return;
    uint8_t *body = NULL;
    uint32_t body_len = 0;
    if (!each_raw_pdu(pkt, &body, &body_len)) return;
    uint32_t off = 0;
    while (off + 6 <= body_len)
    {
        uint32_t pdv_len = rd32(body + off);
        if (pdv_len < 2 || off + 4 + pdv_len > body_len) break;
        uint8_t ctrl = body[off + 5];
        if (ctrl & DICOM_PDV_FLAG_COMMAND)
        {
            dimse_us_update_t u = { elem, value, 0 };
            walk_dimse_command_elements(body + off + 6, pdv_len - 2, update_us_elem_cb, &u);
        }
        off += 4 + pdv_len;
    }
}

static void mutate_dimse_raw_text(dicom_packet_t *pkt, uint16_t elem, const char *value)
{
    if (!pkt || pkt->type != DICOM_PKT_P_DATA_TF || pkt->raw_length < 12) return;
    uint8_t *body = NULL;
    uint32_t body_len = 0;
    if (!each_raw_pdu(pkt, &body, &body_len)) return;
    uint32_t off = 0;
    while (off + 6 <= body_len)
    {
        uint32_t pdv_len = rd32(body + off);
        if (pdv_len < 2 || off + 4 + pdv_len > body_len) break;
        uint8_t ctrl = body[off + 5];
        if (ctrl & DICOM_PDV_FLAG_COMMAND)
        {
            dimse_text_update_t u = { elem, value, 0 };
            walk_dimse_command_elements(body + off + 6, pdv_len - 2, update_text_elem_cb, &u);
        }
        off += 4 + pdv_len;
    }
}

static int pdv_has_dimse(const dicom_pdv_item_t *pdv)
{
    if (!pdv) return 0;
    /* A command PDV may be fragmented across several P-DATA-TF items.  Only
     * the final fragment has a complete command set and therefore a semantic
     * model.  Treating every intermediate fragment as a DIMSE message makes
     * the mutator select a fragment with no command fields, and the fixer then
     * reassembles it as a second (invalid) command. */
    if (pdv->has_dimse_command || pdv->has_dimse_command_fields) return 1;
    return (pdv->control_header & (DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT)) ==
           (DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT) &&
           pdv->data_length >= 8;
}
static void raw_fill_ae(uint8_t *dst, const char *s)
{
    size_t n = strlen(s);
    memset(dst, ' ', 16);
    if (n > 16)
        n = 16;
    memcpy(dst, s, n);
}

static int each_raw_pdu(dicom_packet_t *p, uint8_t **body, uint32_t *body_len)
{
    if (!p || p->raw_length < 6)
        return 0;
    uint32_t len = rd32(p->raw_data + 2);
    if (6U + len > p->raw_length)
        return 0;
    *body = p->raw_data + 6;
    *body_len = len;
    return 1;
}

/* Dataset value mutators are defined with the rest of the dataset helpers
 * below, but are also used by the conservative PDV fallback above. */
static int mutate_explicit_le_dataset_once(uint8_t *data, uint32_t len);
static int mutate_implicit_le_dataset_once(uint8_t *data, uint32_t len);

static uint8_t normalize_pcid(uint8_t pcid)
{
    if (pcid == 0) pcid = 1;
    pcid &= 0x7f;
    if (pcid == 0) pcid = 1;
    if ((pcid & 1u) == 0) pcid++;
    return pcid;
}

static uint8_t preferred_pcid(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return 1;
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_A_ASSOCIATE_RQ) continue;
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        for (uint8_t j = 0; j < rq->presentation_context_count && j < DICOM_MAX_PRESENTATION_CONTEXTS; j++)
        {
            if (rq->presentation_contexts[j].presentation_context_id)
                return normalize_pcid(rq->presentation_contexts[j].presentation_context_id);
        }
    }
    return 1;
}

static int looks_like_dimse_command(const uint8_t *data, uint32_t len)
{
    uint32_t off = 0;
    while (data && off + 8 <= len)
    {
        uint16_t group = rd16le(data + off);
        uint16_t elem = rd16le(data + off + 2);
        uint32_t vlen = rd32le(data + off + 4);
        off += 8;
        if (group != 0x0000 || off + vlen > len) return 0;
        if (elem == 0x0100 && vlen >= 2) return 1;
        off += vlen;
    }
    return 0;
}

static void mutate_called_ae_title(dicom_packet_t *pkts, size_t n)
{
    if (!pkts)
        return;
    static const char *names[] = {"ANY-SCP", "DCM4CHEE", "STORESCP", "FUZZSCP", "ORTHANC", "DCMQRSCP", "DICOMSERVER", "PACS", "OFFIS"};
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_A_ASSOCIATE_RQ && pkts[i].type != DICOM_PKT_A_ASSOCIATE_AC)
            continue;
        const char *v = names[rndn((int)(sizeof(names) / sizeof(names[0])))];
        if (pkts[i].raw_length >= 26)
            raw_fill_ae(pkts[i].raw_data + 10, v);
        if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ)
            fill_ae(pkts[i].u.a_associate_rq.called_ae_title, v);
        else
            fill_ae(pkts[i].u.a_associate_ac.called_ae_title, v);
    }
}

static void mutate_calling_ae_title(dicom_packet_t *pkts, size_t n)
{
    if (!pkts)
        return;
    static const char *names[] = {"ECHOSCU", "FINDSCU", "GETSCU", "STORESCU", "LEMURSCU"};
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_A_ASSOCIATE_RQ && pkts[i].type != DICOM_PKT_A_ASSOCIATE_AC)
            continue;
        const char *v = names[rndn((int)(sizeof(names) / sizeof(names[0])))];
        if (pkts[i].raw_length >= 42)
            raw_fill_ae(pkts[i].raw_data + 26, v);
        if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ)
            fill_ae(pkts[i].u.a_associate_rq.calling_ae_title, v);
        else
            fill_ae(pkts[i].u.a_associate_ac.calling_ae_title, v);
    }
}

static void mutate_protocol_version(dicom_packet_t *pkts, size_t n)
{
    if (!pkts)
        return;
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_A_ASSOCIATE_RQ && pkts[i].type != DICOM_PKT_A_ASSOCIATE_AC)
            continue;
        uint16_t v = (rndn(4) == 0) ? 0x0002 : 0x0001;
        if (pkts[i].raw_length >= 8)
        {
            pkts[i].raw_data[6] = (uint8_t)(v >> 8);
            pkts[i].raw_data[7] = (uint8_t)v;
        }
        if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ)
            pkts[i].u.a_associate_rq.protocol_version = v;
        else
            pkts[i].u.a_associate_ac.protocol_version = v;
    }
}

static void mutate_presentation_context_id(dicom_packet_t *pkts, size_t n)
{
    if (!pkts)
        return;
    uint8_t pcid = preferred_pcid(pkts, n);
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type == DICOM_PKT_P_DATA_TF && pkts[i].raw_length >= 12)
        {
            uint8_t *body = NULL;
            uint32_t body_len = 0;
            if (!each_raw_pdu(&pkts[i], &body, &body_len))
                continue;
            uint32_t off = 0;
            while (off + 6 <= body_len)
            {
                uint32_t pdv_len = rd32(body + off);
                if (pdv_len < 2 || off + 4 + pdv_len > body_len)
                    break;
                body[off + 4] = pcid;
                off += 4 + pdv_len;
            }
        }
        else if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ)
        {
            for (uint8_t j = 0; j < pkts[i].u.a_associate_rq.presentation_context_count && j < DICOM_MAX_PRESENTATION_CONTEXTS; j++)
                pkts[i].u.a_associate_rq.presentation_contexts[j].presentation_context_id = normalize_pcid((uint8_t)(1 + 2 * j));
        }
    }
}

static void mutate_pdv_control_header(dicom_packet_t *pkts, size_t n)
{
    if (!pkts)
        return;
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_P_DATA_TF)
            continue;
        uint8_t *body = NULL;
        uint32_t body_len = 0;
        if (each_raw_pdu(&pkts[i], &body, &body_len))
        {
            uint32_t off = 0;
            while (off + 6 <= body_len)
            {
                uint32_t pdv_len = rd32(body + off);
                if (pdv_len < 2 || off + 4 + pdv_len > body_len)
                    break;
                uint8_t ctrl = DICOM_PDV_FLAG_LAST_FRAGMENT;
                if ((body[off + 5] & DICOM_PDV_FLAG_COMMAND) ||
                    looks_like_dimse_command(body + off + 6, pdv_len - 2))
                    ctrl |= DICOM_PDV_FLAG_COMMAND;
                body[off + 5] = ctrl;
                off += 4 + pdv_len;
            }
        }
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++)
        {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            pdv->control_header = DICOM_PDV_FLAG_LAST_FRAGMENT |
                ((pdv->control_header & DICOM_PDV_FLAG_COMMAND) || pdv->has_dimse_command ? DICOM_PDV_FLAG_COMMAND : 0);
        }
    }
}

static void mutate_pdv_data_bytes(dicom_packet_t *pkts, size_t n)
{
    if (!pkts)
        return;
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_P_DATA_TF)
            continue;
        /* Do not edit raw PDU bytes here.  Reassembly uses the structured
         * PDV representation, and raw edits could touch a tag, VR, or length
         * word and silently turn a valid dataset into an invalid one. */
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++)
        {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            if (pdv_has_dimse(pdv)) continue;
            uint32_t lim = pdv->data_length > DICOM_MAX_PDV_DATA_LEN ? DICOM_MAX_PDV_DATA_LEN : pdv->data_length;
            if (!lim) continue;
            /* This fallback is intentionally conservative: mutate only a
             * value through the structured dataset mutator.  If the transfer
             * syntax is not recognized, leave the seed unchanged. */
            if (!mutate_explicit_le_dataset_once(pdv->data, pdv->data_length) &&
                !mutate_implicit_le_dataset_once(pdv->data, pdv->data_length))
                continue;
            pdv->pdv_length = pdv->data_length + pdv->data_tail_length + 2;
        }
        /* The structured PDV is authoritative during reassembly. */
        pkts[i].raw_length = 0;
    }
}

static uint16_t dicom_select_dimse_request_command(void)
{
    /* dcmqrscp exercises the DIMSE C-service request parser first.  Keep the
     * full PS3.7 request universe reachable, but bias runtime fuzzing toward
     * C-service commands that this SCP is expected to parse beyond association. */
    static const uint16_t c_service_cmds[] = {
        DICOM_DIMSE_C_ECHO_RQ, DICOM_DIMSE_C_ECHO_RQ,
        DICOM_DIMSE_C_STORE_RQ, DICOM_DIMSE_C_STORE_RQ,
        DICOM_DIMSE_C_FIND_RQ, DICOM_DIMSE_C_FIND_RQ,
        DICOM_DIMSE_C_GET_RQ,
        DICOM_DIMSE_C_MOVE_RQ,
        DICOM_DIMSE_C_CANCEL_RQ
    };
    static const uint16_t all_request_cmds[] = {
        DICOM_DIMSE_C_ECHO_RQ,
        DICOM_DIMSE_C_STORE_RQ,
        DICOM_DIMSE_C_FIND_RQ,
        DICOM_DIMSE_C_GET_RQ,
        DICOM_DIMSE_C_MOVE_RQ,
        DICOM_DIMSE_N_EVENT_REPORT_RQ,
        DICOM_DIMSE_N_GET_RQ,
        DICOM_DIMSE_N_SET_RQ,
        DICOM_DIMSE_N_ACTION_RQ,
        DICOM_DIMSE_N_CREATE_RQ,
        DICOM_DIMSE_N_DELETE_RQ,
        DICOM_DIMSE_C_CANCEL_RQ
    };
    if (rndn(10) < 8)
        return c_service_cmds[rndn((int)(sizeof(c_service_cmds) / sizeof(c_service_cmds[0])))];
    return all_request_cmds[rndn((int)(sizeof(all_request_cmds) / sizeof(all_request_cmds[0])))];
}

static void mutate_dimse_command_field(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        uint16_t cmd = dicom_select_dimse_request_command();
        mutate_dimse_raw_us(&pkts[i], 0x0100, cmd);
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++)
        {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            if (!pdv_has_dimse(pdv)) continue;
            pdv->has_dimse_command = 1;
            pdv->dimse_command_field = cmd;
        }
    }
}

static void mutate_dimse_message_id(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        uint16_t msg_id = (uint16_t)(1 + rndn(0xfffe));
        mutate_dimse_raw_us(&pkts[i], 0x0110, msg_id);
        mutate_dimse_raw_us(&pkts[i], 0x0120, msg_id);
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++)
        {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            if (!pdv_has_dimse(pdv)) continue;
            pdv->dimse_message_id = msg_id;
            pdv->dimse_message_id_responded_to = msg_id;
        }
    }
}

static void mutate_dimse_priority(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const uint16_t priorities[] = {0x0000, 0x0001, 0x0002};
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        uint16_t prio = priorities[rndn(3)];
        mutate_dimse_raw_us(&pkts[i], 0x0700, prio);
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++)
            if (pdv_has_dimse(&pkts[i].u.p_data_tf.pdvs[j]))
                pkts[i].u.p_data_tf.pdvs[j].dimse_priority = prio;
    }
}

static void mutate_dimse_dataset_type(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const uint16_t types[] = {0x0101, 0x0102, 0x0000, 0x0001};
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        uint16_t ds = types[rndn(4)];
        mutate_dimse_raw_us(&pkts[i], 0x0800, ds);
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++)
            if (pdv_has_dimse(&pkts[i].u.p_data_tf.pdvs[j]))
                pkts[i].u.p_data_tf.pdvs[j].dimse_command_data_set_type = ds;
    }
}

static void mutate_dimse_affected_sop_class_uid(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const char *uids[] = {
        "1.2.840.10008.1.1",
        "1.2.840.10008.5.1.4.1.1.2",
        "1.2.840.10008.5.1.4.1.1.4",
        "1.2.840.10008.5.1.4.1.1.7",
        "1.2.840.10008.5.1.4.1.2.1.1",
        "1.2.840.10008.5.1.4.1.2.1.2",
        "1.2.840.10008.5.1.4.1.2.1.3",
        "1.2.840.10008.5.1.4.1.2.2.1",
        "1.2.840.10008.5.1.4.1.2.2.2",
        "1.2.840.10008.5.1.4.1.2.2.3",
        "1.2.840.10008.5.1.4.31"
    };
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        const char *uid = uids[rndn((int)(sizeof(uids) / sizeof(uids[0])))];
        mutate_dimse_raw_text(&pkts[i], 0x0002, uid);
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++)
        {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            if (!pdv_has_dimse(pdv)) continue;
            size_t len = strlen(uid);
            if (len > DICOM_MAX_DIMSE_UID_LEN) len = DICOM_MAX_DIMSE_UID_LEN;
            memset(pdv->dimse_affected_sop_class_uid, 0, DICOM_MAX_DIMSE_UID_LEN);
            memcpy(pdv->dimse_affected_sop_class_uid, uid, len);
            pdv->dimse_affected_sop_class_uid_len = (uint16_t)len;
        }
    }
}

static void mutate_dimse_affected_sop_instance_uid(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const char *uids[] = {
        "1.2.840.113654.2.55.1",
        "1.2.840.113654.2.55.2",
        "1.2.826.0.1.3680043.2.1125.1",
        "1.2.840.10008.5.1.4.1.1.2.1"
    };
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        const char *uid = uids[rndn((int)(sizeof(uids) / sizeof(uids[0])))];
        mutate_dimse_raw_text(&pkts[i], 0x1000, uid);
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++)
        {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            if (!pdv_has_dimse(pdv)) continue;
            size_t len = strlen(uid);
            if (len > DICOM_MAX_DIMSE_UID_LEN) len = DICOM_MAX_DIMSE_UID_LEN;
            memset(pdv->dimse_affected_sop_instance_uid, 0, DICOM_MAX_DIMSE_UID_LEN);
            memcpy(pdv->dimse_affected_sop_instance_uid, uid, len);
            pdv->dimse_affected_sop_instance_uid_len = (uint16_t)len;
        }
    }
}

static void mutate_dimse_requested_sop_class_uid(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const char *uids[] = {
        "1.2.840.10008.1.1",
        "1.2.840.10008.5.1.4.1.1.2",
        "1.2.840.10008.5.1.4.1.1.4",
        "1.2.840.10008.5.1.4.1.2.1.1"
    };
    for (size_t i = 0; i < n; i++) {
        if (pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        const char *uid = uids[rndn((int)(sizeof(uids) / sizeof(uids[0])))];
        mutate_dimse_raw_text(&pkts[i], 0x0003, uid);
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            if (!pdv_has_dimse(pdv)) continue;
            size_t len = strlen(uid);
            if (len > DICOM_MAX_DIMSE_UID_LEN) len = DICOM_MAX_DIMSE_UID_LEN;
            memset(pdv->dimse_requested_sop_class_uid, 0, DICOM_MAX_DIMSE_UID_LEN);
            memcpy(pdv->dimse_requested_sop_class_uid, uid, len);
            pdv->dimse_requested_sop_class_uid_len = (uint16_t)len;
        }
    }
}

static void mutate_dimse_requested_sop_instance_uid(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const char *uids[] = {
        "1.2.840.113654.2.55.11",
        "1.2.840.113654.2.55.12",
        "1.2.826.0.1.3680043.2.1125.9"
    };
    for (size_t i = 0; i < n; i++) {
        if (pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        const char *uid = uids[rndn((int)(sizeof(uids) / sizeof(uids[0])))];
        mutate_dimse_raw_text(&pkts[i], 0x1001, uid);
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            if (!pdv_has_dimse(pdv)) continue;
            size_t len = strlen(uid);
            if (len > DICOM_MAX_DIMSE_UID_LEN) len = DICOM_MAX_DIMSE_UID_LEN;
            memset(pdv->dimse_requested_sop_instance_uid, 0, DICOM_MAX_DIMSE_UID_LEN);
            memcpy(pdv->dimse_requested_sop_instance_uid, uid, len);
            pdv->dimse_requested_sop_instance_uid_len = (uint16_t)len;
        }
    }
}

static void mutate_dimse_event_action_ids(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) {
        if (pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        uint16_t event_id = (uint16_t)(1 + rndn(16));
        uint16_t action_id = (uint16_t)(1 + rndn(16));
        mutate_dimse_raw_us(&pkts[i], 0x1002, event_id);
        mutate_dimse_raw_us(&pkts[i], 0x1008, action_id);
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            if (!pdv_has_dimse(pdv)) continue;
            pdv->dimse_event_type_id = event_id;
            pdv->dimse_action_type_id = action_id;
        }
    }
}

static void mutate_dimse_move_originator(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const char *aets[] = {"MOVESCU", "ORIGIN", "LEMURAE", "FINDSCU", "STORESCU", "ECHOSCU", "GETSCU"};
    for (size_t i = 0; i < n; i++) {
        if (pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        const char *ae = aets[rndn((int)(sizeof(aets) / sizeof(aets[0])))];
        uint16_t msg_id = (uint16_t)(1 + rndn(0xfffe));
        mutate_dimse_raw_text(&pkts[i], 0x1030, ae);
        mutate_dimse_raw_us(&pkts[i], 0x1031, msg_id);
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            if (!pdv_has_dimse(pdv)) continue;
            size_t len = strlen(ae);
            if (len > DICOM_MAX_DIMSE_AE_LEN) len = DICOM_MAX_DIMSE_AE_LEN;
            memset(pdv->dimse_move_originator_ae_title, ' ', DICOM_MAX_DIMSE_AE_LEN);
            memcpy(pdv->dimse_move_originator_ae_title, ae, len);
            pdv->dimse_move_originator_ae_title_len = (uint16_t)len;
            pdv->dimse_move_originator_message_id = msg_id;
        }
    }
}

static void mutate_dimse_move_destination(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const char *aets[] = {"ANY-SCP", "STORESCP", "DCMQRSCP", "LEMURDST", "MOVEDEST", "ORTHANC", "PACS", "DCM4CHEE"};
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        const char *ae = aets[rndn((int)(sizeof(aets) / sizeof(aets[0])))];
        mutate_dimse_raw_text(&pkts[i], 0x0600, ae);
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++)
        {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            if (!pdv_has_dimse(pdv)) continue;
            size_t len = strlen(ae);
            if (len > DICOM_MAX_DIMSE_AE_LEN) len = DICOM_MAX_DIMSE_AE_LEN;
            memset(pdv->dimse_move_destination, ' ', DICOM_MAX_DIMSE_AE_LEN);
            memcpy(pdv->dimse_move_destination, ae, len);
            pdv->dimse_move_destination_len = (uint16_t)len;
        }
    }
}

static void mutate_abort_source_reason(dicom_packet_t *pkts, size_t n)
{
    if (!pkts)
        return;
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_A_ABORT)
            continue;
        uint8_t source = (uint8_t)(rndn(3));
        uint8_t reason = (uint8_t)(rndn(8));
        if (pkts[i].raw_length >= 10)
        {
            pkts[i].raw_data[8] = source;
            pkts[i].raw_data[9] = reason;
        }
        pkts[i].u.a_abort.source = source;
        pkts[i].u.a_abort.reason_diag = reason;
    }
}


static void mutate_associate_rj_result_source_reason(dicom_packet_t *pkts, size_t n)
{
    if (!pkts)
        return;
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_A_ASSOCIATE_RJ)
            continue;
        uint8_t result = (uint8_t)(1 + rndn(3));
        uint8_t source = (uint8_t)(1 + rndn(3));
        uint8_t reason = (uint8_t)(1 + rndn(8));
        if (pkts[i].raw_length >= 10)
        {
            pkts[i].raw_data[7] = result;
            pkts[i].raw_data[8] = source;
            pkts[i].raw_data[9] = reason;
        }
        pkts[i].u.a_associate_rj.result = result;
        pkts[i].u.a_associate_rj.source = source;
        pkts[i].u.a_associate_rj.reason_diag = reason;
    }
}

static void mutate_release_reserved(dicom_packet_t *pkts, size_t n)
{
    if (!pkts)
        return;
    for (size_t i = 0; i < n; i++)
    {
        if (pkts[i].type != DICOM_PKT_A_RELEASE_RQ && pkts[i].type != DICOM_PKT_A_RELEASE_RP)
            continue;
        if (pkts[i].raw_length >= 10)
        {
            pkts[i].raw_data[6] = 0;
            pkts[i].raw_data[7] = 0;
            pkts[i].raw_data[8] = 0;
            pkts[i].raw_data[9] = 0;
        }
        if (pkts[i].type == DICOM_PKT_A_RELEASE_RQ) {
            pkts[i].u.a_release_rq.reserved2 = 0;
            pkts[i].u.a_release_rq.reserved3 = 0;
        } else {
            pkts[i].u.a_release_rp.reserved2 = 0;
            pkts[i].u.a_release_rp.reserved3 = 0;
        }
    }
}

/* Field-level mutators generated from the component-generation Step 6 prompt
 * for DICOM PS3.8 association/P-DATA templates and PS3.7 DIMSE fields. */
static void add_transfer_syntaxes(dicom_packet_t *pkts, size_t n);
static void dicom_set_str(dicom_str_t *s, const char *v)
{
    if (!s || !v) return;
    size_t n = strlen(v);
    if (n > DICOM_MAX_UID_LEN) n = DICOM_MAX_UID_LEN;
    s->length = (uint16_t)n;
    memset(s->value, 0, sizeof(s->value));
    memcpy(s->value, v, n);
}

static const char *dicom_pick_sop_uid(void)
{
    /* Weighted toward the ProfuzzBench/DCMTK request seeds while still keeping
     * RFC/PS3.4 service classes reachable at lower probability.  DCMTK's
     * dcmqrscp config accepts the Verification, Q/R and common storage classes
     * used by these seeds; presenting unrelated normalized/print classes too
     * often causes early association rejection and hurts branch coverage. */
    static const char *uids[] = {
        "1.2.840.10008.1.1", "1.2.840.10008.1.1", "1.2.840.10008.1.1",
        "1.2.840.10008.5.1.4.1.2.1.1", "1.2.840.10008.5.1.4.1.2.1.1",
        "1.2.840.10008.5.1.4.1.2.1.3", "1.2.840.10008.5.1.4.1.2.1.3",
        "1.2.840.10008.5.1.4.1.1.9.1.3", "1.2.840.10008.5.1.4.1.1.9.1.3",
        "1.2.840.10008.5.1.4.1.1.2",
        "1.2.840.10008.5.1.4.1.1.4",
        "1.2.840.10008.5.1.4.1.1.7",
        "1.2.840.10008.5.1.4.1.1.128",
        "1.2.840.10008.5.1.4.1.1.9.5.1",
        "1.2.840.10008.5.1.4.1.1.78.2",
        "1.2.840.10008.5.1.4.1.1.131",
        "1.2.840.10008.5.1.4.1.1.88.11",
        "1.2.840.10008.5.1.4.1.1.88.34",
        "1.2.840.10008.5.1.4.1.1.88.65",
        "1.2.840.10008.5.1.4.1.1.88.69",
        "1.2.840.10008.5.1.4.1.2.2.1",
        "1.2.840.10008.5.1.4.1.2.2.3",
        "1.2.840.10008.5.1.4.31",
        "1.2.840.10008.5.1.4.1.2.1.2",
        "1.2.840.10008.5.1.4.1.2.2.2",
        "1.2.840.10008.1.20.1",
        "1.2.840.10008.5.1.1.9",
        "1.2.840.10008.5.1.1.16"
    };
    return uids[rndn((int)(sizeof(uids) / sizeof(uids[0])) )];
}

static const char *dicom_pick_transfer_uid(void)
{
    static const char *uids[] = {
        "1.2.840.10008.1.2",        /* Implicit VR Little Endian */
        "1.2.840.10008.1.2",
        "1.2.840.10008.1.2",
        "1.2.840.10008.1.2.1",      /* Explicit VR Little Endian */
        "1.2.840.10008.1.2.1",
        "1.2.840.10008.1.2.1",
        "1.2.840.10008.1.2.1.99",   /* Deflated Explicit VR Little Endian */
        "1.2.840.10008.1.2.2",      /* Explicit VR Big Endian */
        "1.2.840.10008.1.2.2",
        "1.2.840.10008.1.2.4.50",   /* JPEG Baseline */
        "1.2.840.10008.1.2.4.51",
        "1.2.840.10008.1.2.4.57",
        "1.2.840.10008.1.2.4.70",
        "1.2.840.10008.1.2.4.80",   /* JPEG-LS Lossless */
        "1.2.840.10008.1.2.4.90",   /* JPEG 2000 Lossless */
        "1.2.840.10008.1.2.5"       /* RLE Lossless */
    };
    return uids[rndn((int)(sizeof(uids) / sizeof(uids[0])) )];
}

struct dicom_tag_pair {
    uint16_t group;
    uint16_t elem;
};

static const struct dicom_tag_pair *dicom_pick_identifier_tag(void)
{
    static const struct dicom_tag_pair tags[] = {
        {0x0008, 0x0005}, /* Specific Character Set */
        {0x0008, 0x0016}, /* SOP Class UID */
        {0x0008, 0x0018}, /* SOP Instance UID */
        {0x0008, 0x0020}, /* Study Date */
        {0x0008, 0x0030}, /* Study Time */
        {0x0008, 0x0052}, /* Query/Retrieve Level */
        {0x0008, 0x0060}, /* Modality */
        {0x0008, 0x1030}, /* Study Description */
        {0x0010, 0x0010}, /* Patient Name */
        {0x0010, 0x0020}, /* Patient ID */
        {0x0010, 0x0030}, /* Patient Birth Date */
        {0x0010, 0x0040}, /* Patient Sex */
        {0x0020, 0x000D}, /* Study Instance UID */
        {0x0020, 0x000E}, /* Series Instance UID */
        {0x0020, 0x0010}, /* Study ID */
        {0x0020, 0x0011}, /* Series Number */
        {0x0020, 0x0013}, /* Instance Number */
        {0x0020, 0x1206}, /* Number of Study Related Series */
        {0x0020, 0x1208}  /* Number of Study Related Instances */
    };
    return &tags[rndn((int)(sizeof(tags) / sizeof(tags[0])) )];
}

static void dicom_default_pc(dicom_presentation_context_item_t *pc, uint8_t idx)
{
    if (!pc) return;
    memset(pc, 0, sizeof(*pc));
    pc->item_type = 0x20;
    pc->presentation_context_id = normalize_pcid((uint8_t)(1 + 2 * idx));
    pc->abstract_syntax.item_type = 0x30;
    dicom_set_str(&pc->abstract_syntax.abstract_syntax_name, dicom_pick_sop_uid());
    pc->transfer_syntax_count = 1;
    pc->transfer_syntaxes[0].item_type = 0x40;
    dicom_set_str(&pc->transfer_syntaxes[0].transfer_syntax_name, dicom_pick_transfer_uid());
}

static void dicom_set_pc_profile(dicom_presentation_context_item_t *pc, uint8_t pcid,
                                 const char *abstract_uid,
                                 const char *ts0, const char *ts1, const char *ts2)
{
    if (!pc || !abstract_uid || !ts0) return;
    memset(pc, 0, sizeof(*pc));
    pc->item_type = 0x20;
    pc->presentation_context_id = normalize_pcid(pcid);
    pc->abstract_syntax.item_type = 0x30;
    dicom_set_str(&pc->abstract_syntax.abstract_syntax_name, abstract_uid);
    const char *tsv[3] = {ts0, ts1, ts2};
    pc->transfer_syntax_count = 0;
    for (uint8_t i = 0; i < 3 && tsv[i] && pc->transfer_syntax_count < DICOM_MAX_TRANSFER_SYNTAXES; ++i) {
        dicom_transfer_syntax_item_t *ts = &pc->transfer_syntaxes[pc->transfer_syntax_count++];
        ts->item_type = 0x40;
        dicom_set_str(&ts->transfer_syntax_name, tsv[i]);
    }
}

static void dicom_strengthen_association_branch_variants(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; ++i) {
        if (pkts[i].type != DICOM_PKT_A_ASSOCIATE_RQ) continue;
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        if (rq->presentation_context_count < 8) rq->presentation_context_count = 8;
        if (rq->presentation_context_count > DICOM_MAX_PRESENTATION_CONTEXTS)
            rq->presentation_context_count = DICOM_MAX_PRESENTATION_CONTEXTS;
        uint8_t c = rq->presentation_context_count;
        /* Keep low PCIDs from profuzzbench seeds intact (C-GET uses 1,
         * C-STORE uses 41) and mutate high/last slots to exercise accept,
         * abstract-syntax-refused, transfer-syntax-refused, and role paths. */
        uint8_t ids[4] = {
            normalize_pcid((uint8_t)(1 + 2 * (c > 4 ? c - 4 : 4))),
            normalize_pcid((uint8_t)(1 + 2 * (c > 3 ? c - 3 : 5))),
            normalize_pcid((uint8_t)(1 + 2 * (c > 2 ? c - 2 : 6))),
            normalize_pcid((uint8_t)(1 + 2 * (c > 1 ? c - 1 : 7)))
        };
        dicom_set_pc_profile(&rq->presentation_contexts[c - 4], ids[0],
            "1.2.840.10008.5.1.4.1.2.1.1", /* FIND Patient Root: accepted */
            "1.2.840.10008.1.2", "1.2.840.10008.1.2.1", "1.2.840.10008.1.2.2");
        dicom_set_pc_profile(&rq->presentation_contexts[c - 3], ids[1],
            "1.2.840.10008.5.1.4.1.1.2", /* CT Storage with partly unsupported TS */
            "1.2.840.10008.1.2.4.90", "1.2.840.10008.1.2.4.50", "1.2.840.10008.1.2.1");
        dicom_set_pc_profile(&rq->presentation_contexts[c - 2], ids[2],
            "1.2.826.0.1.3680043.9.999.1", /* unsupported abstract syntax */
            "1.2.840.10008.1.2", "1.2.840.10008.1.2.1", NULL);
        dicom_set_pc_profile(&rq->presentation_contexts[c - 1], ids[3],
            "1.2.840.10008.5.1.4.1.2.1.3", /* GET with unsupported-only TS */
            "1.2.840.10008.1.2.4.91", "1.2.840.10008.1.2.5", NULL);

        rq->has_user_info = 1;
        rq->user_info.item_type = 0x50;
        rq->user_info.has_maximum_length = 1;
        rq->user_info.maximum_length_received = 16384;
        rq->user_info.has_async_ops_window = 1;
        rq->user_info.max_ops_invoked = (uint16_t)(1 + rndn(4));
        rq->user_info.max_ops_performed = (uint16_t)(1 + rndn(4));
        rq->user_info.has_implementation_class_uid = 1;
        dicom_set_str(&rq->user_info.implementation_class_uid, "1.2.826.0.1.3680043.2.1125.99");
        rq->user_info.has_implementation_version_name = 1;
        dicom_set_str(&rq->user_info.implementation_version_name, "LEMUR_ASSOC");
        if (rq->user_info.role_selection_count < 4) rq->user_info.role_selection_count = 4;
        const char *role_uids[4] = {
            "1.2.840.10008.5.1.4.1.2.1.1",
            "1.2.840.10008.5.1.4.1.1.2",
            "1.2.840.10008.5.1.4.1.2.1.3",
            "1.2.826.0.1.3680043.9.999.1"
        };
        for (uint8_t r = 0; r < 4 && r < DICOM_MAX_ROLE_SELECTIONS; ++r) {
            dicom_set_str(&rq->user_info.role_selections[r].sop_class_uid, role_uids[r]);
            rq->user_info.role_selections[r].scu_role = (uint8_t)(r & 1u);
            rq->user_info.role_selections[r].scp_role = (uint8_t)((r >> 1) & 1u);
        }
        if (rndn(2) == 0) {
            rq->user_info.has_sop_class_extended_negotiation = 1;
            dicom_set_str(&rq->user_info.sop_class_extended_uid, "1.2.840.10008.5.1.4.1.2.1.1");
            rq->user_info.sop_class_extended_info_len = 4;
            rq->user_info.sop_class_extended_info[0] = 1;
            rq->user_info.sop_class_extended_info[1] = (uint8_t)rndn(2);
            rq->user_info.sop_class_extended_info[2] = (uint8_t)rndn(2);
            rq->user_info.sop_class_extended_info[3] = 0;
        }
        pkts[i].raw_length = 0;
        return;
    }
}

static void dicom_default_pdv(dicom_pdv_item_t *pdv, uint8_t pcid)
{
    if (!pdv) return;
    memset(pdv, 0, sizeof(*pdv));
    pdv->presentation_context_id = normalize_pcid(pcid);
    pdv->control_header = DICOM_PDV_FLAG_LAST_FRAGMENT | DICOM_PDV_FLAG_COMMAND;
    pdv->has_dimse_command = 1;
    pdv->dimse_command_field = DICOM_DIMSE_C_ECHO_RQ;
    pdv->dimse_message_id = (uint16_t)(1 + rndn(0xfffe));
    pdv->dimse_priority = (uint16_t)rndn(3);
    pdv->dimse_command_data_set_type = 0x0101;
    const char *uid = "1.2.840.10008.1.1";
    size_t ulen = strlen(uid);
    memcpy(pdv->dimse_affected_sop_class_uid, uid, ulen);
    pdv->dimse_affected_sop_class_uid_len = (uint16_t)ulen;
}


static int dimse_cmd_no_dataset(uint16_t cmd);
static void pdv_set_text_field(char *dst, uint16_t *lenp, size_t cap, const char *value, int pad_spaces);
static int dicom_write_curated_dataset(uint8_t *dst, uint32_t cap, uint32_t *out_len);
static int dicom_write_curated_dataset_for_cmd(uint16_t cmd, uint8_t *dst, uint32_t cap, uint32_t *out_len);

static const char *dicom_uid_for_dimse(uint16_t cmd)
{
    switch (cmd) {
    case DICOM_DIMSE_C_ECHO_RQ: return "1.2.840.10008.1.1";
    case DICOM_DIMSE_C_STORE_RQ: {
        static const char *storage[] = {
            "1.2.840.10008.5.1.4.1.1.9.1.3", "1.2.840.10008.5.1.4.1.1.9.1.3",
            "1.2.840.10008.5.1.4.1.1.2", "1.2.840.10008.5.1.4.1.1.4",
            "1.2.840.10008.5.1.4.1.1.7", "1.2.840.10008.5.1.4.1.1.128"
        };
        return storage[rndn((int)(sizeof(storage)/sizeof(storage[0])) )];
    }
    case DICOM_DIMSE_C_FIND_RQ: {
        static const char *finds[] = {
            "1.2.840.10008.5.1.4.1.2.1.1", "1.2.840.10008.5.1.4.1.2.1.1",
            "1.2.840.10008.5.1.4.1.2.2.1",
            "1.2.840.10008.5.1.4.31"
        };
        return finds[rndn((int)(sizeof(finds)/sizeof(finds[0])) )];
    }
    case DICOM_DIMSE_C_GET_RQ: {
        static const char *gets[] = {
            "1.2.840.10008.5.1.4.1.2.1.3", "1.2.840.10008.5.1.4.1.2.1.3",
            "1.2.840.10008.5.1.4.1.2.2.3"
        };
        return gets[rndn((int)(sizeof(gets)/sizeof(gets[0])) )];
    }
    case DICOM_DIMSE_C_MOVE_RQ: {
        static const char *moves[] = {
            "1.2.840.10008.5.1.4.1.2.1.2",
            "1.2.840.10008.5.1.4.1.2.2.2"
        };
        return moves[rndn((int)(sizeof(moves)/sizeof(moves[0])) )];
    }
    case DICOM_DIMSE_N_EVENT_REPORT_RQ:
    case DICOM_DIMSE_N_GET_RQ:
    case DICOM_DIMSE_N_SET_RQ:
    case DICOM_DIMSE_N_ACTION_RQ:
    case DICOM_DIMSE_N_CREATE_RQ:
    case DICOM_DIMSE_N_DELETE_RQ: {
        static const char *normalized[] = {
            "1.2.840.10008.1.20.1", "1.2.840.10008.5.1.1.16",
            "1.2.840.10008.5.1.1.9"
        };
        return normalized[rndn((int)(sizeof(normalized)/sizeof(normalized[0])) )];
    }
    default: return "1.2.840.10008.1.1";
    }
}

static uint16_t dicom_pick_service_dimse(void)
{
    static const uint16_t cmds[] = {
        DICOM_DIMSE_C_ECHO_RQ, DICOM_DIMSE_C_ECHO_RQ,
        DICOM_DIMSE_C_FIND_RQ, DICOM_DIMSE_C_FIND_RQ, DICOM_DIMSE_C_FIND_RQ,
        DICOM_DIMSE_C_GET_RQ, DICOM_DIMSE_C_GET_RQ,
        DICOM_DIMSE_C_STORE_RQ, DICOM_DIMSE_C_STORE_RQ,
        DICOM_DIMSE_C_MOVE_RQ
    };
    return cmds[rndn((int)(sizeof(cmds) / sizeof(cmds[0])) )];
}

static void dicom_apply_dimse_profile_to_pdv(dicom_pdv_item_t *pdv, uint8_t pcid, uint16_t cmd)
{
    if (!pdv) return;
    pdv->presentation_context_id = normalize_pcid(pcid);
    pdv->control_header = DICOM_PDV_FLAG_LAST_FRAGMENT | DICOM_PDV_FLAG_COMMAND;
    pdv->has_dimse_command = 1;
    pdv->has_dimse_command_fields = 1;
    pdv->dimse_fields_present = DICOM_DIMSE_PRESENT_GROUP_LENGTH |
                                DICOM_DIMSE_PRESENT_COMMAND |
                                DICOM_DIMSE_PRESENT_DATASET_TYPE;
    pdv->dimse_command_field = cmd;
    pdv->dimse_message_id = (uint16_t)(1 + rndn(0xfffe));
    if (cmd == DICOM_DIMSE_C_CANCEL_RQ) {
        pdv->dimse_message_id_responded_to = pdv->dimse_message_id;
        pdv->dimse_message_id = 0;
        pdv->dimse_fields_present |= DICOM_DIMSE_PRESENT_RESPONDED_TO;
    } else {
        pdv->dimse_fields_present |= DICOM_DIMSE_PRESENT_MESSAGE_ID;
    }
    pdv->dimse_priority = (uint16_t)rndn(3);
    if (cmd == DICOM_DIMSE_C_STORE_RQ || cmd == DICOM_DIMSE_C_GET_RQ ||
        cmd == DICOM_DIMSE_C_FIND_RQ || cmd == DICOM_DIMSE_C_MOVE_RQ)
        pdv->dimse_fields_present |= DICOM_DIMSE_PRESENT_PRIORITY;
    pdv->dimse_command_data_set_type = dimse_cmd_no_dataset(cmd) ? 0x0101 : 0x0000;
    const char *uid = dicom_uid_for_dimse(cmd);
    pdv_set_text_field(pdv->dimse_affected_sop_class_uid, &pdv->dimse_affected_sop_class_uid_len,
                       DICOM_MAX_DIMSE_UID_LEN, uid, 0);
    pdv_set_text_field(pdv->dimse_requested_sop_class_uid, &pdv->dimse_requested_sop_class_uid_len,
                       DICOM_MAX_DIMSE_UID_LEN, uid, 0);
    if (cmd == DICOM_DIMSE_C_MOVE_RQ) {
        pdv_set_text_field(pdv->dimse_move_destination, &pdv->dimse_move_destination_len,
                           DICOM_MAX_DIMSE_AE_LEN, "DCMQRSCP", 1);
    }
    if (cmd == DICOM_DIMSE_N_EVENT_REPORT_RQ) {
        pdv->dimse_event_type_id = (uint16_t)(1 + rndn(4));
        pdv->dimse_fields_present |= DICOM_DIMSE_PRESENT_EVENT_TYPE;
    }
    if (cmd == DICOM_DIMSE_N_ACTION_RQ) {
        pdv->dimse_action_type_id = (uint16_t)(1 + rndn(8));
        pdv->dimse_fields_present |= DICOM_DIMSE_PRESENT_ACTION_TYPE;
    }
    pdv->data_length = 0;
    pdv->data_tail = NULL;
    pdv->data_tail_length = 0;
    pdv->pdv_length = 2;
}


static void dicom_apply_dataset_profile_to_pdv(dicom_pdv_item_t *pdv, uint8_t pcid, uint16_t cmd)
{
    if (!pdv) return;
    memset(pdv, 0, sizeof(*pdv));
    pdv->presentation_context_id = normalize_pcid(pcid);
    pdv->control_header = DICOM_PDV_FLAG_LAST_FRAGMENT;
    pdv->has_dimse_command = 0;
    pdv->has_dimse_command_fields = 0;
    uint32_t out_len = 0;
    if (!dicom_write_curated_dataset_for_cmd(cmd, pdv->data, DICOM_MAX_PDV_DATA_LEN, &out_len)) {
        out_len = 0;
    }
    pdv->data_length = out_len;
    pdv->pdv_length = out_len + 2;
}

static void dicom_apply_coherent_service_template(dicom_packet_t *pkts, int num_packets)
{
    if (!pkts || num_packets <= 0) return;
    uint16_t cmd = dicom_pick_service_dimse();
    const char *uid = dicom_uid_for_dimse(cmd);
    uint8_t pcid = 1;
    int have_rq = 0;
    for (int i = 0; i < num_packets; ++i) {
        if (pkts[i].type != DICOM_PKT_A_ASSOCIATE_RQ) continue;
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        have_rq = 1;
        rq->pdu_type = DICOM_PDU_A_ASSOCIATE_RQ;
        rq->protocol_version = 1;
        memcpy(rq->called_ae_title, "ANY-SCP         ", 16);
        memcpy(rq->calling_ae_title, "LEMURSCU        ", 16);
        rq->application_context.item_type = 0x10;
        dicom_set_str(&rq->application_context.application_context_name, "1.2.840.10008.3.1.1.1");
        rq->presentation_context_count = rq->presentation_context_count ? rq->presentation_context_count : 1;
        dicom_default_pc(&rq->presentation_contexts[0], 0);
        rq->presentation_contexts[0].presentation_context_id = pcid;
        dicom_set_str(&rq->presentation_contexts[0].abstract_syntax.abstract_syntax_name, uid);
        rq->presentation_contexts[0].transfer_syntax_count = 1;
        rq->presentation_contexts[0].transfer_syntaxes[0].item_type = 0x40;
        dicom_set_str(&rq->presentation_contexts[0].transfer_syntaxes[0].transfer_syntax_name, "1.2.840.10008.1.2.1");
        rq->has_user_info = 1;
        rq->user_info.item_type = 0x50;
        rq->user_info.has_maximum_length = 1;
        rq->user_info.maximum_length_received = 16384;
        rq->user_info.has_implementation_class_uid = 1;
        dicom_set_str(&rq->user_info.implementation_class_uid, "1.2.826.0.1.3680043.2.1125.99");
        break;
    }
    (void)have_rq;
    int command_written = 0;
    int needs_dataset = !dimse_cmd_no_dataset(cmd);
    for (int i = 0; i < num_packets; ++i) {
        if (pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        dicom_p_data_tf_pdu_t *pd = &pkts[i].u.p_data_tf;
        if (pd->pdv_count == 0) pd->pdv_count = 1;
        if (pd->pdv_count > DICOM_MAX_PDV_ITEMS) pd->pdv_count = DICOM_MAX_PDV_ITEMS;
        if (!command_written) {
            dicom_apply_dimse_profile_to_pdv(&pd->pdvs[0], pcid, cmd);
            command_written = 1;
            if (needs_dataset && pd->pdv_count < DICOM_MAX_PDV_ITEMS && rndn(2) == 0) {
                pd->pdv_count = 2;
                dicom_apply_dataset_profile_to_pdv(&pd->pdvs[1], pcid, cmd);
            }
        } else if (needs_dataset) {
            pd->pdv_count = 1;
            dicom_apply_dataset_profile_to_pdv(&pd->pdvs[0], pcid, cmd);
        } else {
            dicom_apply_dimse_profile_to_pdv(&pd->pdvs[0], pcid, cmd);
        }
        pd->pdv_tail = NULL;
        pd->pdv_tail_length = 0;
        pkts[i].raw_length = 0;
    }
}

static void mutate_pdu_length(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) {
        uint32_t len = pkts[i].raw_length >= 6 ? pkts[i].raw_length - 6U : 0;
        if (rndn(4) == 0) len = (uint32_t)rndn(4096);
        switch (pkts[i].type) {
            case DICOM_PKT_A_ASSOCIATE_RQ: pkts[i].u.a_associate_rq.pdu_length = len; break;
            case DICOM_PKT_A_ASSOCIATE_AC: pkts[i].u.a_associate_ac.pdu_length = len; break;
            case DICOM_PKT_A_ASSOCIATE_RJ: pkts[i].u.a_associate_rj.pdu_length = 4; break;
            case DICOM_PKT_P_DATA_TF: pkts[i].u.p_data_tf.pdu_length = len; break;
            case DICOM_PKT_A_RELEASE_RQ: pkts[i].u.a_release_rq.pdu_length = 4; break;
            case DICOM_PKT_A_RELEASE_RP: pkts[i].u.a_release_rp.pdu_length = 4; break;
            case DICOM_PKT_A_ABORT: pkts[i].u.a_abort.pdu_length = 4; break;
            case DICOM_PKT_UNKNOWN: pkts[i].u.unknown.pdu_length = pkts[i].u.unknown.data_length; break;
            default: break;
        }
    }
}

static void mutate_application_context_name(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const char *contexts[] = {"1.2.840.10008.3.1.1.1", "1.2.840.10008.3.1.1.2"};
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        rq->application_context.item_type = 0x10;
        rq->application_context.reserved1 = 0;
        dicom_set_str(&rq->application_context.application_context_name, contexts[rndn(2)]);
    }
}

static void mutate_presentation_context_count(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        uint8_t target = rq->presentation_context_count;
        switch (rndn(6)) {
            case 0: target = 1; break;
            case 1: target = DICOM_MAX_PRESENTATION_CONTEXTS; break;
            case 2: if (target < DICOM_MAX_PRESENTATION_CONTEXTS) target++; break;
            case 3: if (target > 1) target--; break;
            default: target = (uint8_t)(1 + rndn(DICOM_MAX_PRESENTATION_CONTEXTS)); break;
        }
        for (uint8_t j = rq->presentation_context_count; j < target && j < DICOM_MAX_PRESENTATION_CONTEXTS; j++)
            dicom_default_pc(&rq->presentation_contexts[j], j);
        rq->presentation_context_count = target;
    }
}

static void add_presentation_contexts(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        if (rq->presentation_context_count < DICOM_MAX_PRESENTATION_CONTEXTS) {
            dicom_default_pc(&rq->presentation_contexts[rq->presentation_context_count], rq->presentation_context_count);
            rq->presentation_context_count++;
        }
    }
}

static void delete_presentation_contexts(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        if (pkts[i].u.a_associate_rq.presentation_context_count > 1)
            pkts[i].u.a_associate_rq.presentation_context_count--;
    }
}

static void repeat_presentation_contexts(dicom_packet_t *pkts, size_t n)
{
    add_presentation_contexts(pkts, n);
    add_presentation_contexts(pkts, n);
}

static void mutate_presentation_contexts(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        if (rq->presentation_context_count == 0) add_presentation_contexts(pkts + i, 1);
        uint8_t j = (uint8_t)rndn(rq->presentation_context_count ? rq->presentation_context_count : 1);
        if (j >= DICOM_MAX_PRESENTATION_CONTEXTS) j = 0;
        rq->presentation_contexts[j].presentation_context_id = normalize_pcid((uint8_t)(1 + 2 * rndn(64)));
        if (rndn(2)) dicom_set_str(&rq->presentation_contexts[j].abstract_syntax.abstract_syntax_name, dicom_pick_sop_uid());
        if (rndn(2)) add_transfer_syntaxes(pkts + i, 1);
    }
}

static void mutate_abstract_syntax_name(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        for (uint8_t j = 0; j < rq->presentation_context_count && j < DICOM_MAX_PRESENTATION_CONTEXTS; j++) {
            rq->presentation_contexts[j].abstract_syntax.item_type = 0x30;
            dicom_set_str(&rq->presentation_contexts[j].abstract_syntax.abstract_syntax_name, dicom_pick_sop_uid());
        }
    }
}

static void mutate_transfer_syntax_count(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        for (uint8_t j = 0; j < rq->presentation_context_count && j < DICOM_MAX_PRESENTATION_CONTEXTS; j++) {
            dicom_presentation_context_item_t *pc = &rq->presentation_contexts[j];
            uint8_t target = (uint8_t)(1 + rndn(DICOM_MAX_TRANSFER_SYNTAXES));
            for (uint8_t k = pc->transfer_syntax_count; k < target && k < DICOM_MAX_TRANSFER_SYNTAXES; k++) {
                pc->transfer_syntaxes[k].item_type = 0x40;
                dicom_set_str(&pc->transfer_syntaxes[k].transfer_syntax_name, dicom_pick_transfer_uid());
            }
            pc->transfer_syntax_count = target;
        }
    }
}

static void add_transfer_syntaxes(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        for (uint8_t j = 0; j < rq->presentation_context_count && j < DICOM_MAX_PRESENTATION_CONTEXTS; j++) {
            dicom_presentation_context_item_t *pc = &rq->presentation_contexts[j];
            if (pc->transfer_syntax_count < DICOM_MAX_TRANSFER_SYNTAXES) {
                dicom_transfer_syntax_item_t *ts = &pc->transfer_syntaxes[pc->transfer_syntax_count++];
                memset(ts, 0, sizeof(*ts));
                ts->item_type = 0x40;
                dicom_set_str(&ts->transfer_syntax_name, dicom_pick_transfer_uid());
            }
        }
    }
}

static void delete_transfer_syntaxes(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        for (uint8_t j = 0; j < rq->presentation_context_count && j < DICOM_MAX_PRESENTATION_CONTEXTS; j++)
            if (rq->presentation_contexts[j].transfer_syntax_count > 1) rq->presentation_contexts[j].transfer_syntax_count--;
    }
}

static void repeat_transfer_syntaxes(dicom_packet_t *pkts, size_t n)
{
    add_transfer_syntaxes(pkts, n);
    add_transfer_syntaxes(pkts, n);
}

static void mutate_transfer_syntaxes(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        dicom_a_associate_rq_pdu_t *rq = &pkts[i].u.a_associate_rq;
        for (uint8_t j = 0; j < rq->presentation_context_count && j < DICOM_MAX_PRESENTATION_CONTEXTS; j++) {
            dicom_presentation_context_item_t *pc = &rq->presentation_contexts[j];
            if (pc->transfer_syntax_count == 0) pc->transfer_syntax_count = 1;
            for (uint8_t k = 0; k < pc->transfer_syntax_count && k < DICOM_MAX_TRANSFER_SYNTAXES; k++) {
                pc->transfer_syntaxes[k].item_type = 0x40;
                if (rndn(2)) dicom_set_str(&pc->transfer_syntaxes[k].transfer_syntax_name, dicom_pick_transfer_uid());
            }
        }
    }
}

static void add_user_info(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        pkts[i].u.a_associate_rq.has_user_info = 1;
        ui->item_type = 0x50;
        ui->reserved1 = 0;
        if (!ui->has_maximum_length || ui->maximum_length_received == 0) {
            ui->has_maximum_length = 1;
            ui->maximum_length_received = 16384;
        }
        if (!ui->has_implementation_class_uid || ui->implementation_class_uid.length == 0) {
            ui->has_implementation_class_uid = 1;
            dicom_set_str(&ui->implementation_class_uid, "1.2.826.0.1.3680043.10.543.1");
        }
        if (!ui->has_implementation_version_name || ui->implementation_version_name.length == 0) {
            ui->has_implementation_version_name = 1;
            dicom_set_str(&ui->implementation_version_name, "LEMUR_1");
        }
    }
}

static void add_user_maximum_length(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const uint32_t vals[] = {1024, 4096, 8192, 16384, 32768, 65536};
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        ui->has_maximum_length = 1;
        ui->maximum_length_received = vals[rndn((int)(sizeof(vals) / sizeof(vals[0])))];
    }
}

static void delete_user_maximum_length(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ)
        pkts[i].u.a_associate_rq.user_info.has_maximum_length = 0;
}

static void mutate_user_maximum_length(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        ui->has_maximum_length = 1;
        switch (rndn(5)) {
        case 0: ui->maximum_length_received = 0; break;
        case 1: ui->maximum_length_received = 1; break;
        case 2: ui->maximum_length_received = 16384; break;
        case 3: ui->maximum_length_received = 65536; break;
        default: ui->maximum_length_received ^= (uint32_t)(1u << rndn(24)); break;
        }
    }
}

static void add_implementation_class_uid(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const char *uids[] = {
        "1.2.826.0.1.3680043.10.543.1",
        "1.2.840.10008.3.1.1.1",
        "1.3.6.1.4.1.5962.99.1"
    };
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        ui->has_implementation_class_uid = 1;
        dicom_set_str(&ui->implementation_class_uid, uids[rndn((int)(sizeof(uids) / sizeof(uids[0])))]);
    }
}

static void delete_implementation_class_uid(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ)
        pkts[i].u.a_associate_rq.user_info.has_implementation_class_uid = 0;
}

static void mutate_implementation_class_uid(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const char *uids[] = {
        "1.2.826.0.1.3680043.10.543.1",
        "1.2.840.10008.3.1.1.1",
        "1.2.840.10008.5.1.4.1.1.2",
        "1.2.840.10008.1.1"
    };
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        ui->has_implementation_class_uid = 1;
        dicom_set_str(&ui->implementation_class_uid, uids[rndn((int)(sizeof(uids) / sizeof(uids[0])))]);
        if (rndn(4) == 0 && ui->implementation_class_uid.length < DICOM_MAX_UID_LEN) {
            ui->implementation_class_uid.value[ui->implementation_class_uid.length++] = (char)('0' + rndn(10));
        }
    }
}

static void add_async_ops_window(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        ui->has_async_ops_window = 1;
        ui->max_ops_invoked = (uint16_t)(1 + rndn(8));
        ui->max_ops_performed = (uint16_t)(1 + rndn(8));
    }
}

static void delete_async_ops_window(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ)
        pkts[i].u.a_associate_rq.user_info.has_async_ops_window = 0;
}

static void mutate_async_ops_window(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const uint16_t vals[] = {0, 1, 2, 4, 8, 16, 0xffff};
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        ui->has_async_ops_window = 1;
        ui->max_ops_invoked = vals[rndn((int)(sizeof(vals) / sizeof(vals[0])))];
        ui->max_ops_performed = vals[rndn((int)(sizeof(vals) / sizeof(vals[0])))];
    }
}

static void add_role_selections(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        if (ui->role_selection_count >= DICOM_MAX_ROLE_SELECTIONS) continue;
        uint8_t idx = ui->role_selection_count++;
        dicom_set_str(&ui->role_selections[idx].sop_class_uid, dicom_pick_sop_uid());
        ui->role_selections[idx].scu_role = (uint8_t)rndn(2);
        ui->role_selections[idx].scp_role = (uint8_t)rndn(2);
    }
}

static void delete_role_selections(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        if (ui->role_selection_count) ui->role_selection_count--;
    }
}

static void repeat_role_selections(dicom_packet_t *pkts, size_t n)
{
    add_role_selections(pkts, n);
    add_role_selections(pkts, n);
}

static void mutate_role_selections(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        if (ui->role_selection_count == 0) add_role_selections(pkts + i, 1);
        if (ui->role_selection_count == 0) continue;
        uint8_t idx = (uint8_t)rndn(ui->role_selection_count);
        switch (rndn(4)) {
        case 0: dicom_set_str(&ui->role_selections[idx].sop_class_uid, dicom_pick_sop_uid()); break;
        case 1: ui->role_selections[idx].scu_role ^= 1; break;
        case 2: ui->role_selections[idx].scp_role ^= 1; break;
        default:
            ui->role_selections[idx].scu_role = (uint8_t)rnd8();
            ui->role_selections[idx].scp_role = (uint8_t)rnd8();
            break;
        }
    }
}

static void add_implementation_version_name(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const char *names[] = {"LEMUR_1", "DCMTK_367", "ORTHANC", "FUZZSCU"};
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        ui->has_implementation_version_name = 1;
        dicom_set_str(&ui->implementation_version_name, names[rndn((int)(sizeof(names) / sizeof(names[0])))]);
    }
}

static void delete_implementation_version_name(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ)
        pkts[i].u.a_associate_rq.user_info.has_implementation_version_name = 0;
}

static void mutate_implementation_version_name(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const char *names[] = {"LEMUR_1", "LEMUR_2", "DICOMFUZZ", "OPENAI"};
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        ui->has_implementation_version_name = 1;
        dicom_set_str(&ui->implementation_version_name, names[rndn((int)(sizeof(names) / sizeof(names[0])))]);
        if (rndn(3) == 0 && ui->implementation_version_name.length < DICOM_MAX_UID_LEN) {
            ui->implementation_version_name.value[ui->implementation_version_name.length++] = (char)('A' + rndn(26));
        }
    }
}

static void add_sop_class_extended_negotiation(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        ui->has_sop_class_extended_negotiation = 1;
        dicom_set_str(&ui->sop_class_extended_uid, dicom_pick_sop_uid());
        static const uint8_t infos[][4] = {{0x00}, {0x01}, {0x00,0x01}, {0x01,0x00,0x02,0x00}};
        uint32_t idx = (uint32_t)rndn((int)(sizeof(infos)/sizeof(infos[0])));
        ui->sop_class_extended_info_len = (idx == 0) ? 1 : (idx == 1 ? 1 : (idx == 2 ? 2 : 4));
        memcpy(ui->sop_class_extended_info, infos[idx], ui->sop_class_extended_info_len);
    }
}

static void mutate_sop_class_extended_negotiation(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_sop_class_extended_negotiation(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        if (rndn(2)) dicom_set_str(&ui->sop_class_extended_uid, dicom_pick_sop_uid());
        if (ui->sop_class_extended_info_len == 0) ui->sop_class_extended_info_len = 1;
        ui->sop_class_extended_info[rndn(ui->sop_class_extended_info_len)] ^= (uint8_t)(1u << rndn(8));
    }
}

static void add_sop_class_common_extended_negotiation(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        ui->has_sop_class_common_extended_negotiation = 1;
        const char *sop = dicom_pick_sop_uid();
        dicom_set_str(&ui->sop_class_common_sop_uid, sop);
        dicom_set_str(&ui->sop_class_common_service_class_uid, "1.2.840.10008.4.2");
        ui->related_general_sop_class_uid_count = 1 + (uint8_t)rndn(3);
        if (ui->related_general_sop_class_uid_count > DICOM_MAX_RELATED_SOP_CLASSES)
            ui->related_general_sop_class_uid_count = DICOM_MAX_RELATED_SOP_CLASSES;
        for (uint8_t k = 0; k < ui->related_general_sop_class_uid_count; k++)
            dicom_set_str(&ui->related_general_sop_class_uids[k], dicom_pick_sop_uid());
    }
}

static void mutate_sop_class_common_extended_negotiation(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_sop_class_common_extended_negotiation(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        switch (rndn(4)) {
        case 0: dicom_set_str(&ui->sop_class_common_sop_uid, dicom_pick_sop_uid()); break;
        case 1: dicom_set_str(&ui->sop_class_common_service_class_uid, "1.2.840.10008.4.2"); break;
        case 2: if (ui->related_general_sop_class_uid_count < DICOM_MAX_RELATED_SOP_CLASSES) ui->related_general_sop_class_uid_count++; break;
        default: if (ui->related_general_sop_class_uid_count) dicom_set_str(&ui->related_general_sop_class_uids[rndn(ui->related_general_sop_class_uid_count)], dicom_pick_sop_uid()); break;
        }
    }
}

static void add_user_identity_negotiation(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        static const char *users[] = {"", "user", "dicom", "storescu", "findscu", "lemur"};
        static const char *passes[] = {"", "pass", "secret", "dicom"};
        const char *u = users[rndn((int)(sizeof(users)/sizeof(users[0])) )];
        const char *pw = passes[rndn((int)(sizeof(passes)/sizeof(passes[0])) )];
        ui->has_user_identity_negotiation = 1;
        ui->user_identity_type = (uint8_t)(1 + rndn(5));
        ui->user_identity_positive_response_requested = (uint8_t)rndn(2);
        ui->user_identity_primary_field_len = (uint16_t)strlen(u);
        ui->user_identity_secondary_field_len = (uint16_t)strlen(pw);
        memset(ui->user_identity_primary_field, 0, DICOM_MAX_USER_INFO_BYTES);
        memset(ui->user_identity_secondary_field, 0, DICOM_MAX_USER_INFO_BYTES);
        memcpy(ui->user_identity_primary_field, u, ui->user_identity_primary_field_len);
        memcpy(ui->user_identity_secondary_field, pw, ui->user_identity_secondary_field_len);
    }
}

static void mutate_user_identity_negotiation(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_identity_negotiation(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        switch (rndn(4)) {
        case 0: ui->user_identity_type = (uint8_t)(1 + rndn(5)); break;
        case 1: ui->user_identity_positive_response_requested ^= 1; break;
        case 2: if (ui->user_identity_primary_field_len < DICOM_MAX_USER_INFO_BYTES) ui->user_identity_primary_field[ui->user_identity_primary_field_len++] = (uint8_t)('A' + rndn(26)); break;
        default: if (ui->user_identity_secondary_field_len < DICOM_MAX_USER_INFO_BYTES) ui->user_identity_secondary_field[ui->user_identity_secondary_field_len++] = (uint8_t)('0' + rndn(10)); break;
        }
    }
}

static void delete_user_info(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) pkts[i].u.a_associate_rq.has_user_info = 0;
}

static void mutate_has_user_info(dicom_packet_t *pkts, size_t n)
{
    if (rndn(2)) add_user_info(pkts, n); else delete_user_info(pkts, n);
}

static void add_user_data(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        static const uint8_t private_items[][8] = {
            {0x99,0x00,0x00,0x04,'L','M','R','1'},
            {0x5a,0x00,0x00,0x04,'F','U','Z','Z'},
            {0x59,0x00,0x00,0x02,0xaa,0xbb,0x00,0x00}
        };
        const uint8_t *item = private_items[rndn((int)(sizeof(private_items)/sizeof(private_items[0])) )];
        uint32_t len = (item[2] << 8) | item[3];
        uint32_t total = 4U + len;
        if (total > sizeof(private_items[0])) total = sizeof(private_items[0]);
        if (ui->user_data_length + total > DICOM_MAX_USER_INFO_BYTES) ui->user_data_length = 0;
        memcpy(ui->user_data + ui->user_data_length, item, total);
        ui->user_data_length += total;
        ui->has_user_data = 1;
    }
}

static void delete_user_data(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        pkts[i].u.a_associate_rq.user_info.has_user_data = 0;
        pkts[i].u.a_associate_rq.user_info.user_data_length = 0;
    }
}

static void repeat_user_data(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        uint32_t old = ui->user_data_length;
        if (old && old * 2 <= DICOM_MAX_USER_INFO_BYTES) {
            memcpy(ui->user_data + old, ui->user_data, old);
            ui->user_data_length = old * 2;
        }
    }
}

static void mutate_user_data(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        uint32_t lim = ui->user_data_length > DICOM_MAX_USER_INFO_BYTES ? DICOM_MAX_USER_INFO_BYTES : ui->user_data_length;
        if (lim == 0) continue;
        switch (rndn(4)) {
            case 0: memset(ui->user_data, 0, lim); break;
            case 1: ui->user_data[rndn((int)lim)] ^= 0xff; break;
            default: for (uint32_t k = 0; k < lim && k < 64; k++) if (rndn(3) == 0) ui->user_data[k] = rnd8(); break;
        }
    }
}

static void mutate_user_data_length(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_RQ) {
        add_user_info(pkts + i, 1);
        dicom_user_info_item_t *ui = &pkts[i].u.a_associate_rq.user_info;
        static const uint16_t lens[] = {0, 4, 8, 16, 32, 64, 128, 256, 512};
        ui->user_data_length = lens[rndn((int)(sizeof(lens) / sizeof(lens[0])) )];
        if (ui->user_data_length > DICOM_MAX_USER_INFO_BYTES) ui->user_data_length = DICOM_MAX_USER_INFO_BYTES;
        ui->has_user_data = ui->user_data_length ? 1 : 0;
    }
}

static void add_pdvs(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    uint8_t pcid = preferred_pcid(pkts, n);
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_P_DATA_TF) {
        dicom_p_data_tf_pdu_t *p = &pkts[i].u.p_data_tf;
        if (p->pdv_count < DICOM_MAX_PDV_ITEMS) dicom_default_pdv(&p->pdvs[p->pdv_count++], pcid);
    }
}

static void delete_pdvs(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_P_DATA_TF && pkts[i].u.p_data_tf.pdv_count > 1) pkts[i].u.p_data_tf.pdv_count--;
}

static void repeat_pdvs(dicom_packet_t *pkts, size_t n)
{
    add_pdvs(pkts, n);
    add_pdvs(pkts, n);
}

static void mutate_pdvs(dicom_packet_t *pkts, size_t n)
{
    if (rndn(3) == 0) add_pdvs(pkts, n);
    else if (rndn(3) == 0) delete_pdvs(pkts, n);
    else mutate_pdv_data_bytes(pkts, n);
}

static void mutate_pdv_count(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    uint8_t pcid = preferred_pcid(pkts, n);
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_P_DATA_TF) {
        dicom_p_data_tf_pdu_t *p = &pkts[i].u.p_data_tf;
        uint16_t target = (uint16_t)(1 + rndn(DICOM_MAX_PDV_ITEMS));
        for (uint16_t j = p->pdv_count; j < target && j < DICOM_MAX_PDV_ITEMS; j++) dicom_default_pdv(&p->pdvs[j], pcid);
        p->pdv_count = target;
    }
}

static void mutate_pdv_length(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_P_DATA_TF) {
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            /* PDV length is derived from the payload and the two fixed
             * header bytes.  Keeping it derived preserves a legal P-DATA-TF
             * envelope while still exercising the reassembler path. */
            pdv->pdv_length = pdv->data_length + pdv->data_tail_length + 2;
        }
    }
}

static void mutate_data_length(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_P_DATA_TF) {
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            /* A free-form length mutation truncates an element in the
             * dataset or a DIMSE command.  That creates malformed requests,
             * so this mutator now repairs the derived length instead of
             * inventing an inconsistent one.  Dataset value diversity is
             * provided by mutate_dicom_dataset_fields(). */
            if (pdv_has_dimse(pdv)) continue;
            pdv->pdv_length = pdv->data_length + pdv->data_tail_length + 2;
        }
    }
}

static void add_data(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_P_DATA_TF) {
        if (pkts[i].u.p_data_tf.pdv_count == 0) add_pdvs(pkts + i, 1);
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            if (pdv->data_length == 0) {
                pdv->data_length = 4;
                for (uint32_t k = 0; k < pdv->data_length; k++) pdv->data[k] = rnd8();
                pdv->pdv_length = pdv->data_length + 2;
                pdv->control_header &= (uint8_t)~DICOM_PDV_FLAG_COMMAND;
            }
        }
    }
}

static void delete_data(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_P_DATA_TF) {
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) {
            pkts[i].u.p_data_tf.pdvs[j].data_length = 0;
            pkts[i].u.p_data_tf.pdvs[j].pdv_length = 2;
        }
    }
}

static void repeat_data(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_P_DATA_TF) {
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            uint32_t old = pdv->data_length;
            if (old && old * 2 <= DICOM_MAX_PDV_DATA_LEN) {
                memcpy(pdv->data + old, pdv->data, old);
                pdv->data_length = old * 2;
                pdv->pdv_length = pdv->data_length + 2;
            }
        }
    }
}


static int dicom_dataset_is_long_vr(const uint8_t *vr)
{
    return (vr[0]=='O' && (vr[1]=='B' || vr[1]=='D' || vr[1]=='F' || vr[1]=='L' || vr[1]=='W')) ||
           (vr[0]=='S' && vr[1]=='Q') ||
           (vr[0]=='U' && (vr[1]=='C' || vr[1]=='R' || vr[1]=='T' || vr[1]=='N'));
}

static void dicom_dataset_write_text(uint8_t *dst, uint32_t len, const char *value, char pad)
{
    if (!dst || !len || !value) return;
    size_t n = strlen(value);
    if (n > len) n = len;
    memset(dst, pad, len);
    memcpy(dst, value, n);
}

static void dicom_dataset_mutate_value(uint16_t group, uint16_t elem, uint8_t *val, uint32_t len)
{
    if (!val || len == 0) return;
    if (group == 0x0008 && elem == 0x0052) {
        static const char *levels[] = {"PATIENT", "STUDY", "SERIES", "IMAGE"};
        dicom_dataset_write_text(val, len, levels[rndn((int)(sizeof(levels)/sizeof(levels[0])))], ' '); return;
    }
    if (group == 0x0008 && elem == 0x0020) {
        static const char *dates[] = {"", "19000101", "19700101", "19991231", "20000101", "20200101", "20251231"};
        dicom_dataset_write_text(val, len, dates[rndn((int)(sizeof(dates)/sizeof(dates[0])))], ' '); return;
    }
    if (group == 0x0010 && (elem == 0x0010 || elem == 0x0020 || elem == 0x0030 || elem == 0x0040)) {
        static const char *names[] = {"", "DOE^JOHN", "SMITH^JANE", "LEMUR^FUZZ", "*", "A*", "TEST^PATIENT"};
        static const char *ids[] = {"", "1", "12345", "000000", "PATIENTID", "FUZZID"};
        static const char *birth[] = {"", "19000101", "19700101", "20000101"};
        static const char *sex[] = {"", "M", "F", "O"};
        if (elem == 0x0010) dicom_dataset_write_text(val, len, names[rndn((int)(sizeof(names)/sizeof(names[0])))], ' ');
        else if (elem == 0x0020) dicom_dataset_write_text(val, len, ids[rndn((int)(sizeof(ids)/sizeof(ids[0])))], ' ');
        else if (elem == 0x0030) dicom_dataset_write_text(val, len, birth[rndn((int)(sizeof(birth)/sizeof(birth[0])))], ' ');
        else dicom_dataset_write_text(val, len, sex[rndn((int)(sizeof(sex)/sizeof(sex[0])))], ' ');
        return;
    }
    if (group == 0x0020 && (elem == 0x000d || elem == 0x000e || elem == 0x0010 || elem == 0x0011 || elem == 0x0013)) {
        static const char *uids[] = {"", "1.2.826.0.1.3680043.2.1125.1", "1.2.840.113654.2.55.1", "1.2.3.4.5"};
        static const char *nums[] = {"", "1", "2", "999", "FUZZ"};
        if (elem == 0x000d || elem == 0x000e) dicom_dataset_write_text(val, len, uids[rndn((int)(sizeof(uids)/sizeof(uids[0])))], 0);
        else dicom_dataset_write_text(val, len, nums[rndn((int)(sizeof(nums)/sizeof(nums[0])))], ' ');
        return;
    }
    if (group == 0x0008 && (elem == 0x0016 || elem == 0x0018 || elem == 0x0060 || elem == 0x1030)) {
        static const char *modalities[] = {"CT", "MR", "CR", "US", "OT", "SR", "PT"};
        static const char *uids[] = {"1.2.840.10008.5.1.4.1.1.2", "1.2.840.10008.5.1.4.1.1.4", "1.2.840.10008.5.1.4.1.1.7", "1.2.826.0.1.3680043.2.1125.2"};
        static const char *desc[] = {"", "LEMUR", "FUZZ", "HEAD", "CHEST"};
        if (elem == 0x0060) dicom_dataset_write_text(val, len, modalities[rndn((int)(sizeof(modalities)/sizeof(modalities[0])))], ' ');
        else if (elem == 0x1030) dicom_dataset_write_text(val, len, desc[rndn((int)(sizeof(desc)/sizeof(desc[0])))], ' ');
        else dicom_dataset_write_text(val, len, uids[rndn((int)(sizeof(uids)/sizeof(uids[0])))], 0);
        return;
    }
    val[rndn((int)len)] ^= (uint8_t)(1u << rndn(8));
}


static uint32_t dicom_write_explicit_text_elem(uint8_t *dst, uint32_t cap,
                                               uint16_t group, uint16_t elem,
                                               const char vr[2], const char *value,
                                               char pad)
{
    if (!dst || !vr || !value || cap < 8) return 0;
    size_t n = strlen(value);
    uint32_t vlen = (uint32_t)n;
    if (vlen & 1U) vlen++;
    uint32_t hdr = dicom_dataset_is_long_vr((const uint8_t *)vr) ? 12U : 8U;
    if (hdr + vlen > cap) return 0;
    wr16le(dst, group);
    wr16le(dst + 2, elem);
    dst[4] = (uint8_t)vr[0];
    dst[5] = (uint8_t)vr[1];
    if (hdr == 12U) {
        dst[6] = dst[7] = 0;
        wr32le(dst + 8, vlen);
    } else {
        wr16le(dst + 6, (uint16_t)vlen);
    }
    memset(dst + hdr, pad, vlen);
    if (n > vlen) n = vlen;
    memcpy(dst + hdr, value, n);
    if (vr[0] == 'U' && vr[1] == 'I' && vlen > 0 && n < vlen) dst[hdr + n] = 0;
    return hdr + vlen;
}

static int dicom_write_curated_dataset_for_cmd(uint16_t cmd, uint8_t *dst, uint32_t cap, uint32_t *out_len)
{
    if (!dst || !out_len || cap < 64) return 0;
    uint32_t pos = 0;
#define ADD_TXT_CMD(g,e,vr,val,pad) do { \
        uint32_t wrote = dicom_write_explicit_text_elem(dst + pos, cap - pos, (g), (e), (vr), (val), (pad)); \
        if (!wrote) goto done_cmd; \
        pos += wrote; \
    } while (0)
    switch (cmd) {
    case DICOM_DIMSE_C_FIND_RQ:
    case DICOM_DIMSE_C_GET_RQ:
    case DICOM_DIMSE_C_MOVE_RQ:
        switch (rndn(4)) {
        case 0:
            ADD_TXT_CMD(0x0008,0x0052,"CS","PATIENT",' ');
            ADD_TXT_CMD(0x0010,0x0010,"PN", rndn(2) ? "*" : "DOE^JOHN", ' ');
            ADD_TXT_CMD(0x0010,0x0020,"LO", rndn(2) ? "" : "PATIENTID", ' ');
            break;
        case 1:
            ADD_TXT_CMD(0x0008,0x0052,"CS","STUDY",' ');
            ADD_TXT_CMD(0x0010,0x0010,"PN","*",' ');
            ADD_TXT_CMD(0x0010,0x0020,"LO","",' ');
            ADD_TXT_CMD(0x0008,0x0020,"DA", rndn(2) ? "" : "20200101", ' ');
            ADD_TXT_CMD(0x0020,0x000D,"UI", rndn(2) ? "" : "1.2.826.0.1.3680043.2.1125.1", 0);
            break;
        case 2:
            ADD_TXT_CMD(0x0008,0x0052,"CS","SERIES",' ');
            ADD_TXT_CMD(0x0020,0x000D,"UI", rndn(2) ? "" : "1.2.826.0.1.3680043.2.1125.1", 0);
            ADD_TXT_CMD(0x0020,0x000E,"UI", rndn(2) ? "" : "1.2.826.0.1.3680043.2.1125.2", 0);
            ADD_TXT_CMD(0x0008,0x0060,"CS", rndn(2) ? "CT" : "MR", ' ');
            break;
        default:
            ADD_TXT_CMD(0x0008,0x0052,"CS","IMAGE",' ');
            ADD_TXT_CMD(0x0008,0x0018,"UI", rndn(2) ? "" : "1.2.826.0.1.3680043.2.1125.3", 0);
            ADD_TXT_CMD(0x0020,0x000D,"UI","1.2.826.0.1.3680043.2.1125.1",0);
            ADD_TXT_CMD(0x0020,0x000E,"UI","1.2.826.0.1.3680043.2.1125.2",0);
            break;
        }
        if (cmd == DICOM_DIMSE_C_MOVE_RQ)
            ADD_TXT_CMD(0x0008,0x0054,"AE","DCMQRSCP",' ');
        break;
    case DICOM_DIMSE_C_STORE_RQ:
        ADD_TXT_CMD(0x0008,0x0016,"UI", rndn(2) ? "1.2.840.10008.5.1.4.1.1.2" : "1.2.840.10008.5.1.4.1.1.4", 0);
        ADD_TXT_CMD(0x0008,0x0018,"UI", "1.2.826.0.1.3680043.2.1125.100", 0);
        ADD_TXT_CMD(0x0008,0x0020,"DA", rndn(2) ? "20200101" : "", ' ');
        ADD_TXT_CMD(0x0008,0x0030,"TM", rndn(2) ? "120000" : "", ' ');
        ADD_TXT_CMD(0x0008,0x0060,"CS", rndn(2) ? "CT" : "MR", ' ');
        ADD_TXT_CMD(0x0010,0x0010,"PN", rndn(2) ? "LEMUR^PATIENT" : "DOE^JOHN", ' ');
        ADD_TXT_CMD(0x0010,0x0020,"LO", rndn(2) ? "LEMURID" : "12345", ' ');
        ADD_TXT_CMD(0x0020,0x000D,"UI", "1.2.826.0.1.3680043.2.1125.101", 0);
        ADD_TXT_CMD(0x0020,0x000E,"UI", "1.2.826.0.1.3680043.2.1125.102", 0);
        ADD_TXT_CMD(0x0020,0x0010,"SH", "1", ' ');
        ADD_TXT_CMD(0x0020,0x0011,"IS", rndn(2) ? "1" : "2", ' ');
        ADD_TXT_CMD(0x0020,0x0013,"IS", rndn(2) ? "1" : "42", ' ');
        break;
    case DICOM_DIMSE_N_SET_RQ:
    case DICOM_DIMSE_N_ACTION_RQ:
    case DICOM_DIMSE_N_CREATE_RQ:
    case DICOM_DIMSE_N_EVENT_REPORT_RQ:
        ADD_TXT_CMD(0x0008,0x0016,"UI", "1.2.840.10008.1.20.1", 0);
        ADD_TXT_CMD(0x0008,0x0018,"UI", "1.2.826.0.1.3680043.2.1125.200", 0);
        ADD_TXT_CMD(0x0008,0x0100,"SH", rndn(2) ? "LEMUR" : "ACTION", ' ');
        break;
    default:
        return dicom_write_curated_dataset(dst, cap, out_len);
    }
done_cmd:
#undef ADD_TXT_CMD
    if (pos < 16) return 0;
    *out_len = pos;
    return 1;
}

static int dicom_write_curated_dataset(uint8_t *dst, uint32_t cap, uint32_t *out_len)
{
    if (!dst || !out_len || cap < 64) return 0;
    uint32_t pos = 0;
#define ADD_TXT(g,e,vr,val,pad) do { \
        uint32_t wrote = dicom_write_explicit_text_elem(dst + pos, cap - pos, (g), (e), (vr), (val), (pad)); \
        if (!wrote) goto done; \
        pos += wrote; \
    } while (0)
    switch (rndn(6)) {
    case 0: /* C-FIND/C-GET PATIENT query keys. */
        ADD_TXT(0x0008,0x0052,"CS","PATIENT",' ');
        ADD_TXT(0x0010,0x0010,"PN", rndn(2) ? "*" : "DOE^JOHN", ' ');
        ADD_TXT(0x0010,0x0020,"LO", rndn(2) ? "" : "PATIENTID", ' ');
        break;
    case 1: /* STUDY query keys. */
        ADD_TXT(0x0008,0x0052,"CS","STUDY",' ');
        ADD_TXT(0x0010,0x0010,"PN","*",' ');
        ADD_TXT(0x0010,0x0020,"LO","",' ');
        ADD_TXT(0x0008,0x0020,"DA", rndn(2) ? "" : "20200101", ' ');
        ADD_TXT(0x0020,0x000D,"UI", rndn(2) ? "" : "1.2.826.0.1.3680043.2.1125.1", 0);
        break;
    case 2: /* SERIES query keys. */
        ADD_TXT(0x0008,0x0052,"CS","SERIES",' ');
        ADD_TXT(0x0020,0x000D,"UI", rndn(2) ? "" : "1.2.826.0.1.3680043.2.1125.1", 0);
        ADD_TXT(0x0020,0x000E,"UI", rndn(2) ? "" : "1.2.826.0.1.3680043.2.1125.2", 0);
        ADD_TXT(0x0008,0x0060,"CS", rndn(2) ? "CT" : "MR", ' ');
        break;
    case 3: /* IMAGE query keys. */
        ADD_TXT(0x0008,0x0052,"CS","IMAGE",' ');
        ADD_TXT(0x0008,0x0018,"UI", rndn(2) ? "" : "1.2.826.0.1.3680043.2.1125.3", 0);
        ADD_TXT(0x0020,0x000D,"UI","1.2.826.0.1.3680043.2.1125.1",0);
        ADD_TXT(0x0020,0x000E,"UI","1.2.826.0.1.3680043.2.1125.2",0);
        break;
    default: /* Minimal C-STORE-style dataset metadata without pixel data. */
        ADD_TXT(0x0008,0x0016,"UI", rndn(2) ? "1.2.840.10008.5.1.4.1.1.2" : "1.2.840.10008.5.1.4.1.1.4", 0);
        ADD_TXT(0x0008,0x0018,"UI", "1.2.826.0.1.3680043.2.1125.100", 0);
        ADD_TXT(0x0008,0x0060,"CS", rndn(2) ? "CT" : "MR", ' ');
        ADD_TXT(0x0010,0x0010,"PN", rndn(2) ? "LEMUR^PATIENT" : "DOE^JOHN", ' ');
        ADD_TXT(0x0010,0x0020,"LO", rndn(2) ? "LEMURID" : "12345", ' ');
        ADD_TXT(0x0020,0x000D,"UI", "1.2.826.0.1.3680043.2.1125.101", 0);
        ADD_TXT(0x0020,0x000E,"UI", "1.2.826.0.1.3680043.2.1125.102", 0);
        ADD_TXT(0x0020,0x0010,"SH", "1", ' ');
        ADD_TXT(0x0020,0x0011,"IS", "1", ' ');
        ADD_TXT(0x0020,0x0013,"IS", "1", ' ');
        break;
    }
done:
#undef ADD_TXT
    if (pos < 16) return 0;
    *out_len = pos;
    return 1;
}

static int mutate_dicom_dataset_with_curated_template(uint8_t *data, uint32_t *lenp)
{
    if (!data || !lenp || *lenp < 8) return 0;
    uint32_t out = 0;
    if (!dicom_write_curated_dataset(data, DICOM_MAX_PDV_DATA_LEN, &out)) return 0;
    if (out > DICOM_MAX_PDV_DATA_LEN) return 0;
    *lenp = out;
    return 1;
}

static int dicom_append_curated_dataset_elem(uint8_t *data, uint32_t *lenp)
{
    if (!data || !lenp || *lenp >= DICOM_MAX_PDV_DATA_LEN - 32) return 0;
    struct elem_template { uint16_t group, elem; char vr[2]; const char *value; char pad; };
    static const struct elem_template elems[] = {
        {0x0008,0x0052,{'C','S'},"PATIENT",' '}, {0x0008,0x0052,{'C','S'},"STUDY",' '},
        {0x0008,0x0052,{'C','S'},"SERIES",' '}, {0x0008,0x0052,{'C','S'},"IMAGE",' '},
        {0x0008,0x0020,{'D','A'},"20200101",' '}, {0x0008,0x0030,{'T','M'},"120000",' '},
        {0x0008,0x0060,{'C','S'},"CT",' '}, {0x0008,0x0060,{'C','S'},"MR",' '},
        {0x0008,0x1030,{'L','O'},"LEMUR STUDY",' '}, {0x0010,0x0010,{'P','N'},"DOE^JOHN",' '},
        {0x0010,0x0020,{'L','O'},"PATIENTID",' '}, {0x0010,0x0030,{'D','A'},"19700101",' '},
        {0x0010,0x0040,{'C','S'},"M",' '}, {0x0020,0x000d,{'U','I'},"1.2.826.0.1.3680043.2.1125.101",0},
        {0x0020,0x000e,{'U','I'},"1.2.826.0.1.3680043.2.1125.102",0}, {0x0020,0x0010,{'S','H'},"1",' '},
        {0x0020,0x0011,{'I','S'},"1",' '}, {0x0020,0x0013,{'I','S'},"1",' '}
    };
    const struct elem_template *e = &elems[rndn((int)(sizeof(elems)/sizeof(elems[0])) )];
    uint32_t wrote = dicom_write_explicit_text_elem(data + *lenp, DICOM_MAX_PDV_DATA_LEN - *lenp,
                                                    e->group, e->elem, e->vr, e->value, e->pad);
    if (!wrote) return 0;
    *lenp += wrote;
    return 1;
}

static int mutate_explicit_le_dataset_once(uint8_t *data, uint32_t len)
{
    uint32_t off = 0;
    while (off + 8 <= len) {
        uint16_t group = rd16le(data + off), elem = rd16le(data + off + 2);
        uint8_t *vr = data + off + 4;
        if (!((vr[0] >= 'A' && vr[0] <= 'Z') && (vr[1] >= 'A' && vr[1] <= 'Z'))) return 0;
        uint32_t hdr = 8, vlen;
        if (dicom_dataset_is_long_vr(vr)) { if (off + 12 > len) return 0; vlen = rd32le(data + off + 8); hdr = 12; }
        else vlen = rd16le(data + off + 6);
        if (vlen == 0xffffffffU || off + hdr + vlen > len) return 0;
        if (vlen && (rndn(3) == 0 || group == 0x0008 || group == 0x0010 || group == 0x0020)) { dicom_dataset_mutate_value(group, elem, data + off + hdr, vlen); return 1; }
        off += hdr + vlen + (vlen & 1U);
    }
    return 0;
}

static int mutate_implicit_le_dataset_once(uint8_t *data, uint32_t len)
{
    uint32_t off = 0;
    while (off + 8 <= len) {
        uint16_t group = rd16le(data + off), elem = rd16le(data + off + 2);
        uint32_t vlen = rd32le(data + off + 4);
        if (vlen == 0xffffffffU || vlen > DICOM_MAX_PDV_DATA_LEN || off + 8 + vlen > len) return 0;
        if (vlen && (rndn(3) == 0 || group == 0x0008 || group == 0x0010 || group == 0x0020)) { dicom_dataset_mutate_value(group, elem, data + off + 8, vlen); return 1; }
        off += 8 + vlen + (vlen & 1U);
    }
    return 0;
}

static void mutate_dicom_dataset_fields(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_P_DATA_TF) {
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            if ((pdv->control_header & DICOM_PDV_FLAG_COMMAND) || pdv->has_dimse_command || pdv->data_length < 8) continue;
            int ok = 0;
            if (rndn(4) == 0) ok = dicom_append_curated_dataset_elem(pdv->data, &pdv->data_length);
            if (!ok && (pdv->data_length < 64 || rndn(12) == 0)) ok = mutate_dicom_dataset_with_curated_template(pdv->data, &pdv->data_length);
            if (!ok) ok = mutate_explicit_le_dataset_once(pdv->data, pdv->data_length);
            if (!ok) ok = mutate_implicit_le_dataset_once(pdv->data, pdv->data_length);
            if (!ok && rndn(2) == 0) ok = dicom_append_curated_dataset_elem(pdv->data, &pdv->data_length);
            if (!ok) mutate_pdv_data_bytes(pkts + i, 1);
            pdv->pdv_length = pdv->data_length + 2;
            return;
        }
    }
}

static void mutate_data(dicom_packet_t *pkts, size_t n)
{
    if (rndn(4) != 0) mutate_dicom_dataset_fields(pkts, n);
    else mutate_pdv_data_bytes(pkts, n);
}


static int dicom_pdv_is_dataset(const dicom_pdv_item_t *pdv)
{
    return pdv && !(pdv->control_header & DICOM_PDV_FLAG_COMMAND) &&
           !pdv->has_dimse_command && pdv->data_length >= 8;
}

static int dicom_packet_has_dataset_pdv(const dicom_packet_t *pkt)
{
    if (!pkt || pkt->type != DICOM_PKT_P_DATA_TF) return 0;
    uint16_t count = pkt->u.p_data_tf.pdv_count;
    if (count > DICOM_MAX_PDV_ITEMS) count = DICOM_MAX_PDV_ITEMS;
    for (uint16_t j = 0; j < count; ++j)
        if (dicom_pdv_is_dataset(&pkt->u.p_data_tf.pdvs[j])) return 1;
    return 0;
}

static int dicom_packet_has_dimse_pdv(const dicom_packet_t *pkt)
{
    if (!pkt || pkt->type != DICOM_PKT_P_DATA_TF) return 0;
    uint16_t count = pkt->u.p_data_tf.pdv_count;
    if (count > DICOM_MAX_PDV_ITEMS) count = DICOM_MAX_PDV_ITEMS;
    for (uint16_t j = 0; j < count; ++j)
        if (pdv_has_dimse((dicom_pdv_item_t *)&pkt->u.p_data_tf.pdvs[j])) return 1;
    return 0;
}

static dicom_packet_t *select_dataset_pdata_packet(dicom_packet_t *pkts, int n)
{
    if (!pkts || n <= 0) return NULL;
    int matches = 0;
    for (int i = 0; i < n; ++i)
        if (dicom_packet_has_dataset_pdv(&pkts[i])) matches++;
    if (!matches) return NULL;
    int pick = rndn(matches);
    for (int i = 0; i < n; ++i) {
        if (!dicom_packet_has_dataset_pdv(&pkts[i])) continue;
        if (pick-- == 0) return &pkts[i];
    }
    return NULL;
}

static dicom_packet_t *select_dimse_pdata_packet(dicom_packet_t *pkts, int n)
{
    if (!pkts || n <= 0) return NULL;
    int matches = 0;
    for (int i = 0; i < n; ++i)
        if (dicom_packet_has_dimse_pdv(&pkts[i])) matches++;
    if (!matches) return NULL;
    int pick = rndn(matches);
    for (int i = 0; i < n; ++i) {
        if (!dicom_packet_has_dimse_pdv(&pkts[i])) continue;
        if (pick-- == 0) return &pkts[i];
    }
    return NULL;
}

static void mutate_one_dataset_pdv_in_packet(dicom_packet_t *pkt)
{
    if (!pkt || pkt->type != DICOM_PKT_P_DATA_TF) return;
    uint16_t count = pkt->u.p_data_tf.pdv_count;
    if (count > DICOM_MAX_PDV_ITEMS) count = DICOM_MAX_PDV_ITEMS;
    int matches = 0;
    for (uint16_t j = 0; j < count; ++j)
        if (dicom_pdv_is_dataset(&pkt->u.p_data_tf.pdvs[j])) matches++;
    if (!matches) return;
    int pick = rndn(matches);
    for (uint16_t j = 0; j < count; ++j) {
        dicom_pdv_item_t *pdv = &pkt->u.p_data_tf.pdvs[j];
        if (!dicom_pdv_is_dataset(pdv)) continue;
        if (pick-- != 0) continue;
        int ok = 0;
        if (rndn(4) == 0) ok = dicom_append_curated_dataset_elem(pdv->data, &pdv->data_length);
        if (!ok && (pdv->data_length < 64 || rndn(12) == 0)) ok = mutate_dicom_dataset_with_curated_template(pdv->data, &pdv->data_length);
        if (!ok) ok = mutate_explicit_le_dataset_once(pdv->data, pdv->data_length);
        if (!ok) ok = mutate_implicit_le_dataset_once(pdv->data, pdv->data_length);
        if (!ok && rndn(2) == 0) ok = dicom_append_curated_dataset_elem(pdv->data, &pdv->data_length);
        if (!ok) mutate_pdv_data_bytes(pkt, 1);
        pdv->pdv_length = pdv->data_length + 2;
        pkt->raw_length = 0;
        return;
    }
}

static void mutate_dataset_related_to_dimse(dicom_packet_t *pkts, int n, dicom_packet_t *cmd_pkt)
{
    if (!pkts || n <= 0) return;
    if (cmd_pkt) {
        int start = (int)(cmd_pkt - pkts);
        if (start >= 0 && start < n) {
            for (int i = start + 1; i < n; ++i) {
                if (pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
                if (dicom_packet_has_dataset_pdv(&pkts[i])) {
                    mutate_one_dataset_pdv_in_packet(&pkts[i]);
                    return;
                }
                if (dicom_packet_has_dimse_pdv(&pkts[i])) break;
            }
        }
    }
    dicom_packet_t *p = select_dataset_pdata_packet(pkts, n);
    if (p) mutate_one_dataset_pdv_in_packet(p);
}

static void mutate_dimse_status(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    static const uint16_t statuses[] = {0x0000, 0x0001, 0x0105, 0x0110, 0x0122, 0xa700, 0xa900, 0xc000};
    for (size_t i = 0; i < n; i++) {
        if (pkts[i].type != DICOM_PKT_P_DATA_TF) continue;
        uint16_t st = statuses[rndn((int)(sizeof(statuses) / sizeof(statuses[0])) )];
        mutate_dimse_raw_us(&pkts[i], 0x0900, st);
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) if (pdv_has_dimse(&pkts[i].u.p_data_tf.pdvs[j])) pkts[i].u.p_data_tf.pdvs[j].dimse_status = st;
    }
}

static void add_dimse_attribute_identifier_list(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_P_DATA_TF) {
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) if (pdv_has_dimse(&pkts[i].u.p_data_tf.pdvs[j])) {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            uint16_t pairs = (uint16_t)(1 + rndn(6));
            pdv->dimse_attribute_identifier_list_len = (uint16_t)(pairs * 4);
            for (uint16_t k = 0; k < pairs; k++) {
                const struct dicom_tag_pair *tag = dicom_pick_identifier_tag();
                pdv->dimse_attribute_identifier_list[k * 4 + 0] = (uint8_t)tag->group;
                pdv->dimse_attribute_identifier_list[k * 4 + 1] = (uint8_t)(tag->group >> 8);
                pdv->dimse_attribute_identifier_list[k * 4 + 2] = (uint8_t)tag->elem;
                pdv->dimse_attribute_identifier_list[k * 4 + 3] = (uint8_t)(tag->elem >> 8);
            }
        }
    }
}

static void delete_dimse_attribute_identifier_list(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_P_DATA_TF) {
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) pkts[i].u.p_data_tf.pdvs[j].dimse_attribute_identifier_list_len = 0;
    }
}

static void repeat_dimse_attribute_identifier_list(dicom_packet_t *pkts, size_t n)
{
    add_dimse_attribute_identifier_list(pkts, n);
    for (size_t i = 0; pkts && i < n; i++) if (pkts[i].type == DICOM_PKT_P_DATA_TF) {
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            uint16_t old = pdv->dimse_attribute_identifier_list_len;
            if (old && old * 2 <= DICOM_MAX_DIMSE_ATTR_LIST_LEN) {
                memcpy(pdv->dimse_attribute_identifier_list + old, pdv->dimse_attribute_identifier_list, old);
                pdv->dimse_attribute_identifier_list_len = old * 2;
            }
        }
    }
}

static void mutate_dimse_attribute_identifier_list(dicom_packet_t *pkts, size_t n)
{
    if (rndn(3) == 0) add_dimse_attribute_identifier_list(pkts, n);
    for (size_t i = 0; pkts && i < n; i++) if (pkts[i].type == DICOM_PKT_P_DATA_TF) {
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            uint16_t lim = pdv->dimse_attribute_identifier_list_len;
            if (lim >= 4 && rndn(4) != 0) {
                uint16_t off = (uint16_t)(4 * rndn(lim / 4));
                const struct dicom_tag_pair *tag = dicom_pick_identifier_tag();
                pdv->dimse_attribute_identifier_list[off + 0] = (uint8_t)tag->group;
                pdv->dimse_attribute_identifier_list[off + 1] = (uint8_t)(tag->group >> 8);
                pdv->dimse_attribute_identifier_list[off + 2] = (uint8_t)tag->elem;
                pdv->dimse_attribute_identifier_list[off + 3] = (uint8_t)(tag->elem >> 8);
            } else if (lim) {
                pdv->dimse_attribute_identifier_list[rndn(lim)] ^= 0xff;
            }
        }
    }
}

static void mutate_dimse_attribute_identifier_list_len(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_P_DATA_TF) {
        for (uint16_t j = 0; j < pkts[i].u.p_data_tf.pdv_count && j < DICOM_MAX_PDV_ITEMS; j++) {
            dicom_pdv_item_t *pdv = &pkts[i].u.p_data_tf.pdvs[j];
            pdv->dimse_attribute_identifier_list_len = (uint16_t)(2 * rndn(DICOM_MAX_DIMSE_ATTR_LIST_LEN / 2));
        }
    }
}

static void add_raw_items(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_AC) {
        dicom_a_associate_ac_pdu_t *ac = &pkts[i].u.a_associate_ac;
        if (ac->raw_items_length + 4 <= DICOM_MAX_UNKNOWN_PDU_LEN) {
            ac->raw_items[ac->raw_items_length++] = 0x21;
            ac->raw_items[ac->raw_items_length++] = 0;
            ac->raw_items[ac->raw_items_length++] = 0;
            ac->raw_items[ac->raw_items_length++] = 0;
        }
    }
}

static void delete_raw_items(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_AC) pkts[i].u.a_associate_ac.raw_items_length = 0;
}

static void repeat_raw_items(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_AC) {
        dicom_a_associate_ac_pdu_t *ac = &pkts[i].u.a_associate_ac;
        uint32_t old = ac->raw_items_length;
        if (old && old * 2 <= DICOM_MAX_UNKNOWN_PDU_LEN) {
            memcpy(ac->raw_items + old, ac->raw_items, old);
            ac->raw_items_length = old * 2;
        }
    }
}

static void mutate_raw_items(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_AC) {
        dicom_a_associate_ac_pdu_t *ac = &pkts[i].u.a_associate_ac;
        if (!ac->raw_items_length) add_raw_items(pkts + i, 1);
        uint32_t lim = ac->raw_items_length;
        if (lim) ac->raw_items[rndn((int)lim)] ^= rnd8();
    }
}

static void mutate_raw_items_length(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_A_ASSOCIATE_AC) {
        dicom_a_associate_ac_pdu_t *ac = &pkts[i].u.a_associate_ac;
        ac->raw_items_length = (uint32_t)rndn(512);
        if (ac->raw_items_length > DICOM_MAX_UNKNOWN_PDU_LEN) ac->raw_items_length = DICOM_MAX_UNKNOWN_PDU_LEN;
    }
}

static void mutate_unknown_pdu_type(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_UNKNOWN) {
        pkts[i].u.unknown.pdu_type = (uint8_t)(0x80 + rndn(0x7f));
        if (pkts[i].raw_length >= 1) pkts[i].raw_data[0] = pkts[i].u.unknown.pdu_type;
    }
}

static void mutate_unknown_data_length(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_UNKNOWN) {
        pkts[i].u.unknown.data_length = (uint32_t)rndn(512);
        pkts[i].u.unknown.pdu_length = pkts[i].u.unknown.data_length;
        if (pkts[i].u.unknown.data_length + 6 <= DICOM_MAX_UNKNOWN_PDU_LEN) pkts[i].raw_length = pkts[i].u.unknown.data_length + 6;
    }
}

static void mutate_unknown_data(dicom_packet_t *pkts, size_t n)
{
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DICOM_PKT_UNKNOWN) {
        uint32_t len = pkts[i].u.unknown.data_length;
        if (len == 0) { len = 4; pkts[i].u.unknown.data_length = len; }
        if (len > DICOM_MAX_UNKNOWN_PDU_LEN) len = DICOM_MAX_UNKNOWN_PDU_LEN;
        for (uint32_t k = 0; k < len && k < 64; k++) if (rndn(3) == 0) pkts[i].u.unknown.data[k] = rnd8();
    }
}

static dicom_pdv_item_t *select_dimse_pdv_for_dispatch(dicom_packet_t *p)
{
    if (!p || p->type != DICOM_PKT_P_DATA_TF) return NULL;
    dicom_p_data_tf_pdu_t *pd = &p->u.p_data_tf;
    uint16_t count = pd->pdv_count;
    if (count > DICOM_MAX_PDV_ITEMS) count = DICOM_MAX_PDV_ITEMS;
    uint16_t start = count ? (uint16_t)rndn(count) : 0;
    for (uint16_t k = 0; k < count; ++k) {
        uint16_t idx = (uint16_t)((start + k) % count);
        dicom_pdv_item_t *pdv = &pd->pdvs[idx];
        if (pdv_has_dimse(pdv)) return pdv;
    }
    return NULL;
}

static int dimse_cmd_no_dataset(uint16_t cmd)
{
    switch (cmd) {
    case DICOM_DIMSE_C_ECHO_RQ:
    case DICOM_DIMSE_C_CANCEL_RQ:
    case DICOM_DIMSE_N_GET_RQ:
    case DICOM_DIMSE_N_DELETE_RQ:
        return 1;
    default:
        return 0;
    }
}

static void pdv_set_text_field(char *dst, uint16_t *lenp, size_t cap, const char *value, int pad_spaces)
{
    if (!dst || !lenp || cap == 0 || !value) return;
    size_t n = strlen(value);
    if (n > cap) n = cap;
    memset(dst, pad_spaces ? ' ' : 0, cap);
    memcpy(dst, value, n);
    *lenp = (uint16_t)n;
}

static void mutate_pdv_dimse_message_id(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    pdv->dimse_message_id = (uint16_t)(1 + rndn(0xfffe));
}

static void mutate_pdv_dimse_message_id_responded_to(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    pdv->dimse_message_id_responded_to = (uint16_t)(1 + rndn(0xfffe));
}

static void mutate_pdv_dimse_priority(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    static const uint16_t priorities[] = {0x0000, 0x0001, 0x0002};
    pdv->dimse_priority = priorities[rndn((int)(sizeof(priorities) / sizeof(priorities[0])) )];
}

static void mutate_pdv_dimse_dataset_type(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    static const uint16_t with_dataset[] = {0x0000, 0x0001, 0x0101, 0x0102};
    pdv->dimse_command_data_set_type = dimse_cmd_no_dataset(pdv->dimse_command_field)
        ? 0x0101
        : with_dataset[rndn((int)(sizeof(with_dataset) / sizeof(with_dataset[0])) )];
}

static void mutate_pdv_dimse_affected_sop_class_uid(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    static const char *uids[] = {
        "1.2.840.10008.1.1",
        "1.2.840.10008.5.1.4.1.1.2",
        "1.2.840.10008.5.1.4.1.1.4",
        "1.2.840.10008.5.1.4.1.1.7",
        "1.2.840.10008.5.1.4.1.2.1.1",
        "1.2.840.10008.5.1.4.1.2.1.2",
        "1.2.840.10008.5.1.4.1.2.1.3",
        "1.2.840.10008.5.1.4.1.2.2.1",
        "1.2.840.10008.5.1.4.1.2.2.2",
        "1.2.840.10008.5.1.4.1.2.2.3",
        "1.2.840.10008.5.1.4.31"
    };
    pdv_set_text_field(pdv->dimse_affected_sop_class_uid,
                       &pdv->dimse_affected_sop_class_uid_len,
                       DICOM_MAX_DIMSE_UID_LEN,
                       uids[rndn((int)(sizeof(uids) / sizeof(uids[0])) )], 0);
}

static void mutate_pdv_dimse_affected_sop_instance_uid(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    static const char *uids[] = {
        "1.2.840.113654.2.55.1",
        "1.2.840.113654.2.55.2",
        "1.2.826.0.1.3680043.2.1125.1",
        "1.2.840.10008.5.1.4.1.1.2.1"
    };
    pdv_set_text_field(pdv->dimse_affected_sop_instance_uid,
                       &pdv->dimse_affected_sop_instance_uid_len,
                       DICOM_MAX_DIMSE_UID_LEN,
                       uids[rndn((int)(sizeof(uids) / sizeof(uids[0])) )], 0);
}

static void mutate_pdv_dimse_requested_sop_class_uid(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    static const char *uids[] = {
        "1.2.840.10008.1.1",
        "1.2.840.10008.5.1.4.1.1.2",
        "1.2.840.10008.5.1.4.1.1.4",
        "1.2.840.10008.5.1.4.1.2.1.1"
    };
    pdv_set_text_field(pdv->dimse_requested_sop_class_uid,
                       &pdv->dimse_requested_sop_class_uid_len,
                       DICOM_MAX_DIMSE_UID_LEN,
                       uids[rndn((int)(sizeof(uids) / sizeof(uids[0])) )], 0);
}

static void mutate_pdv_dimse_requested_sop_instance_uid(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    static const char *uids[] = {
        "1.2.840.113654.2.55.11",
        "1.2.840.113654.2.55.12",
        "1.2.826.0.1.3680043.2.1125.9"
    };
    pdv_set_text_field(pdv->dimse_requested_sop_instance_uid,
                       &pdv->dimse_requested_sop_instance_uid_len,
                       DICOM_MAX_DIMSE_UID_LEN,
                       uids[rndn((int)(sizeof(uids) / sizeof(uids[0])) )], 0);
}

static void mutate_pdv_dimse_move_destination(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    static const char *aets[] = {"ANY-SCP", "STORESCP", "DCMQRSCP", "LEMURDST", "MOVEDEST", "ORTHANC", "PACS", "DCM4CHEE"};
    pdv_set_text_field(pdv->dimse_move_destination,
                       &pdv->dimse_move_destination_len,
                       DICOM_MAX_DIMSE_AE_LEN,
                       aets[rndn((int)(sizeof(aets) / sizeof(aets[0])) )], 1);
}

static void mutate_pdv_dimse_move_originator(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    static const char *aets[] = {"MOVESCU", "ORIGIN", "LEMURAE", "FINDSCU", "STORESCU", "ECHOSCU", "GETSCU"};
    pdv_set_text_field(pdv->dimse_move_originator_ae_title,
                       &pdv->dimse_move_originator_ae_title_len,
                       DICOM_MAX_DIMSE_AE_LEN,
                       aets[rndn((int)(sizeof(aets) / sizeof(aets[0])) )], 1);
    pdv->dimse_move_originator_message_id = (uint16_t)(1 + rndn(0xfffe));
}

static void mutate_pdv_dimse_event_type_id(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    pdv->dimse_event_type_id = (uint16_t)(1 + rndn(16));
}

static void mutate_pdv_dimse_action_type_id(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    pdv->dimse_action_type_id = (uint16_t)(1 + rndn(16));
}

static void mutate_pdv_dimse_status(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    static const uint16_t statuses[] = {0x0000, 0x0001, 0x0105, 0x0110, 0x0117, 0x0122, 0xA700, 0xA900, 0xC000, 0xFE00, 0xFF00, 0xFF01};
    pdv->dimse_status = statuses[rndn((int)(sizeof(statuses) / sizeof(statuses[0])) )];
}

static void add_pdv_dimse_attribute_identifier_list(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    uint16_t pairs = (uint16_t)(1 + rndn(6));
    pdv->dimse_attribute_identifier_list_len = (uint16_t)(pairs * 4);
    for (uint16_t i = 0; i < pairs; i++) {
        const struct dicom_tag_pair *tag = dicom_pick_identifier_tag();
        pdv->dimse_attribute_identifier_list[i*4+0] = (uint8_t)tag->group;
        pdv->dimse_attribute_identifier_list[i*4+1] = (uint8_t)(tag->group >> 8);
        pdv->dimse_attribute_identifier_list[i*4+2] = (uint8_t)tag->elem;
        pdv->dimse_attribute_identifier_list[i*4+3] = (uint8_t)(tag->elem >> 8);
    }
}

static void delete_pdv_dimse_attribute_identifier_list(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    pdv->dimse_attribute_identifier_list_len = 0;
}

static void repeat_pdv_dimse_attribute_identifier_list(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    if (!pdv->dimse_attribute_identifier_list_len) add_pdv_dimse_attribute_identifier_list(pdv);
    uint16_t old = pdv->dimse_attribute_identifier_list_len;
    if (old && old * 2 <= DICOM_MAX_DIMSE_ATTR_LIST_LEN) {
        memcpy(pdv->dimse_attribute_identifier_list + old, pdv->dimse_attribute_identifier_list, old);
        pdv->dimse_attribute_identifier_list_len = (uint16_t)(old * 2);
    }
}

static void mutate_pdv_dimse_attribute_identifier_list(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    if (!pdv->dimse_attribute_identifier_list_len) add_pdv_dimse_attribute_identifier_list(pdv);
    if (pdv->dimse_attribute_identifier_list_len >= 4 && rndn(4) != 0) {
        uint16_t pairs = (uint16_t)(pdv->dimse_attribute_identifier_list_len / 4);
        uint16_t off = (uint16_t)(4 * rndn(pairs));
        const struct dicom_tag_pair *tag = dicom_pick_identifier_tag();
        pdv->dimse_attribute_identifier_list[off + 0] = (uint8_t)tag->group;
        pdv->dimse_attribute_identifier_list[off + 1] = (uint8_t)(tag->group >> 8);
        pdv->dimse_attribute_identifier_list[off + 2] = (uint8_t)tag->elem;
        pdv->dimse_attribute_identifier_list[off + 3] = (uint8_t)(tag->elem >> 8);
    } else if (pdv->dimse_attribute_identifier_list_len) {
        pdv->dimse_attribute_identifier_list[rndn(pdv->dimse_attribute_identifier_list_len)] ^= 0xff;
    }
}

static void mutate_pdv_dimse_attribute_identifier_list_len(dicom_pdv_item_t *pdv)
{
    if (!pdv) return;
    pdv->dimse_attribute_identifier_list_len = (uint16_t)(2 * rndn(DICOM_MAX_DIMSE_ATTR_LIST_LEN / 2));
}

static void dispatch_dicom_pdata_structure_mutation(dicom_packet_t *p)
{
    if (!p || p->type != DICOM_PKT_P_DATA_TF) return;
    /* Dataset bytes are the most fragile part of a DIMSE request.  Mutating
     * them on three quarters of structural dispatches used to turn otherwise
     * valid GET/STORE/FIND requests into malformed datasets.  That produced
     * many shallow queue entries and made final replay coverage depend heavily
     * on the random seed (the two low 1-hour runs were an example).  Keep raw
     * dataset mutation as an occasional exploration path; the normal path
     * below preserves the command/data relationship and exercises a valid
     * command field instead. */
    if (dicom_packet_has_dataset_pdv(p) && rndn(8) == 0) {
        mutate_one_dataset_pdv_in_packet(p);
        return;
    }
    switch (rndn(12)) {
    case 0:
    case 1:
    case 2: {
        dicom_pdv_item_t *pdv = select_dimse_pdv_for_dispatch(p);
        if (pdv) dicom_apply_dimse_profile_to_pdv(pdv, pdv->presentation_context_id ? pdv->presentation_context_id : 1, dicom_pick_service_dimse());
        else add_pdvs(p, 1);
        break;
    }
    case 3: mutate_presentation_context_id(p, 1); break;
    case 4: mutate_pdv_control_header(p, 1); break;
    case 5: add_pdvs(p, 1); break;
    case 6: mutate_pdvs(p, 1); break;
    case 7: mutate_pdv_count(p, 1); break;
    case 8: mutate_pdv_length(p, 1); break;
    case 9: mutate_data_length(p, 1); break;
    case 10: mutate_data(p, 1); break;
    default: mutate_pdu_length(p, 1); break;
    }
}

static void dispatch_dicom_dimse_mutation(dicom_packet_t *pkts, int num_packets, dicom_packet_t *p)
{
    dicom_pdv_item_t *pdv = select_dimse_pdv_for_dispatch(p);
    if (!pdv) {
        switch (rndn(8)) {
        case 0: mutate_data_length(p, 1); break;
        case 1: add_data(p, 1); break;
        case 2: repeat_data(p, 1); break;
        default: mutate_dataset_related_to_dimse(pkts, num_packets, p); break;
        }
        return;
    }

    if (rndn(32) == 0) {
        dispatch_dicom_pdata_structure_mutation(p);
        return;
    }

    switch (pdv->dimse_command_field) {
    case DICOM_DIMSE_C_STORE_RQ:
        switch (rndn(12)) {
        case 0: mutate_pdv_dimse_message_id(pdv); break;
        case 1: mutate_pdv_dimse_priority(pdv); break;
        case 2: mutate_pdv_dimse_dataset_type(pdv); break;
        case 3: mutate_pdv_dimse_affected_sop_class_uid(pdv); break;
        case 4: mutate_pdv_dimse_affected_sop_instance_uid(pdv); break;
        case 5: mutate_pdv_dimse_move_originator(pdv); break;
        case 6: mutate_dataset_related_to_dimse(pkts, num_packets, p); break;
        case 7: mutate_pdv_dimse_dataset_type(pdv); break;
        default: mutate_pdv_dimse_message_id(pdv); break;
        }
        break;
    case DICOM_DIMSE_C_FIND_RQ:
    case DICOM_DIMSE_C_GET_RQ:
        switch (rndn(12)) {
        case 0: mutate_pdv_dimse_message_id(pdv); break;
        case 1: mutate_pdv_dimse_priority(pdv); break;
        case 2: mutate_pdv_dimse_dataset_type(pdv); break;
        case 3: mutate_pdv_dimse_affected_sop_class_uid(pdv); break;
        case 4: add_pdv_dimse_attribute_identifier_list(pdv); break;
        case 5: mutate_pdv_dimse_attribute_identifier_list(pdv); break;
        case 6: mutate_dataset_related_to_dimse(pkts, num_packets, p); break;
        case 7: mutate_pdv_dimse_dataset_type(pdv); break;
        default: mutate_pdv_dimse_message_id(pdv); break;
        }
        break;
    case DICOM_DIMSE_C_MOVE_RQ:
        switch (rndn(10)) {
        case 0: mutate_pdv_dimse_message_id(pdv); break;
        case 1: mutate_pdv_dimse_priority(pdv); break;
        case 2: mutate_pdv_dimse_dataset_type(pdv); break;
        case 3: mutate_pdv_dimse_affected_sop_class_uid(pdv); break;
        case 4: mutate_pdv_dimse_move_destination(pdv); break;
        case 5: add_pdv_dimse_attribute_identifier_list(pdv); break;
        case 6: mutate_pdv_dimse_attribute_identifier_list(pdv); break;
        case 7: mutate_dataset_related_to_dimse(pkts, num_packets, p); break;
        default: mutate_pdv_dimse_message_id(pdv); break;
        }
        break;
    case DICOM_DIMSE_C_ECHO_RQ:
        switch (rndn(5)) {
        case 0: mutate_pdv_dimse_message_id(pdv); break;
        case 1: mutate_pdv_dimse_dataset_type(pdv); break;
        case 2: mutate_pdv_dimse_affected_sop_class_uid(pdv); break;
        default: mutate_pdv_dimse_message_id(pdv); break;
        }
        break;
    case DICOM_DIMSE_C_CANCEL_RQ:
        if (rndn(2)) mutate_pdv_dimse_message_id_responded_to(pdv);
        else dispatch_dicom_pdata_structure_mutation(p);
        break;
    case DICOM_DIMSE_N_EVENT_REPORT_RQ:
        switch (rndn(8)) {
        case 0: mutate_pdv_dimse_message_id(pdv); break;
        case 1: mutate_pdv_dimse_dataset_type(pdv); break;
        case 2: mutate_pdv_dimse_affected_sop_class_uid(pdv); break;
        case 3: mutate_pdv_dimse_affected_sop_instance_uid(pdv); break;
        case 4: mutate_pdv_dimse_event_type_id(pdv); break;
        case 5: mutate_pdv_dimse_status(pdv); break;
        default: mutate_pdv_dimse_message_id(pdv); break;
        }
        break;
    case DICOM_DIMSE_N_GET_RQ:
        switch (rndn(10)) {
        case 0: mutate_pdv_dimse_message_id(pdv); break;
        case 1: mutate_pdv_dimse_dataset_type(pdv); break;
        case 2: mutate_pdv_dimse_requested_sop_class_uid(pdv); break;
        case 3: mutate_pdv_dimse_requested_sop_instance_uid(pdv); break;
        case 4: add_pdv_dimse_attribute_identifier_list(pdv); break;
        case 5: delete_pdv_dimse_attribute_identifier_list(pdv); break;
        case 6: repeat_pdv_dimse_attribute_identifier_list(pdv); break;
        case 7: mutate_pdv_dimse_attribute_identifier_list(pdv); break;
        case 8: mutate_pdv_dimse_attribute_identifier_list_len(pdv); break;
        default: mutate_pdv_dimse_message_id(pdv); break;
        }
        break;
    case DICOM_DIMSE_N_SET_RQ:
        switch (rndn(8)) {
        case 0: mutate_pdv_dimse_message_id(pdv); break;
        case 1: mutate_pdv_dimse_dataset_type(pdv); break;
        case 2: mutate_pdv_dimse_requested_sop_class_uid(pdv); break;
        case 3: mutate_pdv_dimse_requested_sop_instance_uid(pdv); break;
        case 4: mutate_dataset_related_to_dimse(pkts, num_packets, p); break;
        case 5: mutate_pdv_dimse_status(pdv); break;
        default: mutate_pdv_dimse_message_id(pdv); break;
        }
        break;
    case DICOM_DIMSE_N_ACTION_RQ:
        switch (rndn(9)) {
        case 0: mutate_pdv_dimse_message_id(pdv); break;
        case 1: mutate_pdv_dimse_dataset_type(pdv); break;
        case 2: mutate_pdv_dimse_requested_sop_class_uid(pdv); break;
        case 3: mutate_pdv_dimse_requested_sop_instance_uid(pdv); break;
        case 4: mutate_pdv_dimse_action_type_id(pdv); break;
        case 5: mutate_pdv_dimse_status(pdv); break;
        case 6: mutate_dataset_related_to_dimse(pkts, num_packets, p); break;
        default: mutate_pdv_dimse_message_id(pdv); break;
        }
        break;
    case DICOM_DIMSE_N_CREATE_RQ:
        switch (rndn(8)) {
        case 0: mutate_pdv_dimse_message_id(pdv); break;
        case 1: mutate_pdv_dimse_dataset_type(pdv); break;
        case 2: mutate_pdv_dimse_affected_sop_class_uid(pdv); break;
        case 3: mutate_pdv_dimse_affected_sop_instance_uid(pdv); break;
        case 4: mutate_pdv_dimse_status(pdv); break;
        case 5: mutate_dataset_related_to_dimse(pkts, num_packets, p); break;
        default: mutate_pdv_dimse_message_id(pdv); break;
        }
        break;
    case DICOM_DIMSE_N_DELETE_RQ:
        switch (rndn(5)) {
        case 0: mutate_pdv_dimse_message_id(pdv); break;
        case 1: mutate_pdv_dimse_dataset_type(pdv); break;
        case 2: mutate_pdv_dimse_requested_sop_class_uid(pdv); break;
        case 3: mutate_pdv_dimse_requested_sop_instance_uid(pdv); break;
        case 4: mutate_pdv_dimse_status(pdv); break;
        default: mutate_pdv_dimse_message_id(pdv); break;
        }
        break;
    default:
        dispatch_dicom_pdata_structure_mutation(p);
        break;
    }
}

void dispatch_dicom_multiple_mutations(dicom_packet_t *pkts, int num_packets, int rounds)
{
    if (!pkts || num_packets <= 0) return;
    if (rounds <= 0) rounds = 1;
    for (int r = 0; r < rounds; ++r) {
        /* Whole-message service retargeting is useful, but too frequent retargeting
         * erases valid seed datasets. Keep it as a low-rate structural mutation. */
        if (rndn(80) == 0) {
            dicom_apply_coherent_service_template(pkts, num_packets);
            continue;
        }
        if (rndn(512) == 0) {
            dicom_strengthen_association_branch_variants(pkts, (size_t)num_packets);
            continue;
        }
        dicom_packet_t *p = NULL;
        /* DICOM coverage is dominated by valid association + DIMSE/data
         * handling. Preserve the negotiated association most of the time and
         * spend semantic energy on command/data PDVs from the seed trace. */
        switch (rndn(8)) {
        case 0:
        case 1:
        case 2:
        case 3:
            p = select_dataset_pdata_packet(pkts, num_packets);
            break;
        case 4:
        case 5:
        case 6:
            p = select_dimse_pdata_packet(pkts, num_packets);
            break;
        default:
            p = &pkts[rndn(num_packets)];
            break;
        }
        if (!p) p = select_dimse_pdata_packet(pkts, num_packets);
        if (!p) p = select_dataset_pdata_packet(pkts, num_packets);
        if (!p) p = &pkts[rndn(num_packets)];
        p->raw_length = 0;

        switch (p->type) {
        case DICOM_PKT_A_ASSOCIATE_RQ:
            switch (rndn(52)) {
            case 0: mutate_called_ae_title(p, 1); break;
            case 1: mutate_calling_ae_title(p, 1); break;
            case 2: mutate_application_context_name(p, 1); break;
            case 3:
            case 4:
            case 5: mutate_presentation_contexts(p, 1); break;
            case 6:
            case 7: mutate_abstract_syntax_name(p, 1); break;
            case 8: add_presentation_contexts(p, 1); break;
            case 9: add_transfer_syntaxes(p, 1); break;
            case 10:
            case 11:
            case 12: mutate_transfer_syntaxes(p, 1); break;
            case 13: add_user_info(p, 1); break;
            case 14:
            case 15: add_user_maximum_length(p, 1); break;
            case 16:
            case 17: mutate_user_maximum_length(p, 1); break;
            case 18: add_implementation_class_uid(p, 1); break;
            case 19: mutate_implementation_class_uid(p, 1); break;
            case 20: add_implementation_version_name(p, 1); break;
            case 21: mutate_implementation_version_name(p, 1); break;
            case 22: add_role_selections(p, 1); break;
            case 23: mutate_role_selections(p, 1); break;
            case 24: add_async_ops_window(p, 1); break;
            case 25: mutate_async_ops_window(p, 1); break;
            case 26: add_sop_class_extended_negotiation(p, 1); break;
            case 27: mutate_sop_class_extended_negotiation(p, 1); break;
            case 28: add_sop_class_common_extended_negotiation(p, 1); break;
            case 29: mutate_sop_class_common_extended_negotiation(p, 1); break;
            case 30: add_user_identity_negotiation(p, 1); break;
            case 31: mutate_user_identity_negotiation(p, 1); break;
            case 32: add_user_data(p, 1); break;
            case 33: mutate_user_data(p, 1); break;
            case 34: mutate_user_data_length(p, 1); break;
            case 35: add_user_info(p, 1); break;
            default: add_user_info(p, 1); break;
            }
            break;
        case DICOM_PKT_A_ASSOCIATE_AC:
            switch (rndn(8)) {
            case 0: mutate_called_ae_title(p, 1); break;
            case 1: mutate_calling_ae_title(p, 1); break;
            case 2: mutate_protocol_version(p, 1); break;
            case 3: add_raw_items(p, 1); break;
            case 4: delete_raw_items(p, 1); break;
            case 5: repeat_raw_items(p, 1); break;
            case 6: mutate_raw_items(p, 1); break;
            default: mutate_raw_items_length(p, 1); break;
            }
            break;
        case DICOM_PKT_A_ASSOCIATE_RJ:
            mutate_associate_rj_result_source_reason(p, 1);
            break;
        case DICOM_PKT_P_DATA_TF:
            dispatch_dicom_dimse_mutation(pkts, num_packets, p);
            break;
        case DICOM_PKT_A_RELEASE_RQ:
        case DICOM_PKT_A_RELEASE_RP:
            if (rndn(4)) mutate_release_reserved(p, 1);
            else mutate_pdu_length(p, 1);
            break;
        case DICOM_PKT_A_ABORT:
            if (rndn(4)) mutate_abort_source_reason(p, 1);
            else mutate_pdu_length(p, 1);
            break;
        case DICOM_PKT_UNKNOWN:
            switch (rndn(3)) {
            case 0: mutate_unknown_pdu_type(p, 1); break;
            case 1: mutate_unknown_data_length(p, 1); break;
            default: mutate_unknown_data(p, 1); break;
            }
            break;
        default:
            break;
        }
    }
}
