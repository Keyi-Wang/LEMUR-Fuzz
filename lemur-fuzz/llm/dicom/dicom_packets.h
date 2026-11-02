// ./llm/dicom/dicom_packets.h
#ifndef DICOM_PACKETS_H
#define DICOM_PACKETS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Constants and limits
#define DICOM_MAX_PRESENTATION_CONTEXTS   128 /* all odd PCIDs 1..255, PS3.8 §9.3.2.2 */
#define DICOM_MAX_TRANSFER_SYNTAXES       16
#define DICOM_MAX_UID_LEN                 128
#define DICOM_MAX_USER_INFO_BYTES         8192
#define DICOM_MAX_PDV_ITEMS               64
#define DICOM_MAX_PDV_DATA_LEN            32768
#define DICOM_MAX_UNKNOWN_PDU_LEN         65536
#define DICOM_MAX_DIMSE_UID_LEN           128
#define DICOM_MAX_DIMSE_AE_LEN            16
#define DICOM_MAX_DIMSE_ATTR_LIST_LEN     256
#define DICOM_MAX_ROLE_SELECTIONS          128
#define DICOM_MAX_RELATED_SOP_CLASSES     8

// PDU Type constants (Fixed values per PS 3.8)
#define DICOM_PDU_A_ASSOCIATE_RQ  0x01
#define DICOM_PDU_A_ASSOCIATE_AC  0x02
#define DICOM_PDU_A_ASSOCIATE_RJ  0x03
#define DICOM_PDU_P_DATA_TF       0x04
#define DICOM_PDU_A_RELEASE_RQ    0x05
#define DICOM_PDU_A_RELEASE_RP    0x06
#define DICOM_PDU_A_ABORT         0x07

// PDV Control Header flags
#define DICOM_PDV_FLAG_LAST_FRAGMENT 0x02 // bit 1
#define DICOM_PDV_FLAG_COMMAND       0x01 // bit 0: 1=command, 0=data

// DIMSE command field values for request messages (PS 3.7 command set).
#define DICOM_DIMSE_C_STORE_RQ        0x0001
#define DICOM_DIMSE_C_GET_RQ          0x0010
#define DICOM_DIMSE_C_FIND_RQ         0x0020
#define DICOM_DIMSE_C_MOVE_RQ         0x0021
#define DICOM_DIMSE_C_ECHO_RQ         0x0030
#define DICOM_DIMSE_N_EVENT_REPORT_RQ 0x0100
#define DICOM_DIMSE_N_GET_RQ          0x0110
#define DICOM_DIMSE_N_SET_RQ          0x0120
#define DICOM_DIMSE_N_ACTION_RQ       0x0130
#define DICOM_DIMSE_N_CREATE_RQ       0x0140
#define DICOM_DIMSE_N_DELETE_RQ       0x0150
#define DICOM_DIMSE_C_CANCEL_RQ       0x0FFF

/* Presence is independent of numeric value: zero is a valid Message ID.
 * PS3.7 §§9.3/10.3 command fields, in ascending tag order. */
#define DICOM_DIMSE_PRESENT_GROUP_LENGTH (1u << 0)
#define DICOM_DIMSE_PRESENT_COMMAND (1u << 3)
#define DICOM_DIMSE_PRESENT_MESSAGE_ID (1u << 4)
#define DICOM_DIMSE_PRESENT_RESPONDED_TO (1u << 5)
#define DICOM_DIMSE_PRESENT_PRIORITY (1u << 7)
#define DICOM_DIMSE_PRESENT_DATASET_TYPE (1u << 8)
#define DICOM_DIMSE_PRESENT_STATUS (1u << 9)
#define DICOM_DIMSE_PRESENT_EVENT_TYPE (1u << 12)
#define DICOM_DIMSE_PRESENT_ACTION_TYPE (1u << 14)
#define DICOM_DIMSE_PRESENT_ORIGINATOR_ID (1u << 16)

// Packet type enumeration
typedef enum {
    DICOM_PKT_A_ASSOCIATE_RQ,
    DICOM_PKT_A_ASSOCIATE_AC,
    DICOM_PKT_A_ASSOCIATE_RJ,
    DICOM_PKT_P_DATA_TF,
    DICOM_PKT_A_RELEASE_RQ,
    DICOM_PKT_A_RELEASE_RP,
    DICOM_PKT_A_ABORT,
    DICOM_PKT_UNKNOWN
} dicom_packet_type_t;

// Common helper: string buffer for UIDs and names
typedef struct {
    uint16_t length;
    char     value[DICOM_MAX_UID_LEN];
} dicom_str_t;

// 9.3.2 A-ASSOCIATE-RQ PDU Structure
// Application Context Item (Table 9-12)
typedef struct {
    uint8_t  item_type;                 /* Fixed */ // 0x10
    uint8_t  reserved1;                 /* Fixed */
    uint16_t item_length;
    dicom_str_t application_context_name; // e.g., 1.2.840.10008.3.1.1.1
} dicom_app_context_item_t;

// Abstract Syntax Sub-Item (Table 9-14)
typedef struct {
    uint8_t  item_type;                 /* Fixed */ // 0x30
    uint8_t  reserved1;                 /* Fixed */
    uint16_t item_length;
    dicom_str_t abstract_syntax_name;   // UID of SOP Class or Meta SOP class
} dicom_abstract_syntax_item_t;

// Transfer Syntax Sub-Item (Table 9-15)
typedef struct {
    uint8_t  item_type;                 /* Fixed */ // 0x40
    uint8_t  reserved1;                 /* Fixed */
    uint16_t item_length;
    dicom_str_t transfer_syntax_name;   // UID of transfer syntax
} dicom_transfer_syntax_item_t;

// Presentation Context Item (RQ) (Table 9-13)
typedef struct {
    uint8_t  item_type;                 /* Fixed */ // 0x20
    uint8_t  reserved1;                 /* Fixed */
    uint16_t item_length;
    uint8_t  presentation_context_id;
    uint8_t  reserved2[3];              /* Fixed */

    dicom_abstract_syntax_item_t abstract_syntax; // one per PC

    dicom_transfer_syntax_item_t transfer_syntaxes[DICOM_MAX_TRANSFER_SYNTAXES]; /* Repeatable */
    uint8_t  transfer_syntax_count;
} dicom_presentation_context_item_t;

// User Information Item (PS3.8 Table 9-21/9-22). Known sub-items are modeled
// explicitly; unknown/private sub-items can still be preserved in user_data.
typedef struct {
    uint8_t  item_type;                 /* Fixed */ // 0x50
    uint8_t  reserved1;                 /* Fixed */
    uint16_t item_length;

    uint8_t  has_maximum_length;        /* Optional */
    uint32_t maximum_length_received;   // Maximum Length sub-item 0x51

    uint8_t  has_implementation_class_uid; /* Optional */
    dicom_str_t implementation_class_uid;  // Implementation Class UID sub-item 0x52

    uint8_t  has_async_ops_window;      /* Optional */
    uint16_t max_ops_invoked;           // Asynchronous Operations Window 0x53
    uint16_t max_ops_performed;

    struct {
        dicom_str_t sop_class_uid;
        uint8_t scu_role;
        uint8_t scp_role;
    } role_selections[DICOM_MAX_ROLE_SELECTIONS]; /* Optional, Repeatable */
    uint8_t role_selection_count;

    uint8_t  has_implementation_version_name; /* Optional */
    dicom_str_t implementation_version_name;  // Implementation Version Name 0x55

    uint8_t has_sop_class_extended_negotiation; /* Optional */
    dicom_str_t sop_class_extended_uid;         // 0x56 SOP Class UID
    uint16_t sop_class_extended_info_len;
    uint8_t sop_class_extended_info[DICOM_MAX_USER_INFO_BYTES];

    uint8_t has_sop_class_common_extended_negotiation; /* Optional */
    dicom_str_t sop_class_common_sop_uid;              // 0x57 SOP Class UID
    dicom_str_t sop_class_common_service_class_uid;
    dicom_str_t related_general_sop_class_uids[DICOM_MAX_RELATED_SOP_CLASSES];
    uint8_t related_general_sop_class_uid_count;

    uint8_t has_user_identity_negotiation; /* Optional */
    uint8_t user_identity_type;
    uint8_t user_identity_positive_response_requested;
    uint16_t user_identity_primary_field_len;
    uint8_t user_identity_primary_field[DICOM_MAX_USER_INFO_BYTES];
    uint16_t user_identity_secondary_field_len;
    uint8_t user_identity_secondary_field[DICOM_MAX_USER_INFO_BYTES];

    // Raw unknown/private sub-item bytes for round-trip generality.
    uint32_t user_data_length;
    uint8_t  user_data[DICOM_MAX_USER_INFO_BYTES]; /* Optional, Repeatable */
    uint8_t  has_user_data;             /* Optional */
} dicom_user_info_item_t;

// Full A-ASSOCIATE-RQ PDU
typedef struct {
    uint8_t  pdu_type;                  /* Fixed */ // 0x01
    uint8_t  reserved1;                 /* Fixed */
    uint32_t pdu_length;

    uint16_t protocol_version;
    uint16_t reserved2;                 /* Fixed */

    char     called_ae_title[16];
    char     calling_ae_title[16];

    uint8_t  reserved3[32];             /* Fixed */

    dicom_app_context_item_t application_context;  // required

    dicom_presentation_context_item_t presentation_contexts[DICOM_MAX_PRESENTATION_CONTEXTS]; /* Repeatable */
    uint8_t  presentation_context_count;

    dicom_user_info_item_t user_info;   // required by PS3.8 A-ASSOCIATE-RQ
    uint8_t  has_user_info;             // kept as a presence flag for mutation/fixing
} dicom_a_associate_rq_pdu_t;

typedef struct {
    uint8_t  item_type;                 /* Fixed */ // 0x21
    uint8_t  reserved1;                 /* Fixed */
    uint16_t item_length;
    uint8_t  presentation_context_id;
    uint8_t  reserved2;
    uint8_t  result_reason;
    uint8_t  reserved3;
    dicom_transfer_syntax_item_t transfer_syntax; // one accepted transfer syntax in AC
    uint8_t has_transfer_syntax;
} dicom_presentation_context_ac_item_t;

// 9.3.3 A-ASSOCIATE-AC PDU. The fixed header mirrors A-ASSOCIATE-RQ; the
// variable item area is preserved in raw_items so unknown/less common AC items
// remain round-trippable.
typedef struct {
    uint8_t  pdu_type;                  /* Fixed */ // 0x02
    uint8_t  reserved1;                 /* Fixed */
    uint32_t pdu_length;

    uint16_t protocol_version;
    uint16_t reserved2;                 /* Fixed */

    char     called_ae_title[16];
    char     calling_ae_title[16];

    uint8_t  reserved3[32];             /* Fixed */

    dicom_app_context_item_t application_context;
    uint8_t has_application_context;
    dicom_presentation_context_ac_item_t presentation_contexts[DICOM_MAX_PRESENTATION_CONTEXTS];
    uint8_t presentation_context_count;
    dicom_user_info_item_t user_info;
    uint8_t has_user_info;

    uint32_t raw_items_length;
    uint8_t  raw_items[DICOM_MAX_UNKNOWN_PDU_LEN];
} dicom_a_associate_ac_pdu_t;

// 9.3.4 A-ASSOCIATE-RJ PDU Structure
// PDU length is fixed at 4: reserved, result, source, reason/diagnostic.
typedef struct {
    uint8_t  pdu_type;                  /* Fixed */ // 0x03
    uint8_t  reserved1;                 /* Fixed */
    uint32_t pdu_length;                /* Fixed */ // 0x00000004
    uint8_t  reserved2;                 /* Fixed */
    uint8_t  result;
    uint8_t  source;
    uint8_t  reason_diag;
} dicom_a_associate_rj_pdu_t;

// 9.3.5 P-DATA-TF PDU Structure (Tables 9-22, 9-23)
typedef struct {
    uint32_t pdv_length; // includes 2 bytes: presentation-context-id and control header
    uint8_t  presentation_context_id;
    uint8_t  control_header; // bit 1: last fragment, bit 0: command/data
    uint32_t data_length;    // derived: pdv_length - 2
    uint8_t  data[DICOM_MAX_PDV_DATA_LEN];
    const uint8_t *data_tail;
    uint32_t data_tail_length;
    uint8_t  has_dimse_command;
    uint8_t  has_dimse_command_fields; /* Parsed even when command bytes arrived across PDV fragments. */
    uint32_t dimse_fields_present; /* Parsed tag presence, not truthiness. */
    uint16_t dimse_command_field;
    uint16_t dimse_message_id;
    uint16_t dimse_message_id_responded_to;
    uint16_t dimse_priority;
    uint16_t dimse_command_data_set_type;
    uint16_t dimse_status;
    uint16_t dimse_event_type_id;
    uint16_t dimse_action_type_id;
    uint16_t dimse_move_originator_message_id;
    char     dimse_affected_sop_class_uid[DICOM_MAX_DIMSE_UID_LEN];
    uint16_t dimse_affected_sop_class_uid_len;
    char     dimse_requested_sop_class_uid[DICOM_MAX_DIMSE_UID_LEN];
    uint16_t dimse_requested_sop_class_uid_len;
    char     dimse_affected_sop_instance_uid[DICOM_MAX_DIMSE_UID_LEN];
    uint16_t dimse_affected_sop_instance_uid_len;
    char     dimse_requested_sop_instance_uid[DICOM_MAX_DIMSE_UID_LEN];
    uint16_t dimse_requested_sop_instance_uid_len;
    char     dimse_move_destination[DICOM_MAX_DIMSE_AE_LEN];
    uint16_t dimse_move_destination_len;
    char     dimse_move_originator_ae_title[DICOM_MAX_DIMSE_AE_LEN];
    uint16_t dimse_move_originator_ae_title_len;
    uint8_t  dimse_attribute_identifier_list[DICOM_MAX_DIMSE_ATTR_LIST_LEN];
    uint16_t dimse_attribute_identifier_list_len;
} dicom_pdv_item_t;

typedef struct {
    uint8_t  pdu_type;                  /* Fixed */ // 0x04
    uint8_t  reserved1;                 /* Fixed */
    uint32_t pdu_length;

    const uint8_t *pdv_tail;
    uint32_t pdv_tail_length;
    dicom_pdv_item_t pdvs[DICOM_MAX_PDV_ITEMS]; /* Repeatable */
    uint16_t pdv_count;
} dicom_p_data_tf_pdu_t;

// 9.3.6 A-RELEASE-RQ PDU Structure (Table 9-24)
typedef struct {
    uint8_t  pdu_type;                  /* Fixed */ // 0x05
    uint8_t  reserved1;                 /* Fixed */
    uint32_t pdu_length;                /* Fixed */ // 0x00000004
    uint16_t reserved2;                 /* Fixed */
    uint16_t reserved3;                 /* Fixed */
} dicom_a_release_rq_pdu_t;

// 9.3.7 A-RELEASE-RP PDU Structure (same 4 reserved bytes as RQ)
typedef struct {
    uint8_t  pdu_type;                  /* Fixed */ // 0x06
    uint8_t  reserved1;                 /* Fixed */
    uint32_t pdu_length;                /* Fixed */ // 0x00000004
    uint16_t reserved2;                 /* Fixed */
    uint16_t reserved3;                 /* Fixed */
} dicom_a_release_rp_pdu_t;

// 9.3.8 A-ABORT PDU Structure (Table 9-26)
typedef struct {
    uint8_t  pdu_type;                  /* Fixed */ // 0x07
    uint8_t  reserved1;                 /* Fixed */
    uint32_t pdu_length;                /* Fixed */ // 0x00000004
    uint8_t  reserved2;                 /* Fixed */
    uint8_t  reserved3;                 /* Fixed */
    uint8_t  source;
    uint8_t  reason_diag;
} dicom_a_abort_pdu_t;

// Unknown PDU passthrough container
typedef struct {
    uint8_t  pdu_type;
    uint8_t  reserved1;
    uint32_t pdu_length;
    uint32_t data_length;
    uint8_t  data[DICOM_MAX_UNKNOWN_PDU_LEN];
} dicom_unknown_pdu_t;

// Union packet container
typedef struct {
    dicom_packet_type_t type;
    uint32_t raw_length;
    uint8_t  raw_data[DICOM_MAX_UNKNOWN_PDU_LEN];
    const uint8_t *raw_tail; /* Borrowed input; only used with raw_length > 0. */
    uint32_t raw_tail_length;
    union {
        dicom_a_associate_rq_pdu_t a_associate_rq;
        dicom_a_associate_ac_pdu_t a_associate_ac;
        dicom_a_associate_rj_pdu_t a_associate_rj;
        dicom_p_data_tf_pdu_t      p_data_tf;
        dicom_a_release_rq_pdu_t   a_release_rq;
        dicom_a_release_rp_pdu_t   a_release_rp;
        dicom_a_abort_pdu_t        a_abort;
        dicom_unknown_pdu_t        unknown;
    } u;
} dicom_packet_t;

// API

dicom_packet_t* generate_dicom_packets(int count);
void print_dicom_packets(const dicom_packet_t *packets, int count);

#ifdef __cplusplus
}
#endif

#endif // DICOM_PACKETS_H
