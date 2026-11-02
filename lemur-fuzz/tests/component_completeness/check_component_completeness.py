#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

EXPECTED = {
    "dns": {
        "message_forms": ["QUERY", "IQUERY", "STATUS", "NOTIFY", "UPDATE", "EDNS_OPT"],
        "message_tokens": ["DNS_MESSAGE", "DNS_HEADER", "DNS_QUESTION", "DNS_RESOURCE_RECORD", "DNS_OPT_RECORD"],
        "field_tokens": [
            "id", "qr", "opcode", "aa", "tc", "rd", "ra", "z", "rcode", "qdcount", "ancount", "nscount", "arcount",
            "name_len", "name", "qtype", "qclass", "type", "class_code", "ttl", "rdlength", "rdata_len", "rdata",
            "udp_payload_size", "ext_rcode", "edns_version", "edns_flags", "questions", "answers", "authorities", "additionals", "opt_rr", "has_opt",
        ],
        "parser_tokens": ["parse_DNS_HEADER", "parse_DNS_QUESTION", "parse_DNS_RESOURCE_RECORD", "parse_DNS_OPT_RECORD", "parse_DNS_MESSAGE"],
        "reassembler_tokens": ["reassemble_dns_header", "reassemble_dns_question", "reassemble_dns_resource_record", "reassemble_dns_opt_record", "reassemble_dns_message"],
        "mutators": ["mutate_id", "mutate_qr", "mutate_opcode", "mutate_aa", "mutate_tc", "mutate_rd", "mutate_ra", "mutate_z", "mutate_rcode", "mutate_qdcount", "mutate_ancount", "mutate_nscount", "mutate_arcount", "add_questions", "delete_questions", "repeat_questions", "mutate_questions", "mutate_qtype", "mutate_qclass", "add_answers", "delete_answers", "repeat_answers", "mutate_answers", "add_authorities", "delete_authorities", "repeat_authorities", "mutate_authorities", "add_additionals", "delete_additionals", "repeat_additionals", "mutate_additionals", "add_opt_rr", "delete_opt_rr", "mutate_opt_rr", "mutate_udp_payload_size", "mutate_ext_rcode", "mutate_edns_version", "mutate_edns_flags"],
        "fixers": [
            "fix_RFC1035_4_1_1_QR_is_query", "fix_RFC1035_4_1_1_opcode_known_request", "fix_RFC1035_4_1_1_AA_not_in_query", "fix_RFC1035_4_1_1_Z_zero", "fix_RFC1035_4_1_1_RA_not_in_query", "fix_RFC1035_4_1_1_RCODE_zero_in_query", "fix_RFC1035_4_1_1_count_fields_match_sections", "fix_RFC1035_4_1_2_question_format", "fix_RFC1035_2_3_4_label_and_name_lengths", "fix_RFC1035_3_1_wire_name_sequence", "fix_RFC1035_3_1_length_octet_highbits", "fix_RFC1035_4_1_4_compression_pointers", "fix_RFC1035_4_1_3_rr_rdlength_matches_rdata", "fix_RFC1035_4_2_1_udp_512_and_tc", "fix_RFC1035_4_2_1_no_AXFR_over_udp", "fix_RFC1996_3_NOTIFY_question_section", "fix_RFC2136_2_UPDATE_zone_section", "fix_RFC6891_6_1_2_single_OPT", "fix_RFC6891_6_1_2_OPT_in_additional", "fix_RFC6891_6_1_2_OPT_shape", "fix_RFC6891_6_1_4_OPT_flags_Z_zero", "fix_dns",
        ],
        "constraints": [
            ("RFC1035-4.1.1 QR=0 for requests", "fix_RFC1035_4_1_1_QR_is_query"),
            ("RFC1035-4.1.1 known 4-bit request opcodes", "fix_RFC1035_4_1_1_opcode_known_request"),
            ("RFC1035-4.1.1 AA/RA/RCODE response-only, Z zero, bit flags bounded", "fix_RFC1035_4_1_1_AA_not_in_query"),
            ("RFC1035-4.1.1 section count fields match actual sections", "fix_RFC1035_4_1_1_count_fields_match_sections"),
            ("RFC1035-4.1.2 question is QNAME/QTYPE/QCLASS", "fix_RFC1035_4_1_2_question_format"),
            ("RFC1035-2.3.4/RFC1035-3.1 labels <=63, names <=255, root terminated", "fix_RFC1035_2_3_4_label_and_name_lengths"),
            ("RFC1035-4.1.3 RR RDLENGTH equals RDATA length", "fix_RFC1035_4_1_3_rr_rdlength_matches_rdata"),
            ("RFC1035-4.1.4 compression pointers valid/backward or normalized away", "fix_RFC1035_4_1_4_compression_pointers"),
            ("RFC1035-4.2.1 UDP request truncation/AXFR constraints", "fix_RFC1035_4_2_1_no_AXFR_over_udp"),
            ("RFC1996 NOTIFY carries one SOA question", "fix_RFC1996_3_NOTIFY_question_section"),
            ("RFC2136 UPDATE Zone section has exactly one SOA question", "fix_RFC2136_2_UPDATE_zone_section"),
            ("RFC6891 EDNS OPT is single, additional-only, root-name TYPE=41, Z bits zero", "fix_RFC6891_6_1_2_OPT_shape"),
        ],
    },
    "ssh": {
        "message_forms": ["DISCONNECT", "IGNORE", "UNIMPLEMENTED", "DEBUG", "SERVICE_REQUEST", "SERVICE_ACCEPT", "KEXINIT", "NEWKEYS", "KEXDH_INIT", "KEXDH_REPLY", "USERAUTH_REQUEST", "USERAUTH_FAILURE", "USERAUTH_SUCCESS", "USERAUTH_BANNER", "USERAUTH_METHOD_REPLY", "GLOBAL_REQUEST", "REQUEST_SUCCESS", "REQUEST_FAILURE", "CHANNEL_OPEN", "CHANNEL_OPEN_CONFIRMATION", "CHANNEL_OPEN_FAILURE", "CHANNEL_WINDOW_ADJUST", "CHANNEL_DATA", "CHANNEL_EXTENDED_DATA", "CHANNEL_EOF", "CHANNEL_CLOSE", "CHANNEL_REQUEST", "CHANNEL_SUCCESS", "CHANNEL_FAILURE"],
        "message_tokens": ["SSH_MSG_DISCONNECT", "SSH_MSG_IGNORE", "SSH_MSG_UNIMPLEMENTED", "SSH_MSG_DEBUG", "SSH_MSG_SERVICE_REQUEST", "SSH_MSG_SERVICE_ACCEPT", "SSH_MSG_KEXINIT", "SSH_MSG_NEWKEYS", "SSH_MSG_KEXDH_INIT", "SSH_MSG_KEXDH_REPLY", "SSH_MSG_USERAUTH_REQUEST", "SSH_MSG_USERAUTH_FAILURE", "SSH_MSG_USERAUTH_SUCCESS", "SSH_MSG_USERAUTH_BANNER", "SSH_MSG_USERAUTH_PK_OK", "SSH_MSG_USERAUTH_PASSWD_CHANGEREQ", "SSH_MSG_USERAUTH_METHOD_REPLY", "SSH_MSG_GLOBAL_REQUEST", "SSH_MSG_REQUEST_SUCCESS", "SSH_MSG_REQUEST_FAILURE", "SSH_MSG_CHANNEL_OPEN", "SSH_MSG_CHANNEL_OPEN_CONFIRMATION", "SSH_MSG_CHANNEL_OPEN_FAILURE", "SSH_MSG_CHANNEL_WINDOW_ADJUST", "SSH_MSG_CHANNEL_DATA", "SSH_MSG_CHANNEL_EXTENDED_DATA", "SSH_MSG_CHANNEL_EOF", "SSH_MSG_CHANNEL_CLOSE", "SSH_MSG_CHANNEL_REQUEST", "SSH_MSG_CHANNEL_SUCCESS", "SSH_MSG_CHANNEL_FAILURE"],
        "field_tokens": ["proto_id", "protoversion", "software", "comments", "raw_len", "packet_length", "padding_length", "payload_len", "payload", "cookie", "kex_algorithms", "server_host_key_algorithms", "encryption_algorithms_client_to_server", "mac_algorithms_client_to_server", "compression_algorithms_client_to_server", "languages_client_to_server", "first_kex_packet_follows", "reserved_zero", "e_len", "service_name", "field_schema", "boolean_value", "uint32_values", "strings", "trailing_payload", "publickey", "password", "hostbased"],
        "parser_tokens": ["parse_ssh_banner_pkt", "parse_ssh_transport_packet", "parse_ssh_kexinit_payload", "parse_ssh_kexdh_init_payload", "parse_ssh_service_request_payload", "parse_ssh_typed_fields"],
        "reassembler_tokens": ["reassemble_SSH_BANNER", "reassemble_SSH_TRANSPORT_PACKET", "reassemble_SSH_KEXINIT", "reassemble_SSH_KEXDH_INIT", "reassemble_SSH_SERVICE_REQUEST", "reassemble_SSH_TYPED"],
        "mutators": ["mutate_software", "add_comments", "delete_comments", "mutate_packet_length", "mutate_padding_length", "mutate_payload", "mutate_cookie", "add_kex_algorithms", "delete_kex_algorithms", "mutate_kex_algorithms", "mutate_first_kex_packet_follows", "mutate_kexdh_init_payload", "mutate_service_request_payload", "mutate_newkeys_payload", "mutate_typed_message_code", "mutate_typed_payload_len", "mutate_typed_payload", "mutate_typed_field_schema", "mutate_typed_boolean_value", "mutate_typed_uint32_count", "mutate_typed_uint32_values", "mutate_typed_string_count", "add_typed_strings", "delete_typed_strings", "repeat_typed_strings", "mutate_typed_strings", "add_typed_trailing_payload", "delete_typed_trailing_payload", "repeat_typed_trailing_payload", "mutate_typed_trailing_payload"],
        "fixers": ["fix_RFC4253_4_2_identification_string", "fix_RFC4253_6_binary_packet_length_padding", "fix_RFC4253_7_1_kexinit_namelists_and_reserved", "fix_RFC4253_8_kexdh_init_mpint", "fix_RFC4253_10_service_request_name", "fix_RFC4253_7_3_newkeys_message", "fix_RFC4251_5_typed_payload_fields", "fix_ssh"],
        "constraints": [
            ("RFC4253-4.2 identification string format and 255-byte limit", "fix_RFC4253_4_2_identification_string"),
            ("RFC4253-6 binary packet length/padding/block alignment", "fix_RFC4253_6_binary_packet_length_padding"),
            ("RFC4253-7.1 KEXINIT ten name-lists, boolean, reserved zero", "fix_RFC4253_7_1_kexinit_namelists_and_reserved"),
            ("RFC4253-8 KEXDH_INIT message number and mpint e", "fix_RFC4253_8_kexdh_init_mpint"),
            ("RFC4253-10 SERVICE_REQUEST service name string", "fix_RFC4253_10_service_request_name"),
            ("RFC4253-7.3 NEWKEYS message has only message number", "fix_RFC4253_7_3_newkeys_message"),
            ("RFC4251/RFC4252/RFC4254 typed payload strings, booleans, uint32s and per-message schema", "fix_RFC4251_5_typed_payload_fields"),
        ],
    },
    "tls": {
        "message_forms": ["change_cipher_spec", "alert", "handshake", "application_data", "ClientHello", "Certificate", "ClientKeyExchange", "CertificateVerify", "Finished"],
        "message_tokens": ["TLS_CONTENTTYPE_CHANGE_CIPHER_SPEC", "TLS_CONTENTTYPE_ALERT", "TLS_CONTENTTYPE_HANDSHAKE", "TLS_CONTENTTYPE_APPLICATION_DATA", "TLS_HANDSHAKE_CLIENT_HELLO", "TLS_HANDSHAKE_CERTIFICATE", "TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE", "TLS_HANDSHAKE_CERTIFICATE_VERIFY", "TLS_HANDSHAKE_FINISHED"],
        "field_tokens": ["tls_record_header_t", "type", "version", "length", "tls_change_cipher_spec_msg_t", "tls_alert_msg_t", "level", "description", "tls_handshake_msg_t", "msg_type", "body_len", "has_client_hello", "client_version", "random", "session_id_len", "session_id", "cipher_suites_len", "cipher_suites", "compression_methods_len", "compression_methods", "extensions_len", "extensions", "app_data"],
        "parser_tokens": ["parse_tls_alert", "parse_tls_handshake", "parse_tls_client_hello_body", "parse_tls_application_data", "parse_tls_msg"],
        "reassembler_tokens": ["reassemble_change_cipher_spec", "reassemble_alert", "reassemble_handshake", "write_client_hello_body", "reassemble_application_data"],
        "mutators": ["mutate_record_version_major", "mutate_record_version_minor", "mutate_record_length", "mutate_alert_level", "mutate_alert_description", "mutate_handshake_msg_type", "mutate_handshake_length", "mutate_handshake_length_b0", "mutate_handshake_length_b1", "mutate_handshake_length_b2", "add_handshake_body", "delete_handshake_body", "mutate_handshake_body", "mutate_handshake_body_len", "add_has_client_hello", "delete_has_client_hello", "mutate_has_client_hello", "mutate_client_hello_version", "mutate_client_hello_random", "mutate_client_hello_session_id_len", "mutate_client_hello_session_id", "mutate_client_hello_cipher_suites_len", "mutate_client_hello_cipher_suites", "mutate_client_hello_compression_methods_len", "mutate_client_hello_compression_methods", "mutate_client_hello_extensions_len", "mutate_client_hello_extensions", "add_app_data_data", "delete_app_data_data", "repeat_app_data_data", "mutate_app_data_data", "mutate_app_data_data_len"],
        "fixers": ["ensure_tls_version", "fix_change_cipher_spec_type", "fix_alert_record", "fix_handshake_record", "fix_application_data_record", "fix_RFC5246_6_2_1_record_length_bounds", "fix_RFC5246_7_4_1_2_client_hello_vectors", "fix_tls"],
        "constraints": [
            ("RFC5246-6.2.1 record ContentType/ProtocolVersion/length", "fix_RFC5246_6_2_1_record_length_bounds"),
            ("RFC5246-7.1 ChangeCipherSpec is one byte of value 1", "fix_change_cipher_spec_type"),
            ("RFC5246-7.2 Alert level and description enums", "fix_alert_record"),
            ("RFC5246-7.4 Handshake type and uint24 length match body", "fix_handshake_record"),
            ("RFC5246-7.4.1.2 ClientHello session/cipher/compression vectors", "fix_RFC5246_7_4_1_2_client_hello_vectors"),
            ("RFC6066 extension vector TLV shape", "fix_RFC5246_7_4_1_2_client_hello_vectors"),
            ("RFC5246-6.2.1 application_data fragment length bound", "fix_application_data_record"),
        ],
    },
    "dicom": {
        "message_forms": ["A-ASSOCIATE-RQ", "A-ASSOCIATE-AC", "A-ASSOCIATE-RJ", "P-DATA-TF", "A-RELEASE-RQ", "A-RELEASE-RP", "A-ABORT", "C-STORE-RQ", "C-GET-RQ", "C-FIND-RQ", "C-MOVE-RQ", "C-ECHO-RQ", "C-CANCEL-RQ", "N-EVENT-REPORT-RQ", "N-GET-RQ", "N-SET-RQ", "N-ACTION-RQ", "N-CREATE-RQ", "N-DELETE-RQ"],
        "message_tokens": ["DICOM_PDU_A_ASSOCIATE_RQ", "DICOM_PDU_A_ASSOCIATE_AC", "DICOM_PDU_A_ASSOCIATE_RJ", "DICOM_PDU_P_DATA_TF", "DICOM_PDU_A_RELEASE_RQ", "DICOM_PDU_A_RELEASE_RP", "DICOM_PDU_A_ABORT", "DICOM_DIMSE_C_STORE_RQ", "DICOM_DIMSE_C_GET_RQ", "DICOM_DIMSE_C_FIND_RQ", "DICOM_DIMSE_C_MOVE_RQ", "DICOM_DIMSE_C_ECHO_RQ", "DICOM_DIMSE_C_CANCEL_RQ", "DICOM_DIMSE_N_EVENT_REPORT_RQ", "DICOM_DIMSE_N_GET_RQ", "DICOM_DIMSE_N_SET_RQ", "DICOM_DIMSE_N_ACTION_RQ", "DICOM_DIMSE_N_CREATE_RQ", "DICOM_DIMSE_N_DELETE_RQ"],
        "field_tokens": ["pdu_type", "reserved1", "pdu_length", "protocol_version", "called_ae_title", "calling_ae_title", "application_context", "presentation_contexts", "presentation_context_count", "abstract_syntax", "transfer_syntaxes", "transfer_syntax_count", "user_info", "has_maximum_length", "maximum_length_received", "has_implementation_class_uid", "implementation_class_uid", "has_async_ops_window", "max_ops_invoked", "max_ops_performed", "role_selections", "role_selection_count", "has_implementation_version_name", "implementation_version_name", "raw_items_length", "result", "source", "reason_diag", "pdv_length", "presentation_context_id", "control_header", "data_length", "dimse_command_field", "dimse_message_id", "dimse_message_id_responded_to", "dimse_priority", "dimse_command_data_set_type", "dimse_status", "dimse_event_type_id", "dimse_action_type_id", "dimse_move_originator_message_id", "dimse_affected_sop_class_uid", "dimse_requested_sop_class_uid", "dimse_affected_sop_instance_uid", "dimse_requested_sop_instance_uid", "dimse_move_destination", "dimse_attribute_identifier_list"],
        "parser_tokens": ["parse_a_associate_rq", "parse_a_associate_ac", "parse_a_associate_rj", "parse_p_data_tf", "parse_a_release_rq", "parse_a_release_rp", "parse_a_abort", "parse_dimse_command_data"],
        "reassembler_tokens": ["reassemble_a_associate_rq", "reassemble_a_associate_ac", "reassemble_a_associate_rj", "reassemble_p_data_tf", "reassemble_a_release_rq", "reassemble_a_release_rp", "reassemble_a_abort", "build_dimse_command_data"],
        "mutators": ["mutate_called_ae_title", "mutate_calling_ae_title", "mutate_protocol_version", "mutate_pdu_length", "mutate_application_context_name", "mutate_presentation_context_id", "mutate_presentation_context_count", "add_presentation_contexts", "delete_presentation_contexts", "repeat_presentation_contexts", "mutate_presentation_contexts", "mutate_abstract_syntax_name", "mutate_transfer_syntax_count", "add_transfer_syntaxes", "delete_transfer_syntaxes", "repeat_transfer_syntaxes", "mutate_transfer_syntaxes", "add_user_info", "delete_user_info", "mutate_has_user_info", "add_user_data", "delete_user_data", "repeat_user_data", "mutate_user_data", "mutate_user_data_length", "add_user_maximum_length", "delete_user_maximum_length", "mutate_user_maximum_length", "add_implementation_class_uid", "delete_implementation_class_uid", "mutate_implementation_class_uid", "add_async_ops_window", "delete_async_ops_window", "mutate_async_ops_window", "add_role_selections", "delete_role_selections", "repeat_role_selections", "mutate_role_selections", "add_implementation_version_name", "delete_implementation_version_name", "mutate_implementation_version_name", "add_pdvs", "delete_pdvs", "repeat_pdvs", "mutate_pdvs", "mutate_pdv_count", "mutate_pdv_length", "mutate_pdv_control_header", "mutate_pdv_data_bytes", "mutate_data_length", "add_data", "delete_data", "repeat_data", "mutate_data", "mutate_dimse_command_field", "mutate_dimse_message_id", "mutate_dimse_priority", "mutate_dimse_dataset_type", "mutate_dimse_status", "mutate_dimse_affected_sop_class_uid", "mutate_dimse_affected_sop_instance_uid", "mutate_dimse_requested_sop_class_uid", "mutate_dimse_requested_sop_instance_uid", "mutate_dimse_event_action_ids", "mutate_dimse_move_originator", "mutate_dimse_move_destination", "add_dimse_attribute_identifier_list", "delete_dimse_attribute_identifier_list", "repeat_dimse_attribute_identifier_list", "mutate_dimse_attribute_identifier_list", "mutate_dimse_attribute_identifier_list_len", "add_raw_items", "delete_raw_items", "repeat_raw_items", "mutate_raw_items", "mutate_raw_items_length", "mutate_unknown_pdu_type", "mutate_unknown_data_length", "mutate_unknown_data"],
        "fixers": ["fix_dicom_pdu_header_lengths", "fix_DICOM_PS3_8_9_3_2_associate_rq_items", "fix_DICOM_PS3_8_9_3_3_associate_ac_items", "fix_DICOM_PS3_8_9_3_5_pdata_pdv_items", "fix_DICOM_PS3_7_DIMSE_request_command_set", "fix_DICOM_PS3_8_9_3_4_6_7_8_fixed_length_pdus", "fix_dicom"],
        "constraints": [
            ("PS3.8 9.3 PDU header type/reserved/length fields", "fix_dicom_pdu_header_lengths"),
            ("PS3.8 9.3.2 A-ASSOCIATE-RQ fixed fields and required items", "fix_DICOM_PS3_8_9_3_2_associate_rq_items"),
            ("PS3.8 9.3.2.3 User Information sub-items 0x51/0x52/0x53/0x54/0x55 and private sub-items", "fix_DICOM_PS3_8_9_3_2_associate_rq_items"),
            ("PS3.8 9.3.3 A-ASSOCIATE-AC fixed fields and variable item bytes", "fix_DICOM_PS3_8_9_3_3_associate_ac_items"),
            ("PS3.8 9.3.4 A-ASSOCIATE-RJ fixed length/result/source/reason", "fix_DICOM_PS3_8_9_3_4_6_7_8_fixed_length_pdus"),
            ("PS3.8 9.3.5 P-DATA-TF one-or-more PDVs, PDV length, PCID, control bits", "fix_DICOM_PS3_8_9_3_5_pdata_pdv_items"),
            ("PS3.8 9.3.6/9.3.7 A-RELEASE fixed 4 reserved bytes", "fix_DICOM_PS3_8_9_3_4_6_7_8_fixed_length_pdus"),
            ("PS3.8 9.3.8 A-ABORT fixed length/source/reason", "fix_DICOM_PS3_8_9_3_4_6_7_8_fixed_length_pdus"),
            ("PS3.7 DIMSE request command field, Message ID, priority, dataset type, UIDs and request-specific IDs", "fix_DICOM_PS3_7_DIMSE_request_command_set"),
        ],
    },
}

SUFFIX = {
    "message_tokens": "packets.h",
    "field_tokens": "packets.h",
    "parser_tokens": "parser.c",
    "reassembler_tokens": "reassembler.c",
    "mutators": "mutators.c",
    "fixers": "fixers.c",
}

def read(proto: str, suffix: str) -> str:
    return (ROOT / "llm" / proto / f"{proto}_{suffix}").read_text(errors="ignore")


def dispatch_block(src: str, name: str) -> str:
    start = src.find(name)
    if start < 0:
        return ""
    brace = src.find("{", start)
    if brace < 0:
        return ""
    depth = 0
    for i in range(brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    return src[start:]

def check_dispatchers() -> list[tuple[str, str, str]]:
    failures: list[tuple[str, str, str]] = []
    dispatchers = {
        "dns": "void dispatch_dns_mutation",
        "ssh": "void dispatch_ssh_mutation",
        "tls": "void dispatch_tls_multiple_mutations",
        "dicom": "void dispatch_dicom_multiple_mutations",
    }
    forbidden_by_proto = {
        "ssh": ["mutate_typed_message_code(", "mutate_typed_field_schema("],
        "tls": ["mutate_handshake_msg_type(", "add_has_client_hello(", "delete_has_client_hello(", "mutate_has_client_hello("],
        # DICOM P-DATA-TF carries DIMSE commands. The top-level dispatcher may only
        # call the DIMSE sub-dispatcher; it must not call packet-wide DIMSE mutators
        # that can mutate fields belonging to a different DIMSE request type.
        "dicom": ["mutate_dimse_command_field(", "mutate_dimse_message_id(", "mutate_dimse_priority(", "mutate_dimse_dataset_type(", "mutate_dimse_status(", "mutate_dimse_affected_sop_class_uid(", "mutate_dimse_affected_sop_instance_uid(", "mutate_dimse_requested_sop_class_uid(", "mutate_dimse_requested_sop_instance_uid(", "mutate_dimse_event_action_ids(", "mutate_dimse_move_originator(", "mutate_dimse_move_destination(", "add_dimse_attribute_identifier_list(", "delete_dimse_attribute_identifier_list(", "repeat_dimse_attribute_identifier_list(", "mutate_dimse_attribute_identifier_list(", "mutate_dimse_attribute_identifier_list_len("],
    }
    for proto, marker in dispatchers.items():
        src = read(proto, "mutators.c")
        block = dispatch_block(src, marker)
        if not block:
            failures.append((proto, "dispatcher", f"missing {marker}"))
            continue
        # Runtime dispatch must mutate the selected packet only, not the whole packet array.
        for bad in ("(pkts, pkt_count)", "(pkts, (size_t)num_packets)", "(pkts, num_packets)"):
            if bad in block:
                failures.append((proto, "dispatcher_scope", f"whole-array mutator call {bad}"))
        # Discriminator/message-type fields are fixed for a selected template and must not be dispatch-mutated.
        for token in forbidden_by_proto.get(proto, []):
            if token in block:
                failures.append((proto, "dispatcher_discriminator", token))

    dicom_src = read("dicom", "mutators.c")
    dimse_block = dispatch_block(dicom_src, "static void dispatch_dicom_dimse_mutation")
    if not dimse_block:
        failures.append(("dicom", "dispatcher_dimse", "missing dispatch_dicom_dimse_mutation"))
    else:
        for cmd in [
            "DICOM_DIMSE_C_STORE_RQ", "DICOM_DIMSE_C_GET_RQ", "DICOM_DIMSE_C_FIND_RQ",
            "DICOM_DIMSE_C_MOVE_RQ", "DICOM_DIMSE_C_ECHO_RQ", "DICOM_DIMSE_C_CANCEL_RQ",
            "DICOM_DIMSE_N_EVENT_REPORT_RQ", "DICOM_DIMSE_N_GET_RQ", "DICOM_DIMSE_N_SET_RQ",
            "DICOM_DIMSE_N_ACTION_RQ", "DICOM_DIMSE_N_CREATE_RQ", "DICOM_DIMSE_N_DELETE_RQ",
        ]:
            if cmd not in dimse_block:
                failures.append(("dicom", "dispatcher_dimse_command", cmd))
        for token in forbidden_by_proto["dicom"]:
            if token in dimse_block:
                failures.append(("dicom", "dispatcher_dimse_cross_type", token))
    return failures

def main() -> int:
    failures: list[tuple[str, str, str]] = []
    for proto, spec in EXPECTED.items():
        for key, suffix in SUFFIX.items():
            src = read(proto, suffix)
            for token in spec[key]:
                if token not in src:
                    failures.append((proto, key, token))
        fix_src = read(proto, "fixers.c")
        for constraint, fixer in spec["constraints"]:
            if fixer not in fix_src:
                failures.append((proto, "constraint_fixer", f"{constraint} -> {fixer}"))
    failures.extend(check_dispatchers())
    if failures:
        print("[FAIL] component/RFC completeness gaps:")
        for proto, key, token in failures:
            print(f"  {proto}.{key}: missing {token}")
        return 1
    print("[PASS] Declared component inventory checks for DNS/SSH/TLS/DICOM (full RFC field coverage is audited separately)")
    for proto, spec in EXPECTED.items():
        print(
            f"  {proto}: message_forms={len(spec['message_forms'])}, "
            f"fields>={len(spec['field_tokens'])}, mutators>={len(spec['mutators'])}, "
            f"format_constraints={len(spec['constraints'])}"
        )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
