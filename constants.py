"""
Constants, Enums, and Patterns for Tejas L3 Log Analyzer
Extracted from app.py to reduce file size while preserving 100% logic.
"""

import re

# =============================================================================
# RRC MESSAGE TRACKING
# =============================================================================

rrc_messages_to_track = [
    "RRC CONNECTION REQUEST", "RRC CONNECTION REJECT", "RRC CONNECTION SETUP", "RRC CONNECTION SETUP COMPLETE",
    "RRC CONNECTION RECONFIGURATION", "RRC CONNECTION RECONFIGURATION COMPLETE", "RRC CONNECTION RECONFIGURATION SENT",
    "RRC CONNECTION RELEASE", "RRC Reestablishment Complete indication send to RRM", "HANDOVER REQUEST ACKNOWLEDGE",
    "PATH SWITCH REQUEST", "PATH SWITCH REQUEST ACK", "HO NOTIFY", "RRM UE HO ADM RESPONSE", "RRM UE HO ADM REQUEST",
    "rrc_mac_ho_rach_resource_req", "rrc_mac_ho_rach_resource_resp", "rrc_phy_create_ue_entity_req",
    "rrc_phy_create_ue_entity_resp", "rrc_rrm_ue_ho_adm_cnf", "X2AP_MSG: HANDOVER REQUEST",
    "X2AP_MSG: HANDOVER REQUEST ACKNOWLEDGE", "X2AP_MSG: HANDOVER REQUEST ACK",
    "S1AP_MSG: HANDOVER REQUEST", "S1AP_MSG: ALLOCATE_MME_REQ",
    "S1AP_MSG: INITIAL CONTEXT SETUP REQUEST", "S1AP_MSG: ERAB SETUP REQUEST", "S1AP_MSG: ERAB SETUP RESPONSE",
    "ASN1 encoding failed.", "ASN decoding failed", "X2AP_MSG: HANDOVER CANCEL", "S1AP_MSG: HANDOVER CANCEL",
    "X2AP_RLF_IND from RRC", "handover failure indication to RRM",
    "RRC Connection ReEstablishment reject to UE", "Reestablishment Complete indication send to RRM",
    "RRC CONNECTIONREESTABLISHMENT REQUEST", "RRC CONNECTION RE-ESTABLISHMENT COMPLETE",
    "TEID:RCR UE Release timer expiry", "handover cancel to X2AP",
    "ASN1 encoding of RLF INDICATION failed."
]

# =============================================================================
# HANDOVER TYPE ENUM MAPPING
# =============================================================================

HO_TYPE_ENUM = {
    0: "INTRA_LTE_S1",
    1: "LTE_TO_UTRAN",
    2: "LTE_TO_GERAN",
    3: "UTRAN_TO_LTE",
    4: "GERAN_TO_LTE",
    5: "INTRA_LTE_X2",
    6: "INTRA_CELL",
    7: "LTE_TO_CDMA2000_1XRTT",
    8: "LTE_TO_CDMA2000_HRPD",
    9: "LTE_TO_CDMA2000_CONC_1XRTT_HRPD",
    10: "CCO",
    11: "INTER_CELL",
}

# =============================================================================
# HANDOVER FREQUENCY TYPE ENUM MAPPING
# =============================================================================

HO_FREQ_TYPE_ENUM = {
    0: "HANDOVER_INTRA_FREQ",
    1: "HANDOVER_INTER_FREQ",
}

# =============================================================================
# S1AP UE CONTEXT RELEASE CAUSE ENUM
# =============================================================================

S1AP_CAUSE_ENUM = {
    0: "s1ap_unspecified_2",
    1: "s1ap_tx2relocoverall_expiry",
    2: "s1ap_successful_handover",
    3: "s1ap_release_due_to_eutran_generated_reason",
    4: "s1ap_handover_cancelled",
    5: "s1ap_partial_handover",
    6: "s1ap_ho_failure_in_target_EPC_eNB_or_target_system",
    7: "s1ap_ho_target_not_allowed",
    8: "s1ap_tS1relocoverall_expiry",
    9: "s1ap_tS1relocprep_expiry",
    10: "s1ap_cell_not_available",
    11: "s1ap_unknown_targetID",
    12: "s1ap_no_radio_resources_available_in_target_cell",
    13: "s1ap_unknown_mme_ue_s1ap_id",
    14: "s1ap_unknown_enb_ue_s1ap_id",
    15: "s1ap_unknown_pair_ue_s1ap_id",
    16: "s1ap_handover_desirable_for_radio_reason",
    17: "s1ap_time_critical_handover",
    18: "s1ap_resource_optimisation_handover",
    19: "s1ap_reduce_load_in_serving_cell",
    20: "s1ap_user_inactivity",
    21: "s1ap_radio_connection_with_ue_lost",
    22: "s1ap_load_balancing_tau_required",
    23: "s1ap_cs_fallback_triggered",
    24: "s1ap_ue_not_available_for_ps_service",
    25: "s1ap_radio_resources_not_available",
    26: "s1ap_failure_in_radio_interface_procedure",
    27: "s1ap_invalid_qos_combination",
    28: "s1ap_interrat_redirection",
    29: "s1ap_interaction_with_other_procedure",
    30: "s1ap_unknown_E_RAB_ID",
    31: "s1ap_multiple_E_RAB_ID_instances",
    32: "s1ap_encryption_and_or_integrity_protection_algorithms_not_supported",
    33: "s1ap_s1_intra_system_handover_triggered",
    34: "s1ap_s1_inter_system_handover_triggered",
    35: "s1ap_x2_handover_triggered",
}

# =============================================================================
# S1AP FAILURE CAUSES
# Causes that indicate a FAILURE release (UE marked as failed only for these)
# =============================================================================

S1AP_CAUSE_FAILURE = {
    3,   # s1ap_release_due_to_eutran_generated_reason
    6,   # s1ap_ho_failure_in_target_EPC_eNB_or_target_system
    8,   # s1ap_tS1relocoverall_expiry
    9,   # s1ap_tS1relocprep_expiry
    21,  # s1ap_radio_connection_with_ue_lost
    25,  # s1ap_radio_resources_not_available
    26,  # s1ap_failure_in_radio_interface_procedure
    29,  # s1ap_interaction_with_other_procedure
}

# =============================================================================
# PRECOMPILED REGEX PATTERNS FOR PERFORMANCE
# =============================================================================

REGEX_CONVERTED = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<file>[\w_.]+\.c)\s+"
    r"(?P<line>\d+)\s+"
    r"(?P<message>.*)$"
)

REGEX_LEGACY = re.compile(
    r"^(?P<date>\d{2}\.\d{2}\.\d{4})\s+"
    r"(?P<time>[\d:.]+)\s+"
    r"(?P<file>[\w_.]+\.c)\s+"
    r"(?P<line>\d+)\s+"
    r"(?P<message>.*)$"
)

# =============================================================================
# CELL SETUP MILESTONES
# Milestones tracked during cell setup (order matters for display)
# =============================================================================

CELL_SETUP_MILESTONES = [
    {"key": "rrc_init",           "pattern": r"ueccmd_init\.c.*Init\.",                          "label": "RRC Init"},
    {"key": "s1ap_init",          "pattern": r"s1ap_init\.c.*Init\.",                            "label": "S1AP Init"},
    {"key": "x2ap_init",          "pattern": r"x2ap_init\.c.*x2ap Init\.",                       "label": "X2AP Init"},
    {"key": "oam_prov_req",       "pattern": r"API:RRC_OAM_PROVISION_REQ",                       "label": "OAM Provision REQ"},
    {"key": "oam_prov_resp",      "pattern": r"API:RRC_OAM_PROVISION_RESP",                      "label": "OAM Provision RESP"},
    {"key": "s1ap_oam_prov_req",  "pattern": r"API:S1AP_OAM_PROVISION_REQ",                      "label": "S1AP OAM Provision REQ"},
    {"key": "s1ap_oam_prov_resp", "pattern": r"API:S1AP_OAM_PROVISION_RESP",                     "label": "S1AP OAM Provision RESP"},
    {"key": "s1ap_active",        "pattern": r"S1AP has entered Active State",                   "label": "S1AP Active State"},
    {"key": "sctp_assoc_up",      "pattern": r"SCTP Association is UP",                          "label": "SCTP Association UP"},
    {"key": "s1_setup_sent",      "pattern": r"S1 setup request is sent",                        "label": "S1 Setup Request Sent"},
    {"key": "s1_setup_resp",      "pattern": r"S1 SETUP RESPONSE|MME_EVENT_S1_SETUP_RSP(?!_FAIL)",  "label": "S1 Setup Response (Success)"},
    {"key": "s1_setup_failure",   "pattern": r"S1 SETUP FAILURE",                                "label": "S1 Setup Failure"},
    {"key": "x2ap_oam_prov_resp", "pattern": r"X2AP_OAM_PROVISION_RESP",                         "label": "X2AP OAM Provision RESP"},
    {"key": "cell_setup_req",     "pattern": r"API:RRC_RRM_CELL_SETUP_REQ",                      "label": "Cell Setup REQ"},
    {"key": "cell_setup_resp",    "pattern": r"API:RRC_RRM_CELL_SETUP_RESP",                     "label": "Cell Setup RESP"},
    {"key": "cell_start_ind",     "pattern": r"API:CSC_OAMH_CELL_START_IND",                     "label": "Cell Start IND"},
    {"key": "cell_configured",    "pattern": r"is_cell_configured\s*=\s*TRUE",                   "label": "Cell Configured = True"},
]

# =============================================================================
# MILESTONE PATTERNS FOR UE JOURNEY TRACKING
# =============================================================================

MILESTONE_PATTERNS = [
    {"name": "Value of U16 crnti", "type": "RNTI", "occur": 1},
    {"name": "Value of U8 cell_index", "type": "cell_id", "occur": 1},
    {"name": "RRC_MSG: RRC CONNECTION REQUEST", "type": "RRC Connection Request", "occur": 0},
    {"name": "RRC_MSG: RRC CONNECTION SETUP", "type": "RRC Connection Setup", "occur": 0},
    {"name": "RRC_MSG: RRC CONNECTION SETUP COMPLETE", "type": "RRC Connection Setup Complete", "occur": 0},
    {"name": "RRC_MSG: SECURITY MODE COMMAND", "type": "Security Mode Command", "occur": 0},
    {"name": "RRC_MSG: SECURITY MODE COMPLETE", "type": "Security Mode Complete", "occur": 0},
    {"name": "X2AP_MSG: HANDOVER REQUEST", "type": "X2AP HO Request", "occur": 0},
    {"name": "X2AP_MSG: HANDOVER REQUEST ACKNOWLEDGE", "type": "X2AP HO ACK", "occur": 0},
    {"name": "S1AP_MSG: HANDOVER REQUEST", "type": "S1AP HO Request", "occur": 0},
    {"name": "RRC_MSG: RRC CONNECTIONREESTABLISHMENT REQUEST", "type": "RRC Reestablishment Request", "occur": 0},
    {"name": "RRC_MSG: RRC CONNECTION REESTABLISHMENT", "type": "RRC Reestablishment", "occur": 0},
    {"name": "RRC_MSG: RRC CONNECTION RE-ESTABLISHMENT COMPLETE", "type": "RRC Re-establishment Complete", "occur": 0},
    {"name": "PATH SWITCH REQUEST", "type": "Path Switch Request", "occur": 0},
    {"name": "PATH SWITCH REQUEST ACK", "type": "Path Switch Request Ack", "occur": 0},
    {"name": "Value of U8 is256QAMSupported", "type": "DL 256QAM", "occur": 0},
    {"name": "TTI BUNDLING is supported by UE", "type": "TTI BUNDLING", "occur": 0},
    {"name": "RRC_MSG: UE INFORMATION REQUEST", "type": "UE Information Request", "occur": 0},
    {"name": "RRC_MSG: UL UE INFORMATION", "type": "UL UE Information", "occur": 0},
    {"name": "RRC_MSG: MEASUREMENT REPORT", "type": "Measurement Report", "occur": 0},
    {"name": "X2AP_MSG: UE CONTEXT RELEASE", "type": "UE Context Release", "occur": 0},
    {"name": "TEID:RCR UE Release timer expiry", "type": "UE Release", "occur": 0}
]
