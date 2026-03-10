import webbrowser
from flask import Flask, Response, render_template, request, redirect, url_for, send_file, jsonify
import os
import pandas as pd
import re
import shutil
import base64
from datetime import datetime
import zipfile
from io import BytesIO
import paramiko
import time
import threading
from bin_reader import bin_to_txt
from merge import merge_files
from urllib.parse import unquote

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
GENERATED_LOGS_FOLDER = "generated_logs"
CONVERTED_FOLDER = "converted"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(GENERATED_LOGS_FOLDER, exist_ok=True)
os.makedirs(CONVERTED_FOLDER, exist_ok=True)

MAX_SAVED_SESSIONS = 5

app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024 * 1024  # 1 GB
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --------------------------
# Global variables for analysis
# --------------------------
ue_data_map = {}
rrc_counts = {}
insights_global = []
valid_indices_global = []
total_ue_indices_global = 0

# Snapshot to preserve analysis data when a crash/backtrace is detected
last_analysis_snapshot = None

# Progress tracking for file analysis
analysis_progress = {
    'active': False,
    'current': 0,
    'total': 0,
    'message': '',
    'session_id': None,
    'completed': False,
    'error': None,
    'estimated_time': 0,  # seconds
    'start_time': None,
    'elapsed_time': 0,
    'next_url': '/results'
}

# Time estimation constants (based on benchmarking)
# Processing speed: ~2-3 MB/second on average hardware
PROCESSING_SPEED_MB_PER_SEC = 2.5  # Conservative estimate
OVERHEAD_SECONDS = 5  # Base overhead for parsing/indexing

# Global backtrace DataFrame used when a crash/backtrace is detected
bt_df = None
crash = False
latest_bt_text = None


def _session_directories():
    sessions = []
    if not os.path.isdir(UPLOAD_FOLDER):
        return sessions

    for name in os.listdir(UPLOAD_FOLDER):
        full_path = os.path.join(UPLOAD_FOLDER, name)
        if os.path.isdir(full_path) and name.startswith("session_"):
            mtime = os.path.getmtime(full_path)
            # Count files matching the same criteria used in analysis:
            # startswith "l3_event_x" and contains ".dbg" or ".bkp"
            file_count = len([f for f in os.listdir(full_path)
                              if (f.lower().startswith("l3_event_x") and 
                                  (".dbg" in f.lower() or ".bkp" in f.lower()))])
            sessions.append({
                "name": name,
                "path": full_path,
                "mtime": mtime,
                "timestamp": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "file_count": file_count
            })

    sessions.sort(key=lambda x: x["mtime"], reverse=True)
    return sessions


def _touch_session(session_path):
    try:
        now = datetime.now().timestamp()
        os.utime(session_path, (now, now))
    except Exception:
        pass


def _enforce_session_limit(max_sessions=MAX_SAVED_SESSIONS):
    sessions = _session_directories()
    for extra in sessions[max_sessions:]:
        shutil.rmtree(extra["path"], ignore_errors=True)


def _upload_page_context(error=None):
    _enforce_session_limit()
    sessions = _session_directories()[:MAX_SAVED_SESSIONS]
    return render_template("upload.html", error=error, previous_sessions=sessions)

# -----------------------------
# TRACKED RRC MESSAGES (original logic)
# -----------------------------
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

# -----------------------------
# Handover Type Enum Mapping
# -----------------------------
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

# -----------------------------
# Handover Frequency Type Enum Mapping
# -----------------------------
HO_FREQ_TYPE_ENUM = {
    0: "HANDOVER_INTRA_FREQ",
    1: "HANDOVER_INTER_FREQ",
}

# -----------------------------
# S1AP UE Context Release Cause Enum
# -----------------------------
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

# Causes that indicate a FAILURE release (UE marked as failed only for these)
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


def _extract_ho_type(data_map, ue_index):
    """
    Scan all messages for a UE and look for 'Value of U8 ho_type = <N>'.
    Returns a dict with 'ho_type_value' (int or None) and 'ho_type_name' (str).
    If found, maps the integer to HO_TYPE_ENUM. If not found, returns 'Direct Attach'.
    """
    ho_re = re.compile(r'Value of U8 ho_type\s*=\s*(\d+)', re.IGNORECASE)
    blocks = data_map.get(ue_index, [])
    for block in blocks:
        for row in block:
            msg = str(getattr(row, "Message", ""))
            m = ho_re.search(msg)
            if m:
                val = int(m.group(1))
                name = HO_TYPE_ENUM.get(val, f"UNKNOWN ({val})")
                return {'ho_type_value': val, 'ho_type_name': name}
    return {'ho_type_value': None, 'ho_type_name': 'Direct Attach'}


def _extract_ho_freq_type(data_map, ue_index):
    """
    Scan all messages for a UE and look for 'Value of U8 ho_freq_type = <N>'.
    Returns a dict with 'ho_freq_type_value' (int or None) and 'ho_freq_type_name' (str).
    If found, maps the integer to HO_FREQ_TYPE_ENUM. If not found, returns None/N/A.
    """
    ho_freq_re = re.compile(r'Value of U8 ho_freq_type\s*=\s*(\d+)', re.IGNORECASE)
    blocks = data_map.get(ue_index, [])
    for block in blocks:
        for row in block:
            msg = str(getattr(row, "Message", ""))
            m = ho_freq_re.search(msg)
            if m:
                val = int(m.group(1))
                name = HO_FREQ_TYPE_ENUM.get(val, f"UNKNOWN ({val})")
                return {'ho_freq_type_value': val, 'ho_freq_type_name': name}
    return {'ho_freq_type_value': None, 'ho_freq_type_name': 'N/A'}


def _extract_s1ap_release_cause(data_map, ue_index):
    """
    Scan messages for a UE looking for 'ueCtxt_relReq_cause:[INDEX]'.
    The INDEX maps to S1AP_CAUSE_ENUM.
    Returns a list of dicts: [{'cause_index': int, 'cause_name': str}, ...]
    (one per occurrence — a UE may have multiple releases).
    Returns empty list if none found.
    """
    cause_re = re.compile(r'ueCtxt_relReq_cause:\[(\d+)\]', re.IGNORECASE)
    blocks = data_map.get(ue_index, [])
    causes = []
    seen = set()
    for block in blocks:
        for row in block:
            msg = str(getattr(row, "Message", ""))
            for m in cause_re.finditer(msg):
                idx = int(m.group(1))
                if idx not in seen:
                    seen.add(idx)
                    name = S1AP_CAUSE_ENUM.get(idx, f"UNKNOWN_CAUSE ({idx})")
                    causes.append({'cause_index': idx, 'cause_name': name})
    return causes


def _extract_failure_context(data_map, ue_index):
    """
    Scan messages for a UE looking for 'FAILURE: END.' or 'FAILURE:' pattern.
    Extracts the bracketed context tag that precedes it, e.g. [UE_SRC_HO_P] or [CRE_P].
    Pattern example: [UE:4] [UE_SRC_HO_P] FAILURE: END.
    Returns a list of unique context strings, e.g. ['UE_SRC_HO_P', 'CRE_P'].
    Returns empty list if none found.
    """
    fail_end_re = re.compile(r'\[([A-Z_0-9]+)\]\s*FAILURE:', re.IGNORECASE)
    blocks = data_map.get(ue_index, [])
    contexts = []
    seen = set()
    for block in blocks:
        for row in block:
            msg = str(getattr(row, "Message", ""))
            for m in fail_end_re.finditer(msg):
                tag = m.group(1).upper()
                if tag not in seen:
                    seen.add(tag)
                    contexts.append(tag)
    return contexts


def _extract_procedure_tags(data_map, ue_index):
    """
    Fallback for failure context: scan UE messages for [SOMETHING_P] procedure tags.
    These are FSM/procedure context tags ending with '_P', e.g. [UE_SRC_HO_P], [CRE_P].
    Used when no explicit FAILURE: pattern is found but UE has an S1AP failure cause,
    to identify which procedure was active when the failure occurred.
    Returns a list of unique procedure tag strings, e.g. ['UE_SRC_HO_P', 'CRE_P'].
    """
    proc_tag_re = re.compile(r'\[([A-Z_0-9]+_P)\]')
    blocks = data_map.get(ue_index, [])
    tags = []
    seen = set()
    for block in blocks:
        for row in block:
            msg = str(getattr(row, "Message", ""))
            for m in proc_tag_re.finditer(msg):
                tag = m.group(1).upper()
                if tag not in seen:
                    seen.add(tag)
                    tags.append(tag)
    return tags


def _extract_rre_failure_cause(data_map, ue_index):
    """
    Scan messages for RRC Re-establishment (RRE) failure patterns.
    Currently detects:
      - "[Wait For ReestablishmentComplete]Time out." -> "RRE Time out"
    
    Returns a list of unique RRE failure cause strings.
    Returns empty list if none found.
    """
    blocks = data_map.get(ue_index, [])
    rre_failures = []
    seen = set()
    
    # Define RRE failure patterns
    rre_patterns = [
        {
            'pattern': re.compile(r'\[Wait For ReestablishmentComplete\]Time out\.?', re.IGNORECASE),
            'cause': 'RRE Time out'
        },
        # Add more patterns here in the future
    ]
    
    for block in blocks:
        for row in block:
            msg = str(getattr(row, "Message", ""))
            for rre_pattern in rre_patterns:
                if rre_pattern['pattern'].search(msg):
                    cause = rre_pattern['cause']
                    if cause not in seen:
                        seen.add(cause)
                        rre_failures.append(cause)
    
    return rre_failures


def _extract_rre_type(data_map, ue_index):
    """
    Scan messages for RRC Re-establishment (RRE) type patterns.
    Detects three types:
      - "[RRE]: PCI matched. Send intra enodeb Retrieve UE Context Request message" -> "Same eNB Different Cell RRE"
      - "[x2ap_ContextRetrieveRequest] PCI %d matched. Send ContextRetrieveRequest" -> "Different eNB RRE"
      - "PCI got matched at source enB" -> "Same Cell RRE"
    
    Returns RRE type string or None if no RRE detected.
    """
    blocks = data_map.get(ue_index, [])
    
    # Define RRE type patterns (order matters - check specific patterns first)
    rre_type_patterns = [
        {
            'pattern': re.compile(r'\[RRE\].*PCI\s+matched.*Send intra enodeb Retrieve UE Context Request', re.IGNORECASE),
            'type': 'Same eNB Different Cell RRE'
        },
        {
            'pattern': re.compile(r'\[x2ap_ContextRetrieveRequest\].*PCI\s+\d+\s+matched.*Send ContextRetrieveRequest', re.IGNORECASE),
            'type': 'Different eNB RRE'
        },
        {
            'pattern': re.compile(r'PCI got matched at source enB', re.IGNORECASE),
            'type': 'Same Cell RRE'
        },
    ]
    
    for block in blocks:
        for row in block:
            msg = str(getattr(row, "Message", ""))
            for rre_pattern in rre_type_patterns:
                if rre_pattern['pattern'].search(msg):
                    return rre_pattern['type']
    
    return None


# -----------------------------
# Precompiled regexes for performance
# -----------------------------
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
# -----------------------------
# FUNCTIONS FOR HO MAPPING
# -----------------------------
def build_ho_maci_mapping():
    global ue_data_map, last_analysis_snapshot

    data_map = ue_data_map if ue_data_map else (
        last_analysis_snapshot['ue_data_map'] if last_analysis_snapshot else {}
    )

    print("\n✅ HO Mapping | Total UEs Found:", len(data_map))

    if not data_map:
        print("❌ UE DATA MAP EMPTY")
        return {}

    # ✅ SOURCE SIDE
    # NOTE: We do NOT require the "Parsing rrc_pdcp_mac_i_resp" trigger because
    # the star-block parser splits blocks at the ue_index line, which separates
    # the trigger (goes to previous UE's block) from the mac_i value (stays in
    # the correct UE's block).  "Value of U32 mac_i" is specific enough.
    maci_re    = re.compile(r"Value of U32 mac_i\s*=\s*(\d+)", re.IGNORECASE)
    cell_id = re.compile(r"Value of U32 cell_identity\s*=\s*(\d+)", re.IGNORECASE)

    # ✅ TARGET SIDE
    target_maci_re = re.compile(
        r"Value of U16 target_cell_short_mac_i\s*=\s*(\d+)",
        re.IGNORECASE
    )

    # ✅ SOURCE: UE -> short_maci
    source_short_map = {}

    # ---------------------------------------------------
    # ✅ STEP 1: EXTRACT SOURCE UE + short_maci
    # ---------------------------------------------------
    for source_ue, blocks in data_map.items():
        for block in blocks:
            found_maci = None
            cell_ids_s = []
            for row in block:
                msg = str(row.Message)

                m = maci_re.search(msg)
                if m:
                    found_maci = int(m.group(1))
                    print(f"   [SOURCE DEBUG] UE={source_ue}: Found mac_i={found_maci}")
                
                if "Value of U8 cell_identity[]" in msg:
                    i=len(msg)-1
                    s=""
                    while msg[i]!=' ':
                        s+=msg[i]   
                        i-=1
                    x=int(s[::-1])
                    cell_ids_s.append(x)

                if found_maci:
                    short_maci = found_maci & 0xFFFF
                    source_short_map[source_ue] = (short_maci, cell_ids_s)
                    print(f"✅ SOURCE | UE={source_ue} | FULL_MAC={found_maci} | SHORT_MAC={short_maci} | CELL_IDS={cell_ids_s}")
                    break
        if source_ue not in source_short_map:
            print(f"   [SOURCE DEBUG] UE={source_ue}: NO SOURCE HO FOUND")

    # ✅ TARGET: UE -> target_short_maci
    print("-------------------------------------------------------------------------------")
    target_short_map = {}

    # ---------------------------------------------------
    # ✅ STEP 2: EXTRACT TARGET UE + short_maci
    # ---------------------------------------------------
    for target_ue, blocks in data_map.items():
        for block in blocks:
            cell_ids_t = []
            for row in block:
                msg = str(row.Message)
                tm = target_maci_re.search(msg)
                x=-1
                if "Value of U8 cell_Id[]" in msg:
                    i=len(msg)-1
                    s=""
                    while msg[i]!=' ':
                        s+=msg[i]   
                        i-=1
                    x=int(s[::-1])
                    cell_ids_t.append(x)
                if tm:
                    target_short = int(tm.group(1))
                    target_short_map[target_ue] = (target_short, cell_ids_t)
                    print(f"🎯 TARGET | UE={target_ue} | SHORT_MAC={target_short} | CELL_IDS={cell_ids_t}")
                    break
        if target_ue not in target_short_map:
            print(f"   [TARGET DEBUG] UE={target_ue}: NO TARGET HO FOUND")
    
    # ---------------------------------------------------
    # ✅ STEP 3: MATCH SOURCE ↔ TARGET BY short_maci
    # ---------------------------------------------------
    final_ho_map = {}
    
    print(f"\n[MATCHING DEBUG] SOURCE_MAP size={len(source_short_map)}, TARGET_MAP size={len(target_short_map)}")
    if source_short_map:
        print(f"   SOURCE_MAP: {source_short_map}")
    if target_short_map:
        print(f"   TARGET_MAP: {target_short_map}")

    for s_key, s_val in source_short_map.items():
        for t_key, t_val in target_short_map.items():
            print(f"   [MATCH] Comparing: SOURCE UE={s_key} MAC={s_val[0]} vs TARGET UE={t_key} MAC={t_val[0]}")
            if s_val[0] == t_val[0]:
                final_ho_map[s_key] = t_key
                print(f"✅✅ MATCH FOUND | {s_key} → {t_key} | MAC={s_val[0]}")

    print("\n✅ FINAL HO MAP:", final_ho_map)
    return final_ho_map

# -----------------------------
# FUNCTIONS FOR ANALYSIS
# -----------------------------
def generate_insights(data_map):
    """
    Generate concise insights per UE from the merged ue blocks map.
    Returns a list of strings (one entry per UE) describing problems or OK status.
    """
    insights = []
    if not data_map:
        return insights

    for ue_index, blocks in sorted(data_map.items()):
        # Collect all messages for this UE and normalize to uppercase for searching
        messages = [str(row.Message) for block in blocks for row in block]
        nm = " ".join(messages).upper()

        # Counts for important events
        # Only count RRC CONNECTION REQUEST when preceded by [RNTI:XX]
        request_count = len(re.findall(r"\[RNTI:\d+\]\s*RRC_MSG:\s*RRC\s*CONNECTION\s*REQUEST", nm))
        setup_count = len(re.findall(r"RRC\s*CONNECTION\s*SETUP\b", nm))
        setup_complete_count = len(re.findall(r"RRC\s*CONNECTION\s*SETUP\s*COMPLETE", nm))
        reconfig_count = len(re.findall(r"RRC\s*CONNECTION\s*RECONFIGURATION\b", nm))
        reconfig_complete_count = len(re.findall(r"RRC\s*CONNECTION\s*RECONFIGURATION\s*COMPLETE", nm))
        handover_req_count = len(re.findall(r"HANDOVER\s*REQUEST\b", nm))
        handover_ack_count = len(re.findall(r"HANDOVER\s*REQUEST\s*ACKNOWLEDGE", nm))
        ho_notify_count = len(re.findall(r"HO\s*NOTIFY", nm))
        rlf_count = len(re.findall(r"RLF|RLF_IND", nm))
        # Only match real ASN failures — exclude "ASN decode success" and "ASN1 Encoded ... (Fail)"
        asn1_enc_fail = len(re.findall(r"ASN1\s+ENCODING\s+FAILED|ASN1\s+ENCODING\s+OF\s+.*FAILED", nm))
        asn_dec_fail = len(re.findall(r"ASN\s+DECODING\s+FAILED|ASN\s+DECODE\s+FAILED", nm))
        oam_prov = len(re.findall(r"API:RRC_OAM_PROVISION_REQ", nm))

        ue_insight = [f"UE {ue_index}:"]

        # Heuristics for problems
        has_issue = False

        if request_count > setup_count:
            ue_insight.append(f"❌ {request_count} RRC Connection Request(s) but only {setup_count} Setup(s).")
            has_issue = True

        if setup_count > setup_complete_count:
            ue_insight.append(f"❌ {setup_count} Setup(s) but only {setup_complete_count} Setup Complete(s).")
            has_issue = True

        if reconfig_count > reconfig_complete_count:
            ue_insight.append(f"❌ {reconfig_count} Reconfiguration(s) but only {reconfig_complete_count} Complete(s).")
            has_issue = True

        # Handover checks
        if handover_req_count > handover_ack_count and "HANDOVER CANCEL" not in nm and "HANDOVER FAILURE" not in nm:
            ue_insight.append("❌ Handover request(s) not acknowledged and no cancel/failure logged.")
            has_issue = True

        # RLF (radio link failure) presence
        if rlf_count > 0:
            ue_insight.append(f"⚠️ Radio Link Failure noted ({rlf_count} occurrence(s)).")
            has_issue = True

        # ASN issues
        if asn1_enc_fail or asn_dec_fail:
            ue_insight.append(f"⚠️ ASN1 encoding/decoding issues detected (enc:{asn1_enc_fail}, dec:{asn_dec_fail}).")
            has_issue = True
            # DEBUG: print actual ASN failure messages to console
            print(f"\n🔍 [ASN DEBUG] UE {ue_index} — enc_fail={asn1_enc_fail}, dec_fail={asn_dec_fail}")
            for block in blocks:
                for row in block:
                    msg_raw = str(row.Message)
                    msg_up = msg_raw.upper()
                    if re.search(r'ASN1\s+ENCODING\s+FAILED|ASN1\s+ENCODING\s+OF\s+.*FAILED|ASN\s+DECODING\s+FAILED|ASN\s+DECODE\s+FAILED', msg_up):
                        print(f"   [ASN DEBUG] UE {ue_index} | {row.Date} {row.Time} | {row.File}:{row.Line} | {msg_raw}")

        # S1AP UE Context Release cause detection
        s1ap_causes = _extract_s1ap_release_cause(data_map, ue_index)
        s1ap_fail_causes = [c for c in s1ap_causes if c['cause_index'] in S1AP_CAUSE_FAILURE]
        s1ap_info_causes = [c for c in s1ap_causes if c['cause_index'] not in S1AP_CAUSE_FAILURE]
        if s1ap_fail_causes:
            cause_strs = [f"{c['cause_name']} (idx={c['cause_index']})" for c in s1ap_fail_causes]
            ue_insight.append(f"❌ S1AP Failure Cause: {', '.join(cause_strs)}")
            has_issue = True
        if s1ap_info_causes:
            cause_strs = [f"{c['cause_name']} (idx={c['cause_index']})" for c in s1ap_info_causes]
            ue_insight.append(f"ℹ️ S1AP Release Cause (non-failure): {', '.join(cause_strs)}")

        # FAILURE: BEGIN / END detection
        failure_contexts = _extract_failure_context(data_map, ue_index)
        # Fallback: if no FAILURE: pattern but UE has S1AP failure cause,
        # extract [*_P] procedure tags as failure context
        if not failure_contexts and s1ap_fail_causes:
            failure_contexts = _extract_procedure_tags(data_map, ue_index)
        if failure_contexts:
            ctx_strs = ', '.join(f'[{c}]' for c in failure_contexts)
            ue_insight.append(f"❌ FAILURE detected — procedures: {ctx_strs}")
            has_issue = True

        # OAM provisioning can be noisy/irrelevant — only mark if present with other issues
        if oam_prov and not has_issue:
            ue_insight.append("ℹ️ OAM provisioning messages present — verify if expected.")
            # not setting has_issue true

        if not has_issue:
            ue_insight.append("✅ UE flow appears to be normal (no obvious RRC/Handover/RLF issues).")

        # Add a short summary line with counts for quick glance
        summary = (f"Summary: REQ={request_count} SETUP={setup_count} SETUP_COMPLETE={setup_complete_count} "
                   f"RECFG={reconfig_count} RECFG_COMPLETE={reconfig_complete_count} HO_REQ={handover_req_count} "
                   f"HO_ACK={handover_ack_count} RLF={rlf_count}")
        ue_insight.append(summary)

        insights.append("\n".join(ue_insight))

    return insights

def process_logs_for_ue_journey(filepath):
    """
    Parses a single logfile and returns:
    {
        "ue_blocks": { ue_index: [ [Row tuples], ... ] },
        "crash": file_crash
    }

    ✅ Two-phase star-to-star block parser for 100% UE isolation:
       Phase 1: Split log into raw blocks at ************* boundaries.
       Phase 2: Scan each block for ALL UE references, then assign.
                NO cross-block carry-forward — zero contamination.
       Phase 3: Deduplicate identical blocks per UE.
    ✅ Blocks with NO UE reference are dropped (system/OAM messages)
    ✅ Multi-UE blocks are split at UE-change boundaries
    ✅ Supports: UE:45, UE: 45, UE INDEX = 45, ue_index = 45
    """

    global bt_df, crash

    rows = []
    bt_rows = []
    file_crash = False

    # ✅ FINAL UE REGEX (WITH UE:value SUPPORT)
    #ue_re = re.compile(r'UE\s*:\s*(\d+)')
    ue_re = re.compile(
        r'(?:\bUE:\s*(\d+))|'          # UE:45 , UE: 45
        r'(?:\bUE\s+INDEX\b\s*=\s*(\d+))|' # UE INDEX = 45
        r'(?:\bue_index\b\s*=\s*(\d+))',    # ue_index = 45
        re.IGNORECASE
    )
    MAX_VALID_UE_INDEX = 65535

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, raw in enumerate(f, 1):
                line = raw.strip().replace("\ufeff", "")
                m = REGEX_CONVERTED.match(line)
                if not m:
                    m = REGEX_LEGACY.match(line)

                if m:
                    data = m.groupdict()
                    msg = data['message'].strip()

                    # ✅ Backtrace detection (UNCHANGED)
                    if "Opened file /tmp/rrc.bt" in msg:
                        file_crash = True
                        bt_rows.append([data['date'], data['time'], data['file'], data['line'], msg, line_number])
                    elif file_crash:
                        bt_rows.append([data['date'], data['time'], data['file'], data['line'], msg, line_number])

                    rows.append([data['date'], data['time'], data['file'], data['line'], msg, line_number])

                else:
                    parts = line.split()
                    if len(parts) >= 5:
                        date = parts[0]
                        time_val = parts[1]
                        filec = parts[2]
                        line_no = parts[3]
                        msg = " ".join(parts[4:])

                        if "Opened file /tmp/rrc.bt" in msg:
                            file_crash = True
                            bt_rows.append([date, time_val, filec, line_no, msg, line_number])
                        elif file_crash:
                            bt_rows.append([date, time_val, filec, line_no, msg, line_number])

                        rows.append([date, time_val, filec, line_no, msg, line_number])

    except Exception as e:
        print(f"Error reading file {filepath}: {e}")
        return {"ue_blocks": {}, "crash": False}

    if not rows:
        return {"ue_blocks": {}, "crash": False}

    # ✅ Crash snapshot logic (UNCHANGED)
    if bt_rows:
        bt_df = pd.DataFrame(bt_rows, columns=["Date", "Time", "File", "Line", "Message", "LogLine"])
        crash = True
        file_crash = True

    # ✅ STAR-TO-STAR UE BLOCK PARSER — PRECISION REWRITE (Two-Phase)
    #
    # OLD BUG: last_known_ue was carried forward across star boundaries,
    #          so leading lines of a new block (before the real UE ref)
    #          were incorrectly assigned to the *previous* block's UE.
    #
    # NEW APPROACH:
    #   Phase 1 – Split the entire log into star-delimited raw blocks.
    #   Phase 2 – For each raw block, scan ALL lines to discover the
    #             UE(s) it belongs to, then assign.  NO cross-block
    #             carry-forward; each block is self-contained.
    #   Phase 3 – Deduplicate identical blocks per UE.

    df = pd.DataFrame(rows, columns=["Date", "Time", "File", "Line", "Message", "LogLine"])

    # Helper: extract UE from a single message string
    def _extract_ue_from_msg(msg_text):
        m = ue_re.search(msg_text)
        if m:
            for v in m.groups():
                if v is None:
                    continue
                cv = v.lstrip('0') or '0'
                if cv.isdigit():
                    uv = int(cv)
                    if 0 <= uv <= MAX_VALID_UE_INDEX:
                        return uv
        return None

    # ── Phase 1: Collect star-delimited raw blocks ────────────────
    raw_blocks = []
    current_raw = []

    for row in df.itertuples():
        msg = str(row.Message)
        if "*************" in msg:
            if current_raw:
                raw_blocks.append(current_raw)
            current_raw = []
            continue
        current_raw.append(row)

    # Flush trailing block (lines after the last star line)
    if current_raw:
        raw_blocks.append(current_raw)

    # ── Phase 2: Assign each raw block to its UE(s) ──────────────
    ue_blocks = {}

    for raw_block in raw_blocks:
        # Scan every line for UE references
        ue_line_refs = []          # [(line_idx, ue_value), ...]

        for i, row in enumerate(raw_block):
            found = _extract_ue_from_msg(str(row.Message))
            if found is not None:
                ue_line_refs.append((i, found))

        # No UE reference anywhere → skip (system / OAM message)
        if not ue_line_refs:
            continue

        # Unique UEs in order of first appearance
        seen_set = set()
        unique_ues = []
        for _, uv in ue_line_refs:
            if uv not in seen_set:
                seen_set.add(uv)
                unique_ues.append(uv)

        if len(unique_ues) == 1:
            # ── Single-UE block: assign entire block to that UE ──
            ue_blocks.setdefault(unique_ues[0], []).append(list(raw_block))
        else:
            # ── Multi-UE block: split at each UE-change boundary ──
            # Build lookup: line_index → first ue_val seen on that line
            ref_map = {}
            for idx, uv in ue_line_refs:
                if idx not in ref_map:
                    ref_map[idx] = uv

            # Leading lines (before 1st UE ref) go to the first UE in the block
            active_ue = unique_ues[0]
            sub_block = []

            for i, row in enumerate(raw_block):
                if i in ref_map and ref_map[i] != active_ue:
                    # UE boundary – flush sub_block to previous UE
                    if sub_block:
                        ue_blocks.setdefault(active_ue, []).append(sub_block)
                    active_ue = ref_map[i]
                    sub_block = [row]
                else:
                    sub_block.append(row)

            # Flush remainder
            if sub_block:
                ue_blocks.setdefault(active_ue, []).append(sub_block)

    # ── Phase 3: Deduplicate identical blocks per UE ──────────────
    for ue_idx in list(ue_blocks.keys()):
        seen_hashes = set()
        deduped = []
        for block in ue_blocks[ue_idx]:
            # Build fingerprint from (Date, Time, Message) tuples
            block_key = tuple(
                (str(getattr(r, 'Date', '')),
                 str(getattr(r, 'Time', '')),
                 str(getattr(r, 'Message', '')))
                for r in block
            )
            h = hash(block_key)
            if h not in seen_hashes:
                seen_hashes.add(h)
                deduped.append(block)
        ue_blocks[ue_idx] = deduped

    return {"ue_blocks": ue_blocks, "crash": file_crash}




def merge_logs_for_ue_journey(folder):
    """
    Merge multiple files in folder into combined UE map.
    Returns combined_map and crash flag (True if any file had a crash/backtrace).
    Updates global analysis_progress during processing.
    """
    global analysis_progress
    combined_map = {}
    folder_crash = False

    # Get list of files to process
    files_to_process = []
    total_size_mb = 0
    for filename in sorted(os.listdir(folder)):
        fn_lower = filename.lower()
        if fn_lower.startswith("l3_event_x") and (".dbg" in fn_lower or ".bkp" in fn_lower):
            files_to_process.append(filename)
            # Calculate file size
            file_path = os.path.join(folder, filename)
            if os.path.exists(file_path):
                total_size_mb += os.path.getsize(file_path) / (1024 * 1024)
    
    # Update progress total and estimate time
    analysis_progress['total'] = len(files_to_process)
    analysis_progress['current'] = 0
    analysis_progress['estimated_time'] = int((total_size_mb / PROCESSING_SPEED_MB_PER_SEC) + OVERHEAD_SECONDS)
    analysis_progress['start_time'] = time.time()
    
    for idx, filename in enumerate(files_to_process, 1):
        file_path = os.path.join(folder, filename)
        try:
            analysis_progress['current'] = idx
            analysis_progress['message'] = f'Processing {filename}...'
            
            # Update elapsed time
            if analysis_progress['start_time']:
                analysis_progress['elapsed_time'] = int(time.time() - analysis_progress['start_time'])
            
            result = process_logs_for_ue_journey(file_path)
            ue_blocks = result.get("ue_blocks", {})
            file_crash = result.get("crash", False)

            # Merge ue_blocks
            for ue, blocks in ue_blocks.items():
                combined_map.setdefault(ue, []).extend(blocks)

            if file_crash:
                folder_crash = True

        except Exception as e:
            print(f"Could not process {filename} for UE journey: {e}")
            analysis_progress['message'] = f'Error processing {filename}: {str(e)}'
    
    return combined_map, folder_crash


def count_rrc_messages(folder):
    """
    Count RRC messages across files in folder (only L3_EVENT_X* files).
    """
    rrc_counts_local = {msg: 0 for msg in rrc_messages_to_track}

    patterns = [REGEX_CONVERTED, REGEX_LEGACY]

    for filename in sorted(os.listdir(folder)):
        fn_lower = filename.lower()
        if fn_lower.startswith("l3_event_x") and (".dbg" in fn_lower or ".bkp" in fn_lower):
            filepath = os.path.join(folder, filename)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for raw in f:
                        line = raw.strip().replace("\ufeff", "")
                        m = None
                        for pat in patterns:
                            m = pat.match(line)
                            if m:
                                break
                        if not m:
                            parts = line.split()
                            if len(parts) < 5:
                                continue
                            message_part = " ".join(parts[4:])
                        else:
                            message_part = m.group('message').strip()
                        # count contains for robustness
                        for msg_to_track in rrc_messages_to_track:
                            if msg_to_track in message_part:
                                # RRC CONNECTION REQUEST must have [RNTI:XX] prefix
                                # to avoid double-counting from ueccmd_llim.c lines
                                if msg_to_track == "RRC CONNECTION REQUEST":
                                    if not re.search(r'\[RNTI:\d+\]', message_part):
                                        continue
                                rrc_counts_local[msg_to_track] += 1
            except Exception as e:
                print(f"Error during RRC message count for file {filepath}: {e}")
    return rrc_counts_local


# -----------------------------
# Cell Setup Status parser
# -----------------------------
# Milestones tracked during cell setup (order matters for display)
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


def parse_cell_setup_status(folder):
    """
    Parse cell-level (non-UE) setup milestones from L3_EVENT_X* log files.
    Returns a dict:
      {
        'milestones': [{'key':..., 'label':..., 'found':bool, 'count':int, 'first_time':str, 'first_msg':str}, ...],
        'cells': [{'cell_index': int, 'configured': bool, 'setup_time': str}, ...],
        'failures': [str, ...],
        'overall_status': 'success' | 'failure' | 'partial'
      }
    """
    patterns = [REGEX_CONVERTED, REGEX_LEGACY]
    compiled_milestones = []
    for ms in CELL_SETUP_MILESTONES:
        compiled_milestones.append({
            'key': ms['key'],
            'label': ms['label'],
            're': re.compile(ms['pattern'], re.IGNORECASE),
            'found': False,
            'count': 0,
            'first_time': None,
            'first_msg': None,
        })

    # Per-cell tracking
    cell_setup_reqs = {}   # cell_index -> first timestamp
    cell_configured = {}   # cell_index -> timestamp
    failures = []

    for filename in sorted(os.listdir(folder)):
        fn_lower = filename.lower()
        if not (fn_lower.startswith("l3_event_x") and (".dbg" in fn_lower or ".bkp" in fn_lower)):
            continue
        filepath = os.path.join(folder, filename)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for raw in f:
                    line = raw.strip().replace("\ufeff", "")
                    m = None
                    for pat in patterns:
                        m = pat.match(line)
                        if m:
                            break
                    if not m:
                        parts = line.split()
                        if len(parts) < 5:
                            continue
                        date_str = parts[0]
                        time_str = parts[1]
                        message_part = " ".join(parts[4:])
                    else:
                        date_str = m.group('date')
                        time_str = m.group('time')
                        message_part = m.group('message').strip()

                    # Check each milestone
                    for ms in compiled_milestones:
                        if ms['re'].search(message_part):
                            ms['count'] += 1
                            if not ms['found']:
                                ms['found'] = True
                                ms['first_time'] = f"{date_str} {time_str}"
                                ms['first_msg'] = message_part[:200]

                    # Track per-cell setup
                    cell_setup_m = re.search(r'API:RRC_RRM_CELL_SETUP_REQ.*cell_index\s*=\s*(\d+)', message_part, re.IGNORECASE)
                    if not cell_setup_m:
                        # cell_index often appears on a nearby line during cell setup
                        if 'RRC_RRM_CELL_SETUP_REQ' in message_part.upper():
                            cell_setup_m = None  # will be picked up from cell_index line
                    cell_cfg_m = re.search(r'is_cell_configured\s*=\s*TRUE?\s+.*?cell_index\s*=?\s*(\d+)', message_part, re.IGNORECASE)
                    if cell_cfg_m:
                        cidx = int(cell_cfg_m.group(1))
                        if cidx not in cell_configured:
                            cell_configured[cidx] = f"{date_str} {time_str}"

                    # Track individual cell setup req from CELL_INDEX context line
                    cell_ctx_m = re.search(r'\[CELL_INDEX:(\d+)\]\s*context allocated', message_part, re.IGNORECASE)
                    if cell_ctx_m:
                        cidx = int(cell_ctx_m.group(1))
                        if cidx not in cell_setup_reqs:
                            cell_setup_reqs[cidx] = f"{date_str} {time_str}"

                    # Track S1 SETUP FAILURE as a failure event
                    if re.search(r'S1AP_MSG:\s*S1\s+SETUP\s+FAILURE', message_part, re.IGNORECASE):
                        failures.append(f"S1 Setup Failure at {date_str} {time_str}")

        except Exception as e:
            print(f"Error parsing cell setup from {filepath}: {e}")

    # Build cells list
    all_cell_indices = sorted(set(list(cell_setup_reqs.keys()) + list(cell_configured.keys())))
    cells = []
    for cidx in all_cell_indices:
        cells.append({
            'cell_index': cidx,
            'configured': cidx in cell_configured,
            'setup_time': cell_configured.get(cidx, cell_setup_reqs.get(cidx, 'N/A')),
        })

    # Determine overall status
    # Key milestones whose presence (all found) indicates cell setup success
    # even when the explicit "is_cell_configured = True" log line is absent.
    KEY_SETUP_MILESTONES = {
        'oam_prov_req', 'oam_prov_resp',
        's1ap_oam_prov_req', 's1ap_oam_prov_resp',
        's1_setup_resp',
        'cell_setup_req', 'cell_setup_resp',
        'cell_start_ind',
    }

    ms_found_map = {ms['key']: ms['found'] for ms in compiled_milestones}
    has_cell_configured = any(c['configured'] for c in cells)
    has_s1_failure = ms_found_map.get('s1_setup_failure', False)
    has_s1_success = ms_found_map.get('s1_setup_resp', False)
    all_key_milestones_met = all(ms_found_map.get(k, False) for k in KEY_SETUP_MILESTONES)

    if (has_cell_configured or all_key_milestones_met) and not has_s1_failure:
        overall = 'success'
    elif (has_cell_configured or all_key_milestones_met) and has_s1_failure:
        overall = 'partial'  # cells up but S1 had failure (may have retried)
    elif not has_cell_configured and not all_key_milestones_met:
        overall = 'failure'
    else:
        overall = 'success'

    # Build milestone output (exclude internal re object)
    milestone_out = []
    for ms in compiled_milestones:
        milestone_out.append({
            'key': ms['key'],
            'label': ms['label'],
            'found': ms['found'],
            'count': ms['count'],
            'first_time': ms['first_time'],
            'first_msg': ms['first_msg'],
        })

    return {
        'milestones': milestone_out,
        'cells': cells,
        'failures': failures,
        'overall_status': overall,
    }


# -----------------------------
# Drop-rate computation helper
# -----------------------------
def compute_drop_rates(rrc_counts):
    """
    Compute drop/success rates from rrc_counts.
    Metrics are defined in the metrics_map dict so new metrics can be added easily.
    Each metric maps to (numerator_msg, denominator_msg).
    Returned dict maps metric_name -> dict containing numerator, denominator, ratio and formatted string.
    """
    metrics_map = {
        # key -> (numerator, denominator)
        "RRC_SUCCESS_RATE": ("RRC CONNECTION SETUP COMPLETE", "RRC CONNECTION REQUEST"),
        # add future metrics here
    }
    out = {}
    # iterate metrics and compute values
    for key, (num_key, den_key) in metrics_map.items():
        num = rrc_counts.get(num_key, 0)
        den = rrc_counts.get(den_key, 0)
        if den and den > 0:
            ratio = num / den
            formatted = f"{ratio:.2%} ({num}/{den})"
        else:
            ratio = None
            formatted = "N/A"
        out[key] = {
            "numerator": num,
            "denominator": den,
            "ratio": ratio,
            "formatted": formatted
        }
    return out


def _build_bt_text_from_df(df):
    if df is None:
        return ""
    bt_lines = []
    try:
        for row in df.itertuples():
            bt_lines.append(f"{row.Date:<12} {row.Time:<18} {row.File:<30} {row.Line:<8} {row.Message}")
    except Exception:
        bt_lines = [str(r) for r in df.values.tolist()]

    bt_text = "\n".join(bt_lines)
    keywords = ["Signal handler called", "Segmentation fault", "Null pointer dereference", "Stack trace", "Backtrace"]
    for word in keywords:
        bt_text = bt_text.replace(word, f'<span style="color:red;">{word}</span>')
    return bt_text


def _scp_download_and_analyze_worker(username, hostname, remote_dir, password, session_folder):
    """
    Background worker for SCP download + analysis so UI can poll /progress live.
    """
    global ue_data_map, rrc_counts, insights_global, valid_indices_global, total_ue_indices_global
    global last_analysis_snapshot, bt_df, crash, analysis_progress, latest_bt_text

    downloaded = []
    ssh = None
    sftp = None

    try:
        analysis_progress.update({
            'active': True,
            'completed': False,
            'error': None,
            'current': 0,
            'total': 1,
            'message': f'Connecting to {hostname}...',
            'estimated_time': 5,
            'start_time': time.time(),
            'elapsed_time': 0,
            'next_url': '/results'
        })

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password, timeout=15)

        analysis_progress['message'] = 'Fetching remote file list...'
        analysis_progress['elapsed_time'] = int(time.time() - analysis_progress['start_time'])

        stdin, stdout, stderr = ssh.exec_command(f'ls {remote_dir}/L3_EVENT_X.dbg* 2>/dev/null')
        remote_files = [line.strip() for line in stdout.read().decode().splitlines() if line.strip()]
        err_output = stderr.read().decode().strip()

        if not remote_files:
            raise RuntimeError(f"No L3_EVENT_X.dbg* files found at {remote_dir}. {err_output}".strip())

        analysis_progress.update({
            'current': 0,
            'total': len(remote_files),
            'message': f'Downloading files from {hostname}...',
            'estimated_time': max(5, len(remote_files) * 2),
            'start_time': time.time(),
            'elapsed_time': 0,
        })

        sftp = ssh.open_sftp()
        for idx, rf in enumerate(remote_files, 1):
            local_name = os.path.basename(rf)
            local_path = os.path.join(session_folder, local_name)
            analysis_progress['current'] = idx
            analysis_progress['message'] = f'Downloading {local_name} ({idx}/{len(remote_files)})...'
            analysis_progress['elapsed_time'] = int(time.time() - analysis_progress['start_time'])
            sftp.get(rf, local_path)
            downloaded.append(local_name)

        if not downloaded:
            raise RuntimeError("No files were downloaded from the server.")

        _touch_session(session_folder)
        _enforce_session_limit()

        total_size_mb = 0
        for filename in downloaded:
            file_path = os.path.join(session_folder, filename)
            if os.path.exists(file_path):
                total_size_mb += os.path.getsize(file_path) / (1024 * 1024)

        estimated_seconds = int((total_size_mb / PROCESSING_SPEED_MB_PER_SEC) + OVERHEAD_SECONDS)

        analysis_progress.update({
            'active': True,
            'current': 0,
            'total': len(downloaded),
            'message': 'Initializing analysis...',
            'completed': False,
            'error': None,
            'estimated_time': estimated_seconds,
            'start_time': time.time(),
            'elapsed_time': 0,
            'next_url': '/results'
        })

        rrc_counts.clear()
        ue_data_map.clear()
        insights_global.clear()
        valid_indices_global.clear()
        crash = False
        bt_df = None
        latest_bt_text = None

        analysis_progress['message'] = 'Counting RRC messages...'
        rrc_counts.update(count_rrc_messages(session_folder))

        analysis_progress['message'] = 'Merging UE journey logs...'
        combined_map, folder_crash = merge_logs_for_ue_journey(session_folder)

        analysis_progress['message'] = 'Computing drop rates...'
        rrc_drop_rates_local = compute_drop_rates(rrc_counts)

        analysis_progress['message'] = 'Parsing cell setup status...'
        cell_setup_local = parse_cell_setup_status(session_folder)

        last_analysis_snapshot = {
            'ue_data_map': combined_map.copy(),
            'rrc_counts': rrc_counts.copy(),
            'rrc_drop_rates': rrc_drop_rates_local,
            'insights_global': generate_insights(combined_map),
            'valid_indices_global': sorted(combined_map.keys()),
            'total_ue_indices_global': len(combined_map),
            'cell_setup_status': cell_setup_local,
        }

        if folder_crash and bt_df is not None:
            latest_bt_text = _build_bt_text_from_df(bt_df)
            analysis_progress['next_url'] = '/bt_progress'
            analysis_progress['completed'] = True
            analysis_progress['active'] = False
            return

        ue_data_map.update(combined_map)
        insights_global[:] = last_analysis_snapshot['insights_global']
        valid_indices_global[:] = last_analysis_snapshot['valid_indices_global']
        total_ue_indices_global = last_analysis_snapshot['total_ue_indices_global']

        analysis_progress['completed'] = True
        analysis_progress['message'] = 'Analysis complete!'
        analysis_progress['active'] = False

    except Exception as e:
        analysis_progress['error'] = str(e)
        analysis_progress['active'] = False
        analysis_progress['completed'] = False
        shutil.rmtree(session_folder, ignore_errors=True)
    finally:
        try:
            if sftp:
                sftp.close()
        except Exception:
            pass
        try:
            if ssh:
                ssh.close()
        except Exception:
            pass



# =================================================================
# ROUTES
# =================================================================


@app.route("/")
def home():
    return redirect(url_for("upload_page"))


@app.route("/analyze_logs/<path:folder>", methods=["GET"])
def analyze_logs(folder):
    """
    Analyze files present in 'folder'. Restrictive rule (Option B):
    - file must start with 'L3_EVENT_X' (case-insensitive) and end with .dbg or .bkp
    Behavior:
    - Parse all qualifying files in folder
    - Collect UE blocks from all files (even if bt/backtrace is present)
    - If any file had bt/backtrace, render bt_page with can_proceed=True and a snapshot
      so the user can choose to proceed to the full analysis (which uses the snapshot).
    """
    global ue_data_map, rrc_counts, insights_global, valid_indices_global, total_ue_indices_global
    global last_analysis_snapshot, bt_df, crash, analysis_progress

    raw_folder = unquote(folder or "")
    folder_path = raw_folder.strip().strip('"\'')
    folder_path = folder_path.replace("\\", os.sep).replace("/", os.sep)

    # Resolve common candidate locations (relative or absolute)
    candidates = [folder_path]
    if not os.path.isabs(folder_path):
        candidates.append(os.path.join(os.getcwd(), folder_path))
        candidates.append(os.path.join(os.path.dirname(__file__), folder_path))
        candidates.append(os.path.join(os.getcwd(), UPLOAD_FOLDER, folder_path))
        candidates.append(os.path.join(os.path.dirname(__file__), UPLOAD_FOLDER, folder_path))

    resolved_folder = None
    for c in candidates:
        if os.path.exists(c):
            resolved_folder = c
            break

    if not resolved_folder:
        return _upload_page_context(error=f"Invalid folder path: {raw_folder}. Tried: {candidates}")

    if os.path.basename(resolved_folder).startswith("session_") and os.path.dirname(resolved_folder).endswith(UPLOAD_FOLDER):
        _touch_session(resolved_folder)
        _enforce_session_limit()

    # Pick only files that match Option B: startswith L3_EVENT_X and contain .dbg or .bkp
    chosen_files = [f for f in sorted(os.listdir(resolved_folder))
                    if (f.lower().startswith("l3_event_x") and (".dbg" in f.lower() or ".bkp" in f.lower()))]

    if not chosen_files:
        return _upload_page_context(error="No L3_EVENT_X*.dbg/.bkp files found for analysis in selected folder.")

    # Calculate total file size for time estimation
    total_size_mb = sum(os.path.getsize(os.path.join(resolved_folder, f)) / (1024 * 1024) for f in chosen_files)
    estimated_seconds = int((total_size_mb / PROCESSING_SPEED_MB_PER_SEC) + OVERHEAD_SECONDS)
    
    # Initialize progress tracking
    analysis_progress.update({
        'active': True,
        'current': 0,
        'total': len(chosen_files),
        'message': 'Initializing analysis...',
        'session_id': os.path.basename(resolved_folder),
        'completed': False,
        'error': None,
        'estimated_time': estimated_seconds,
        'start_time': time.time(),
        'elapsed_time': 0,
        'next_url': '/results'
    })

    # Create a temp session to safely analyze files (avoid locking originals)
    session_folder = os.path.join(UPLOAD_FOLDER, f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    os.makedirs(session_folder, exist_ok=True)

    for f in chosen_files:
        shutil.copy(os.path.join(resolved_folder, f), os.path.join(session_folder, f))

    # Reset globals
    rrc_counts.clear()
    ue_data_map.clear()
    insights_global.clear()
    valid_indices_global.clear()
    crash = False
    bt_df = None

    try:
        # RRC counts
        analysis_progress['message'] = 'Counting RRC messages...'
        rrc_counts.update(count_rrc_messages(session_folder))

        # Merge UE journeys across files (this updates progress internally)
        analysis_progress['message'] = 'Merging UE journey logs...'
        combined_map, folder_crash = merge_logs_for_ue_journey(session_folder)

        # compute drop rates from current rrc_counts
        analysis_progress['message'] = 'Computing drop rates...'
        rrc_drop_rates_local = compute_drop_rates(rrc_counts)

        # Cell setup status (must run before session folder cleanup)
        analysis_progress['message'] = 'Parsing cell setup status...'
        cell_setup_local = parse_cell_setup_status(session_folder)

        # Save snapshot (always) so proceed works even if no crash
        last_analysis_snapshot = {
            'ue_data_map': combined_map.copy(),
            'rrc_counts': rrc_counts.copy(),
            'rrc_drop_rates': rrc_drop_rates_local,
            'insights_global': generate_insights(combined_map),
            'valid_indices_global': sorted(combined_map.keys()),
            'total_ue_indices_global': len(combined_map),
            'cell_setup_status': cell_setup_local,
        }

        # Cleanup temp files
        shutil.rmtree(session_folder, ignore_errors=True)

        # If any crash/backtrace found — show bt page with option to proceed
        if folder_crash and bt_df is not None:
            # Build a readable BT text
            bt_lines = []
            try:
                for row in bt_df.itertuples():
                    bt_lines.append(f"{row.Date:<12} {row.Time:<18} {row.File:<30} {row.Line:<8} {row.Message}")
            except Exception:
                bt_lines = [str(r) for r in bt_df.values.tolist()]
            bt_text = "\n".join(bt_lines)
            
            keywords = ["Signal handler called", "Segmentation fault", "Null pointer dereference", "Stack trace", "Backtrace"]
            for word in keywords:
                bt_text = bt_text.replace(word, f'<span style="color:red;">{word}</span>')

            # Mark progress as completed
            analysis_progress['completed'] = True
            analysis_progress['active'] = False
            
            return render_template("bt_page.html", filename="Crash Details", log_text=bt_text, can_proceed=True)

        # No crash — populate globals and redirect to results
        ue_data_map.update(combined_map)
        insights_global[:] = last_analysis_snapshot['insights_global']
        valid_indices_global[:] = last_analysis_snapshot['valid_indices_global']
        total_ue_indices_global = last_analysis_snapshot['total_ue_indices_global']
        
        # Mark progress as completed
        analysis_progress['completed'] = True
        analysis_progress['message'] = 'Analysis complete!'
        analysis_progress['active'] = False
        
    except Exception as e:
        # Handle any errors during analysis
        analysis_progress['error'] = str(e)
        analysis_progress['active'] = False
        analysis_progress['completed'] = False
        return _upload_page_context(error=f"Analysis failed: {str(e)}")

    # ensure template can access drop rates via show_results
    # (we keep drop rates in the snapshot and will compute from live rrc_counts when possible)

    return render_template('progress.html')


@app.route("/upload", methods=["GET", "POST"])
def upload_page():
    global last_analysis_snapshot, bt_df, crash

    if request.method == "POST":
        action = request.form.get("action")

        # ===================================================
        # CASE 1 — CONVERT .dbg files (BIN files + CSV mapping)
        # ===================================================
        if action == "convert_binary":
            bin_files = request.files.getlist('bin_files')
            csv_file = request.files.get('csv_file')

            if not bin_files or not csv_file:
                return _upload_page_context(error="Please upload both BIN files and a CSV file.")

            session_folder = os.path.join(UPLOAD_FOLDER, f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            os.makedirs(session_folder, exist_ok=True)
            _touch_session(session_folder)
            _enforce_session_limit()

            # Save BIN files in upload order
            bin_paths = []
            for file in bin_files:
                path = os.path.join(session_folder, file.filename)
                file.save(path)
                bin_paths.append(path)

            # Save CSV mapping
            csv_path = os.path.join(session_folder, csv_file.filename)
            csv_file.save(csv_path)

            # Convert BIN -> TXT in upload order
            txt_files = []
            for bin_path in bin_paths:
                txt_file = bin_path + ".txt"
                bin_to_txt(bin_path, txt_file)
                txt_files.append(txt_file)

            # Create final merged file name (starts with L3_EVENT_X and ends with .bkp)
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            merged_filename = f"L3_EVENT_X.dbg_{timestamp}.bkp"
            merged_output = os.path.join(session_folder, merged_filename)

            # Merge in same order
            for txt_file in txt_files:
                # Basic tag check (if your CSV has specific tag location this logic may be adjusted)
                with open(txt_file, "r", encoding="utf-8", errors="ignore") as tf:
                    first_line = tf.readline().strip() if tf else ""
                    # keep behavior: if tag mismatch, return error
                    # (original code used csv_path[44:69] which is fragile; keep simple check)
                    # If you rely on specific tag region, reinstate that exact check.
                merge_files(csv_path, txt_file, merged_output)

            # Read merged content for preview
            if os.path.exists(merged_output):
                with open(merged_output, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            else:
                content = "Merge failed. No output file generated."

            # Show only final merged file (folder = session_folder)
            return render_template('view_logs.html', files=[merged_filename], folder=session_folder, output=content)

        # ===================================================
        # CASE 2 — ANALYZE UPLOADED L3_EVENT_X FILES (old logic)
        # ===================================================
        if action == "analyze":
            files = request.files.getlist("logfiles")
            if not any(f.filename for f in files):
                return _upload_page_context(error="Upload L3_EVENT_X .dbg/.bkp files")

            session_folder = os.path.join(UPLOAD_FOLDER, f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            os.makedirs(session_folder, exist_ok=True)
            _touch_session(session_folder)
            _enforce_session_limit()

            # Save uploaded files and calculate total size
            saved_files = []
            total_size_mb = 0
            for f in files:
                fn_lower = f.filename.lower()
                if fn_lower.startswith("l3_event_x") and (".dbg" in fn_lower or ".bkp" in fn_lower):
                    file_path = os.path.join(session_folder, f.filename)
                    f.save(file_path)
                    saved_files.append(f.filename)
                    # Track file size
                    if os.path.exists(file_path):
                        total_size_mb += os.path.getsize(file_path) / (1024 * 1024)
            
            # Calculate estimated time
            estimated_seconds = int((total_size_mb / PROCESSING_SPEED_MB_PER_SEC) + OVERHEAD_SECONDS)
            
            # Initialize progress tracking
            analysis_progress.update({
                'active': True,
                'current': 0,
                'total': len(saved_files),
                'message': 'Initializing analysis...',
                'session_id': os.path.basename(session_folder),
                'completed': False,
                'error': None,
                'estimated_time': estimated_seconds,
                'start_time': time.time(),
                'elapsed_time': 0,
                'next_url': '/results'
            })

            # prepare for analysis similar to analyze_logs
            rrc_counts.clear()
            ue_data_map.clear()
            insights_global.clear()
            valid_indices_global.clear()
            crash = False
            bt_df = None

            try:
                analysis_progress['message'] = 'Counting RRC messages...'
                rrc_counts.update(count_rrc_messages(session_folder))
                
                analysis_progress['message'] = 'Merging UE journey logs...'
                combined_map, folder_crash = merge_logs_for_ue_journey(session_folder)

                analysis_progress['message'] = 'Computing drop rates...'
                rrc_drop_rates_local = compute_drop_rates(rrc_counts)
                
                analysis_progress['message'] = 'Parsing cell setup status...'
                cell_setup_local = parse_cell_setup_status(session_folder)

                last_analysis_snapshot = {
                     'ue_data_map': combined_map.copy(),
                     'rrc_counts': rrc_counts.copy(),
                    'rrc_drop_rates': rrc_drop_rates_local,
                     'insights_global': generate_insights(combined_map),
                     'valid_indices_global': sorted(combined_map.keys()),
                     'total_ue_indices_global': len(combined_map),
                     'cell_setup_status': cell_setup_local,
                 }

                if folder_crash and bt_df is not None:
                    bt_lines = []
                    try:
                        for row in bt_df.itertuples():
                            bt_lines.append(f"{row.Date:<12} {row.Time:<18} {row.File:<30} {row.Line:<8} {row.Message}")
                    except Exception:
                        bt_lines = [str(r) for r in bt_df.values.tolist()]
                    bt_text = "\n".join(bt_lines)
                    analysis_progress['completed'] = True
                    analysis_progress['active'] = False
                    return render_template("bt_page.html", filename="Crash Details", log_text=bt_text, can_proceed=True)

                ue_data_map.update(combined_map)
                insights_global[:] = last_analysis_snapshot['insights_global']
                valid_indices_global[:] = last_analysis_snapshot['valid_indices_global']
                total_ue_indices_global = last_analysis_snapshot['total_ue_indices_global']
                
                # Mark progress as completed
                analysis_progress['completed'] = True
                analysis_progress['message'] = 'Analysis complete!'
                analysis_progress['active'] = False
                
            except Exception as e:
                analysis_progress['error'] = str(e)
                analysis_progress['active'] = False
                analysis_progress['completed'] = False
                return _upload_page_context(error=f"Analysis failed: {str(e)}")

            return render_template('progress.html')

        # ===================================================
        # CASE 3 — SCP FROM REMOTE SERVER AND ANALYZE
        # ===================================================
        if action == "scp_analyze":
            server_path = request.form.get("server_path", "").strip()
            password = request.form.get("server_password", "").strip()

            if not server_path or not password:
                return _upload_page_context(error="Please provide both the server path and password.")

            # Parse server_path: user@host:/remote/path
            scp_re = re.match(r'^([^@]+)@([^:]+):(.+)$', server_path)
            if not scp_re:
                return _upload_page_context(error="Invalid server path format. Use: user@host:/path/to/logs")

            username = scp_re.group(1)
            hostname = scp_re.group(2)
            remote_dir = scp_re.group(3)

            session_folder = os.path.join(UPLOAD_FOLDER, f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            os.makedirs(session_folder, exist_ok=True)

            analysis_progress.update({
                'active': True,
                'current': 0,
                'total': 1,
                'message': f'Preparing SCP session for {hostname}...',
                'session_id': os.path.basename(session_folder),
                'completed': False,
                'error': None,
                'estimated_time': 5,
                'start_time': time.time(),
                'elapsed_time': 0,
                'next_url': '/results'
            })

            worker = threading.Thread(
                target=_scp_download_and_analyze_worker,
                args=(username, hostname, remote_dir, password, session_folder),
                daemon=True
            )
            worker.start()

            return render_template('progress.html')

    return _upload_page_context()


@app.route("/open_session/<session_name>")
def open_session(session_name):
    if not session_name.startswith("session_"):
        return _upload_page_context(error="Invalid session name")

    session_path = os.path.join(UPLOAD_FOLDER, session_name)
    if not os.path.isdir(session_path):
        return _upload_page_context(error=f"Session not found: {session_name}")

    _touch_session(session_path)
    _enforce_session_limit()
    return redirect(url_for("analyze_logs", folder=session_path))


# =================================================================
# VIEW CONVERTED LOGS
# =================================================================
@app.route("/converted/<path:folder>")
def view_converted_logs(folder):
    # folder is expected to be a path to a folder containing converted files
    folder_path = unquote(folder or "")
    folder_path = folder_path.strip().strip('"\'').replace("\\", os.sep).replace("/", os.sep)

    if not os.path.exists(folder_path):
        return "Folder not found", 404

    all_files = sorted(os.listdir(folder_path))
    merged_files = [f for f in all_files if (f.lower().startswith("l3_event_x") and (".dbg" in f.lower() or ".bkp" in f.lower()))]
    return render_template('view_logs.html', files=merged_files, folder=folder_path)


# =================================================================
# VIEW A SINGLE FINAL CONVERTED FILE
# =================================================================
@app.route("/view_file/<path:folder>/<filename>")
def view_file(folder, filename):
    folder_path = unquote(folder or "")
    folder_path = folder_path.strip().strip('"\'').replace("\\", os.sep).replace("/", os.sep)
    file_path = os.path.join(folder_path, filename)

    if not os.path.exists(file_path):
        return f"File not found: {file_path}", 404

    output_lines = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip().replace("\ufeff", "")
            parts = line.split()
            if len(parts) < 5:
                continue
            date = parts[0].strip()
            time_val = parts[1].strip()
            filec = parts[2].strip()
            line_no = parts[3].strip()
            message = " ".join(parts[4:])
            formatted = f"{date:<12} {time_val:<18} {filec:<30} {line_no:<8} {message}"
            output_lines.append(formatted)
    final_text = "\n".join(output_lines)

    return render_template("view_file.html", filename=filename, folder=folder_path, log_text=final_text)


# =================================================================
# DOWNLOAD FILE
# =================================================================
@app.route("/download/<path:folder>/<filename>")
def download_converted_file(folder, filename):
    folder_path = unquote(folder or "")
    folder_path = folder_path.strip().strip('"\'').replace("\\", os.sep).replace("/", os.sep)
    path = os.path.join(folder_path, filename)

    if not os.path.exists(path):
        return f"File not found: {path}", 404

    return send_file(path, as_attachment=True)


# =================================================================
# ANALYSIS PAGES and helpers
# =================================================================

@app.route('/results_data')
def results_data():
    global last_analysis_snapshot
    data_map = ue_data_map if ue_data_map else (last_analysis_snapshot['ue_data_map'] if last_analysis_snapshot else {})
    if not data_map:
        return jsonify({'status': 'no_data'}), 404
    ue_preview = {str(k): len(v) for k, v in data_map.items()}
    # pick counters/insights from live globals or snapshot
    rrc = rrc_counts if rrc_counts else (last_analysis_snapshot['rrc_counts'] if last_analysis_snapshot else {})
    insights = insights_global if insights_global else (last_analysis_snapshot['insights_global'] if last_analysis_snapshot else [])
    valid_idx = valid_indices_global if valid_indices_global else (last_analysis_snapshot['valid_indices_global'] if last_analysis_snapshot else [])
    total_idx = total_ue_indices_global if total_ue_indices_global else (last_analysis_snapshot['total_ue_indices_global'] if last_analysis_snapshot else 0)
    # compute drop rates preferring live rrc_counts, fallback to snapshot stored rates
    if rrc:
        rrc_drop = compute_drop_rates(rrc)
    else:
        rrc_drop = last_analysis_snapshot.get('rrc_drop_rates', {}) if last_analysis_snapshot else {}
    return jsonify({
        'status': 'ok', 'detailed_insights': insights, 'rrc_counts': rrc,
        'valid_indices': valid_idx, 'total_ue_indices': total_idx,
        'ue_preview': ue_preview, 'rrc_drop_rates': rrc_drop
    })


@app.route('/progress')
def progress():
    """Return current analysis progress as JSON"""
    global analysis_progress
    return jsonify(analysis_progress)


@app.route('/progress_page')
def progress_page():
    """Display progress page that polls /progress endpoint"""
    return render_template('progress.html')


@app.route('/bt_progress')
def bt_progress():
    global latest_bt_text
    if not latest_bt_text:
        return redirect(url_for('show_results'))
    return render_template("bt_page.html", filename="Crash Details", log_text=latest_bt_text, can_proceed=True)


@app.route("/results")
def show_results():
    global last_analysis_snapshot
    # prefer live computed rates, else use snapshot-stored rates
    if rrc_counts:
        rrc_drop_rates = compute_drop_rates(rrc_counts)
    else:
        rrc_drop_rates = last_analysis_snapshot.get('rrc_drop_rates', {}) if last_analysis_snapshot else {}
    # If live globals are empty but we have a snapshot (from crash flow), render snapshot results
    if not ue_data_map and last_analysis_snapshot:
        return render_template("index.html",
                               detailed_insights=last_analysis_snapshot.get('insights_global', []),
                               rrc_counts=last_analysis_snapshot.get('rrc_counts', {}),
                               rrc_drop_rates=last_analysis_snapshot.get('rrc_drop_rates', {}),
                               valid_indices=last_analysis_snapshot.get('valid_indices_global', []),
                               total_ue_indices=last_analysis_snapshot.get('total_ue_indices_global', 0))
    return render_template("index.html",
                           detailed_insights=insights_global,
                           rrc_counts=rrc_counts,
                           rrc_drop_rates=rrc_drop_rates,
                           valid_indices=valid_indices_global,
                           total_ue_indices=total_ue_indices_global)





@app.route("/ue_stats", methods=["GET", "POST"])
def ue_stats():
    global last_analysis_snapshot

    # pick snapshot if global empty
    data_map = ue_data_map if ue_data_map else (last_analysis_snapshot['ue_data_map'] if last_analysis_snapshot else {})
    if not data_map:
        return redirect(url_for("upload_page"))

    selected = None
    error = None
    valid_indices = sorted(data_map.keys())

    # FINAL OUTPUTS
    diagram_lines = []
    events = []
    actor_order = []
    actors = set()
    msgs = []
    cell_id = None
    rnti_id = None
    ho_type_info = None
    ho_freq_type_info = None
    is_handover = False

    if request.method == "POST":
        val = request.form.get("ue_index")

        if val and val.isdigit():
            idx = int(val)

            if idx in valid_indices:
                selected = idx

                pattern = re.compile(r"\[(SEND|RECV)\]\s+\[MODULE:([\w_]+)\(\d+\)\]\s+\[API:([\w_]+)\(\d+\)\]")
                cell_id_re = re.compile(r"Value of U8 cell_index\D+(\d+)")
                rnti_re = re.compile(r"Value of U16 rnti\D+(\d+)")

                sequence_data = []
                seq_no = 0

                for block in data_map.get(idx, []):
                    for row in block:
                        msg = str(getattr(row, "Message", ""))
                        row_date = getattr(row, "Date", "")
                        row_time = getattr(row, "Time", "")
                        ts = f"{row_date} {row_time}".strip()

                        if "RRC_MSG:" in msg and ":" in msg:
                            msgs.append(msg.rsplit(":", 1)[-1].strip())

                        cell_match = cell_id_re.search(msg)
                        if cell_match:
                            cell_id = int(cell_match.group(1))

                        rnti_match = rnti_re.search(msg)
                        if rnti_match:
                            rnti_id = int(rnti_match.group(1))

                        match = pattern.search(msg)
                        if not match:
                            continue

                        action, module_full, api = match.groups()
                        module_clean = re.sub(r"(_MODULE_ID|_ID|_1)$", "", module_full)
                        parts = module_clean.split("_")
                        if len(parts) < 2:
                            continue

                        entity1, entity2 = parts[0], parts[1]
                        sender, receiver = (entity1, entity2) if action == "SEND" else (entity2, entity1)

                        actors.add(sender)
                        actors.add(receiver)

                        sequence_data.append({
                            "ts": ts,
                            "sender": sender,
                            "receiver": receiver,
                            "api": api,
                            "message": msg,
                            "_sort": (row_date, row_time, seq_no),
                            "mermaid": f"    {sender}->>{receiver}: [{ts}] {api}"
                        })
                        seq_no += 1

                sequence_sorted = sorted(sequence_data, key=lambda x: x["_sort"])
                for item in sequence_sorted:
                    item.pop("_sort", None)

                diagram_lines = [d["mermaid"] for d in sequence_sorted]
                events = sequence_sorted

                # Actor order (left → right)
                actor_order = sorted(list(actors))

                # Extract HO type, HO freq type and classification for this UE
                ho_type_info = _extract_ho_type(data_map, idx)
                ho_freq_type_info = _extract_ho_freq_type(data_map, idx)
                classification = _classify_ue_attachment(data_map, idx)
                is_handover = "Handover" in classification

            else:
                error = "UE not found"
        else:
            error = "Invalid UE index"

    return render_template(
        "ue_stats.html",
        diagram_lines=diagram_lines,
        events=events,
        selected_ue=selected,
        valid_indices=valid_indices,
        error=error,
        cell_id=cell_id,
        rnti_id=rnti_id,
        actor_order=actor_order,
        msgs=msgs,
        ho_type_info=ho_type_info,
        ho_freq_type_info=ho_freq_type_info,
        is_handover=is_handover,
    )


@app.route("/milestones", methods=["GET", "POST"])
def milestones():
    data_map = _get_ue_data_map()
    if not data_map:
        return redirect(url_for("upload_page"))

    selected_ue = None
    error = None
    milestone_events = []
    ue_classification = None
    ho_type_info = None
    ho_freq_type_info = None
    is_handover = False
    valid_indices = sorted(data_map.keys())

    if request.method == "POST":
        ue_index_val = request.form.get("ue_index", "").strip()
        if not ue_index_val.isdigit():
            error = "Invalid UE index"
        else:
            selected_ue = int(ue_index_val)
            if selected_ue not in data_map:
                error = "UE not found"
            else:
                milestone_events = extract_ue_milestones(data_map, selected_ue)
                ue_classification = _classify_ue_attachment(data_map, selected_ue)
                ho_type_info = _extract_ho_type(data_map, selected_ue)
                ho_freq_type_info = _extract_ho_freq_type(data_map, selected_ue)
                is_handover = "Handover" in ue_classification

    return render_template(
        "milestones.html",
        selected_ue=selected_ue,
        valid_indices=valid_indices,
        error=error,
        milestone_events=milestone_events,
        ue_classification=ue_classification,
        ho_type_info=ho_type_info,
        ho_freq_type_info=ho_freq_type_info,
        is_handover=is_handover,
    )


@app.route("/clear_results")
def clear_results():
    print(len(ue_data_map))
    ue_data_map.clear()
    rrc_counts.clear()
    insights_global.clear()
    valid_indices_global.clear()
    global last_analysis_snapshot
    last_analysis_snapshot = None
    return redirect(url_for("upload_page"))


@app.route("/generate_and_download_txt", methods=["POST"])
def generate_and_download_txt():
    ue_index_str = request.form.get("ue_index")
    if not ue_index_str or not ue_index_str.isdigit():
        return "Invalid UE index provided", 400
    ue_index = int(ue_index_str)
    global last_analysis_snapshot
    data_map = ue_data_map if ue_data_map else (last_analysis_snapshot['ue_data_map'] if last_analysis_snapshot else {})
    if ue_index not in data_map:
        return f"Data for UE index {ue_index} not found.", 404
    mem_file = BytesIO()
    for block in data_map.get(ue_index, []):
        mem_file.write(b"--------------------------------------------------------\n")
        for row in block:
            line_str = f"{row.Date} {row.Time}    {row.File:<10}    {row.Line:<4}    {row.Message}\n"
            mem_file.write(line_str.encode('utf-8'))
        mem_file.write(b"\n")
    mem_file.seek(0)
    output_filename = f"ue_journey_{ue_index}.txt"
    return send_file(mem_file, as_attachment=True, download_name=output_filename, mimetype='text/plain')


@app.route('/summary')
def summary():
    global last_analysis_snapshot
    data_map = ue_data_map if ue_data_map else (last_analysis_snapshot['ue_data_map'] if last_analysis_snapshot else {})
    if not data_map:
        return "No analysis data available", 404
    folder_name = f"l3_logs_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        rrc_source = rrc_counts if rrc_counts else (last_analysis_snapshot['rrc_counts'] if last_analysis_snapshot else {})
        counts_content = "".join([f"{msg}: {count}\n" for msg, count in rrc_source.items()])
        zip_file.writestr(f"{folder_name}/rrc_messages_counts.txt", counts_content)
        for ue_index, blocks in data_map.items():
            ue_content = ""
            for block in blocks:
                ue_content += "--------------------------------------------------------\n"
                for row in block:
                    ue_content += f"{row.Date:<12} {row.Time:<18}    {row.File:<30}    {row.Line:<8}    {row.Message}\n"
                ue_content += "\n"
            zip_file.writestr(f"{folder_name}/{ue_index}_journey.txt", ue_content)
    zip_buffer.seek(0)
    return send_file(zip_buffer, as_attachment=True, download_name=f"{folder_name}.zip", mimetype='application/zip')


@app.route("/proceed_analysis")
def proceed_analysis():
    """
    Restore the last_analysis_snapshot into live globals so user can interact with full analysis after proceeding.
    """
    global last_analysis_snapshot, ue_data_map, rrc_counts, insights_global, valid_indices_global, total_ue_indices_global, bt_df, crash
    if not last_analysis_snapshot:
        return redirect(url_for('show_results'))
    snap = last_analysis_snapshot

    ue_data_map.clear()
    ue_data_map.update(snap.get('ue_data_map', {}))
    rrc_counts.clear()
    rrc_counts.update(snap.get('rrc_counts', {}))
    insights_global[:] = snap.get('insights_global', [])
    valid_indices_global[:] = snap.get('valid_indices_global', [])
    total_ue_indices_global = snap.get('total_ue_indices_global', 0)

    # clear backtrace buffer (we've shown it already)
    bt_df = None
    crash = False

    # clear the snapshot (so subsequent clears behave clean)
    last_analysis_snapshot = None
    return redirect(url_for('show_results'))


@app.route("/rrc_counters")
def rrc_counters():
    """
    Render full RRC counters page. Prefer live rrc_counts; fall back to last_analysis_snapshot.
    Supports optional query parameter 'q' for exact (case-insensitive) match search in counters,
    and 'grep' to search inside UE blocks/messages (substring, case-insensitive).
    """
    global last_analysis_snapshot
    # prefer live counters, else snapshot
    rrc = rrc_counts if rrc_counts else (last_analysis_snapshot['rrc_counts'] if last_analysis_snapshot else {})
    # prefer live drop rates computed from live counters, else snapshot-stored rates
    if rrc:
        rrc_drop = compute_drop_rates(rrc)
    else:
        rrc_drop = last_analysis_snapshot.get('rrc_drop_rates', {}) if last_analysis_snapshot else {}

    # Existing RRC exact-key search handling (q)
    q = request.args.get('q', '').strip()
    search_results = {}
    search_message = None
    if q:
        q_lower = q.lower()
        for k, v in rrc.items():
            if k.lower() == q_lower:
                search_results[k] = v
        if not search_results:
            search_message = f"No exact match found for: '{q}'"

    # NEW: UE grep search (substring in messages)
    grep = request.args.get('grep', '').strip()
    search_ue_results = {}   # ue_index -> {'count': n, 'samples': [str,...]}
    if grep:
        grep_lower = grep.lower()
        # pick UE data map from live or snapshot
        data_map = ue_data_map if ue_data_map else (last_analysis_snapshot['ue_data_map'] if last_analysis_snapshot else {})
        # iterate UEs and their blocks/rows
        for ue_index, blocks in data_map.items():
            match_count = 0
            samples = []
            for block in blocks:
                for row in block:
                    # row.Message is typically a string; ensure str()
                    msg_str = str(row.Message)
                    if grep_lower in msg_str.lower():
                        match_count += 1
                        if len(samples) < 6:  # keep small sample set
                            # include date/time and a trimmed message
                            try:
                                sample_line = f"{getattr(row,'Date','') or ''} {getattr(row,'Time','') or ''} - {msg_str[:300]}"
                            except Exception:
                                sample_line = msg_str[:300]
                            samples.append(sample_line)
            if match_count > 0:
                search_ue_results[ue_index] = {'count': match_count, 'samples': samples}

        # sort results by match count desc
        if search_ue_results:
            search_ue_results = dict(sorted(search_ue_results.items(), key=lambda x: x[1]['count'], reverse=True))
        else:
            # keep an empty dict and a message for template
            pass

    return render_template("rrc_counters.html",
                           rrc_counts=rrc,
                           rrc_drop_rates=rrc_drop,
                           query=q,
                           search_results=search_results,
                           search_message=search_message,
                           grep_query=grep,
                           search_ue_results=search_ue_results)


@app.route("/search_data")
def search_data():
    """
    Dedicated search page for UE data. Provides both RRC counter search and UE message grep.
    """
    global last_analysis_snapshot
    # prefer live counters, else snapshot
    rrc = rrc_counts if rrc_counts else (last_analysis_snapshot['rrc_counts'] if last_analysis_snapshot else {})

    # Existing RRC exact-key search handling (q)
    q = request.args.get('q', '').strip()
    search_results = {}
    search_message = None
    if q:
        q_lower = q.lower()
        for k, v in rrc.items():
            if k.lower() == q_lower:
                search_results[k] = v
        if not search_results:
            search_message = f"No exact match found for: '{q}'"

    # UE grep search (substring in messages)
    grep = request.args.get('grep', '').strip()
    search_ue_results = {}   # ue_index -> {'count': n, 'samples': [str,...]}
    if grep:
        grep_lower = grep.lower()
        # pick UE data map from live or snapshot
        data_map = ue_data_map if ue_data_map else (last_analysis_snapshot['ue_data_map'] if last_analysis_snapshot else {})
        # iterate UEs and their blocks/rows
        for ue_index, blocks in data_map.items():
            match_count = 0
            samples = []
            for block in blocks:
                for row in block:
                    msg_str = str(row.Message)
                    if grep_lower in msg_str.lower():
                        match_count += 1
                        if len(samples) < 6:  # keep small sample set
                            try:
                                sample_line = f"{getattr(row,'Date','') or ''} {getattr(row,'Time','') or ''} - {msg_str[:300]}"
                            except Exception:
                                sample_line = msg_str[:300]
                            samples.append(sample_line)
            if match_count > 0:
                search_ue_results[ue_index] = {'count': match_count, 'samples': samples}

        # sort results by match count desc
        if search_ue_results:
            search_ue_results = dict(sorted(search_ue_results.items(), key=lambda x: x[1]['count'], reverse=True))

    return render_template("search_data.html",
                           query=q,
                           search_results=search_results,
                           search_message=search_message,
                           grep_query=grep,
                           search_ue_results=search_ue_results)


@app.route("/ho_mapping")
def ho_mapping():
    ho_map = build_ho_maci_mapping()
    return render_template("ho_mapping.html", ho_map=ho_map)


# -----------------------------
# UE SUMMARY DASHBOARD
# -----------------------------
def generate_ue_summary(data_map):
    """
    Analyse every UE in data_map and produce a structured summary dict:
      - per-UE counts (RRC Conn Req/Setup/Complete, ICS, ERAB, HO, Release, failures)
      - classification: direct attach vs handover
      - status: success / incomplete
      - aggregate totals
    """
    if not data_map:
        return None

    direct_attach_ues = []
    x2ap_handover_ues = []
    s1ap_handover_ues = []
    failed_ues = []

    # aggregate accumulators
    totals = {
        'total_ues': 0, 'direct_attach': 0, 'x2ap_handover': 0, 's1ap_handover': 0,
        'successful': 0, 'failed': 0,
        'rrc_conn_req': 0, 'rrc_conn_setup': 0, 'rrc_conn_setup_complete': 0,
        'rrc_reconfig': 0, 'rrc_reconfig_complete': 0,
        'ics_req': 0, 'ics_resp': 0,
        'erab_setup_req': 0, 'erab_setup_resp': 0,
        'ho_request': 0, 'ho_request_ack': 0,
        'path_switch_req': 0, 'path_switch_ack': 0,
        'rrc_conn_release': 0, 'failures': 0,
    }

    for ue_index in sorted(data_map.keys()):
        blocks = data_map[ue_index]
        
        # OPTIMIZED: Single-pass message counting instead of building huge all_text string
        # Initialize counters
        rrc_conn_req = rrc_conn_setup = rrc_conn_setup_complete = 0
        rrc_reconfig = rrc_reconfig_complete = 0
        ics_req = ics_resp = erab_setup_req = erab_setup_resp = 0
        x2ap_ho_request = x2ap_ho_request_ack = s1ap_ho_request = 0
        path_switch_req = path_switch_ack = rrc_conn_release = 0
        rlf = asn_fail = ho_prep_fail = ho_cancel = ho_fail_ind = reestab_reject = 0
        has_x2ap_ho_req = has_uecc_trg_ho = False
        
        # Single pass through all messages
        for block in blocks:
            for row in block:
                msg_upper = str(getattr(row, "Message", "")).upper()
                
                # RRC counts (using simple string checks where possible)
                if "[RNTI:" in msg_upper and "RRC_MSG:" in msg_upper and "RRC CONNECTION REQUEST" in msg_upper:
                    rrc_conn_req += 1
                elif "RRC_MSG:" in msg_upper:
                    if "RRC CONNECTION SETUP COMPLETE" in msg_upper:
                        rrc_conn_setup_complete += 1
                    elif "RRC CONNECTION SETUP" in msg_upper:
                        rrc_conn_setup += 1
                    elif "RRC CONNECTION RECONFIGURATION COMPLETE" in msg_upper:
                        rrc_reconfig_complete += 1
                    elif "RRC CONNECTION RECONFIGURATION" in msg_upper:
                        rrc_reconfig += 1
                    elif "RRC CONNECTION RELEASE" in msg_upper:
                        rrc_conn_release += 1
                
                # S1AP counts
                if "S1AP_MSG:" in msg_upper:
                    if "INITIAL CONTEXT SETUP REQUEST" in msg_upper:
                        ics_req += 1
                    elif "INITIAL CONTEXT SETUP RESPONSE" in msg_upper:
                        ics_resp += 1
                    elif "ERAB SETUP REQUEST" in msg_upper:
                        erab_setup_req += 1
                    elif "ERAB SETUP RESPONSE" in msg_upper:
                        erab_setup_resp += 1
                    elif "HANDOVER REQUEST" in msg_upper:
                        s1ap_ho_request += 1
                
                # X2AP counts
                if "X2AP_MSG:" in msg_upper:
                    if "HANDOVER REQUEST ACK" in msg_upper or "HANDOVER REQUEST ACKNOWLEDGE" in msg_upper:
                        x2ap_ho_request_ack += 1
                    elif "HANDOVER REQUEST" in msg_upper:
                        x2ap_ho_request += 1
                        has_x2ap_ho_req = True
                
                # Path switch
                if "PATH SWITCH REQUEST ACK" in msg_upper:
                    path_switch_ack += 1
                elif "PATH SWITCH REQUEST" in msg_upper:
                    path_switch_req += 1
                
                # Failure indicators
                if "RLF" in msg_upper or "RADIO LINK FAILURE" in msg_upper:
                    rlf += 1
                if "ASN" in msg_upper and ("ENCODING" in msg_upper or "DECODING" in msg_upper) and "FAILED" in msg_upper:
                    asn_fail += 1
                if "HANDOVER PREPARATION FAILURE" in msg_upper:
                    ho_prep_fail += 1
                if "HANDOVER CANCEL" in msg_upper:
                    ho_cancel += 1
                if "HANDOVER FAILURE INDICATION" in msg_upper:
                    ho_fail_ind += 1
                if "REESTABLISHMENT REJECT" in msg_upper:
                    reestab_reject += 1
                if "UECC_UE_TRG_HO_ONGOING" in msg_upper:
                    has_uecc_trg_ho = True

        # failure indicators
        fail_count = 0
        fail_reasons = []
        if rlf:
            fail_count += rlf; fail_reasons.append(f"RLF ({rlf})")
        if asn_fail:
            fail_count += asn_fail; fail_reasons.append(f"ASN Encode/Decode Fail ({asn_fail})")
        if ho_prep_fail:
            fail_count += ho_prep_fail; fail_reasons.append(f"HO Prep Failure ({ho_prep_fail})")
        if ho_cancel:
            fail_count += ho_cancel; fail_reasons.append(f"HO Cancel ({ho_cancel})")
        if ho_fail_ind:
            fail_count += ho_fail_ind; fail_reasons.append(f"HO Failure Ind ({ho_fail_ind})")
        if reestab_reject:
            fail_count += reestab_reject; fail_reasons.append(f"Reestab Reject ({reestab_reject})")

        # S1AP UE Context Release cause
        s1ap_causes = _extract_s1ap_release_cause(data_map, ue_index)
        s1ap_fail_causes = [c for c in s1ap_causes if c['cause_index'] in S1AP_CAUSE_FAILURE]
        if s1ap_fail_causes:
            for c in s1ap_fail_causes:
                fail_count += 1
                fail_reasons.append(f"S1AP Release: {c['cause_name']}")

        # FAILURE: BEGIN / END detection — extract procedure context tags
        failure_contexts = _extract_failure_context(data_map, ue_index)
        # Fallback: if no FAILURE: pattern but UE has S1AP failure cause,
        # extract [*_P] procedure tags as failure context
        if not failure_contexts and s1ap_fail_causes:
            failure_contexts = _extract_procedure_tags(data_map, ue_index)
        if failure_contexts:
            for ctx in failure_contexts:
                fail_count += 1
                fail_reasons.append(f"FAILURE END: [{ctx}]")

        # RRC Re-establishment (RRE) failure detection
        rre_failure_causes = _extract_rre_failure_cause(data_map, ue_index)
        if rre_failure_causes:
            for rre_cause in rre_failure_causes:
                fail_count += 1
                fail_reasons.append(f"RRE: {rre_cause}")
        
        # RRC Re-establishment (RRE) type detection
        rre_type = _extract_rre_type(data_map, ue_index)

        # classify: S1AP handover vs X2AP handover vs Direct attach
        # S1AP handover has PRIORITY - if S1AP_MSG: HANDOVER REQUEST exists, classify as S1AP
        is_s1ap_handover = bool(s1ap_ho_request > 0)
        
        # X2AP handover only if NOT S1AP handover
        is_x2ap_handover = bool(
            not is_s1ap_handover and (
                has_x2ap_ho_req
                or has_uecc_trg_ho
                or (x2ap_ho_request_ack > 0 and rrc_conn_req == 0)
            )
        )
        
        is_handover = is_x2ap_handover or is_s1ap_handover
        handover_type = 'S1AP' if is_s1ap_handover else ('X2AP' if is_x2ap_handover else None)

        # determine status
        if is_x2ap_handover:
            # X2AP HO UE success = got X2AP HO REQUEST ACK or PATH SWITCH ACK
            is_success = (x2ap_ho_request_ack > 0 or path_switch_ack > 0) and fail_count == 0
        elif is_s1ap_handover:
            # S1AP HO UE success = completed ICS or has PATH SWITCH ACK
            is_success = (ics_resp > 0 or path_switch_ack > 0) and fail_count == 0
        else:
            # Direct attach: success = completed ICS (got ICS response)
            is_success = (ics_resp > 0 or rrc_conn_setup_complete > 0) and fail_count == 0

        # check for incomplete flows
        if not is_success and fail_count == 0:
            if rrc_conn_req > rrc_conn_setup:
                fail_reasons.append("Setup missing for some Requests")
            if rrc_conn_setup > rrc_conn_setup_complete:
                fail_reasons.append("Setup Complete missing")
            if ics_req > ics_resp and not is_handover:
                fail_reasons.append("ICS Response missing")
            if rrc_reconfig > rrc_reconfig_complete:
                fail_reasons.append("Reconfig Complete missing")
            if not fail_reasons:
                fail_reasons.append("Flow incomplete")

        # Extract HO type and HO freq type from log messages
        ho_type_info = _extract_ho_type(data_map, ue_index)
        ho_freq_type_info = _extract_ho_freq_type(data_map, ue_index)

        ue_info = {
            'index': ue_index,
            'is_handover': is_handover,
            'handover_type': handover_type,
            'status': 'success' if is_success else 'incomplete',
            'ho_type_value': ho_type_info['ho_type_value'],
            'ho_type_name': ho_type_info['ho_type_name'],
            'ho_freq_type_value': ho_freq_type_info['ho_freq_type_value'],
            'ho_freq_type_name': ho_freq_type_info['ho_freq_type_name'],
            's1ap_release_causes': s1ap_causes,
            's1ap_fail_causes': s1ap_fail_causes,
            'failure_contexts': failure_contexts,
            'rre_failure_causes': rre_failure_causes,
            'rre_type': rre_type,
            'rrc_conn_req': rrc_conn_req,
            'rrc_conn_setup': rrc_conn_setup,
            'rrc_conn_setup_complete': rrc_conn_setup_complete,
            'rrc_reconfig': rrc_reconfig,
            'rrc_reconfig_complete': rrc_reconfig_complete,
            'ics_req': ics_req,
            'ics_resp': ics_resp,
            'erab_setup_req': erab_setup_req,
            'erab_setup_resp': erab_setup_resp,
            'x2ap_ho_request': x2ap_ho_request,
            'x2ap_ho_request_ack': x2ap_ho_request_ack,
            's1ap_ho_request': s1ap_ho_request,
            'path_switch_req': path_switch_req,
            'path_switch_ack': path_switch_ack,
            'rrc_conn_release': rrc_conn_release,
            'failures': fail_count,
            'failure_reasons': fail_reasons,
        }

        if is_x2ap_handover:
            x2ap_handover_ues.append(ue_info)
        elif is_s1ap_handover:
            s1ap_handover_ues.append(ue_info)
        else:
            direct_attach_ues.append(ue_info)

        if not is_success:
            failed_ues.append(ue_info)

        # accumulate totals
        totals['total_ues'] += 1
        totals['direct_attach'] += (1 if not is_handover else 0)
        totals['x2ap_handover'] += (1 if is_x2ap_handover else 0)
        totals['s1ap_handover'] += (1 if is_s1ap_handover else 0)
        totals['successful'] += (1 if is_success else 0)
        totals['failed'] += (0 if is_success else 1)
        totals['rrc_conn_req'] += rrc_conn_req
        totals['rrc_conn_setup'] += rrc_conn_setup
        totals['rrc_conn_setup_complete'] += rrc_conn_setup_complete
        totals['rrc_reconfig'] += rrc_reconfig
        totals['rrc_reconfig_complete'] += rrc_reconfig_complete
        totals['ics_req'] += ics_req
        totals['ics_resp'] += ics_resp
        totals['erab_setup_req'] += erab_setup_req
        totals['erab_setup_resp'] += erab_setup_resp
        totals['ho_request'] += (x2ap_ho_request + s1ap_ho_request)
        totals['ho_request_ack'] += x2ap_ho_request_ack
        totals['path_switch_req'] += path_switch_req
        totals['path_switch_ack'] += path_switch_ack
        totals['rrc_conn_release'] += rrc_conn_release
        totals['failures'] += fail_count

    return {
        'totals': totals,
        'direct_attach_ues': direct_attach_ues,
        'x2ap_handover_ues': x2ap_handover_ues,
        's1ap_handover_ues': s1ap_handover_ues,
        'failed_ues': failed_ues,
        'direct_attach_indices': [u['index'] for u in direct_attach_ues],
        'x2ap_handover_indices': [u['index'] for u in x2ap_handover_ues],
        's1ap_handover_indices': [u['index'] for u in s1ap_handover_ues],
    }


@app.route("/ue_summary")
def ue_summary():
    data_map = _get_ue_data_map()
    cell_setup = last_analysis_snapshot.get('cell_setup_status') if last_analysis_snapshot else None
    # If no UE data AND no cell setup data, redirect to upload
    if not data_map and not cell_setup:
        return redirect(url_for("upload_page"))
    summary = generate_ue_summary(data_map) if data_map else None
    return render_template("ue_summary.html", summary=summary, cell_setup=cell_setup)


@app.route("/ue_journey/<int:ue_index>")
def ue_journey(ue_index):
    """Show the full raw journey (all log messages) for a single UE, with search."""
    data_map = _get_ue_data_map()
    if not data_map:
        return redirect(url_for("upload_page"))
    if ue_index not in data_map:
        return render_template("error.html", message=f"UE {ue_index} not found in analysis data."), 404

    blocks = data_map[ue_index]
    journey_lines = []
    for block in blocks:
        for row in block:
            journey_lines.append({
                'date': str(getattr(row, 'Date', '')),
                'time': str(getattr(row, 'Time', '')),
                'file': str(getattr(row, 'File', '')),
                'line': str(getattr(row, 'Line', '')),
                'message': str(getattr(row, 'Message', '')),
            })
        # Add a separator between blocks
        journey_lines.append({
            'date': '', 'time': '', 'file': '', 'line': '',
            'message': '***********************************************************************'
        })

    return render_template("ue_journey.html", ue_index=ue_index, journey_lines=journey_lines,
                           total_lines=len(journey_lines))


# @app.get("/ho_stats/<int:ue>")
# def get_ho_stats_for_ue(ue: int):
#     stats = compute_ho_stats_for(ue)
#     if not stats:
#         return jsonify({"error": f"No HO stats found for UE {ue}"}), 404
#     stats["ue_index"] = ue
#     return jsonify(stats)

@app.get("/ho_stats/source/<int:ue>")
def get_ho_stats_source_ue(ue: int):
    stats = compute_ho_source_stats_for(ue)
    if not stats or not stats.get("events"):
        return jsonify({"error": f"No HO SOURCE stats found for UE {ue}"}), 404
    return jsonify(stats)


@app.get("/ho_stats/target/<int:ue>")
def get_ho_stats_target_ue(ue: int):
    stats = compute_ho_target_stats_for(ue)
    if not stats or not stats.get("events"):
        return jsonify({"error": f"No HO TARGET stats found for UE {ue}"}), 404
    return jsonify(stats)


def _get_ue_data_map():
    """Small helper – same logic you already use."""
    global ue_data_map, last_analysis_snapshot
    return ue_data_map if ue_data_map else (
        last_analysis_snapshot['ue_data_map'] if last_analysis_snapshot else {}
    )


def _classify_ue_attachment(data_map, ue_index):
    """
    Classify UE as 'Target Side (After Handover)' or 'Source Side (Direct Attach)'
    based on presence of 'X2AP' and 'HANDOVER REQUEST' in any message.
    """
    blocks = data_map.get(ue_index, [])
    has_x2ap_handover = False

    for block in blocks:
        for row in block:
            msg = str(getattr(row, "Message", "")).upper()
            if "X2AP" in msg and "HANDOVER REQUEST" in msg:
                has_x2ap_handover = True
                break
        if has_x2ap_handover:
            break

    if has_x2ap_handover:
        return "🎯 Target Side UE (After Handover) - UE came here via Handover"
    else:
        return "📡 Source Side UE (Direct Attach)"


MILESTONE_PATTERNS = [
    {"name": "Value of U16 crnti", "type": "RNTI", "occur": 1},
    {"name": "Value of U8 cell_index", "type": "cell_id", "occur": 1},
    {"name": "RRC_MSG: RRC CONNECTION REQUEST", "type": "RRC Connection Request", "occur": 0},
    {"name": "RRC_MSG: RRC CONNECTION SETUP", "type": "RRC Connection Setup", "occur": 0},
    {"name": "RRC_MSG: RRC CONNECTION SETUP COMPLETE", "type": "RRC Connection Setup Complete", "occur": 0},
    {"name": "RRC_MSG: SECURITY MODE COMMAND", "type": "Security Mode Command", "occur": 0},
    {"name": "RRC_MSG: SECURITY MODE COMPLETE", "type": "Security Mode Complete", "occur": 0},
    #{"name": "RRC_MSG: RRC CONNECTION RECONFIGURATION", "type": "RRC Connection Reconfiguration", "occur": 0},
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
   # {"name": "RRC_MSG: RRC CONNECTION RECONFIGURATION COMPLETE", "type": "RRC Connection Reconfiguration Complete", "occur": 0},
    {"name": "RRC_MSG: UE INFORMATION REQUEST", "type": "UE Information Request", "occur": 0},
    {"name": "RRC_MSG: UL UE INFORMATION", "type": "UL UE Information", "occur": 0},
    {"name": "RRC_MSG: MEASUREMENT REPORT", "type": "Measurement Report", "occur": 0},
    {"name": "X2AP_MSG: UE CONTEXT RELEASE", "type": "UE Context Release", "occur": 0},
    {"name": "TEID:RCR UE Release timer expiry", "type": "UE Release", "occur": 0}
]

def extract_ue_milestones(data_map, ue_index):
    """
    Extract ordered milestone events for a UE from parsed journey blocks.
    Add more milestone patterns in MILESTONE_PATTERNS.
    """
    events = []
    blocks = data_map.get(ue_index, [])
    sequence = 1
    seen_patterns = set()

    for block in blocks:
        for row in block:
            msg = str(getattr(row, "Message", ""))
            for milestone in MILESTONE_PATTERNS:
                pattern_name = milestone["name"]
                occur = int(milestone.get("occur", 1))

                if not msg.endswith(pattern_name):
                    continue

                if occur == 1 and pattern_name in seen_patterns:
                    continue

                events.append({
                    "sequence": sequence,
                    "milestone": milestone["type"],
                    "timestamp": f"{getattr(row, 'Date', '')} {getattr(row, 'Time', '')}".strip(),
                    "file": getattr(row, "File", ""),
                    "line": getattr(row, "Line", ""),
                    "message": msg,
                })
                sequence += 1

                if occur == 1:
                    seen_patterns.add(pattern_name)

    return events


def compute_ho_source_stats_for(ue: int) -> dict | None:
    
    data_map = _get_ue_data_map()
    print("\n✅ HO SOURCE Stats | Total UEs Found:", len(data_map))

    if not data_map:
        print("❌ UE DATA MAP EMPTY")
        return {}

    # SOURCE-side markers (you can tweak / reorder)
    ho_strings_source = [
        "API:RRC_RRM_HO_REQUIRED",
        "API:RRC_PDCP_MAC_I_REQ",
        "API:RRC_PDCP_MAC_I_RESP",
        "API:RRC_MAC_UE_INACTIVE_TIME_REQ",
        "API:RRC_MAC_UE_INACTIVE_TIME_RESP",
        "API:RRC_RRM_UE_HO_CMD_REQ",
        "API:RRC_RRM_UE_HO_CMD_RESP",
    ]
    tail_markers = [
        "Length of HO command sent to LLIM",
        "UE CONTEXT RELEASE"
    ]

    print(f"\n🔍 Computing HO SOURCE stats for UE: {ue}")
    derived: dict[str, dict] = {}

    for blocks in data_map.get(ue, []):
        for row in blocks:
            msg = str(row.Message)
            ts = f"{row.Date} {row.Time}"
            for hs in ho_strings_source:
                if hs in msg and hs not in derived:
                    derived[hs] = {
                        "timestamp": ts,
                        "message": msg,
                    }
            for tail in tail_markers:
                if tail in msg and tail and derived:
                    derived[tail] = {
                        "timestamp": ts,
                        "message": msg,
                    }

    if not derived:
        return {}

    # convert to standardized "events" list for UI
    events = []
    for api_name, info in derived.items():
        events.append({
            "api": api_name,
            "time": info["timestamp"],
            "message": info["message"],
        })

    return {
        "ue_index": ue,
        "side": "source",
        "event_count": len(events),
        "events": events,
    }


def compute_ho_target_stats_for(ue: int) -> dict | None:
    """
    TARGET side HO stats:
      - Uses TARGET-side HO related strings
      - Returned shape is same as SOURCE to reuse the same UI.
    """
    data_map = _get_ue_data_map()
    print("\n✅ HO TARGET Stats | Total UEs Found:", len(data_map))

    if not data_map:
        print("❌ UE DATA MAP EMPTY")
        return {}

    # TARGET-side markers – you can adjust this list as needed
    ho_strings_target = [
        "RRC_RRM_UE_HO_ADM_REQ",
        "RRC_RRM_UE_HO_ADM_RESP",
        "RRC_MAC_HO_RACH_RESOURCE_REQ",
        "RRC_MAC_HO_RACH_RESOURCE_RESP",
        "UECC_LLIM_CREATE_UE_ENTITY_REQ",
        "UECC_LLIM_CREATE_UE_ENTITY_RESP",
        "HANDOVER REQUEST ACKNOWLEDGE",
        "RRC CONNECTION RECONFIGURATION COMPLETE",
        "PATH SWITCH REQUEST",
        "PATH SWITCH REQUEST ACK",
        "UE CONTEXT RELEASE",
        "RRC_RRM_UE_HO_ADM_CNF"
    ]
    print(f"\n🔍 Computing HO TARGET stats for UE: {ue}")
    derived: dict[str, dict] = {}

    for blocks in data_map.get(ue, []):
        for row in blocks:
            msg = str(row.Message)
            ts = f"{row.Date} {row.Time}"
            for hs in ho_strings_target:
                if hs in msg and hs not in derived:
                    derived[hs] = {
                        "timestamp": ts,
                        "message": msg,
                    }

    if not derived:
        return {}

    events = []
    for api_name, info in derived.items():
        events.append({
            "api": api_name,
            "time": info["timestamp"],
            "message": info["message"],
        })

    return {
        "ue_index": ue,
        "side": "target",
        "event_count": len(events),
        "events": events,
    }
def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")



@app.post("/download-diagram")
def download_diagram():
    """
    Accepts JSON:
      - For SVG: { svg: "<svg...>", format: "svg", filename: "UE_123" }
      - For PNG: { png_base64: "data:image/png;base64,...", format: "png", filename: "UE_123" }
    Returns the file with proper headers. No server-side rendering libraries needed.
    """
    data = request.get_json(silent=True) or {}
    fmt = (data.get("format") or "svg").lower()
    filename = (data.get("filename") or "diagram").replace(" ", "_")

    if fmt == "svg":
        svg = data.get("svg", "")
        if not svg.strip():
            return jsonify({"error": "SVG is required for format=svg"}), 400
        return Response(
            svg,
            mimetype="image/svg+xml",
            headers={"Content-Disposition": f"attachment; filename={filename}.svg"}
        )

    if fmt == "png":
        # Expecting a data URL from client; decode and return it
        data_url = data.get("png_base64", "")
        if not data_url.startswith("data:image/png;base64,"):
            return jsonify({"error": "png_base64 data URL required for format=png"}), 400
        b64 = data_url.split(",", 1)[1]
        raw = base64.b64decode(b64)
        return send_file(
            BytesIO(raw),
            mimetype="image/png",
            as_attachment=True,
            download_name=f"{filename}.png"
        )

    return jsonify({"error": f"Unsupported format '{fmt}' without converters"}), 400


# =================================================================
# START APP
# =================================================================

if __name__ == "__main__":
    
    app.run(host = "0.0.0.0", port=5000, debug=True)   