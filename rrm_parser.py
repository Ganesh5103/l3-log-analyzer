"""
RRM Log Parser Module
Parses RRM logs and correlates them with L3 logs for UE journey analysis.

OPTIMIZED APPROACH:
1. Pre-parse ALL RRM files and extract blocks by UE index
2. Store in structure: {ue_index: [{timestamp, lines}, ...]}
3. Fast lookup during UE journey display
"""

import os
import re
import pandas as pd
from datetime import datetime
from collections import defaultdict

# Regex patterns for RRM log lines
REGEX_RRM = re.compile(
    r"^(?P<date>\d{2}\.\d{2}\.\d{4})\s+"
    r"(?P<time>[\d:.]+)\s+"
    r"(?P<file>[\w_.]+\.c)\s+"
    r"(?P<line>\d+)\s+"
    r"(?P<message>.*)$"
)

# Time window for matching L3 and RRM logs (seconds)
TIME_WINDOW_SECONDS = 3.0

# Global RRM data structure: { ue_index: [{timestamp: datetime, lines: [row_dicts]}, ...] }
# This stores ALL RRM blocks organized by UE index for fast lookup
rrm_ue_blocks_map = {}


def parse_timestamp(date_str, time_str):
    """
    Parse DD.MM.YYYY and HH:MM:SS.microseconds into datetime object.
    Returns None if parsing fails.
    """
    try:
        # Handle time with microseconds
        dt_str = f"{date_str} {time_str}"
        # Try multiple formats
        for fmt in ["%d.%m.%Y %H:%M:%S.%f", "%d.%m.%Y %H:%M:%S"]:
            try:
                return datetime.strptime(dt_str, fmt)
            except ValueError:
                continue
        return None
    except Exception:
        return None


def parse_rrm_log_file(filepath):
    """
    Parse a single RRM log file and extract all log lines as rows.
    Returns a DataFrame with columns: Date, Time, File, Line, Message, Timestamp (datetime object).
    """
    rows = []
    
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                match = REGEX_RRM.match(line)
                if match:
                    date = match.group("date")
                    time = match.group("time")
                    file = match.group("file")
                    line_no = match.group("line")
                    message = match.group("message")
                    
                    # Parse timestamp
                    timestamp = parse_timestamp(date, time)
                    
                    rows.append({
                        'Date': date,
                        'Time': time,
                        'File': file,
                        'Line': line_no,
                        'Message': message,
                        'Timestamp': timestamp,
                        'LogLine': line_num
                    })
    except Exception as e:
        print(f"Error reading RRM file {filepath}: {e}")
        return pd.DataFrame()
    
    if not rows:
        return pd.DataFrame()
    
    return pd.DataFrame(rows)


def extract_all_rrm_blocks_by_ue(rrm_folder):
    """
    PRE-PARSE all RRM files and extract blocks organized by UE index.
    
    Block structure:
    - Starts with: "rrm_rrc_msg_handler Received uecc_ue_index [X]"
    - Ends with: "rrm_handle_ue_admission_req_ev Sending RRC_RRM_UE_ADMISSION_RESP to RRC"
    
    Returns: { ue_index: [{timestamp: datetime, lines: [row_dicts]}, ...] }
    
    This function is called ONCE when logs are uploaded/analyzed.
    Multiple blocks per UE (with different timestamps) are preserved.
    """
    global rrm_ue_blocks_map
    
    print("\n🔍 Pre-parsing ALL RRM files and extracting blocks by UE index...")
    
    ue_blocks = defaultdict(list)
    
    if not os.path.isdir(rrm_folder):
        print(f"⚠️ RRM folder not found: {rrm_folder}")
        return {}
    
    # Find all RRM files
    rrm_files = []
    for filename in sorted(os.listdir(rrm_folder)):
        fname_lower = filename.lower()
        if (fname_lower.startswith('rrm_event_x') and '.dbg' in fname_lower):
            filepath = os.path.join(rrm_folder, filename)
            if os.path.isfile(filepath):
                rrm_files.append(filepath)
    
    if not rrm_files:
        print(f"⚠️ No RRM log files found in {rrm_folder}")
        return {}
    
    print(f"📂 Found {len(rrm_files)} RRM log files")
    
    # Patterns
    received_pattern = re.compile(r'rrm_rrc_msg_handler.*Received\s+uecc_ue_index\s*\[(\d+)\]', re.IGNORECASE)
    resp_pattern = re.compile(r'rrm_handle_ue_admission_req_ev.*Sending\s+RRC_RRM_UE_ADMISSION_RESP\s+to\s+RRC', re.IGNORECASE)
    
    total_lines = 0
    
    # Parse each RRM file
    for filepath in rrm_files:
        print(f"   📄 Parsing: {os.path.basename(filepath)}")
        rrm_df = parse_rrm_log_file(filepath)
        
        if rrm_df.empty:
            continue
        
        total_lines += len(rrm_df)
        
        current_block = None
        current_ue = None
        block_start_time = None
        
        for idx, row in rrm_df.iterrows():
            msg = str(row['Message'])
            
            # Check for block start
            received_match = received_pattern.search(msg)
            if received_match:
                # Save previous incomplete block if any
                if current_block and current_ue is not None and block_start_time:
                    ue_blocks[current_ue].append({
                        'timestamp': block_start_time,
                        'lines': current_block
                    })
                
                # Start new block
                current_ue = int(received_match.group(1))
                block_start_time = row['Timestamp']
                current_block = [row.to_dict()]
                continue
            
            # If tracking a block, add this row
            if current_block is not None and current_ue is not None:
                current_block.append(row.to_dict())
                
                # Check for block end
                if resp_pattern.search(msg):
                    # Block complete - save it
                    if block_start_time:
                        ue_blocks[current_ue].append({
                            'timestamp': block_start_time,
                            'lines': current_block
                        })
                    current_block = None
                    current_ue = None
                    block_start_time = None
        
        # Save any remaining incomplete block from this file
        if current_block and current_ue is not None and block_start_time:
            ue_blocks[current_ue].append({
                'timestamp': block_start_time,
                'lines': current_block
            })
    
    # Convert to regular dict and store globally
    rrm_ue_blocks_map = dict(ue_blocks)
    
    print(f"✅ Parsed {total_lines} RRM log lines")
    print(f"✅ Extracted RRM blocks for {len(rrm_ue_blocks_map)} UE indices")
    
    if rrm_ue_blocks_map:
        print(f"   📊 UE indices found: {sorted(list(rrm_ue_blocks_map.keys())[:20])}")
        
        # Show sample block counts
        for ue_idx in sorted(list(rrm_ue_blocks_map.keys())[:5]):
            blocks = rrm_ue_blocks_map[ue_idx]
            print(f"   - UE {ue_idx}: {len(blocks)} block(s), timestamps: {[b['timestamp'].strftime('%H:%M:%S.%f')[:-3] if b['timestamp'] else 'N/A' for b in blocks]}")
    
    return rrm_ue_blocks_map


def get_rrm_blocks_for_ue_with_timestamp(ue_index, l3_timestamp, time_window=TIME_WINDOW_SECONDS):
    """
    Get RRM blocks for a specific UE that match the L3 timestamp within the time window.
    
    Args:
        ue_index: UE index to lookup
        l3_timestamp: L3 admission request timestamp (datetime object)
        time_window: Maximum time difference in seconds (default: 3.0)
    
    Returns: List of matching RRM blocks [{timestamp, lines}, ...]
    """
    global rrm_ue_blocks_map
    
    if ue_index not in rrm_ue_blocks_map:
        return []
    
    if not l3_timestamp:
        return []
    
    matched_blocks = []
    
    for block in rrm_ue_blocks_map[ue_index]:
        rrm_timestamp = block['timestamp']
        
        if not rrm_timestamp:
            continue
        
        # Calculate time difference (RRM received time - L3 sent time)
        time_diff = (rrm_timestamp - l3_timestamp).total_seconds()
        
        # Match if within time window (RRM should come AFTER L3 request, but allow small negative values)
        if abs(time_diff) <= time_window:
            matched_blocks.append(block)
    
    return matched_blocks


def extract_l3_admission_timestamp(l3_block):
    """
    Extract the timestamp of RRC_RRM_UE_ADMISSION_REQ from an L3 block.
    
    Returns: datetime object or None
    """
    req_pattern = re.compile(r'\[API:RRC_RRM_UE_ADMISSION_REQ\(7\)\]', re.IGNORECASE)
    
    for row in l3_block:
        msg = str(row.Message) if hasattr(row, 'Message') else str(row[4])
        
        if req_pattern.search(msg):
            # Extract timestamp
            date = row.Date if hasattr(row, 'Date') else row[0]
            time = row.Time if hasattr(row, 'Time') else row[1]
            return parse_timestamp(date, time)
    
    return None


def get_rrm_journey_for_ue(ue_index):
    """
    Get ALL RRM blocks for a specific UE (without time filtering).
    Returns list of blocks: [{timestamp, lines}, ...]
    """
    global rrm_ue_blocks_map
    return rrm_ue_blocks_map.get(ue_index, [])


def get_all_rrm_journeys():
    """
    Get all RRM blocks for all UEs.
    Returns the complete rrm_ue_blocks_map.
    """
    global rrm_ue_blocks_map
    return rrm_ue_blocks_map


def clear_rrm_journeys():
    """
    Clear the global RRM blocks map.
    """
    global rrm_ue_blocks_map
    rrm_ue_blocks_map = {}
    print("🧹 Cleared RRM blocks data")


def get_rrm_stats():
    """
    Get statistics about parsed RRM data.
    """
    global rrm_ue_blocks_map
    
    if not rrm_ue_blocks_map:
        return {
            'total_ues': 0,
            'total_blocks': 0,
            'ue_list': []
        }
    
    total_blocks = sum(len(blocks) for blocks in rrm_ue_blocks_map.values())
    
    return {
        'total_ues': len(rrm_ue_blocks_map),
        'total_blocks': total_blocks,
        'ue_list': sorted(list(rrm_ue_blocks_map.keys()))
    }


def format_rrm_journey_for_display(ue_index):
    """
    Format RRM blocks for a UE into displayable text.
    """
    blocks = get_rrm_journey_for_ue(ue_index)
    
    if not blocks:
        return f"No RRM blocks found for UE {ue_index}"
    
    output = []
    output.append(f"{'='*80}")
    output.append(f"RRM Blocks for UE {ue_index}")
    output.append(f"{'='*80}\n")
    
    for idx, block in enumerate(blocks, 1):
        timestamp = block['timestamp']
        lines = block['lines']
        
        ts_str = timestamp.strftime('%d.%m.%Y %H:%M:%S.%f')[:-3] if timestamp else 'N/A'
        output.append(f"--- Block {idx} (Timestamp: {ts_str}) ---")
        
        for row in lines:
            date = row.get('Date', '')
            time = row.get('Time', '')
            file = row.get('File', '')
            line = row.get('Line', '')
            msg = row.get('Message', '')
            output.append(f"{date} {time}  {file:30s} {line:6s}  {msg}")
        output.append("")
    
    return "\n".join(output)
