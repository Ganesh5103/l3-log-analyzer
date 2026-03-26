"""
L3-RRM Log Correlation Module

STRICT EVENT-DRIVEN CORRELATION RULES (UPDATED):
1. L3 START: Find [SEND] [MODULE:RRC_RRM_MODULE_ID(2)] [API:<ANY_API_NAME>(<ANY_API_ID>)]
   Extract: timestamp (T_L3), api_id, UE index from L3 context
2. RRM SEARCH WINDOW: Search RRM logs ONLY within +3 seconds after T_L3
3. RRM HEADER MATCH: Find [HEADER]: src_id[X] api_id[Y] where api_id matches L3 api_id
4. UE INDEX CONSTRAINT: Find "Received uecc_ue_index [N]" where N matches L3 UE index
5. RRM JOURNEY RANGE: Extract from [HEADER] line until "Length of Buffer Received" (NOT inclusive)
6. MERGING: Insert RRM logs chronologically in UE journey view

STRICT PROHIBITIONS:
- ❌ NO timestamp-only correlation
- ❌ NO api_id mismatch
- ❌ NO UE index mismatch
- ❌ NO unbounded extraction
- ❌ NO guessing or inferring missing data
"""

import os
import re
from datetime import datetime, timedelta
from collections import defaultdict


class L3RRMCorrelator:
    """
    Event-driven correlator for L3 and RRM logs.
    Follows strict correlation rules - no time-based assumptions.
    """
    
    def __init__(self):
        # Store all RRM log lines with timestamps (not pre-organized by UE)
        self.rrm_logs = []  # List of dicts: {'timestamp': datetime, 'date': str, 'time': str, 'file': str, 'line': str, 'message': str}
        
        # Correlation results: {ue_index: [RRM blocks]}
        self.ue_rrm_blocks = defaultdict(list)
        
        # L3 trigger pattern - matches ANY API and extracts api_id
        # Pattern: [SEND] [MODULE:RRC_RRM_MODULE_ID(2)] [API:<ANY_NAME>(<API_ID>)]
        self.l3_trigger_pattern = re.compile(
            r'\[SEND\]\s*\[MODULE:RRC_RRM_MODULE_ID\(2\)\]\s*\[API:[^(]+\((\d+)\)\]',
            re.IGNORECASE
        )
        
        # RRM header pattern - extracts api_id from RRM header
        # Pattern: [HEADER]: src_id[X] api_id[Y] msg_size[Z] dst_id[A] sec_id[B]
        self.rrm_header_pattern = re.compile(
            r'\[HEADER\]:\s*src_id\[\d+\]\s+api_id\[(\d+)\]',
            re.IGNORECASE
        )
        
        # RRM UE index pattern after header
        self.rrm_ue_index_pattern = re.compile(
            r'rrm_rrc_msg_handler\s+Received\s+uecc_ue_index\s*\[(\d+)\]',
            re.IGNORECASE
        )
        
        # RRM end marker pattern - "Length of Buffer Received" marks the END (not inclusive)
        self.rrm_end_pattern = re.compile(
            r'Length of Buffer Received',
            re.IGNORECASE
        )
        
        # Time window for RRM search (seconds)
        self.time_window_seconds = 3.0
        
        # Regex for parsing log lines
        self.log_regex_rrm = re.compile(
            r"^(?P<date>\d{2}\.\d{2}\.\d{4})\s+"
            r"(?P<time>[\d:.]+)\s+"
            r"(?P<file>[\w_.]+\.c)\s+"
            r"(?P<line>\d+)\s+"
            r"(?P<message>.*)$"
        )
        
        self.log_regex_l3 = re.compile(
            r"^(?P<date>\d{4}-\d{2}-\d{2}|\d{2}\.\d{2}\.\d{4})\s+"
            r"(?P<time>[\d:.]+)\s+"
            r"(?P<file>[\w_.]+\.c)\s+"
            r"(?P<line>\d+)\s+"
            r"(?P<message>.*)$"
        )
    
    
    def parse_timestamp(self, date_str, time_str):
        """
        Parse date and time strings to datetime object.
        Supports multiple formats: DD.MM.YYYY and YYYY-MM-DD
        """
        try:
            dt_str = f"{date_str} {time_str}"
            formats = [
                "%d.%m.%Y %H:%M:%S.%f",
                "%d.%m.%Y %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S"
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(dt_str, fmt)
                except ValueError:
                    continue
            return None
        except Exception:
            return None
    
    
    def load_rrm_logs(self, rrm_folder):
        """
        Load ALL RRM log lines with timestamps.
        Does NOT pre-organize by UE - keeps chronological order.
        
        Args:
            rrm_folder: Path to folder containing RRM_EVENT_X*.dbg files
        
        Returns:
            Number of RRM log lines loaded
        """
        self.rrm_logs = []
        
        if not os.path.isdir(rrm_folder):
            print(f"⚠️  RRM folder not found: {rrm_folder}")
            return 0
        
        # Find all RRM files
        rrm_files = []
        for filename in sorted(os.listdir(rrm_folder)):
            fname_lower = filename.lower()
            if fname_lower.startswith('rrm_event_x') and '.dbg' in fname_lower:
                filepath = os.path.join(rrm_folder, filename)
                if os.path.isfile(filepath):
                    rrm_files.append(filepath)
        
        if not rrm_files:
            print(f"⚠️  No RRM log files found in {rrm_folder}")
            return 0
        
        print(f"\n📂 Loading RRM logs from {len(rrm_files)} file(s)...")
        
        # Parse each RRM file
        total_lines = 0
        for filepath in rrm_files:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line:
                            continue
                        
                        match = self.log_regex_rrm.match(line)
                        if match:
                            date = match.group('date')
                            time = match.group('time')
                            file = match.group('file')
                            line_no = match.group('line')
                            message = match.group('message')
                            timestamp = self.parse_timestamp(date, time)
                            
                            self.rrm_logs.append({
                                'timestamp': timestamp,
                                'date': date,
                                'time': time,
                                'file': file,
                                'line': line_no,
                                'message': message,
                                'log_line': line_num,
                                'filepath': filepath
                            })
                            total_lines += 1
            except Exception as e:
                print(f"⚠️  Error reading RRM file {filepath}: {e}")
                continue
        
        print(f"✅ Loaded {total_lines} RRM log lines")
        return total_lines
    
    
    def correlate_l3_block_with_rrm(self, l3_block, l3_ue_index):
        """
        Correlate a single L3 UE block with RRM logs using STRICT event-driven rules.
        
        RULES:
        1. Find L3 [SEND] message and extract api_id
        2. Search RRM within +3s window
        3. Find RRM [HEADER] with matching api_id
        4. Validate uecc_ue_index matches L3 UE index
        5. Extract from [HEADER] until "Length of Buffer Received" (not inclusive)
        
        Args:
            l3_block: List of L3 log rows (namedtuples or dicts) for a UE
            l3_ue_index: The L3 UE index this block belongs to
        
        Returns:
            List of correlated RRM blocks with metadata
        """
        if not l3_block or not self.rrm_logs:
            return []
        
        correlated_blocks = []
        
        # PART 1: L3 START CONDITION - Find ALL L3 → RRM requests
        l3_triggers = []
        for row in l3_block:
            # Handle both namedtuple and dict formats
            if hasattr(row, 'Message'):
                message = str(row.Message)
                date = str(row.Date)
                time = str(row.Time)
            else:
                message = str(row.get('message', ''))
                date = str(row.get('date', ''))
                time = str(row.get('time', ''))
            
            # Match L3 SEND pattern and extract api_id
            match = self.l3_trigger_pattern.search(message)
            if match:
                api_id = int(match.group(1))
                timestamp = self.parse_timestamp(date, time)
                if timestamp:
                    l3_triggers.append({
                        'timestamp': timestamp,
                        'api_id': api_id,
                        'message': message
                    })
                    print(f"🔍 L3 Trigger: UE {l3_ue_index}, API_ID {api_id}, Time: {timestamp}")
        
        if not l3_triggers:
            return []
        
        # PART 2-6: For each L3 trigger, find matching RRM journey
        for trigger in l3_triggers:
            l3_timestamp = trigger['timestamp']
            l3_api_id = trigger['api_id']
            time_window_end = l3_timestamp + timedelta(seconds=self.time_window_seconds)
            
            # PART 2: RRM SEARCH WINDOW (STRICT +3s window)
            rrm_block_lines = []
            rrm_ue_index = None
            rrm_header_found = False
            ue_index_validated = False
            capturing = False
            
            for idx, rrm_log in enumerate(self.rrm_logs):
                rrm_timestamp = rrm_log['timestamp']
                message = rrm_log['message']
                
                if not rrm_timestamp:
                    continue
                
                # Only search within +3s window AFTER L3 trigger
                if rrm_timestamp < l3_timestamp:
                    continue  # Before L3 trigger
                if rrm_timestamp > time_window_end:
                    if capturing:
                        break  # Past window and we're capturing, stop
                    continue
                
                # PART 3: RRM START POINT - Find [HEADER] with matching api_id
                if not rrm_header_found:
                    header_match = self.rrm_header_pattern.search(message)
                    if header_match:
                        rrm_api_id = int(header_match.group(1))
                        # Validate api_id MUST match
                        if rrm_api_id == l3_api_id:
                            rrm_header_found = True
                            rrm_block_lines.append(rrm_log)
                            print(f"   🔗 RRM Header: api_id [{rrm_api_id}] at {rrm_timestamp}, "
                                  f"Time diff: +{(rrm_timestamp - l3_timestamp).total_seconds():.3f}s")
                            continue
                        else:
                            # api_id mismatch - skip this RRM flow
                            continue
                
                # PART 4: UE INDEX CONSTRAINT - Validate after header
                if rrm_header_found and not ue_index_validated:
                    rrm_block_lines.append(rrm_log)
                    
                    # Look for uecc_ue_index
                    ue_match = self.rrm_ue_index_pattern.search(message)
                    if ue_match:
                        rrm_ue_index = int(ue_match.group(1))
                        # MANDATORY: UE index MUST match
                        if rrm_ue_index == l3_ue_index:
                            ue_index_validated = True
                            capturing = True
                            print(f"   ✅ UE Index Validated: uecc_ue_index [{rrm_ue_index}] matches L3 UE {l3_ue_index}")
                            continue
                        else:
                            # UE index mismatch - discard this RRM flow completely
                            print(f"   ❌ UE Index Mismatch: RRM UE {rrm_ue_index} != L3 UE {l3_ue_index} - discarding")
                            rrm_block_lines = []
                            rrm_header_found = False
                            ue_index_validated = False
                            capturing = False
                            continue
                
                # PART 5: RRM JOURNEY RANGE - Capture until end marker
                if capturing:
                    # Check for end marker BEFORE adding line
                    if self.rrm_end_pattern.search(message):
                        # Found "Length of Buffer Received" - DO NOT include this line
                        print(f"   ✅ RRM Journey Complete: {len(rrm_block_lines)} lines (ended at end marker)")
                        
                        correlated_blocks.append({
                            'l3_trigger_time': l3_timestamp,
                            'rrm_start_time': rrm_block_lines[0]['timestamp'] if rrm_block_lines else None,
                            'rrm_ue_index': rrm_ue_index,
                            'l3_ue_index': l3_ue_index,
                            'api_id': l3_api_id,
                            'lines': rrm_block_lines,
                            'incomplete': False
                        })
                        
                        # Reset state to prevent duplicate block creation
                        rrm_block_lines = []
                        capturing = False
                        break
                    else:
                        # Not end marker yet, keep capturing
                        rrm_block_lines.append(rrm_log)
            
            # Handle incomplete block (reached time window end without finding end marker)
            if capturing and rrm_block_lines:
                print(f"   ⚠️  RRM Journey Incomplete (no end marker within {self.time_window_seconds}s): "
                      f"{len(rrm_block_lines)} lines extracted")
                correlated_blocks.append({
                    'l3_trigger_time': l3_timestamp,
                    'rrm_start_time': rrm_block_lines[0]['timestamp'] if rrm_block_lines else None,
                    'rrm_ue_index': rrm_ue_index,
                    'l3_ue_index': l3_ue_index,
                    'api_id': l3_api_id,
                    'lines': rrm_block_lines,
                    'incomplete': True
                })
        
        return correlated_blocks
    
    
    def correlate_all_l3_blocks(self, l3_ue_data_map):
        """
        Correlate ALL L3 UE blocks with RRM logs.
        
        Args:
            l3_ue_data_map: Dict {ue_index: [blocks]} where each block is a list of log rows
        
        Returns:
            Dict {l3_ue_index: [RRM blocks]}
        """
        if not l3_ue_data_map:
            print("⚠️  No L3 data provided for correlation")
            return {}
        
        if not self.rrm_logs:
            print("⚠️  No RRM logs loaded for correlation")
            return {}
        
        print(f"\n🔗 Starting L3-RRM Correlation...")
        print(f"   L3 UEs: {len(l3_ue_data_map)}")
        print(f"   RRM logs: {len(self.rrm_logs)} lines")
        
        self.ue_rrm_blocks = defaultdict(list)
        
        total_correlations = 0
        ue_mismatch_count = 0
        
        for l3_ue_index, l3_blocks in sorted(l3_ue_data_map.items()):
            # Process all blocks for this L3 UE
            for block_idx, l3_block in enumerate(l3_blocks):
                rrm_correlations = self.correlate_l3_block_with_rrm(l3_block, l3_ue_index)
                
                for correlation in rrm_correlations:
                    rrm_ue_index = correlation['rrm_ue_index']
                    
                    # Validate UE index match (warning if mismatch)
                    if rrm_ue_index != l3_ue_index:
                        print(f"⚠️  UE Index Mismatch: L3 UE {l3_ue_index} triggered RRM block for UE {rrm_ue_index}")
                        ue_mismatch_count += 1
                    
                    # Store RRM block under L3 UE index (as per user requirement)
                    self.ue_rrm_blocks[l3_ue_index].append(correlation)
                    total_correlations += 1
        
        print(f"\n✅ Correlation Complete:")
        print(f"   Total correlations: {total_correlations}")
        print(f"   UEs with RRM data: {len(self.ue_rrm_blocks)}")
        print(f"   UE index mismatches: {ue_mismatch_count}")
        
        if self.ue_rrm_blocks:
            sample_ues = sorted(list(self.ue_rrm_blocks.keys()))[:5]
            for ue_idx in sample_ues:
                blocks = self.ue_rrm_blocks[ue_idx]
                print(f"   - UE {ue_idx}: {len(blocks)} RRM block(s)")
        
        return dict(self.ue_rrm_blocks)
    
    
    def get_rrm_blocks_for_ue(self, ue_index):
        """
        Get all correlated RRM blocks for a specific L3 UE index.
        
        Returns:
            List of RRM blocks: [{'l3_trigger_time': ..., 'rrm_ue_index': ..., 'lines': [...]}, ...]
        """
        return self.ue_rrm_blocks.get(ue_index, [])
    
    
    def set_time_window(self, seconds):
        """
        Set the RRM search time window (default: 3.0 seconds).
        
        Args:
            seconds: Time window in seconds (must be > 0)
        """
        if seconds > 0:
            self.time_window_seconds = float(seconds)
            print(f"✅ Set RRM search window to {seconds}s")
        else:
            print(f"❌ Invalid time window: {seconds} (must be > 0)")
    
    
    def get_stats(self):
        """
        Get correlation statistics.
        """
        return {
            'rrm_log_lines': len(self.rrm_logs),
            'ues_with_rrm': len(self.ue_rrm_blocks),
            'total_rrm_blocks': sum(len(blocks) for blocks in self.ue_rrm_blocks.values()),
            'time_window_seconds': self.time_window_seconds,
            'correlation_rules': 'Event-driven with api_id and UE index validation'
        }
    
    
    def clear(self):
        """
        Clear all loaded data.
        """
        self.rrm_logs = []
        self.ue_rrm_blocks = defaultdict(list)
        print("🧹 Cleared L3-RRM correlation data")


# Global correlator instance
_global_correlator = None


def get_correlator():
    """
    Get the global correlator instance.
    """
    global _global_correlator
    if _global_correlator is None:
        _global_correlator = L3RRMCorrelator()
    return _global_correlator


def initialize_correlation(rrm_folder, l3_ue_data_map):
    """
    Initialize and run L3-RRM correlation.
    
    Args:
        rrm_folder: Path to folder containing RRM logs
        l3_ue_data_map: Dict {ue_index: [blocks]} of L3 UE data
    
    Returns:
        Dict {ue_index: [RRM blocks]}
    """
    correlator = get_correlator()
    correlator.clear()
    correlator.load_rrm_logs(rrm_folder)
    return correlator.correlate_all_l3_blocks(l3_ue_data_map)


def get_rrm_for_ue(ue_index):
    """
    Get correlated RRM blocks for a specific UE.
    """
    correlator = get_correlator()
    return correlator.get_rrm_blocks_for_ue(ue_index)


def get_correlation_stats():
    """
    Get correlation statistics.
    """
    correlator = get_correlator()
    return correlator.get_stats()


def clear_correlation():
    """
    Clear correlation data.
    """
    correlator = get_correlator()
    correlator.clear()


def set_correlation_time_window(seconds):
    """
    Set the RRM search time window (default: 3.0 seconds).
    
    Example:
        set_correlation_time_window(5.0)  # Increase to 5 seconds
    """
    correlator = get_correlator()
    correlator.set_time_window(seconds)
