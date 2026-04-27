"""
Data Preprocessor - Pre-compute ALL statistics and indexes ONCE at startup
This eliminates the need for loops in request handlers.
"""

import re
from typing import Dict, List, Set, Any, Tuple
from collections import defaultdict
import time


class DataPreprocessor:
    """
    Pre-computes ALL statistics, indexes, and aggregations for instant O(1) lookups.
    Run this ONCE when a session is uploaded/loaded.
    """
    
    def __init__(self, ue_data_map: Dict[int, List], rrc_counts: Dict[str, int]):
        self.ue_data_map = ue_data_map
        self.rrc_counts = rrc_counts
        self.cache = {
            'ue_stats': {},
            'ue_insights': {},
            'ue_milestones': {},
            'ue_classification': {},
            'ue_failures': {},
            'search_index': {},
            'keyword_to_ues': {},
            'message_patterns': {},
            'ho_mapping': {},
            'summary': {},
            'rrc_drop_rates': {},
            'quick_lookup': {}
        }
        
        #Pre-compile regex patterns once
        self.patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Pre-compile ALL regex patterns for reuse"""
        return {
            'rrc_req': re.compile(r"\[RNTI:\d+\]\s*RRC_MSG:\s*RRC\s*CONNECTION\s*REQUEST", re.IGNORECASE),
            'rrc_setup': re.compile(r"RRC\s*CONNECTION\s*SETUP\b", re.IGNORECASE),
            'rrc_setup_complete': re.compile(r"RRC\s*CONNECTION\s*SETUP\s*COMPLETE", re.IGNORECASE),
            'rrc_reconfig': re.compile(r"RRC\s*CONNECTION\s*RECONFIGURATION\b", re.IGNORECASE),
            'rrc_reconfig_complete': re.compile(r"RRC\s*CONNECTION\s*RECONFIGURATION\s*COMPLETE", re.IGNORECASE),
            'handover_req': re.compile(r"HANDOVER\s*REQUEST\b", re.IGNORECASE),
            'handover_ack': re.compile(r"HANDOVER\s*REQUEST\s*ACKNOWLEDGE", re.IGNORECASE),
            'x2ap_ho_req': re.compile(r"X2AP.*HANDOVER REQUEST", re.IGNORECASE),
            's1ap_ho_req': re.compile(r"S1AP_MSG:\s*HANDOVER REQUEST", re.IGNORECASE),
            'ics_req': re.compile(r"INITIAL CONTEXT SETUP REQUEST", re.IGNORECASE),
            'ics_resp': re.compile(r"INITIAL CONTEXT SETUP RESPONSE", re.IGNORECASE),
            'path_switch_req': re.compile(r"PATH SWITCH REQUEST\b", re.IGNORECASE),
            'path_switch_ack': re.compile(r"PATH SWITCH REQUEST ACK", re.IGNORECASE),
            'rlf': re.compile(r"RLF|RLF_IND", re.IGNORECASE),
            'asn_fail': re.compile(r"ASN1\s+ENCODING\s+FAILED|ASN\s+DECODING\s+FAILED", re.IGNORECASE),
            'rnti': re.compile(r"Value of U16 crnti\s*=\s*(\d+)", re.IGNORECASE),
            'cell_id': re.compile(r"Value of U8 cell_index\s*=\s*(\d+)", re.IGNORECASE),
        }
    
    def precompute_all(self) -> Dict[str, Any]:
        """
        Main entry point: Pre-compute EVERYTHING in one pass.
        This runs ONCE and builds all caches.
        """
        print(f"🚀 Starting pre-computation for {len(self.ue_data_map)} UEs...")
        start_time = time.time()
        
        # Build all caches
        self._build_ue_stats()
        self._build_ue_insights()
        self._build_ue_milestones()
        self._build_search_index()
        self._build_quick_lookup()
        self._build_summary()
        self._compute_rrc_drop_rates()
        
        elapsed = time.time() - start_time
        print(f"✅ Pre-computation complete in {elapsed:.2f}s")
        print(f"   - UE Stats: {len(self.cache['ue_stats'])} entries")
        print(f"   - Insights: {len(self.cache['ue_insights'])} entries")
        print(f"   - Search Index: {len(self.cache['search_index'])} keywords")
        
        return self.cache
    
    def _build_ue_stats(self):
        """Pre-compute statistics for ALL UEs in a single pass"""
        print("  📊 Building UE statistics...")
        
        for ue_idx, blocks in self.ue_data_map.items():
            stats = {
                'rrc_req': 0, 'rrc_setup': 0, 'rrc_setup_complete': 0,
                'rrc_reconfig': 0, 'rrc_reconfig_complete': 0,
                'handover_req': 0, 'handover_ack': 0,
                'x2ap_ho_req': 0, 's1ap_ho_req': 0,
                'ics_req': 0, 'ics_resp': 0,
                'path_switch_req': 0, 'path_switch_ack': 0,
                'rlf': 0, 'asn_fail': 0,
                'rnti': None, 'cell_id': None,
                'first_timestamp': None, 'last_timestamp': None
            }
            
            # Single pass through all messages
            for block in blocks:
                for row in block:
                    msg = str(getattr(row, 'Message', '')).upper()
                    
                    # Count patterns
                    if self.patterns['rrc_req'].search(msg):
                        stats['rrc_req'] += 1
                    if self.patterns['rrc_setup'].search(msg):
                        stats['rrc_setup'] += 1
                    if self.patterns['rrc_setup_complete'].search(msg):
                        stats['rrc_setup_complete'] += 1
                    if self.patterns['rrc_reconfig'].search(msg):
                        stats['rrc_reconfig'] += 1
                    if self.patterns['rrc_reconfig_complete'].search(msg):
                        stats['rrc_reconfig_complete'] += 1
                    if self.patterns['handover_req'].search(msg):
                        stats['handover_req'] += 1
                    if self.patterns['handover_ack'].search(msg):
                        stats['handover_ack'] += 1
                    if self.patterns['x2ap_ho_req'].search(msg):
                        stats['x2ap_ho_req'] += 1
                    if self.patterns['s1ap_ho_req'].search(msg):
                        stats['s1ap_ho_req'] += 1
                    if self.patterns['ics_req'].search(msg):
                        stats['ics_req'] += 1
                    if self.patterns['ics_resp'].search(msg):
                        stats['ics_resp'] += 1
                    if self.patterns['path_switch_req'].search(msg):
                        stats['path_switch_req'] += 1
                    if self.patterns['path_switch_ack'].search(msg):
                        stats['path_switch_ack'] += 1
                    if self.patterns['rlf'].search(msg):
                        stats['rlf'] += 1
                    if self.patterns['asn_fail'].search(msg):
                        stats['asn_fail'] += 1
                    
                    # Extract RNTI and Cell ID
                    if stats['rnti'] is None:
                        m = self.patterns['rnti'].search(msg)
                        if m:
                            stats['rnti'] = int(m.group(1))
                    
                    if stats['cell_id'] is None:
                        m = self.patterns['cell_id'].search(msg)
                        if m:
                            stats['cell_id'] = int(m.group(1))
                    
                    # Track timestamps
                    timestamp = f"{getattr(row, 'Date', '')} {getattr(row, 'Time', '')}"
                    if stats['first_timestamp'] is None:
                        stats['first_timestamp'] = timestamp
                    stats['last_timestamp'] = timestamp
            
            self.cache['ue_stats'][ue_idx] = stats
    
    def _build_ue_insights(self):
        """Pre-generate insights for ALL UEs"""
        print("  💡 Generating insights...")
        
        for ue_idx, stats in self.cache['ue_stats'].items():
            insights = []
            has_issue = False
            
            # Check for issues
            if stats['rrc_req'] > stats['rrc_setup']:
                insights.append(f"❌ {stats['rrc_req']} RRC Requests but only {stats['rrc_setup']} Setups")
                has_issue = True
            
            if stats['rrc_setup'] > stats['rrc_setup_complete']:
                insights.append(f"❌ {stats['rrc_setup']} Setups but only {stats['rrc_setup_complete']} Complete")
                has_issue = True
            
            if stats['rrc_reconfig'] > stats['rrc_reconfig_complete']:
                insights.append(f"❌ {stats['rrc_reconfig']} Reconfigs but only {stats['rrc_reconfig_complete']} Complete")
                has_issue = True
            
            if stats['rlf'] > 0:
                insights.append(f"⚠️ Radio Link Failure detected ({stats['rlf']} occurrences)")
                has_issue = True
            
            if stats['asn_fail'] > 0:
                insights.append(f"⚠️ ASN encoding/decoding failures ({stats['asn_fail']} occurrences)")
                has_issue = True
            
            if not has_issue:
                insights.append("✅ UE flow appears normal")
            
            self.cache['ue_insights'][ue_idx] = "\n".join(insights)
    
    def _build_ue_milestones(self):
        """Pre-extract milestones for ALL UEs"""
        print("  🎯 Extracting milestones...")
        
        milestone_patterns = [
            ("RRC CONNECTION REQUEST", "RRC Connection Request"),
            ("RRC CONNECTION SETUP", "RRC Connection Setup"),
            ("RRC CONNECTION SETUP COMPLETE", "RRC Connection Setup Complete"),
            ("SECURITY MODE COMMAND", "Security Mode Command"),
            ("SECURITY MODE COMPLETE", "Security Mode Complete"),
            ("X2AP.*HANDOVER REQUEST", "X2AP HO Request"),
            ("PATH SWITCH REQUEST", "Path Switch Request"),
        ]
        
        for ue_idx, blocks in self.ue_data_map.items():
            milestones = []
            sequence = 1
            
            for block in blocks:
                for row in block:
                    msg = str(getattr(row, 'Message', ''))
                    timestamp = f"{getattr(row, 'Date', '')} {getattr(row, 'Time', '')}"
                    
                    for pattern, label in milestone_patterns:
                        if re.search(pattern, msg, re.IGNORECASE):
                            milestones.append({
                                'sequence': sequence,
                                'timestamp': timestamp,
                                'event': label,
                                'message': msg[:100]  # Truncate long messages
                            })
                            sequence += 1
                            break
            
            self.cache['ue_milestones'][ue_idx] = milestones
    
    def _build_search_index(self):
        """Build reverse index for O(1) keyword search"""
        print("  🔍 Building search index...")
        
        keyword_index = defaultdict(set)
        
        for ue_idx, blocks in self.ue_data_map.items():
            keywords_for_ue = set()
            
            for block in blocks:
                for row in block:
                    msg = str(getattr(row, 'Message', '')).upper()
                    
                    # Extract important keywords
                    important_patterns = [
                        'HANDOVER', 'RRC', 'S1AP', 'X2AP', 'ERAB',
                        'SECURITY', 'PATH SWITCH', 'RLF', 'ASN',
                        'FAILURE', 'REJECT', 'CANCEL', 'TIMEOUT'
                    ]
                    
                    for keyword in important_patterns:
                        if keyword in msg:
                            keywords_for_ue.add(keyword)
                            keyword_index[keyword].add(ue_idx)
            
            self.cache['ue_classification'][ue_idx] = list(keywords_for_ue)
        
        # Convert sets to lists for JSON serialization
        self.cache['search_index'] = {k: list(v) for k, v in keyword_index.items()}
    
    def _build_quick_lookup(self):
        """Build denormalized quick-lookup table for O(1) access"""
        print("  ⚡ Building quick lookup table...")
        
        for ue_idx, stats in self.cache['ue_stats'].items():
            # Classify UE type
            is_x2ap_ho = stats['x2ap_ho_req'] > 0
            is_s1ap_ho = stats['s1ap_ho_req'] > 0
            
            ue_type = 'direct_attach'
            if is_s1ap_ho:
                ue_type = 's1ap_handover'
            elif is_x2ap_ho:
                ue_type = 'x2ap_handover'
            
            # Determine status
            is_success = (
                (stats['ics_resp'] > 0 or stats['rrc_setup_complete'] > 0) and
                stats['rlf'] == 0 and stats['asn_fail'] == 0
            )
            
            self.cache['quick_lookup'][ue_idx] = {
                'type': ue_type,
                'status': 'success' if is_success else 'failed',
                'stats': stats,
                'insight': self.cache['ue_insights'].get(ue_idx, ''),
                'milestones_count': len(self.cache['ue_milestones'].get(ue_idx, []))
            }
    
    def _build_summary(self):
        """Pre-compute dashboard summary"""
        print("  📈 Building summary...")
        
        total_ues = len(self.ue_data_map)
        direct_attach = sum(1 for v in self.cache['quick_lookup'].values() if v['type'] == 'direct_attach')
        x2ap_ho = sum(1 for v in self.cache['quick_lookup'].values() if v['type'] == 'x2ap_handover')
        s1ap_ho = sum(1 for v in self.cache['quick_lookup'].values() if v['type'] == 's1ap_handover')
        successful = sum(1 for v in self.cache['quick_lookup'].values() if v['status'] == 'success')
        failed = total_ues - successful
        
        self.cache['summary'] = {
            'total_ues': total_ues,
            'direct_attach': direct_attach,
            'x2ap_handover': x2ap_ho,
            's1ap_handover': s1ap_ho,
            'successful': successful,
            'failed': failed,
            'success_rate': round(successful / total_ues * 100, 2) if total_ues > 0 else 0
        }
    
    def _compute_rrc_drop_rates(self):
        """Pre-compute RRC drop rates"""
        print("  📉 Computing drop rates...")
        
        rrc_req = self.rrc_counts.get('RRC CONNECTION REQUEST', 0)
        rrc_complete = self.rrc_counts.get('RRC CONNECTION SETUP COMPLETE', 0)
        
        if rrc_req > 0:
            success_rate = (rrc_complete / rrc_req) * 100
            self.cache['rrc_drop_rates'] = {
                'RRC_SUCCESS_RATE': {
                    'numerator': rrc_complete,
                    'denominator': rrc_req,
                    'ratio': success_rate / 100,
                    'formatted': f"{success_rate:.2f}% ({rrc_complete}/{rrc_req})"
                }
            }
        else:
            self.cache['rrc_drop_rates'] = {
                'RRC_SUCCESS_RATE': {
                    'numerator': 0,
                    'denominator': 0,
                    'ratio': None,
                    'formatted': 'N/A'
                }
            }


# Example usage:
if __name__ == "__main__":
    # Mock data for testing
    test_data = {}  # Would be populated with actual UE data
    test_rrc = {}   # Would be populated with RRC counts
    
    preprocessor = DataPreprocessor(test_data, test_rrc)
    cache = preprocessor.precompute_all()
    
    print(f"\n📦 Cache contains {len(cache)} top-level keys")
    print(f"   Keys: {list(cache.keys())}")
