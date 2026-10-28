#!/usr/bin/env python3
"""
EX4 Studio
A comprehensive GUI application for analyzing MetaTrader 4 EX4 binary files
and converting them into multiple readable programming languages.

Consolidates all analysis techniques: pattern recognition, x86 disassembly,
PE header analysis, string extraction, trading strategy detection, and
multi-language code generation (MQL4, MQL5, Python, C, R, Text).
"""

import os
import sys
import struct
import re
import json
import math
import logging
import binascii
import threading
from datetime import datetime
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional

import customtkinter as ctk
from tkinter import filedialog, messagebox
import tkinter as tk

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("EX4Studio")
logger.setLevel(logging.DEBUG)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MT4_FUNCTIONS = {
    b'OrderSend': 'OrderSend (Place order)',
    b'OrderClose': 'OrderClose (Close order)',
    b'OrderModify': 'OrderModify (Modify order)',
    b'OrderDelete': 'OrderDelete (Delete pending)',
    b'OrderSelect': 'OrderSelect (Select order)',
    b'OrdersTotal': 'OrdersTotal (Count orders)',
    b'OrderTicket': 'OrderTicket (Get ticket)',
    b'OrderProfit': 'OrderProfit (Get profit)',
    b'OrderLots': 'OrderLots (Get lot size)',
    b'OrderType': 'OrderType (Get order type)',
    b'OrderSymbol': 'OrderSymbol (Get symbol)',
    b'OrderOpenPrice': 'OrderOpenPrice (Get open price)',
    b'OrderClosePrice': 'OrderClosePrice (Get close price)',
    b'OrderStopLoss': 'OrderStopLoss (Get SL)',
    b'OrderTakeProfit': 'OrderTakeProfit (Get TP)',
    b'OrderMagicNumber': 'OrderMagicNumber (Get magic)',
    b'OrderComment': 'OrderComment (Get comment)',
}

MT4_INDICATORS = {
    b'iMA': 'Moving Average',
    b'iRSI': 'Relative Strength Index',
    b'iMACD': 'MACD',
    b'iATR': 'Average True Range',
    b'iBands': 'Bollinger Bands',
    b'iStochastic': 'Stochastic Oscillator',
    b'iCCI': 'Commodity Channel Index',
    b'iADX': 'Average Directional Index',
    b'iIchimoku': 'Ichimoku Kinko Hyo',
    b'iFractals': 'Fractals',
    b'iAlligator': 'Alligator',
    b'iSAR': 'Parabolic SAR',
    b'iCustom': 'Custom Indicator',
    b'iOBV': 'On Balance Volume',
    b'iMFI': 'Money Flow Index',
    b'iWPR': 'Williams Percent Range',
    b'iDeMarker': 'DeMarker',
    b'iForce': 'Force Index',
    b'iMomentum': 'Momentum',
    b'iEnvelopes': 'Envelopes',
}

MT4_BUFFER_FUNCTIONS = {
    b'SetIndexBuffer': 'Buffer Setup',
    b'SetIndexStyle': 'Style Setup',
    b'SetIndexLabel': 'Label Setup',
    b'SetIndexDrawBegin': 'Draw Begin',
    b'IndicatorBuffers': 'Buffer Count',
    b'IndicatorShortName': 'Short Name',
    b'SetLevelValue': 'Level Value',
    b'SetLevelStyle': 'Level Style',
}

MT4_EVENT_HANDLERS = [
    b'OnInit', b'OnDeinit', b'OnStart', b'OnTick', b'OnCalculate',
    b'OnTimer', b'OnChartEvent', b'OnTester', b'OnTesterInit',
    b'OnTesterDeinit', b'OnTesterPass',
]

STRATEGY_PATTERNS = {
    b'Martingale': 'Martingale',
    b'martingale': 'Martingale',
    b'Grid': 'Grid Trading',
    b'grid': 'Grid Trading',
    b'Scalp': 'Scalping',
    b'scalp': 'Scalping',
    b'Breakout': 'Breakout',
    b'breakout': 'Breakout',
    b'Trend': 'Trend Following',
    b'trend': 'Trend Following',
    b'Hedg': 'Hedging',
    b'hedg': 'Hedging',
    b'MeanReversion': 'Mean Reversion',
    b'Momentum': 'Momentum',
    b'Swing': 'Swing Trading',
    b'DayTrad': 'Day Trading',
    b'Arbitrage': 'Arbitrage',
}

TIMEFRAME_PATTERNS = {
    b'PERIOD_M1': 'M1', b'PERIOD_M5': 'M5', b'PERIOD_M15': 'M15',
    b'PERIOD_M30': 'M30', b'PERIOD_H1': 'H1', b'PERIOD_H4': 'H4',
    b'PERIOD_D1': 'D1', b'PERIOD_W1': 'W1', b'PERIOD_MN1': 'MN1',
}

MIN_STRUCTURED_STRING_LEN = 4
URL_PATTERN = r'https?://[^\x00\s\'"]{4,}'
WWW_PATTERN = r'www\.[^\x00\s\'"]{4,}'
METADATA_STRING_MAX_LEN = 120
DESCRIPTION_MIN_LEN = 12
DESCRIPTION_MAX_LEN = 100
HIGH_ENTROPY_THRESHOLD = 7.2
LOW_SEMANTIC_RATIO_THRESHOLD = 0.08
HIGH_OBFUSCATION_SCORE = 5
MEDIUM_OBFUSCATION_SCORE = 3

AUDIT_KEYWORDS = {
    'credential_access': [
        'AccountPassword', 'Password',
    ],
    'network_io': [
        'WebRequest', 'SendMail', 'URLDownloadToFile',
        'InternetOpen', 'Wininet', 'Socket',
    ],
    'dll_usage': [
        '#import', 'LoadLibrary', 'GetProcAddress',
    ],
    'account_locking': [
        'AccountNumber', 'AccountServer', 'AccountCompany',
    ],
    'account_queries': [
        'AccountBalance', 'AccountEquity', 'AccountName',
        'AccountCurrency', 'AccountLeverage',
    ],
    'backtest_detection': [
        'IsTesting', 'TesterStatistics', 'MQL_TESTER',
    ],
    'time_gating': [
        'TimeCurrent', 'TimeLocal', 'TimeGMT', 'Hour',
        'DayOfWeek', 'TimeDayOfWeek', 'Expiration',
    ],
}

PARAM_TYPE_HINTS = {
    'period': ('int', 14), 'shift': ('int', 0), 'lot': ('double', 0.1),
    'lots': ('double', 0.1), 'stoploss': ('int', 50), 'sl': ('int', 50),
    'takeprofit': ('int', 100), 'tp': ('int', 100),
    'maxlots': ('double', 1.0), 'slippage': ('int', 3),
    'magic': ('int', 12345), 'risk': ('double', 1.0),
    'percent': ('double', 2.0), 'deviation': ('int', 10),
    'fast': ('int', 12), 'slow': ('int', 26), 'signal': ('int', 9),
    'bands': ('int', 20), 'multiplier': ('double', 2.0),
    'atr': ('int', 14), 'rsi': ('int', 14),
}


# ---------------------------------------------------------------------------
# Core Analysis Engine
# ---------------------------------------------------------------------------

class EX4AnalysisEngine:
    """Comprehensive EX4 binary analysis engine combining all techniques."""

    def __init__(self):
        if HAS_CAPSTONE:
            self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            self.cs.detail = False
        else:
            self.cs = None

    # -- top-level entry point ------------------------------------------------

    def analyze(self, filepath: str) -> Dict:
        """Full analysis pipeline."""
        logger.info("Starting analysis of %s", filepath)
        with open(filepath, 'rb') as fh:
            data = fh.read()

        if len(data) < 16:
            raise ValueError("File too small to be a valid EX4 file")

        metadata = self._extract_metadata(data)

        # For old format, also extract parameter names from sections
        ex4_params = self._parse_ex4_parameters(data, metadata)
        structured_strings = self._extract_structured_strings(
            data, metadata, ex4_params)
        strings, string_sources = self._merge_string_sources(
            structured_strings, self._extract_strings(data))
        metadata = self._enrich_metadata_from_strings(metadata, strings)

        categories = self._categorize_strings(strings)

        # Search for patterns in both raw data and extracted strings
        string_blob = '\n'.join(strings).encode('ascii', errors='ignore')
        patterns = self._find_patterns(data)
        string_patterns = self._find_patterns(string_blob)
        seen_pats = {p['pattern'] for p in patterns}
        for sp in string_patterns:
            if sp['pattern'] not in seen_pats:
                patterns.append(sp)
                seen_pats.add(sp['pattern'])

        # Detect event handlers from both binary and strings
        handlers = self._find_event_handlers(data)
        for s in strings:
            for h in MT4_EVENT_HANDLERS:
                hname = h.decode()
                if hname in s and hname not in handlers:
                    handlers.append(hname)

        # Detect indicators from strings too
        indicators = self._find_indicators(data)
        ind_names = {i['name'] for i in indicators}
        for s in strings:
            for pat, desc in MT4_INDICATORS.items():
                pname = pat.decode()
                if pname in s and pname not in ind_names:
                    indicators.append({'name': pname, 'description': desc,
                                       'count': 1})
                    ind_names.add(pname)

        # Detect trading functions from strings too
        trading_funcs = self._find_trading_functions(data)
        tf_names = {f['name'] for f in trading_funcs}
        for s in strings:
            for pat, desc in MT4_FUNCTIONS.items():
                pname = pat.decode()
                if pname in s and pname not in tf_names:
                    trading_funcs.append({'name': pname, 'description': desc,
                                          'count': 1})
                    tf_names.add(pname)

        # Extract input parameters from both strings and EX4 sections
        input_params = self._extract_input_parameters(categories)
        param_names = {p['name'] for p in input_params}
        for ep in ex4_params:
            if ep['name'] not in param_names:
                input_params.append(ep)
                param_names.add(ep['name'])

        result = {
            'filepath': filepath,
            'filename': os.path.basename(filepath),
            'metadata': metadata,
            'pe_info': self._parse_pe_header(data),
            'patterns': patterns,
            'strings': strings,
            'string_sources': string_sources,
            'string_categories': categories,
            'event_handlers': handlers,
            'trading_functions': trading_funcs,
            'indicators_detected': indicators,
            'buffer_functions': self._find_buffer_functions(data),
            'input_parameters': input_params,
            'trading_strategy': self._analyze_strategy(data),
            'risk_management': self._analyze_risk(data, strings),
            'audit_report': self._audit_binary(data, strings),
            'disassembly': self._disassemble(data),
            'statistics': self._statistics(data, strings, string_sources),
        }
        result['recovery_profile'] = self._build_recovery_profile(result)
        logger.info("Analysis complete – %d patterns, %d strings",
                     len(result['patterns']), len(strings))
        return result

    # -- metadata -------------------------------------------------------------

    def _extract_metadata(self, data: bytes) -> Dict:
        meta: Dict = {
            'type': 'Unknown', 'version': 'Unknown',
            'creation_date': 'Unknown', 'file_size': len(data),
            'copyright': 'Unknown', 'description': 'Unknown',
            'author': 'Unknown', 'link': 'Unknown',
            'format': 'Unknown', 'build': 0, 'codepage': 0,
        }

        # Detect EX4 format from magic bytes
        magic = data[:4]
        if magic == b'EX4\x00':
            # Legacy format (build < 600, unencrypted)
            meta['format'] = 'Legacy (EX4, unencrypted)'
            if len(data) >= 12:
                meta['_data_size'] = struct.unpack('<I', data[4:8])[0]
                meta['_code_size'] = struct.unpack('<I', data[8:12])[0]
            # Copyright string at offset 0x0C (null-terminated ASCII)
            if len(data) > 12:
                end = data.index(b'\x00', 12) if b'\x00' in data[12:100] else min(100, len(data))
                raw = data[12:end]
                if len(raw) >= 3:
                    meta['copyright'] = raw.decode('ascii', errors='replace').strip()
            # Old format is always an indicator for build < 600
            meta['type'] = 'Indicator'
        elif magic == b'EX-\x04':
            # New format (build 600+, encrypted)
            meta['format'] = 'Modern (EX-, encrypted)'
            if len(data) >= 20:
                meta['build'] = struct.unpack('<H', data[6:8])[0]
                meta['codepage'] = struct.unpack('<I', data[16:20])[0]
            # Type detection from header flags at offset 0x0B
            if len(data) > 11:
                type_byte = data[11]
                if type_byte & 0x80:
                    meta['type'] = 'Expert Advisor'
                elif type_byte & 0x40:
                    meta['type'] = 'Indicator'
                elif type_byte & 0x20:
                    meta['type'] = 'Script'
                else:
                    meta['type'] = 'Library'
            meta['version'] = f"Build {meta['build']}"
        else:
            meta['format'] = 'Unknown'

        # Fallback type detection from string content
        if meta['type'] == 'Unknown':
            dl = data.lower()
            if b'expert' in dl or b'EA' in data:
                meta['type'] = 'Expert Advisor'
            elif b'script' in dl:
                meta['type'] = 'Script'
            elif b'library' in dl:
                meta['type'] = 'Library'
            elif b'indicator' in dl:
                meta['type'] = 'Indicator'

        # Extract version from string patterns
        if meta['version'] == 'Unknown':
            for pat in [
                rb'version[\s=:]+([\d]+\.[\d]+(?:\.[\d]+)?)',
                rb'v[\s]*([\d]+\.[\d]+(?:\.[\d]+)?)',
            ]:
                m = re.search(pat, data, re.IGNORECASE)
                if m:
                    meta['version'] = m.group(1).decode('ascii', errors='ignore')
                    break

        # Extract copyright, description, author from string patterns
        if meta['copyright'] == 'Unknown':
            for field, regex in [
                ('copyright', rb'copyright[\s]*[:(\s]*([^\x00]{3,50})'),
                ('description', rb'description[\s]*[:(\s]*([^\x00]{3,100})'),
                ('author', rb'author[\s]*[:(\s]*([^\x00]{3,50})'),
            ]:
                m = re.search(regex, data, re.IGNORECASE)
                if m:
                    meta[field] = m.group(1).decode('ascii', errors='ignore').strip()

        m = re.search(rb'(https?://[^\x00\s]{3,100})', data)
        if m:
            meta['link'] = m.group(1).decode('ascii', errors='ignore').strip()

        return meta

    # -- EX4 parameter section parsing ----------------------------------------

    def _parse_ex4_parameters(self, data: bytes, metadata: Dict) -> List[Dict]:
        """Parse input parameters from old-format EX4 parameter tables."""
        params = []
        magic = data[:4]
        if magic != b'EX4\x00' or len(data) < 100:
            return params

        # In old format, find the parameter table by looking for
        # blocks of 56 bytes containing null-terminated ASCII names
        # Skip header: magic(4) + data_size(4) + code_size(4) + copyright
        pos = 12
        while pos < min(len(data), 200) and data[pos] != 0:
            pos += 1
        pos += 1  # skip null terminator

        # Scan for parameter table entries (56-byte records)
        entry_size = 56
        name_offset = 12  # name starts 12 bytes into each entry
        search_start = max(pos, 0x100)

        # Find first entry by looking for readable names at 12-byte offsets
        for scan in range(search_start, min(len(data) - entry_size, 0x800)):
            candidate = data[scan + name_offset:scan + entry_size]
            null_idx = candidate.find(b'\x00')
            if null_idx < 3:
                continue
            name = candidate[:null_idx]
            if all(32 <= b <= 126 for b in name) and len(name) >= 3:
                # Verify next entry also has a name
                next_candidate = data[scan + entry_size + name_offset:
                                      scan + 2 * entry_size]
                next_null = next_candidate.find(b'\x00')
                if next_null >= 3:
                    next_name = next_candidate[:next_null]
                    if all(32 <= b <= 126 for b in next_name):
                        # Found the parameter table
                        table_start = scan
                        while table_start < len(data) - entry_size:
                            entry = data[table_start:table_start + entry_size]
                            name_bytes = entry[name_offset:]
                            ni = name_bytes.find(b'\x00')
                            if ni < 2:
                                break
                            pname = name_bytes[:ni].decode('ascii',
                                                           errors='ignore')
                            if not all(32 <= b <= 126 for b in
                                       name_bytes[:ni]):
                                break

                            # Determine type from value patterns
                            raw_val = struct.unpack('<I', entry[0:4])[0]
                            ptype = 'int'
                            default = raw_val

                            # Color values (common in indicator params)
                            pname_lower = pname.lower()
                            if 'color' in pname_lower:
                                ptype = 'color'
                                default = f"0x{raw_val:06X}"
                            elif 'show' in pname_lower or 'use' in pname_lower:
                                ptype = 'bool'
                                default = bool(raw_val)
                            elif 'lot' in pname_lower or 'risk' in pname_lower:
                                ptype = 'double'
                                default = struct.unpack('<f', entry[0:4])[0]
                                default = round(default, 4)

                            params.append({
                                'name': pname,
                                'type': ptype,
                                'default': default,
                            })
                            table_start += entry_size
                        break

        return params

    def _extract_structured_strings(self, data: bytes, metadata: Dict,
                                    params: List[Dict]) -> List[Dict]:
        structured: List[Dict] = []

        def add(value: str, source: str):
            value = value.strip()
            # Filter out tiny fragments that are usually binary noise.
            if len(value) >= MIN_STRUCTURED_STRING_LEN:
                structured.append({'value': value, 'source': source})

        for field in ['copyright', 'description', 'author', 'link']:
            value = metadata.get(field, 'Unknown')
            if isinstance(value, str) and value != 'Unknown':
                add(value, 'metadata_header')

        for param in params:
            add(param['name'], 'parameter_table')

        blob = data.decode('latin1', errors='ignore')
        for match in re.finditer(URL_PATTERN, blob, re.IGNORECASE):
            add(match.group(0), 'embedded_link')

        for match in re.finditer(WWW_PATTERN, blob, re.IGNORECASE):
            add(match.group(0), 'embedded_link')

        # Keep copyright-style strings bounded to avoid swallowing large blobs.
        for match in re.finditer(
                rf'copyright[^\x00\r\n]{{0,{METADATA_STRING_MAX_LEN}}}',
                blob, re.IGNORECASE):
            add(match.group(0), 'metadata_regex')

        for match in re.finditer(
                rf'\(c\)[^\x00\r\n]{{{MIN_STRUCTURED_STRING_LEN},'
                rf'{METADATA_STRING_MAX_LEN}}}',
                blob, re.IGNORECASE):
            add(match.group(0), 'metadata_regex')

        return structured

    def _merge_string_sources(self, structured_strings: List[Dict],
                              extracted_strings: List[str]) -> Tuple[List[str], Dict[str, List[str]]]:
        ordered: List[str] = []
        seen = set()
        sources: Dict[str, List[str]] = defaultdict(list)

        for item in structured_strings:
            value = item['value']
            if value not in seen:
                ordered.append(value)
                seen.add(value)
            if value not in sources[item['source']]:
                sources[item['source']].append(value)

        for value in extracted_strings:
            if value not in seen:
                ordered.append(value)
                seen.add(value)
                if value not in sources['fallback_scan']:
                    sources['fallback_scan'].append(value)

        return ordered, dict(sources)

    def _enrich_metadata_from_strings(self, metadata: Dict,
                                      strings: List[str]) -> Dict:
        enriched = dict(metadata)

        for value in strings:
            lower_value = value.lower()
            if enriched.get('link') == 'Unknown':
                if re.search(r'https?://|www\.|t\.me/', value, re.IGNORECASE):
                    enriched['link'] = value.strip()

            if enriched.get('copyright') == 'Unknown':
                if 'copyright' in lower_value or lower_value.startswith('(c)'):
                    enriched['copyright'] = value.strip()

            if enriched.get('author') == 'Unknown' and ' by ' in lower_value:
                enriched['author'] = value.strip()

            if enriched.get('description') == 'Unknown':
                if (DESCRIPTION_MIN_LEN <= len(value) <= DESCRIPTION_MAX_LEN
                        and 'indicator' in lower_value):
                    enriched['description'] = value.strip()

        return enriched

    # -- PE header ------------------------------------------------------------

    def _parse_pe_header(self, data: bytes) -> Dict:
        info: Dict = {'valid_mz': False, 'valid_pe': False}
        if not data[:2] == b'MZ':
            return info
        info['valid_mz'] = True
        if len(data) <= 0x3C + 4:
            return info
        pe_off = struct.unpack('<I', data[0x3C:0x40])[0]
        if pe_off + 12 > len(data):
            return info
        if data[pe_off:pe_off + 4] != b'PE\x00\x00':
            return info
        info['valid_pe'] = True
        ts = struct.unpack('<I', data[pe_off + 8:pe_off + 12])[0]
        if ts > 0:
            try:
                info['timestamp'] = datetime.fromtimestamp(ts).strftime(
                    '%Y-%m-%d %H:%M:%S')
            except (OSError, ValueError):
                pass
        machine = struct.unpack('<H', data[pe_off + 4:pe_off + 6])[0]
        info['machine'] = {
            0x014c: 'x86 (32-bit)', 0x8664: 'x64 (64-bit)',
            0x0200: 'Intel Itanium'
        }.get(machine, f'Unknown (0x{machine:04x})')

        # Number of sections
        if pe_off + 6 < len(data):
            info['num_sections'] = struct.unpack(
                '<H', data[pe_off + 6:pe_off + 8])[0]

        return info

    # -- pattern detection ----------------------------------------------------

    def _find_patterns(self, data: bytes) -> List[Dict]:
        all_pats = {}
        all_pats.update({k: v for k, v in MT4_FUNCTIONS.items()})
        all_pats.update({k: v for k, v in MT4_INDICATORS.items()})
        all_pats.update({k: v for k, v in MT4_BUFFER_FUNCTIONS.items()})
        all_pats.update({k: v for k, v in STRATEGY_PATTERNS.items()})
        all_pats.update({k: v for k, v in TIMEFRAME_PATTERNS.items()})
        # Additional generic patterns
        extra = {
            b'extern': 'External Variable', b'#property': 'Property Directive',
            b'copyright': 'Copyright Info', b'indicator': 'Indicator Marker',
            b'expert': 'Expert Marker',
        }
        all_pats.update(extra)

        results = []
        for pat, desc in all_pats.items():
            cnt = data.count(pat)
            if cnt > 0:
                results.append({'pattern': pat.decode('ascii', errors='ignore'),
                                'type': desc, 'count': cnt})
        return results

    # -- string extraction ----------------------------------------------------

    def _extract_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        strings: List[str] = []
        cur = ''
        for b in data:
            if 32 <= b <= 126:
                cur += chr(b)
            else:
                if len(cur) >= min_len:
                    strings.append(cur)
                cur = ''
        if len(cur) >= min_len:
            strings.append(cur)

        # UTF-16LE pass (common in Windows binaries)
        i = 0
        while i < len(data) - 1:
            if data[i] != 0 and data[i + 1] == 0 and 32 <= data[i] <= 126:
                buf = bytearray()
                j = i
                while j < len(data) - 1 and j < i + 400:
                    if data[j] == 0 and data[j + 1] == 0:
                        break
                    if data[j] != 0 and data[j + 1] == 0 and 32 <= data[j] <= 126:
                        buf.append(data[j])
                        j += 2
                    else:
                        break
                if len(buf) >= min_len:
                    decoded = buf.decode('ascii', errors='ignore')
                    if decoded not in strings:
                        strings.append(decoded)
                i = max(j, i + 1)
            else:
                i += 1

        # deduplicate preserving order
        seen = set()
        unique = []
        for s in strings:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique

    # -- string categorisation ------------------------------------------------

    def _categorize_strings(self, strings: List[str]) -> Dict[str, List[str]]:
        cats: Dict[str, List[str]] = {
            'functions': [], 'variables': [], 'indicators': [],
            'symbols': [], 'parameters': [], 'links': [],
            'metadata': [], 'security': [], 'comments': [], 'other': [],
        }
        func_kw = [
            'OnInit', 'OnDeinit', 'OnTick', 'OnCalculate', 'OnStart',
            'OrderSend', 'OrderClose', 'OrderModify', 'iMA', 'iRSI',
            'SetIndexBuffer', 'SetIndexStyle', 'IndicatorBuffers',
        ]
        param_kw = [
            'period', 'shift', 'method', 'price', 'lot', 'stop', 'take',
            'risk', 'magic', 'slippage',
        ]
        ind_kw = ['MA', 'RSI', 'MACD', 'ATR', 'Bollinger', 'Stochastic',
                   'CCI', 'ADX', 'Ichimoku']
        for s in strings:
            sl = s.lower()
            placed = False
            if re.search(r'https?://|www\.|t\.me/', s, re.IGNORECASE):
                cats['links'].append(s)
                continue
            if any(token in sl for token in ['copyright', '(c)', 'telegram',
                                             'author', 'description']):
                cats['metadata'].append(s)
                continue
            if any(token.lower() in sl for group in AUDIT_KEYWORDS.values()
                   for token in group):
                cats['security'].append(s)
                continue
            for kw in func_kw:
                if kw.lower() in sl:
                    cats['functions'].append(s)
                    placed = True
                    break
            if placed:
                continue
            for kw in param_kw:
                if kw in sl:
                    cats['parameters'].append(s)
                    placed = True
                    break
            if placed:
                continue
            for kw in ind_kw:
                if kw.lower() in sl:
                    cats['indicators'].append(s)
                    placed = True
                    break
            if placed:
                continue
            if len(s) == 6 and s.isalpha() and s.isupper():
                cats['symbols'].append(s)
            elif '//' in s or '#' in s:
                cats['comments'].append(s)
            else:
                cats['other'].append(s)
        return cats

    # -- event handlers -------------------------------------------------------

    def _find_event_handlers(self, data: bytes) -> List[str]:
        return [h.decode() for h in MT4_EVENT_HANDLERS if h in data]

    # -- trading functions ----------------------------------------------------

    def _find_trading_functions(self, data: bytes) -> List[Dict]:
        found = []
        for pat, desc in MT4_FUNCTIONS.items():
            cnt = data.count(pat)
            if cnt:
                found.append({'name': pat.decode(), 'description': desc,
                              'count': cnt})
        return found

    # -- indicators -----------------------------------------------------------

    def _find_indicators(self, data: bytes) -> List[Dict]:
        found = []
        for pat, desc in MT4_INDICATORS.items():
            cnt = data.count(pat)
            if cnt:
                found.append({'name': pat.decode(), 'description': desc,
                              'count': cnt})
        return found

    # -- buffer functions -----------------------------------------------------

    def _find_buffer_functions(self, data: bytes) -> List[Dict]:
        found = []
        for pat, desc in MT4_BUFFER_FUNCTIONS.items():
            cnt = data.count(pat)
            if cnt:
                found.append({'name': pat.decode(), 'description': desc,
                              'count': cnt})
        return found

    # -- parameters -----------------------------------------------------------

    def _extract_input_parameters(self, cats: Dict) -> List[Dict]:
        params = []
        seen_names = set()
        for s in cats.get('parameters', []):
            sl = s.lower()
            # Skip timeframe constants and other non-parameter strings
            if sl.startswith('period_') or sl.startswith('mode_'):
                continue
            # Skip strings that are too long to be parameter names
            if len(s) > 40:
                continue
            # Skip strings that look like sentences/descriptions
            if ' ' in s.strip() and len(s.strip().split()) >= 3:
                continue
            # Generate a clean name for dedup
            clean = re.sub(r'[^a-z0-9]', '', sl)
            if clean in seen_names:
                continue
            seen_names.add(clean)
            ptype, default = 'int', 0
            for kw, (t, d) in PARAM_TYPE_HINTS.items():
                if kw in sl:
                    ptype, default = t, d
                    break
            params.append({'name': s, 'type': ptype, 'default': default})
        return params

    # -- strategy detection ---------------------------------------------------

    def _analyze_strategy(self, data: bytes) -> Dict:
        strat: Dict = {
            'type': 'Unknown', 'indicators_used': [],
            'entry_patterns': [], 'exit_patterns': [], 'timeframes': [],
        }
        for pat, name in STRATEGY_PATTERNS.items():
            if pat in data:
                strat['type'] = name
                break
        for pat, name in MT4_INDICATORS.items():
            if pat in data:
                strat['indicators_used'].append(name)
        for pat, name in TIMEFRAME_PATTERNS.items():
            if pat in data:
                strat['timeframes'].append(name)
        if b'Buy' in data and b'Signal' in data:
            strat['entry_patterns'].append('Buy Signal Based')
        if b'Sell' in data and b'Signal' in data:
            strat['entry_patterns'].append('Sell Signal Based')
        if b'Cross' in data or b'cross' in data:
            strat['entry_patterns'].append('Indicator Crossover')
        if b'StopLoss' in data or b'SL' in data:
            strat['exit_patterns'].append('Stop Loss')
        if b'TakeProfit' in data or b'TP' in data:
            strat['exit_patterns'].append('Take Profit')
        if b'TrailingStop' in data:
            strat['exit_patterns'].append('Trailing Stop')
        return strat

    # -- risk management ------------------------------------------------------

    def _analyze_risk(self, data: bytes, strings: List[str]) -> Dict:
        string_blob = '\n'.join(strings).lower()
        lower_data = data.lower()

        def has_token(*tokens: str) -> bool:
            for token in tokens:
                token_bytes = token.encode('ascii', errors='ignore').lower()
                if token_bytes in lower_data or token.lower() in string_blob:
                    return True
            return False

        r: Dict = {
            'has_stop_loss': has_token('StopLoss'),
            'has_take_profit': has_token('TakeProfit'),
            'has_trailing_stop': has_token('TrailingStop'),
            'has_money_management': has_token('MoneyManagement', 'MM'),
            'has_risk_percent': has_token('RiskPercent', 'Risk'),
            'has_max_lots': has_token('MaxLots', 'MaxLot'),
            'has_max_orders': has_token('MaxOrders', 'MaxTrades'),
            'has_account_locking': has_token('AccountNumber', 'AccountServer',
                                             'AccountCompany'),
            'has_backtest_detection': has_token('IsTesting',
                                                'TesterStatistics'),
            'has_time_gating': has_token('TimeCurrent', 'TimeLocal', 'TimeGMT',
                                         'DayOfWeek', 'Hour'),
            'features': [],
        }
        label_map = {
            'has_stop_loss': 'Stop Loss Protection',
            'has_take_profit': 'Take Profit Targets',
            'has_trailing_stop': 'Trailing Stop',
            'has_money_management': 'Money Management',
            'has_risk_percent': 'Risk Percentage Based',
            'has_max_lots': 'Maximum Lot Size Limit',
            'has_max_orders': 'Maximum Order Limit',
            'has_account_locking': 'Account/Broker Locking Logic',
            'has_backtest_detection': 'Backtest/Tester Detection',
            'has_time_gating': 'Time-Based Enable/Disable Logic',
        }
        for k, lbl in label_map.items():
            if r.get(k):
                r['features'].append(lbl)
        return r

    def _audit_binary(self, data: bytes, strings: List[str]) -> Dict:
        blob = '\n'.join(strings)
        lower_blob = blob.lower()
        lower_data = data.lower()
        findings = []

        def evidence_for(keywords: List[str]) -> List[str]:
            evidence = []
            for keyword in keywords:
                token = keyword.lower()
                if token.encode('ascii', errors='ignore') in lower_data or token in lower_blob:
                    evidence.append(keyword)
            return evidence

        severity_map = {
            'credential_access': 'critical',
            'network_io': 'medium',
            'dll_usage': 'medium',
            'account_locking': 'medium',
            'account_queries': 'medium',
            'backtest_detection': 'medium',
            'time_gating': 'low',
        }
        title_map = {
            'credential_access': 'Credential access surfaces',
            'network_io': 'Network or remote communication hooks',
            'dll_usage': 'DLL or native import usage',
            'account_locking': 'Account or broker locking hooks',
            'account_queries': 'Account inspection hooks',
            'backtest_detection': 'Backtest or tester detection',
            'time_gating': 'Time-based logic gates',
        }

        for category, keywords in AUDIT_KEYWORDS.items():
            evidence = evidence_for(keywords)
            if evidence:
                findings.append({
                    'severity': severity_map[category],
                    'title': title_map[category],
                    'evidence': evidence,
                })

        links = []
        for value in strings:
            if re.search(r'https?://|www\.|t\.me/', value, re.IGNORECASE):
                links.append(value)
        if links:
            findings.append({
                'severity': 'info',
                'title': 'Embedded external links',
                'evidence': links[:5],
            })

        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        overall = 'none'
        if findings:
            overall = max(findings, key=lambda item: severity_order[item['severity']])['severity']

        return {
            'severity': overall,
            'findings': findings,
        }

    # -- disassembly ----------------------------------------------------------

    def _disassemble(self, data: bytes) -> Dict:
        result: Dict = {'functions': [], 'total_instructions': 0}
        if not HAS_CAPSTONE or self.cs is None:
            result['error'] = 'Capstone not available'
            return result

        funcs = self._find_function_boundaries(data)
        for start, end in funcs[:50]:  # limit to first 50
            instrs = []
            try:
                for ins in self.cs.disasm(data[start:end], start):
                    instrs.append(f"0x{ins.address:08x}:  {ins.mnemonic} {ins.op_str}")
            except Exception:
                pass
            if instrs:
                result['functions'].append({
                    'start': f'0x{start:08x}', 'end': f'0x{end:08x}',
                    'size': end - start, 'instructions': instrs,
                })
                result['total_instructions'] += len(instrs)
        return result

    def _find_function_boundaries(self, data: bytes) -> List[Tuple[int, int]]:
        funcs = []
        cur = None
        for i in range(len(data) - 3):
            if data[i:i + 3] == b'\x55\x89\xE5':
                if cur is not None:
                    funcs.append((cur, i))
                cur = i
            elif data[i:i + 2] == b'\x5D\xC3' and cur is not None:
                funcs.append((cur, i + 2))
                cur = None
        return funcs

    # -- statistics -----------------------------------------------------------

    def _statistics(self, data: bytes, strings: List[str],
                    string_sources: Dict[str, List[str]]) -> Dict:
        entropy = 0.0
        if data:
            counts = Counter(data)
            total = len(data)
            entropy = -sum(
                (c / total) * math.log2(c / total) for c in counts.values())
        source_counts = {
            source: len(values) for source, values in string_sources.items()
        }
        return {
            'file_size_bytes': len(data),
            'file_size_kb': round(len(data) / 1024, 2),
            'total_strings': len(strings),
            'unique_strings': len(set(strings)),
            'has_mz_header': data[:2] == b'MZ',
            'entropy': round(entropy, 4),
            'string_source_counts': source_counts,
        }

    def _build_recovery_profile(self, analysis: Dict) -> Dict:
        meta = analysis.get('metadata', {})
        stats = analysis.get('statistics', {})
        strings = analysis.get('strings', [])
        categories = analysis.get('string_categories', {})
        source_counts = stats.get('string_source_counts', {})
        structured_count = sum(
            count for source, count in source_counts.items()
            if source != 'fallback_scan'
        )
        meaningful_count = sum(
            len(categories.get(name, []))
            for name in ['functions', 'indicators', 'parameters',
                         'links', 'metadata', 'security']
        )
        total_strings = max(len(strings), 1)
        semantic_ratio = round(
            meaningful_count / total_strings, 4) if strings else 0.0

        score = 0
        if meta.get('format', '').startswith('Modern'):
            score += 2
        # Entropy at or above HIGH_ENTROPY_THRESHOLD usually indicates
        # compressed/encrypted payloads.
        if stats.get('entropy', 0) >= HIGH_ENTROPY_THRESHOLD:
            score += 2
        # Very few meaningful strings usually means aggressive obfuscation.
        if semantic_ratio < LOW_SEMANTIC_RATIO_THRESHOLD:
            score += 1
        if structured_count == 0:
            score += 1
        if not analysis.get('patterns'):
            score += 1

        # Score buckets use MEDIUM_OBFUSCATION_SCORE and
        # HIGH_OBFUSCATION_SCORE as the classification thresholds.
        if score >= HIGH_OBFUSCATION_SCORE:
            obfuscation = 'High'
        elif score >= MEDIUM_OBFUSCATION_SCORE:
            obfuscation = 'Medium'
        else:
            obfuscation = 'Low'

        if meta.get('format', '').startswith('Legacy') and analysis.get('input_parameters'):
            recovery = 'Structured partial recovery'
            confidence = 'Medium'
        elif structured_count or analysis.get('audit_report', {}).get('findings'):
            recovery = 'Metadata-oriented recovery'
            confidence = 'Low'
        else:
            recovery = 'Minimal recoverable semantics'
            confidence = 'Low'

        notes = [
            'Recovered metadata/parameters are grounded in preserved EX4 strings or tables.',
            'Generated code remains a reconstruction template, not exact source recovery.',
        ]
        if meta.get('format', '').startswith('Modern'):
            notes.append(
                'Modern encrypted EX4 payloads preserve little high-confidence '
                'logic without opcode-level decoding.')

        return {
            'recovery_level': recovery,
            'confidence': confidence,
            'obfuscation_level': obfuscation,
            'semantic_string_ratio': semantic_ratio,
            'structured_strings': structured_count,
            'notes': notes,
        }


# ---------------------------------------------------------------------------
# Multi-Language Code Generator
# ---------------------------------------------------------------------------

class CodeGenerator:
    """Generates code in multiple target languages from analysis results."""

    def generate(self, analysis: Dict, language: str) -> str:
        gen_map = {
            'MQL4': self._mql4, 'MQL5': self._mql5,
            'Python': self._python, 'C': self._c,
            'R': self._r, 'Text': self._text,
        }
        fn = gen_map.get(language)
        if fn is None:
            return f"// Unsupported language: {language}"
        return fn(analysis)

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _header_box(text: str, width: int = 68) -> List[str]:
        border = '//' + '+' + '-' * width + '+'
        inner = '//| ' + text.ljust(width - 2) + ' |'
        return [border, inner, border]

    @staticmethod
    def _recovery_note_lines(comment_prefix: str) -> List[str]:
        prefix = f"{comment_prefix} " if comment_prefix else ""
        return [
            f"{prefix}declarations are inferred from preserved EX4 data.",
            f"{prefix}reconstructed logic is lower confidence.",
        ]

    @staticmethod
    def _safe_class_name(analysis: Dict, fallback: str = 'EX4Program') -> str:
        name = os.path.splitext(os.path.basename(
            analysis.get('filepath', fallback)))[0]
        name = re.sub(r'[^A-Za-z0-9_]', '_', name)
        if not name or name[0].isdigit():
            name = '_' + name
        return name

    # -- MQL4 -----------------------------------------------------------------

    def _mql4(self, a: Dict) -> str:
        L = []
        meta = a['metadata']
        recovery = a.get('recovery_profile', {})
        L += self._header_box(f"Reconstructed MQL4 Template \u2013 {meta['type']}")
        L.append(f"// Version:   {meta['version']}")
        L.append(f"// Format:    {meta.get('format', 'Unknown')}")
        if meta.get('build', 0) > 0:
            L.append(f"// Build:     {meta['build']}")
        if meta.get('creation_date', 'Unknown') != 'Unknown':
            L.append(f"// Created:   {meta['creation_date']}")
        if meta.get('copyright', 'Unknown') != 'Unknown':
            L.append(f"// Copyright: {meta['copyright']}")
        L.append(f"// Recovery:  {recovery.get('recovery_level', 'Unknown')}")
        L += self._recovery_note_lines("// Note:")
        L.append('')

        strat = a.get('trading_strategy', {})
        if strat.get('type', 'Unknown') != 'Unknown':
            L.append(f"// Strategy: {strat['type']}")
            if strat.get('indicators_used'):
                L.append(f"// Indicators: {', '.join(strat['indicators_used'])}")
            L.append('')

        if meta['type'] == 'Indicator':
            L.append('#property indicator_separate_window')
            L.append('#property indicator_buffers 1')
            L.append('')

        params = a.get('input_parameters', [])
        if params:
            L.append('// Input Parameters (inferred)')
            for p in params:
                L.append(f"extern {p['type']} {p['name']} = {p['default']};")
            L.append('')

        if meta['type'] == 'Indicator':
            L += ['// Indicator Buffers', 'double Buffer1[];', '']

        L += self._header_box('Initialization')
        L += ['int init()', '{']
        if meta['type'] == 'Indicator':
            L += ['    SetIndexStyle(0, DRAW_LINE);',
                  '    SetIndexBuffer(0, Buffer1);',
                  '    SetIndexLabel(0, "Main Buffer");']
        L += ['    return(0);', '}', '']

        L += self._header_box('Deinitialization')
        L += ['int deinit()', '{', '    return(0);', '}', '']

        if meta['type'] == 'Expert Advisor':
            L += self._header_box('Expert tick function')
            L += ['void OnTick()', '{']
        elif meta['type'] == 'Script':
            L += self._header_box('Script entry point')
            L += ['void OnStart()', '{']
        else:
            L += self._header_box('Indicator calculation')
            L += ['int start()', '{']

        for ind in a.get('indicators_detected', []):
            n = ind['name']
            if n == 'iMA':
                L.append('    double ma = iMA(Symbol(), Period(), 14, 0, MODE_SMA, PRICE_CLOSE, 0);')
            elif n == 'iRSI':
                L.append('    double rsi = iRSI(Symbol(), Period(), 14, PRICE_CLOSE, 0);')
            elif n == 'iMACD':
                L.append('    double macd_main = iMACD(Symbol(), Period(), 12, 26, 9, PRICE_CLOSE, MODE_MAIN, 0);')
            elif n == 'iATR':
                L.append('    double atr = iATR(Symbol(), Period(), 14, 0);')
            elif n == 'iBands':
                L.append('    double bb_upper = iBands(Symbol(), Period(), 20, 2, 0, PRICE_CLOSE, MODE_UPPER, 0);')
                L.append('    double bb_lower = iBands(Symbol(), Period(), 20, 2, 0, PRICE_CLOSE, MODE_LOWER, 0);')
            elif n == 'iStochastic':
                L.append('    double stoch_main = iStochastic(Symbol(), Period(), 5, 3, 3, MODE_SMA, 0, MODE_MAIN, 0);')
            elif n == 'iCCI':
                L.append('    double cci = iCCI(Symbol(), Period(), 14, PRICE_CLOSE, 0);')

        if meta['type'] == 'Expert Advisor':
            rm = a.get('risk_management', {})
            L.append('')
            L.append('    // Risk management')
            if rm.get('has_stop_loss'):
                L.append('    double stopLoss = 50 * Point;')
            if rm.get('has_take_profit'):
                L.append('    double takeProfit = 100 * Point;')
            L.append('')
            L.append('    // Entry logic')
            L.append('    if(OrdersTotal() < 1) {')
            for tf in a.get('trading_functions', []):
                if 'OrderSend' in tf['name']:
                    sl_str = 'Ask - stopLoss' if rm.get('has_stop_loss') else '0'
                    tp_str = 'Ask + takeProfit' if rm.get('has_take_profit') else '0'
                    L.append(f'        int ticket = OrderSend(Symbol(), OP_BUY, 0.1, Ask, 3, {sl_str}, {tp_str}, "Trade", 0, 0, clrGreen);')
                    break
            L.append('    }')
        else:
            L.append('    return(0);')

        L.append('}')
        return '\n'.join(L)

    # -- MQL5 -----------------------------------------------------------------

    def _mql5(self, a: Dict) -> str:
        L = []
        meta = a['metadata']
        cn = self._safe_class_name(a)
        recovery = a.get('recovery_profile', {})
        L += self._header_box(f"Reconstructed MQL5 Template – {meta['type']}")
        L.append(f"// Version: {meta['version']}")
        L.append(f"// Recovery: {recovery.get('recovery_level', 'Unknown')}")
        L += self._recovery_note_lines("// Note:")
        L.append('')
        L.append('#include <Trade/Trade.mqh>')
        L.append('#include <Indicators/Indicators.mqh>')
        L.append('')

        params = a.get('input_parameters', [])
        if params:
            for p in params:
                L.append(f"input {p['type']} {p['name']} = {p['default']};")
            L.append('')

        L.append('CTrade trade;')
        L.append('')

        L.append('int OnInit()')
        L.append('{')
        if meta['type'] == 'Indicator':
            L.append('    SetIndexBuffer(0, Buffer1);')
        L.append('    return(INIT_SUCCEEDED);')
        L.append('}')
        L.append('')

        L.append('void OnDeinit(const int reason)')
        L.append('{')
        L.append('}')
        L.append('')

        if meta['type'] == 'Expert Advisor':
            L.append('void OnTick()')
            L.append('{')
            for ind in a.get('indicators_detected', []):
                n = ind['name']
                if n == 'iMA':
                    L.append('    int ma_handle = iMA(_Symbol, PERIOD_CURRENT, 14, 0, MODE_SMA, PRICE_CLOSE);')
                elif n == 'iRSI':
                    L.append('    int rsi_handle = iRSI(_Symbol, PERIOD_CURRENT, 14, PRICE_CLOSE);')
            L.append('')
            L.append('    if(PositionsTotal() < 1) {')
            L.append('        trade.Buy(0.1, _Symbol);')
            L.append('    }')
            L.append('}')
        elif meta['type'] == 'Script':
            L.append('void OnStart()')
            L.append('{')
            L.append('    // Script execution logic')
            L.append('    Print("Script started");')
            for ind in a.get('indicators_detected', []):
                n = ind['name']
                if n == 'iMA':
                    L.append('    int ma_handle = iMA(_Symbol, PERIOD_CURRENT, 14, 0, MODE_SMA, PRICE_CLOSE);')
            L.append('    Print("Script completed");')
            L.append('}')
        else:
            L.append('int OnCalculate(const int rates_total,')
            L.append('                const int prev_calculated,')
            L.append('                const datetime &time[],')
            L.append('                const double &open[],')
            L.append('                const double &high[],')
            L.append('                const double &low[],')
            L.append('                const double &close[],')
            L.append('                const long &tick_volume[],')
            L.append('                const long &volume[],')
            L.append('                const int &spread[])')
            L.append('{')
            L.append('    return(rates_total);')
            L.append('}')
        return '\n'.join(L)

    # -- Python ---------------------------------------------------------------

    def _python(self, a: Dict) -> str:
        L = []
        meta = a['metadata']
        cn = self._safe_class_name(a, 'TradingStrategy')
        recovery = a.get('recovery_profile', {})

        L.append('"""')
        L.append(f"Converted from MT4 {meta['type']}")
        L.append(f"Version: {meta['version']}")
        L.append(f"Recovery: {recovery.get('recovery_level', 'Unknown')}")
        L += self._recovery_note_lines("")
        strat = a.get('trading_strategy', {})
        if strat.get('type', 'Unknown') != 'Unknown':
            L.append(f"Strategy: {strat['type']}")
        if strat.get('indicators_used'):
            L.append(f"Indicators: {', '.join(strat['indicators_used'])}")
        L.append('"""')
        L.append('')
        L.append('import numpy as np')
        L.append('import pandas as pd')
        L.append('from datetime import datetime')
        L.append('from typing import Dict, List, Optional')
        L.append('')
        L.append('')
        L.append(f'class {cn}:')
        L.append(f'    """MT4 {meta["type"]} converted to Python."""')
        L.append('')

        params = a.get('input_parameters', [])
        if params:
            args = ', '.join(
                f"{p['name'].lower()}: {'float' if p['type'] == 'double' else 'int'} = {p['default']}"
                for p in params)
            L.append(f"    def __init__(self, {args}):")
        else:
            L.append("    def __init__(self):")

        L.append("        self.data: pd.DataFrame = pd.DataFrame()")
        L.append("        self.indicators: Dict[str, pd.Series] = {}")
        for p in params:
            L.append(f"        self.{p['name'].lower()} = {p['name'].lower()}")
        L.append('')

        L.append("    def initialize(self, data: pd.DataFrame) -> bool:")
        L.append('        """Load OHLCV data and compute indicators."""')
        L.append("        if data.empty:")
        L.append("            return False")
        L.append("        self.data = data")
        L.append("        self._calculate_indicators()")
        L.append("        return True")
        L.append('')

        L.append("    def _calculate_indicators(self) -> None:")
        inds = strat.get('indicators_used', [])
        if 'Moving Average' in inds:
            L.append("        # Moving Average")
            L.append("        period = getattr(self, 'period', 14)")
            L.append("        self.indicators['ma'] = self.data['close'].rolling(window=period).mean()")
        if 'Relative Strength Index' in inds:
            L.append("        # RSI")
            L.append("        delta = self.data['close'].diff()")
            L.append("        gain = delta.where(delta > 0, 0).rolling(14).mean()")
            L.append("        loss = (-delta.where(delta < 0, 0)).rolling(14).mean()")
            L.append("        self.indicators['rsi'] = 100 - 100 / (1 + gain / loss)")
        if 'MACD' in inds:
            L.append("        # MACD")
            L.append("        e12 = self.data['close'].ewm(span=12).mean()")
            L.append("        e26 = self.data['close'].ewm(span=26).mean()")
            L.append("        self.indicators['macd'] = e12 - e26")
            L.append("        self.indicators['macd_signal'] = self.indicators['macd'].ewm(span=9).mean()")
        if 'Bollinger Bands' in inds:
            L.append("        # Bollinger Bands")
            L.append("        sma = self.data['close'].rolling(20).mean()")
            L.append("        std = self.data['close'].rolling(20).std()")
            L.append("        self.indicators['bb_upper'] = sma + 2 * std")
            L.append("        self.indicators['bb_lower'] = sma - 2 * std")
        if not inds:
            L.append("        pass  # No indicators detected")
        L.append('')

        if meta['type'] == 'Expert Advisor':
            L.append("    def on_tick(self) -> Optional[Dict]:")
            L.append('        """Process a new tick."""')
            L.append("        self._calculate_indicators()")
            L.append("        return {'action': None, 'price': self.data['close'].iloc[-1]}")
        else:
            L.append("    def calculate(self) -> pd.DataFrame:")
            L.append('        """Return indicator values."""')
            L.append("        self._calculate_indicators()")
            L.append("        return pd.DataFrame(self.indicators)")
        return '\n'.join(L)

    # -- C --------------------------------------------------------------------

    def _c(self, a: Dict) -> str:
        L = []
        meta = a['metadata']
        recovery = a.get('recovery_profile', {})
        L.append(f'/* Converted from MT4 {meta["type"]} */')
        L.append(f'/* Version: {meta["version"]} */')
        L.append(f'/* Recovery: {recovery.get("recovery_level", "Unknown")} */')
        L += ['/* declarations are inferred from preserved EX4 data. */',
              '/* reconstructed body logic is lower confidence. */']
        L.append('')
        L.append('#include <stdio.h>')
        L.append('#include <stdlib.h>')
        L.append('#include <math.h>')
        L.append('')
        L.append('typedef struct { double open, high, low, close; long volume; } Bar;')
        L.append('')

        for p in a.get('input_parameters', []):
            ctype = 'double' if p['type'] == 'double' else 'int'
            L.append(f"{ctype} {p['name']} = {p['default']};")
        if a.get('input_parameters'):
            L.append('')

        L.append('int initialize(void) { return 1; }')
        L.append('')

        for ind in a.get('indicators_detected', []):
            n = ind['name']
            if n == 'iMA':
                L.append('double calc_ma(Bar *bars, int n, int period) {')
                L.append('    double sum = 0;')
                L.append('    for (int i = n - period; i < n; i++) sum += bars[i].close;')
                L.append('    return sum / period;')
                L.append('}')
                L.append('')
            elif n == 'iRSI':
                L.append('double calc_rsi(Bar *bars, int n, int period) {')
                L.append('    double gain = 0, loss = 0;')
                L.append('    for (int i = n - period; i < n; i++) {')
                L.append('        double d = bars[i].close - bars[i-1].close;')
                L.append('        if (d > 0) gain += d; else loss -= d;')
                L.append('    }')
                L.append('    double rs = (loss == 0) ? 100 : gain / loss;')
                L.append('    return 100.0 - 100.0 / (1.0 + rs);')
                L.append('}')
                L.append('')

        L.append('int process_tick(Bar *bars, int n) {')
        L.append('    if (n < 1) return 0;')
        for ind in a.get('indicators_detected', []):
            n = ind['name']
            if n == 'iMA':
                L.append('    double ma = calc_ma(bars, n, 14);')
            elif n == 'iRSI':
                L.append('    double rsi = calc_rsi(bars, n, 14);')
        L.append('    return 1;')
        L.append('}')
        return '\n'.join(L)

    # -- R --------------------------------------------------------------------

    def _r(self, a: Dict) -> str:
        L = []
        meta = a['metadata']
        cn = self._safe_class_name(a, 'trading_strategy')
        recovery = a.get('recovery_profile', {})
        L.append(f'# Converted from MT4 {meta["type"]}')
        L.append(f'# Version: {meta["version"]}')
        L.append(f'# Recovery: {recovery.get("recovery_level", "Unknown")}')
        L += self._recovery_note_lines("#")
        L.append('')
        L.append('library(quantmod)')
        L.append('library(TTR)')
        L.append('')
        L.append(f'{cn} <- function(data) {{')
        for p in a.get('input_parameters', []):
            L.append(f"    {p['name']} <- {p['default']}")
        L.append('    indicators <- list()')
        for ind in a.get('indicators_detected', []):
            n = ind['name']
            if n == 'iMA':
                L.append('    indicators$ma <- SMA(Cl(data), n = 14)')
            elif n == 'iRSI':
                L.append('    indicators$rsi <- RSI(Cl(data), n = 14)')
            elif n == 'iMACD':
                L.append('    indicators$macd <- MACD(Cl(data), nFast = 12, nSlow = 26, nSig = 9)')
            elif n == 'iBands':
                L.append('    indicators$bbands <- BBands(HLC(data), n = 20)')
            elif n == 'iATR':
                L.append('    indicators$atr <- ATR(HLC(data), n = 14)')
        L.append('    return(indicators)')
        L.append('}')
        return '\n'.join(L)

    # -- Text report ----------------------------------------------------------

    def _text(self, a: Dict) -> str:
        W = 72
        L = []
        meta = a['metadata']
        strat = a.get('trading_strategy', {})
        risk = a.get('risk_management', {})
        stats = a.get('statistics', {})
        recovery = a.get('recovery_profile', {})
        audit = a.get('audit_report', {})

        L.append('=' * W)
        L.append('EX4 FILE ANALYSIS REPORT'.center(W))
        L.append('=' * W)
        L.append('')
        L.append('FILE INFORMATION')
        L.append('-' * W)
        L.append(f"  Filename:      {a.get('filename', 'N/A')}")
        L.append(f"  Format:        {meta.get('format', 'Unknown')}")
        L.append(f"  Type:          {meta['type']}")
        L.append(f"  Version:       {meta['version']}")
        if meta.get('build', 0) > 0:
            L.append(f"  Build:         {meta['build']}")
        if meta.get('creation_date', 'Unknown') != 'Unknown':
            L.append(f"  Created:       {meta['creation_date']}")
        if meta.get('copyright', 'Unknown') != 'Unknown':
            L.append(f"  Copyright:     {meta['copyright']}")
        if meta.get('author', 'Unknown') != 'Unknown':
            L.append(f"  Author:        {meta['author']}")
        if meta.get('link', 'Unknown') != 'Unknown':
            L.append(f"  Link:          {meta['link']}")
        L.append(f"  Size:          {stats.get('file_size_kb', 0)} KB")
        L.append(f"  Entropy:       {stats.get('entropy', 0)}")
        L.append('')

        if recovery:
            L.append('RECOVERY PROFILE')
            L.append('-' * W)
            L.append(f"  Level:         {recovery.get('recovery_level', 'Unknown')}")
            L.append(f"  Confidence:    {recovery.get('confidence', 'Unknown')}")
            L.append(f"  Obfuscation:   {recovery.get('obfuscation_level', 'Unknown')}")
            L.append(f"  Structured:    {recovery.get('structured_strings', 0)} strings")
            L.append(f"  Semantic ratio:{recovery.get('semantic_string_ratio', 0)}")
            for note in recovery.get('notes', []):
                L.append(f"  - {note}")
            L.append('')

        pe = a.get('pe_info', {})
        if pe.get('valid_pe'):
            L.append('PE HEADER')
            L.append('-' * W)
            L.append(f"  Machine:       {pe.get('machine', 'N/A')}")
            if pe.get('timestamp'):
                L.append(f"  Compiled:      {pe['timestamp']}")
            if pe.get('num_sections'):
                L.append(f"  Sections:      {pe['num_sections']}")
            L.append('')

        if strat.get('type', 'Unknown') != 'Unknown':
            L.append('TRADING STRATEGY')
            L.append('-' * W)
            L.append(f"  Type:          {strat['type']}")
            if strat.get('indicators_used'):
                L.append(f"  Indicators:    {', '.join(strat['indicators_used'])}")
            if strat.get('timeframes'):
                L.append(f"  Timeframes:    {', '.join(strat['timeframes'])}")
            if strat.get('entry_patterns'):
                L.append(f"  Entry:         {', '.join(strat['entry_patterns'])}")
            if strat.get('exit_patterns'):
                L.append(f"  Exit:          {', '.join(strat['exit_patterns'])}")
            L.append('')

        if risk.get('features'):
            L.append('RISK MANAGEMENT')
            L.append('-' * W)
            for f in risk['features']:
                L.append(f"  \u2713 {f}")
            L.append('')

        if audit.get('findings'):
            L.append('AUDIT FINDINGS')
            L.append('-' * W)
            for finding in audit['findings']:
                L.append(
                    f"  [{finding['severity'].upper()}] {finding['title']}: "
                    f"{', '.join(finding['evidence'])}")
            L.append('')

        handlers = a.get('event_handlers', [])
        if handlers:
            L.append('EVENT HANDLERS')
            L.append('-' * W)
            for h in handlers:
                L.append(f"  \u2022 {h}()")
            L.append('')

        tfuncs = a.get('trading_functions', [])
        if tfuncs:
            L.append('TRADING FUNCTIONS')
            L.append('-' * W)
            for tf in tfuncs:
                L.append(f"  \u2022 {tf['name']} – {tf['description']} (x{tf['count']})")
            L.append('')

        inds = a.get('indicators_detected', [])
        if inds:
            L.append('INDICATORS DETECTED')
            L.append('-' * W)
            for i in inds:
                L.append(f"  \u2022 {i['name']} – {i['description']} (x{i['count']})")
            L.append('')

        params = a.get('input_parameters', [])
        if params:
            L.append('INPUT PARAMETERS')
            L.append('-' * W)
            for p in params:
                L.append(f"  \u2022 {p['name']} ({p['type']}, default={p['default']})")
            L.append('')

        dis = a.get('disassembly', {})
        if dis.get('functions'):
            L.append('DISASSEMBLY SUMMARY')
            L.append('-' * W)
            L.append(f"  Functions found:      {len(dis['functions'])}")
            L.append(f"  Total instructions:   {dis['total_instructions']}")
            L.append('')

        L.append('ANALYSIS SUMMARY')
        L.append('-' * W)
        L.append(f"  Patterns found:       {len(a.get('patterns', []))}")
        L.append(f"  Strings extracted:    {stats.get('total_strings', 0)}")
        L.append(f"  Event handlers:       {len(handlers)}")
        L.append(f"  Indicators:           {len(inds)}")
        L.append(f"  Trading functions:    {len(tfuncs)}")
        L.append('')
        L.append('=' * W)
        return '\n'.join(L)


# ---------------------------------------------------------------------------
# GUI Application
# ---------------------------------------------------------------------------

# Color palette based on #FAF3E1 #F5E7C6 #FA8112 #222222
THEMES = {
    'dark': {
        'bg_primary': '#1a1a1a',
        'bg_secondary': '#222222',
        'bg_card': '#2d2d2d',
        'accent': '#FA8112',
        'accent_hover': '#FB9A3E',
        'text_primary': '#FAF3E1',
        'text_secondary': '#C8B793',
        'success': '#4CAF50',
        'warning': '#FF9800',
        'code_bg': '#121212',
        'code_fg': '#E0E0E0',
        'sidebar_bg': '#0f0f0f',
        'sidebar_active': '#2a2a2a',
        'seg_selected': '#FA8112',
    },
    'light': {
        'bg_primary': '#F5EFE0',
        'bg_secondary': '#EDE0C8',
        'bg_card': '#E0D0B0',
        'accent': '#D45500',
        'accent_hover': '#E06000',
        'text_primary': '#1A1A1A',
        'text_secondary': '#4A4030',
        'success': '#2E7D32',
        'warning': '#C44800',
        'code_bg': '#FFFFFF',
        'code_fg': '#1A1A1A',
        'sidebar_bg': '#E8D8BC',
        'sidebar_active': '#D4C0A0',
        'seg_selected': '#FFE0B2',
    },
}

# Emoji icons (render reliably on Windows/macOS/Linux)
ICON_OPEN = "📂"
ICON_ANALYZE = "🔍"
ICON_EXPORT = "💾"
ICON_JSON = "📋"
ICON_FILE = "📄"
ICON_THEME = "🌙"


def _detect_os_theme() -> str:
    """Detect OS-level dark/light theme preference."""
    try:
        import darkdetect
        mode = darkdetect.theme()
        if mode and mode.lower() == 'light':
            return 'light'
    except Exception:
        pass
    return 'dark'


class SidebarButton(ctk.CTkButton):
    """Custom sidebar navigation button."""

    def __init__(self, master, text, icon="", command=None, **kw):
        # Use provided colors or defaults
        text_color = kw.pop('text_color', "#FAF3E1")
        hover_color = kw.pop('hover_color', "#333333")
        super().__init__(
            master, text=f"  {icon}  {text}", command=command,
            fg_color="transparent",
            text_color=text_color,
            hover_color=hover_color,
            anchor="w",
            font=ctk.CTkFont(size=14), height=44, corner_radius=8, **kw)


class EX4StudioApp(ctk.CTk):
    """Main application window."""

    WIDTH = 1360
    HEIGHT = 820

    def __init__(self):
        # Detect OS theme and set appearance before creating window
        self._theme_name = _detect_os_theme()
        ctk.set_appearance_mode("dark" if self._theme_name == 'dark' else "light")
        ctk.set_default_color_theme("blue")

        super().__init__()

        self.title("EX4 Studio")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.minsize(1024, 680)

        self.engine = EX4AnalysisEngine()
        self.codegen = CodeGenerator()
        self.current_analysis: Optional[Dict] = None
        self.current_code: Optional[str] = None
        self.raw_data: Optional[bytes] = None

        self._build_ui()

    @property
    def T(self) -> Dict:
        """Current theme colors."""
        return THEMES[self._theme_name]

    def _set_theme_mode(self):
        if self._theme_name == 'dark':
            ctk.set_appearance_mode("dark")
        else:
            ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

    # -- UI construction ------------------------------------------------------

    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self._build_sidebar()

        # Main content area
        self.main_frame = ctk.CTkFrame(self, fg_color=self.T['bg_primary'],
                                        corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        # Header
        self._build_header()

        # Content notebook area
        self.content = ctk.CTkFrame(self.main_frame,
                                     fg_color=self.T['bg_primary'])
        self.content.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 8))
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        # Tab view
        self.tabview = ctk.CTkTabview(
            self.content, fg_color=self.T['bg_secondary'],
            segmented_button_fg_color=self.T['bg_card'],
            segmented_button_selected_color=self.T['seg_selected'],
            segmented_button_unselected_color=self.T['bg_card'],
            text_color=self.T['text_primary'],
            corner_radius=12)
        self.tabview.grid(row=0, column=0, sticky="nsew")

        # Create tabs
        for tab_name in ["Overview", "Generated Code", "Disassembly",
                         "Strings", "Hex View", "Log"]:
            self.tabview.add(tab_name)

        self._build_overview_tab()
        self._build_code_tab()
        self._build_disasm_tab()
        self._build_strings_tab()
        self._build_hex_tab()
        self._build_log_tab()

        # Status bar
        self._build_status_bar()

        # Show welcome
        self._show_welcome()

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=220,
                                     fg_color=self.T['sidebar_bg'],
                                     corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        # Logo area
        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent",
                                   height=80)
        logo_frame.pack(fill="x", padx=16, pady=(20, 8))
        logo_frame.pack_propagate(False)

        ctk.CTkLabel(logo_frame, text="EX4 Studio",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=self.T['accent']).pack(pady=(8, 0))
        ctk.CTkLabel(logo_frame, text="Binary Analyzer",
                     font=ctk.CTkFont(size=11),
                     text_color=self.T['text_secondary']).pack()

        ctk.CTkFrame(self.sidebar, height=1,
                     fg_color=self.T['bg_card']).pack(
            fill="x", padx=16, pady=12)

        # Navigation buttons
        SidebarButton(self.sidebar, "Open File", icon=ICON_OPEN,
                      command=self.open_file,
                      text_color=self.T['text_primary'],
                      hover_color=self.T['sidebar_active']).pack(
            fill="x", padx=16, pady=3)
        SidebarButton(self.sidebar, "Analyze", icon=ICON_ANALYZE,
                      command=self._run_analysis,
                      text_color=self.T['text_primary'],
                      hover_color=self.T['sidebar_active']).pack(
            fill="x", padx=16, pady=3)

        ctk.CTkFrame(self.sidebar, height=1,
                     fg_color=self.T['bg_card']).pack(
            fill="x", padx=16, pady=12)

        # Language selector
        ctk.CTkLabel(self.sidebar, text="Target Language",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=self.T['text_primary']).pack(
            padx=16, anchor="w", pady=(0, 4))
        self.lang_var = ctk.StringVar(value="MQL4")
        self.lang_menu = ctk.CTkOptionMenu(
            self.sidebar,
            values=["MQL4", "MQL5", "Python", "C", "R", "Text"],
            variable=self.lang_var, command=self._on_language_change,
            fg_color=self.T['bg_card'],
            button_color=self.T['accent'],
            button_hover_color=self.T['accent_hover'],
            text_color=self.T['text_primary'],
            width=180)
        self.lang_menu.pack(padx=16, pady=(0, 12))

        ctk.CTkFrame(self.sidebar, height=1,
                     fg_color=self.T['bg_card']).pack(
            fill="x", padx=16, pady=4)

        # Export buttons
        SidebarButton(self.sidebar, "Export Code", icon=ICON_EXPORT,
                      command=self._export_code,
                      text_color=self.T['text_primary'],
                      hover_color=self.T['sidebar_active']).pack(
            fill="x", padx=16, pady=3)
        SidebarButton(self.sidebar, "Export JSON", icon=ICON_JSON,
                      command=self._export_json,
                      text_color=self.T['text_primary'],
                      hover_color=self.T['sidebar_active']).pack(
            fill="x", padx=16, pady=3)

        ctk.CTkFrame(self.sidebar, height=1,
                     fg_color=self.T['bg_card']).pack(
            fill="x", padx=16, pady=4)

        # Theme toggle
        theme_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        theme_frame.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(theme_frame, text=f"{ICON_THEME}  Theme",
                     font=ctk.CTkFont(size=12),
                     text_color=self.T['text_primary']).pack(
            side="left")
        self.theme_switch = ctk.CTkSwitch(
            theme_frame, text="",
            command=self._toggle_theme,
            onvalue=1, offvalue=0,
            progress_color=self.T['accent'],
            switch_width=48,
            button_length=22,
            button_color=self.T['accent'],
            width=40)
        self.theme_switch.pack(side="right")
        if self._theme_name == 'dark':
            self.theme_switch.select()

        # Spacer
        ctk.CTkFrame(self.sidebar, fg_color="transparent").pack(
            fill="both", expand=True)

        # Version
        ctk.CTkLabel(self.sidebar, text="v3.0.0",
                     font=ctk.CTkFont(size=10),
                     text_color=self.T['text_secondary']).pack(pady=8)

    def _build_header(self):
        header = ctk.CTkFrame(self.main_frame,
                              fg_color=self.T['bg_secondary'],
                              height=64, corner_radius=0)
        header.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header.grid_propagate(False)
        header.grid_columnconfigure(1, weight=1)

        self.file_label = ctk.CTkLabel(
            header, text="No file loaded",
            font=ctk.CTkFont(size=14),
            text_color=self.T['text_secondary'])
        self.file_label.grid(row=0, column=0, padx=20, pady=16, sticky="w")

        self.info_label = ctk.CTkLabel(
            header, text="",
            font=ctk.CTkFont(size=12),
            text_color=self.T['text_secondary'])
        self.info_label.grid(row=0, column=1, padx=20, pady=16, sticky="e")

    def _build_overview_tab(self):
        tab = self.tabview.tab("Overview")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        self.overview_text = ctk.CTkTextbox(
            tab, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=self.T['code_bg'], text_color=self.T['code_fg'],
            corner_radius=8, wrap="word")
        self.overview_text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

    def _build_code_tab(self):
        tab = self.tabview.tab("Generated Code")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        self.code_text = ctk.CTkTextbox(
            tab, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=self.T['code_bg'], text_color=self.T['code_fg'],
            corner_radius=8, wrap="none")
        self.code_text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

    def _build_disasm_tab(self):
        tab = self.tabview.tab("Disassembly")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        disasm_fg = "#7ee787" if self._theme_name == 'dark' else "#1B5E20"
        self.disasm_text = ctk.CTkTextbox(
            tab, font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=self.T['code_bg'], text_color=disasm_fg,
            corner_radius=8, wrap="none")
        self.disasm_text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

    def _build_strings_tab(self):
        tab = self.tabview.tab("Strings")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        strings_fg = self.T['accent']
        self.strings_text = ctk.CTkTextbox(
            tab, font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=self.T['code_bg'], text_color=strings_fg,
            corner_radius=8, wrap="word")
        self.strings_text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

    def _build_hex_tab(self):
        tab = self.tabview.tab("Hex View")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        hex_fg = "#d2a8ff" if self._theme_name == 'dark' else "#6A1B9A"
        self.hex_text = ctk.CTkTextbox(
            tab, font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=self.T['code_bg'], text_color=hex_fg,
            corner_radius=8, wrap="none")
        self.hex_text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

    def _build_log_tab(self):
        tab = self.tabview.tab("Log")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        log_fg = "#8b949e" if self._theme_name == 'dark' else "#555555"
        self.log_text = ctk.CTkTextbox(
            tab, font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=self.T['code_bg'], text_color=log_fg,
            corner_radius=8, wrap="word")
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

        # Hook logger
        class _Handler(logging.Handler):
            def __init__(self, widget):
                super().__init__()
                self.w = widget

            def emit(self, record):
                msg = self.format(record) + '\n'
                self.w.insert("end", msg)
                self.w.see("end")

        h = _Handler(self.log_text)
        h.setFormatter(logging.Formatter(
            '%(asctime)s  %(levelname)-8s  %(message)s',
            datefmt='%H:%M:%S'))
        logger.addHandler(h)

    def _build_status_bar(self):
        bar = ctk.CTkFrame(self.main_frame, height=32,
                           fg_color=self.T['bg_card'], corner_radius=0)
        bar.grid(row=2, column=0, sticky="ew")
        bar.grid_propagate(False)
        self.status_label = ctk.CTkLabel(
            bar, text="Ready", font=ctk.CTkFont(size=12),
            text_color=self.T['text_secondary'])
        self.status_label.pack(side="left", padx=16)

    # -- Theme toggle ---------------------------------------------------------

    def _toggle_theme(self):
        if self._theme_name == 'dark':
            self._theme_name = 'light'
        else:
            self._theme_name = 'dark'
        ctk.set_appearance_mode(self._theme_name)
        self._apply_theme_to_widgets()

    def _apply_theme_to_widgets(self):
        """Update theme colors on all widgets without full rebuild."""
        T = self.T

        # Sidebar
        self.sidebar.configure(fg_color=T['sidebar_bg'])
        for w in self.sidebar.winfo_children():
            self._update_widget_theme(w, T)

        # Main frame
        self.main_frame.configure(fg_color=T['bg_primary'])
        self.content.configure(fg_color=T['bg_primary'])

        # Header
        for w in self.main_frame.winfo_children():
            if isinstance(w, ctk.CTkFrame) and w.cget('height') == 64:
                w.configure(fg_color=T['bg_secondary'])
                for child in w.winfo_children():
                    if isinstance(child, ctk.CTkLabel):
                        child.configure(text_color=T['text_secondary'])

        # Tabview - update colors (text_color is a supported CTkTabview param)
        self.tabview.configure(
            fg_color=T['bg_secondary'],
            segmented_button_fg_color=T['bg_card'],
            segmented_button_selected_color=T['seg_selected'],
            segmented_button_unselected_color=T['bg_card'],
            text_color=T['text_primary'])

        # Text widgets
        for attr in ['overview_text', 'code_text', 'disasm_text',
                     'strings_text', 'hex_text', 'log_text']:
            widget = getattr(self, attr, None)
            if widget:
                widget.configure(fg_color=T['code_bg'],
                                 text_color=self._get_text_color(attr, T))

        # Status bar
        for w in self.main_frame.winfo_children():
            if isinstance(w, ctk.CTkFrame) and w.cget('height') == 32:
                w.configure(fg_color=T['bg_card'])
                for child in w.winfo_children():
                    if isinstance(child, ctk.CTkLabel):
                        child.configure(text_color=T['text_secondary'])

        # Sidebar buttons
        for w in self.sidebar.winfo_children():
            if isinstance(w, ctk.CTkButton):
                w.configure(text_color=T['text_primary'],
                            hover_color=T['sidebar_active'])

        # Update status
        self.status_label.configure(text_color=T['text_secondary'])
        self.file_label.configure(text_color=T['text_primary'])

        # Tabview text colors
        try:
            for tab_name in ["Overview", "Generated Code", "Disassembly",
                             "Strings", "Hex View", "Log"]:
                tab = self.tabview.tab(tab_name)
                if tab:
                    for child in tab.winfo_children():
                        self._recolor_text_widgets(child, T)
        except Exception:
            pass

    def _recolor_text_widgets(self, widget, T: Dict):
        """Recursively update text widget colors, preserving per-tab colors."""
        try:
            if isinstance(widget, ctk.CTkTextbox):
                # Keep the widget's existing text color (per-tab syntax colors)
                current_fg = widget.cget('text_color')
                if current_fg in (T['code_fg'], T['text_primary'],
                                  T['text_secondary']):
                    widget.configure(fg_color=T['code_bg'],
                                     text_color=T['code_fg'])
                else:
                    widget.configure(fg_color=T['code_bg'])
        except Exception:
            pass
        try:
            for child in widget.winfo_children():
                self._recolor_text_widgets(child, T)
        except Exception:
            pass

    def _get_text_color(self, attr: str, T: Dict) -> str:
        """Get appropriate text color for a widget based on theme."""
        if attr == 'disasm':
            return "#7ee787" if self._theme_name == 'dark' else "#1B5E20"
        elif attr == 'strings':
            return T['accent']
        elif attr == 'hex':
            return "#d2a8ff" if self._theme_name == 'dark' else "6A1B9A"
        elif attr == 'log':
            return "#8b949e" if self._theme_name == 'dark' else "555555"
        return T['code_fg']

    def _update_widget_theme(self, widget, T: Dict):
        """Recursively update widget theme colors."""
        try:
            if isinstance(widget, ctk.CTkButton):
                widget.configure(text_color=T['text_primary'],
                                hover_color=T['sidebar_active'])
            elif isinstance(widget, ctk.CTkLabel):
                text = widget.cget('text')
                if text in ["EX4 Studio", "Binary Analyzer"]:
                    pass  # Keep logo labels as-is
                elif text == "Target Language" or text.endswith("Theme"):
                    widget.configure(text_color=T['text_primary'])
                else:
                    widget.configure(text_color=T['text_secondary'])
            elif isinstance(widget, ctk.CTkFrame):
                current_fg = widget.cget('fg_color')
                if current_fg in ['#0f0f0f', '#E8D8BC']:
                    widget.configure(fg_color=T['sidebar_bg'])
                elif current_fg in ['#2d2d2d', '#E0D0B0']:
                    widget.configure(fg_color=T['bg_card'])
                elif current_fg in ['#222222', '#EDE0C8']:
                    widget.configure(fg_color=T['bg_secondary'])
                elif current_fg in ['#1a1a1a', '#F5EFE0']:
                    widget.configure(fg_color=T['bg_primary'])
        except Exception:
            pass
        try:
            for child in widget.winfo_children():
                self._update_widget_theme(child, T)
        except Exception:
            pass
        try:
            for child in widget.winfo_children():
                self._update_widget_theme(child, T)
        except Exception:
            pass

    # -- Welcome screen -------------------------------------------------------

    def _show_welcome(self):
        welcome = (
            "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n"
            "\u2551               EX4 STUDIO  v3.0                        \u2551\n"
            "\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n"
            "\u2551                                                            \u2551\n"
            "\u2551  Features:                                                 \u2551\n"
            "\u2551  \u2022 EX4 header analysis (legacy & modern formats)          \u2551\n"
            "\u2551  \u2022 Binary pattern recognition (60+ patterns)               \u2551\n"
            "\u2551  \u2022 x86 disassembly via Capstone engine                     \u2551\n"
            "\u2551  \u2022 PE header analysis                                      \u2551\n"
            "\u2551  \u2022 ASCII + UTF-16LE string extraction                      \u2551\n"
            "\u2551  \u2022 Trading strategy & indicator detection                  \u2551\n"
            "\u2551  \u2022 Input parameter extraction                              \u2551\n"
            "\u2551  \u2022 Risk management analysis                                \u2551\n"
            "\u2551  \u2022 Multi-language code generation:                         \u2551\n"
            "\u2551      MQL4 \u00b7 MQL5 \u00b7 Python \u00b7 C \u00b7 R \u00b7 Text                  \u2551\n"
            "\u2551  \u2022 Hex viewer for binary inspection                        \u2551\n"
            "\u2551  \u2022 JSON export for further processing                      \u2551\n"
            "\u2551  \u2022 Light / Dark theme with OS detection                    \u2551\n"
            "\u2551                                                            \u2551\n"
            "\u2551  Click 'Open File' in the sidebar to begin.                \u2551\n"
            "\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n"
        )
        self.overview_text.insert("end", welcome)

    # -- Actions --------------------------------------------------------------

    def open_file(self):
        path = filedialog.askopenfilename(
            title="Select EX4 File",
            filetypes=[("EX4 files", "*.ex4"), ("All files", "*.*")])
        if not path:
            return
        self._set_status(f"Loading {os.path.basename(path)}...")
        try:
            with open(path, 'rb') as f:
                self.raw_data = f.read()
            self.file_label.configure(
                text=f"{ICON_FILE}  {os.path.basename(path)}",
                text_color=self.T['text_primary'])
            size_kb = round(len(self.raw_data) / 1024, 1)
            self.info_label.configure(text=f"{size_kb} KB")
            self._filepath = path
            self._set_status(f"Loaded {os.path.basename(path)} \u2013 click Analyze")
            logger.info("File loaded: %s (%d bytes)", path, len(self.raw_data))
            # Auto-analyze
            self._run_analysis()
        except Exception as e:
            self._set_status(f"Error: {e}")
            logger.error("File load error: %s", e)

    def _run_analysis(self):
        if not hasattr(self, '_filepath') or self.raw_data is None:
            self._set_status("No file loaded – use Open File first")
            return
        self._set_status("Analyzing…")
        self.update()
        try:
            analysis = self.engine.analyze(self._filepath)
            self.current_analysis = analysis
            self._populate_overview(analysis)
            self._populate_code(analysis)
            self._populate_disasm(analysis)
            self._populate_strings(analysis)
            self._populate_hex()
            self._set_status(
                f"Analysis complete – {len(analysis.get('patterns', []))} "
                f"patterns, {len(analysis.get('strings', []))} strings")
        except Exception as e:
            self._set_status(f"Analysis error: {e}")
            logger.error("Analysis error: %s", e, exc_info=True)

    def _on_language_change(self, _=None):
        if self.current_analysis:
            self._populate_code(self.current_analysis)

    def _export_code(self):
        if not self.current_code:
            self._set_status("No code to export")
            return
        ext_map = {'MQL4': '.mq4', 'MQL5': '.mq5', 'Python': '.py',
                   'C': '.c', 'R': '.R', 'Text': '.txt'}
        lang = self.lang_var.get()
        ext = ext_map.get(lang, '.txt')
        path = filedialog.asksaveasfilename(
            title=f"Export {lang} Code", defaultextension=ext,
            filetypes=[(f"{lang} files", f"*{ext}"), ("All files", "*.*")])
        if path:
            with open(path, 'w') as f:
                f.write(self.current_code)
            self._set_status(f"Exported to {os.path.basename(path)}")

    def _export_json(self):
        if not self.current_analysis:
            self._set_status("No analysis to export")
            return
        path = filedialog.asksaveasfilename(
            title="Export Analysis", defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if path:
            with open(path, 'w') as f:
                json.dump(self.current_analysis, f, indent=2, default=str)
            self._set_status(f"Exported to {os.path.basename(path)}")

    # -- populate views -------------------------------------------------------

    def _populate_overview(self, a: Dict):
        self.overview_text.delete("0.0", "end")
        meta = a['metadata']
        pe = a.get('pe_info', {})
        strat = a.get('trading_strategy', {})
        risk = a.get('risk_management', {})
        stats = a.get('statistics', {})
        recovery = a.get('recovery_profile', {})
        audit = a.get('audit_report', {})

        lines = []
        lines.append(f"{'═' * 60}")
        lines.append(f"  FILE: {a.get('filename', 'N/A')}")
        lines.append(f"{'═' * 60}")
        lines.append("")
        lines.append(f"  Format:       {meta.get('format', 'Unknown')}")
        lines.append(f"  Type:         {meta['type']}")
        lines.append(f"  Version:      {meta['version']}")
        if meta.get('build', 0) > 0:
            lines.append(f"  Build:        {meta['build']}")
        lines.append(f"  Size:         {stats.get('file_size_kb', 0)} KB")
        lines.append(f"  Entropy:      {stats.get('entropy', 0)}")
        if meta.get('copyright', 'Unknown') != 'Unknown':
            lines.append(f"  Copyright:    {meta['copyright']}")
        if meta.get('author', 'Unknown') != 'Unknown':
            lines.append(f"  Author:       {meta['author']}")
        if meta.get('link', 'Unknown') != 'Unknown':
            lines.append(f"  Link:         {meta['link']}")
        lines.append("")

        if recovery:
            lines.append("  RECOVERY PROFILE")
            lines.append(
                f"  ├─ Level:      {recovery.get('recovery_level', 'Unknown')}")
            lines.append(
                f"  ├─ Confidence: {recovery.get('confidence', 'Unknown')}")
            lines.append(
                f"  ├─ Obfuscation:{recovery.get('obfuscation_level', 'Unknown')}")
            lines.append(
                f"  └─ Structured: {recovery.get('structured_strings', 0)} "
                f"strings @ {recovery.get('semantic_string_ratio', 0)} ratio")
            lines.append("")

        if pe.get('valid_pe'):
            lines.append("  PE HEADER")
            lines.append(f"  ├─ Machine:    {pe.get('machine', 'N/A')}")
            if pe.get('timestamp'):
                lines.append(f"  ├─ Compiled:   {pe['timestamp']}")
            if pe.get('num_sections'):
                lines.append(f"  └─ Sections:   {pe['num_sections']}")
            lines.append("")

        if strat.get('type', 'Unknown') != 'Unknown':
            lines.append(f"  STRATEGY: {strat['type']}")
            if strat.get('indicators_used'):
                lines.append(f"  ├─ Indicators: {', '.join(strat['indicators_used'])}")
            if strat.get('timeframes'):
                lines.append(f"  ├─ Timeframes: {', '.join(strat['timeframes'])}")
            if strat.get('entry_patterns'):
                lines.append(f"  ├─ Entry:      {', '.join(strat['entry_patterns'])}")
            if strat.get('exit_patterns'):
                lines.append(f"  └─ Exit:       {', '.join(strat['exit_patterns'])}")
            lines.append("")

        if risk.get('features'):
            lines.append("  RISK MANAGEMENT")
            for i, f in enumerate(risk['features']):
                prefix = "  └─" if i == len(risk['features']) - 1 else "  ├─"
                lines.append(f"{prefix} {f}")
            lines.append("")

        if audit.get('findings'):
            lines.append(f"  AUDIT: {audit.get('severity', 'none').upper()}")
            for finding in audit['findings']:
                lines.append(
                    f"  • [{finding['severity']}] {finding['title']} -> "
                    f"{', '.join(finding['evidence'])}")
            lines.append("")

        handlers = a.get('event_handlers', [])
        if handlers:
            lines.append(f"  EVENT HANDLERS: {', '.join(handlers)}")
            lines.append("")

        tfuncs = a.get('trading_functions', [])
        if tfuncs:
            lines.append("  TRADING FUNCTIONS")
            for tf in tfuncs:
                lines.append(f"  • {tf['name']} (x{tf['count']})")
            lines.append("")

        inds = a.get('indicators_detected', [])
        if inds:
            lines.append("  INDICATORS")
            for ind in inds:
                lines.append(f"  • {ind['name']} – {ind['description']} (x{ind['count']})")
            lines.append("")

        params = a.get('input_parameters', [])
        if params:
            lines.append("  INPUT PARAMETERS")
            for p in params:
                lines.append(f"  • {p['name']} : {p['type']} = {p['default']}")
            lines.append("")

        dis = a.get('disassembly', {})
        if dis.get('functions'):
            lines.append(f"  DISASSEMBLY: {len(dis['functions'])} functions, "
                         f"{dis['total_instructions']} instructions")
            lines.append("")

        lines.append(f"  Patterns: {len(a.get('patterns', []))}  |  "
                     f"Strings: {stats.get('total_strings', 0)}  |  "
                     f"Handlers: {len(handlers)}  |  "
                     f"Indicators: {len(inds)}")
        lines.append(f"{'═' * 60}")

        self.overview_text.insert("end", "\n".join(lines))

    def _populate_code(self, a: Dict):
        lang = self.lang_var.get()
        code = self.codegen.generate(a, lang)
        self.current_code = code
        self.code_text.delete("0.0", "end")
        self.code_text.insert("end", code)

    def _populate_disasm(self, a: Dict):
        self.disasm_text.delete("0.0", "end")
        dis = a.get('disassembly', {})
        meta = a.get('metadata', {})

        # Always show file format info
        lines = []
        lines.append(f"{'─' * 50}")
        lines.append(f"  Binary Analysis: {a.get('filename', 'N/A')}")
        lines.append(f"  Format: {meta.get('format', 'Unknown')}")
        lines.append(f"  Type: {meta.get('type', 'Unknown')}")
        if meta.get('build', 0) > 0:
            lines.append(f"  Build: {meta['build']}")
        lines.append(f"{'─' * 50}")
        lines.append("")

        if dis.get('error'):
            lines.append(f"[!] {dis['error']}")
            lines.append("")

        funcs = dis.get('functions', [])
        if funcs:
            lines.append(f"  Functions detected: {len(funcs)}")
            lines.append(f"  Total instructions: {dis.get('total_instructions', 0)}")
            lines.append("")
            for fn in funcs:
                lines.append(f"{'─' * 50}")
                lines.append(f"  Function @ {fn['start']} \u2013 {fn['end']}  "
                             f"({fn['size']} bytes)")
                lines.append(f"{'─' * 50}")
                for ins in fn['instructions']:
                    lines.append(f"    {ins}")
                lines.append("")
        else:
            if meta.get('format', '').startswith('Modern'):
                lines.append("  [i] Content is encrypted (modern EX4 format)")
                lines.append("      x86 function prologues not directly visible")
                lines.append("      String extraction and pattern analysis used instead")
            else:
                lines.append("  [i] No standard x86 function prologues detected")
            lines.append("")

        # Show binary statistics
        stats = a.get('statistics', {})
        lines.append(f"{'─' * 50}")
        lines.append("  BINARY STATISTICS")
        lines.append(f"{'─' * 50}")
        lines.append(f"  File size:     {stats.get('file_size_kb', 0)} KB")
        lines.append(f"  Entropy:       {stats.get('entropy', 0)}")
        lines.append(f"  Has MZ header: {stats.get('has_mz_header', False)}")
        lines.append(f"  Total strings: {stats.get('total_strings', 0)}")
        lines.append(f"  Patterns:      {len(a.get('patterns', []))}")

        self.disasm_text.insert("end", "\n".join(lines))

    def _populate_strings(self, a: Dict):
        self.strings_text.delete("0.0", "end")
        cats = a.get('string_categories', {})
        has_content = False
        for cat_name, items in cats.items():
            if items:
                has_content = True
                self.strings_text.insert(
                    "end", f"\n{'─' * 40}\n  {cat_name.upper()} "
                           f"({len(items)})\n{'─' * 40}\n")
                for s in items:
                    self.strings_text.insert("end", f"  {s}\n")

        if not has_content:
            self.strings_text.insert(
                "end", "  No categorized strings found.\n"
                "  Load and analyze an EX4 file to see extracted strings.\n")

    def _populate_hex(self, max_bytes: int = 4096):
        self.hex_text.delete("0.0", "end")
        if not self.raw_data:
            return
        data = self.raw_data[:max_bytes]
        lines = []
        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f"{offset:08x}  {hex_part:<48s}  |{ascii_part}|")
        if len(self.raw_data) > max_bytes:
            lines.append(f"\n... ({len(self.raw_data) - max_bytes} more bytes)")
        self.hex_text.insert("end", "\n".join(lines))

    # -- helpers --------------------------------------------------------------

    def _set_status(self, text: str):
        self.status_label.configure(text=text)
        self.update_idletasks()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    app = EX4StudioApp()
    app.mainloop()


if __name__ == "__main__":
    main()
