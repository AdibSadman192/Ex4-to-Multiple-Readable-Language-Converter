#!/usr/bin/env python3
"""
EX4 Studio
A comprehensive GUI application for decompiling MetaTrader 4 EX4 binary files
into multiple readable programming languages.

Consolidates all analysis techniques: EX4 header parsing (v400/v500+),
pattern recognition, x86 disassembly, PE header analysis, string extraction
with quality filtering, trading strategy detection, filename analysis, and
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

        ex4_header = self._parse_ex4_header(data)
        strings = self._extract_strings(data)

        # Filter strings based on encryption status
        quality_strings = self._filter_quality_strings(strings, ex4_header.get('is_encrypted', False))
        categories = self._categorize_strings(quality_strings)

        # Use filename for additional hints
        filename = os.path.basename(filepath)
        filename_hints = self._analyze_filename(filename)

        result = {
            'filepath': filepath,
            'filename': filename,
            'ex4_header': ex4_header,
            'metadata': self._extract_metadata(data, ex4_header, filename_hints),
            'pe_info': self._parse_pe_header(data),
            'patterns': self._find_patterns(data),
            'strings': quality_strings,
            'all_strings_count': len(strings),
            'string_categories': categories,
            'event_handlers': self._find_event_handlers(data),
            'trading_functions': self._find_trading_functions(data),
            'indicators_detected': self._find_indicators(data),
            'buffer_functions': self._find_buffer_functions(data),
            'input_parameters': self._extract_input_parameters(categories),
            'trading_strategy': self._analyze_strategy(data),
            'risk_management': self._analyze_risk(data),
            'disassembly': self._disassemble(data),
            'statistics': self._statistics(data, strings),
            'filename_hints': filename_hints,
        }
        logger.info("Analysis complete – %d patterns, %d strings (%d quality)",
                     len(result['patterns']), len(strings), len(quality_strings))
        return result

    # -- EX4 header parsing ---------------------------------------------------

    def _parse_ex4_header(self, data: bytes) -> Dict:
        """Parse the EX4-specific binary header."""
        info = {
            'is_ex4': False,
            'format_version': 'Unknown',
            'build_number': 0,
            'is_encrypted': False,
            'header_hash': '',
            'program_type_flags': 0,
        }

        if len(data) < 48:
            return info

        magic = data[0:4]

        if magic == b'EX4\x00':
            info['is_ex4'] = True
            info['format_version'] = '400 (Unencrypted)'
            info['is_encrypted'] = False
            if len(data) > 8:
                info['header_size'] = struct.unpack('<I', data[4:8])[0]

        elif magic == b'EX-\x04':
            info['is_ex4'] = True
            info['format_version'] = '500+ (Protected)'
            info['is_encrypted'] = True
            if len(data) > 8:
                info['build_number'] = struct.unpack('<H', data[6:8])[0]
            if len(data) > 48:
                info['header_hash'] = data[32:48].hex()
            if len(data) > 12:
                info['program_type_flags'] = struct.unpack('<I', data[8:12])[0]

        elif magic[:2] == b'EX':
            info['is_ex4'] = True
            info['format_version'] = f'Unknown ({magic.hex()})'

        return info

    # -- filename analysis ----------------------------------------------------

    def _analyze_filename(self, filename: str) -> Dict:
        """Extract hints from the filename itself."""
        name = os.path.splitext(filename)[0]
        hints = {
            'name': name,
            'possible_type': 'Indicator',
            'keywords': [],
        }

        name_lower = name.lower()

        type_keywords = {
            'EA': 'Expert Advisor', 'expert': 'Expert Advisor',
            'indicator': 'Indicator', 'indi': 'Indicator',
            'script': 'Script', 'timer': 'Timer Utility',
            'channel': 'Channel Indicator', 'fibo': 'Fibonacci Indicator',
            'magic': 'Custom Indicator', 'snr': 'Support & Resistance Indicator',
            'kombiner': 'Multi-Indicator Combiner', 'hyper': 'Custom Indicator',
        }
        for kw, ptype in type_keywords.items():
            if kw.lower() in name_lower:
                hints['possible_type'] = ptype
                hints['keywords'].append(kw)

        return hints

    # -- string quality scoring -----------------------------------------------

    def _score_string_quality(self, s: str) -> float:
        """Score how likely a string is to be a real identifier/text vs random noise."""
        if len(s) < 3:
            return 0.0
        score = 0.0

        known = ['Order', 'Price', 'Stop', 'Profit', 'Loss', 'Buy', 'Sell',
                 'Close', 'Open', 'High', 'Low', 'Volume', 'Time', 'Period',
                 'Buffer', 'Index', 'Draw', 'Color', 'Alert', 'Comment',
                 'Symbol', 'Bars', 'Line', 'Level', 'Mode', 'Style',
                 'Chart', 'Object', 'Window', 'Init', 'Start', 'Tick',
                 'Magic', 'Lot', 'Slippage', 'Expert', 'Indicator',
                 'Script', 'Show', 'Display', 'Enable', 'Disable',
                 'Copyright', 'Version', 'Link', 'Author', 'Description',
                 'Fibo', 'Channel', 'Timer', 'Signal', 'Trend']
        for kw in known:
            if kw.lower() in s.lower():
                score += 3.0

        if re.search(r'[a-z][A-Z]', s):
            score += 2.0

        if '.' in s or '_' in s:
            score += 1.5

        if 5 <= len(s) <= 50:
            score += 1.0

        vowels = sum(1 for c in s.lower() if c in 'aeiou')
        ratio = vowels / max(len(s), 1)
        if 0.15 < ratio < 0.6:
            score += 1.0

        special = sum(1 for c in s if not c.isalnum() and c not in '._- ')
        if special / max(len(s), 1) > 0.3:
            score -= 2.0

        known_short = ['SMA', 'EMA', 'RSI', 'ATR', 'CCI', 'ADX', 'SAR']
        if len(s) < 6 and s.isupper() and not any(
                kw.upper() == s for kw in known_short):
            score -= 1.0

        return score

    def _filter_quality_strings(self, strings: List[str], is_encrypted: bool) -> List[str]:
        """Filter strings based on quality score, more aggressive for encrypted files."""
        threshold = 1.5 if is_encrypted else 0.0
        scored = [(s, self._score_string_quality(s)) for s in strings]
        return [s for s, score in scored if score >= threshold]

    # -- metadata -------------------------------------------------------------

    def _extract_metadata(self, data: bytes, ex4_header: Dict = None, filename_hints: Dict = None) -> Dict:
        meta: Dict = {
            'type': 'Unknown', 'version': 'Unknown',
            'creation_date': 'Unknown', 'file_size': len(data),
            'copyright': 'Unknown', 'description': 'Unknown',
            'author': 'Unknown', 'link': 'Unknown',
            'format': 'Unknown', 'is_encrypted': False,
            'build_number': 0,
        }

        # Use EX4 header info
        if ex4_header:
            meta['format'] = ex4_header.get('format_version', 'Unknown')
            meta['is_encrypted'] = ex4_header.get('is_encrypted', False)
            meta['build_number'] = ex4_header.get('build_number', 0)

        # Use filename hints for type detection
        if filename_hints:
            if meta['type'] == 'Unknown':
                meta['type'] = filename_hints.get('possible_type', 'Unknown')

        # Original type detection from binary content
        dl = data.lower()
        if meta['type'] == 'Unknown':
            if b'expert' in dl or b'EA' in data:
                meta['type'] = 'Expert Advisor'
            elif b'script' in dl:
                meta['type'] = 'Script'
            elif b'library' in dl:
                meta['type'] = 'Library'
            elif b'indicator' in dl:
                meta['type'] = 'Indicator'

        for pat in [
            rb'version[\s=:]+([\d]+\.[\d]+(?:\.[\d]+)?)',
            rb'v[\s]*([\d]+\.[\d]+(?:\.[\d]+)?)',
        ]:
            m = re.search(pat, data, re.IGNORECASE)
            if m:
                meta['version'] = m.group(1).decode('ascii', errors='ignore')
                break

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
            'symbols': [], 'parameters': [], 'comments': [], 'other': [],
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
            if len(s) > 60:
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

    def _analyze_risk(self, data: bytes) -> Dict:
        r: Dict = {
            'has_stop_loss': b'StopLoss' in data or b'stoploss' in data.lower(),
            'has_take_profit': b'TakeProfit' in data or b'takeprofit' in data.lower(),
            'has_trailing_stop': b'TrailingStop' in data,
            'has_money_management': b'MoneyManagement' in data or b'MM' in data,
            'has_risk_percent': b'RiskPercent' in data or b'Risk' in data,
            'has_max_lots': b'MaxLots' in data or b'MaxLot' in data,
            'has_max_orders': b'MaxOrders' in data or b'MaxTrades' in data,
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
        }
        for k, lbl in label_map.items():
            if r.get(k):
                r['features'].append(lbl)
        return r

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

    def _statistics(self, data: bytes, strings: List[str]) -> Dict:
        entropy = 0.0
        if data:
            counts = Counter(data)
            total = len(data)
            entropy = -sum(
                (c / total) * math.log2(c / total) for c in counts.values())

        null_bytes = sum(1 for b in data if b == 0)
        printable_bytes = sum(1 for b in data if 32 <= b <= 126)
        high_bytes = sum(1 for b in data if b >= 128)

        return {
            'file_size_bytes': len(data),
            'file_size_kb': round(len(data) / 1024, 2),
            'total_strings': len(strings),
            'unique_strings': len(set(strings)),
            'has_mz_header': data[:2] == b'MZ',
            'has_ex4_header': data[:2] == b'EX',
            'entropy': round(entropy, 4),
            'null_byte_pct': round(null_bytes / max(len(data), 1) * 100, 1),
            'printable_pct': round(printable_bytes / max(len(data), 1) * 100, 1),
            'high_byte_pct': round(high_bytes / max(len(data), 1) * 100, 1),
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
        cn = self._safe_class_name(a)
        hints = a.get('filename_hints', {})
        ex4h = a.get('ex4_header', {})

        L += self._header_box(f"Decompiled MQL4 – {meta['type']}")
        L.append(f"// Source:    {a.get('filename', 'unknown')}")
        L.append(f"// Version:   {meta['version']}")
        L.append(f"// Format:    EX4 {ex4h.get('format_version', 'Unknown')}")
        if ex4h.get('build_number'):
            L.append(f"// Build:     {ex4h['build_number']}")
        if meta.get('copyright', 'Unknown') != 'Unknown':
            L.append(f"// Copyright: {meta['copyright']}")
        if meta.get('is_encrypted'):
            L.append("// Note:      Encrypted EX4 - structure inferred from analysis")
        L.append('')

        # Property directives
        L.append(f'#property copyright "{meta.get("copyright", cn)}"')
        L.append(f'#property description "{hints.get("possible_type", meta["type"])} - decompiled from {a.get("filename", "EX4")}"')
        if meta.get('link', 'Unknown') != 'Unknown':
            L.append(f'#property link      "{meta["link"]}"')
        L.append(f'#property version   "{meta["version"]}"')
        L.append('#property strict')
        L.append('')

        strat = a.get('trading_strategy', {})
        if strat.get('type', 'Unknown') != 'Unknown':
            L.append(f"// Strategy: {strat['type']}")
            if strat.get('indicators_used'):
                L.append(f"// Indicators: {', '.join(strat['indicators_used'])}")
            L.append('')

        if meta['type'] in ('Indicator', 'Channel Indicator', 'Fibonacci Indicator',
                            'Custom Indicator', 'Support & Resistance Indicator',
                            'Multi-Indicator Combiner') or 'indicator' in meta['type'].lower():
            L.append('#property indicator_chart_window')
            L.append('#property indicator_buffers 2')
            L.append('#property indicator_color1 DodgerBlue')
            L.append('#property indicator_color2 Red')
            L.append('#property indicator_width1 2')
            L.append('#property indicator_width2 2')
            L.append('')

        params = a.get('input_parameters', [])
        if params:
            L.append('// Input Parameters (inferred from binary analysis)')
            for p in params:
                L.append(f"extern {p['type']} {p['name']} = {p['default']};")
            L.append('')
        else:
            L.append('// Input Parameters (defaults - no parameters detected in binary)')
            L.append('extern int    InpPeriod    = 14;')
            L.append('extern int    InpShift     = 0;')
            L.append('extern double InpDeviation = 2.0;')
            L.append('')

        L.append('// Indicator Buffers')
        L.append('double Buffer1[];')
        L.append('double Buffer2[];')
        L.append('')

        L += self._header_box('Initialization')
        L += ['int OnInit()', '{']
        L.append(f'    IndicatorShortName("{cn}");')
        L.append('    SetIndexStyle(0, DRAW_LINE);')
        L.append('    SetIndexBuffer(0, Buffer1);')
        L.append('    SetIndexLabel(0, "Main");')
        L.append('    SetIndexStyle(1, DRAW_LINE);')
        L.append('    SetIndexBuffer(1, Buffer2);')
        L.append('    SetIndexLabel(1, "Signal");')
        for bf in a.get('buffer_functions', []):
            L.append(f'    // Detected: {bf["name"]} (x{bf["count"]})')
        L += ['    return(INIT_SUCCEEDED);', '}', '']

        L += self._header_box('Deinitialization')
        L += ['void OnDeinit(const int reason)', '{',
              '    ObjectsDeleteAll(0, "' + cn + '_");',
              '    Comment("");',
              '}', '']

        if meta['type'] == 'Expert Advisor':
            L += self._header_box('Expert tick function')
            L += ['void OnTick()', '{']
        else:
            L += self._header_box('Indicator calculation')
            L += ['int OnCalculate(const int rates_total,',
                  '                const int prev_calculated,',
                  '                const datetime &time[],',
                  '                const double &open[],',
                  '                const double &high[],',
                  '                const double &low[],',
                  '                const double &close[],',
                  '                const long &tick_volume[],',
                  '                const long &volume[],',
                  '                const int &spread[])',
                  '{',
                  '    int limit = rates_total - prev_calculated;',
                  '    if(prev_calculated > 0) limit++;',
                  '']

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
                    L.append(f'        int ticket = OrderSend(Symbol(), OP_BUY, 0.1, Ask, 3,')
                    L.append(f'            {sl_str}, {tp_str}, "{cn}", 0, 0, clrGreen);')
                    break
            L.append('    }')
        else:
            L.append('')
            L.append('    // Main calculation loop')
            L.append('    for(int i = limit - 1; i >= 0; i--)')
            L.append('    {')
            L.append('        Buffer1[i] = close[i];  // Placeholder - actual logic encrypted')
            L.append('        Buffer2[i] = EMPTY_VALUE;')
            L.append('    }')
            L.append('')
            L.append('    return(rates_total);')

        L.append('}')
        return '\n'.join(L)

    # -- MQL5 -----------------------------------------------------------------

    def _mql5(self, a: Dict) -> str:
        L = []
        meta = a['metadata']
        cn = self._safe_class_name(a)
        hints = a.get('filename_hints', {})
        ex4h = a.get('ex4_header', {})

        L += self._header_box(f"Decompiled MQL5 – {meta['type']}")
        L.append(f"// Source:  {a.get('filename', 'unknown')}")
        L.append(f"// Version: {meta['version']}")
        L.append(f"// Format:  EX4 {ex4h.get('format_version', 'Unknown')}")
        if meta.get('is_encrypted'):
            L.append("// Note:    Encrypted EX4 - structure inferred")
        L.append('')

        L.append(f'#property copyright "{meta.get("copyright", cn)}"')
        L.append(f'#property description "{hints.get("possible_type", meta["type"])}"')
        L.append(f'#property version   "{meta["version"]}"')
        L.append('#property strict')
        L.append('')

        L.append('#include <Trade/Trade.mqh>')
        L.append('#include <Indicators/Indicators.mqh>')
        L.append('')

        params = a.get('input_parameters', [])
        if params:
            for p in params:
                L.append(f"input {p['type']} {p['name']} = {p['default']};")
        else:
            L.append('input int    InpPeriod    = 14;')
            L.append('input int    InpShift     = 0;')
            L.append('input double InpDeviation = 2.0;')
        L.append('')

        L.append('CTrade trade;')
        L.append('double Buffer1[];')
        L.append('double Buffer2[];')
        L.append('')

        L.append('int OnInit()')
        L.append('{')
        is_indicator = meta['type'] != 'Expert Advisor'
        if is_indicator:
            L.append('    SetIndexBuffer(0, Buffer1, INDICATOR_DATA);')
            L.append('    SetIndexBuffer(1, Buffer2, INDICATOR_DATA);')
            L.append('    PlotIndexSetInteger(0, PLOT_DRAW_TYPE, DRAW_LINE);')
            L.append('    PlotIndexSetInteger(1, PLOT_DRAW_TYPE, DRAW_LINE);')
            L.append(f'    IndicatorSetString(INDICATOR_SHORTNAME, "{cn}");')
        else:
            L.append('    trade.SetExpertMagicNumber(12345);')
            L.append('    trade.SetDeviationInPoints(10);')
        L.append('    return(INIT_SUCCEEDED);')
        L.append('}')
        L.append('')

        L.append('void OnDeinit(const int reason)')
        L.append('{')
        L.append(f'    ObjectsDeleteAll(0, "{cn}_");')
        L.append('    Comment("");')
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
            L.append('    // Entry logic')
            L.append('    if(PositionsTotal() < 1) {')
            L.append('        trade.Buy(0.1, _Symbol);')
            L.append('    }')
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
            L.append('    int limit = rates_total - prev_calculated;')
            L.append('    if(prev_calculated > 0) limit++;')
            L.append('')
            L.append('    for(int i = limit - 1; i >= 0; i--)')
            L.append('    {')
            L.append('        Buffer1[i] = close[i];  // Placeholder')
            L.append('        Buffer2[i] = EMPTY_VALUE;')
            L.append('    }')
            L.append('')
            L.append('    return(rates_total);')
            L.append('}')
        return '\n'.join(L)

    # -- Python ---------------------------------------------------------------

    def _python(self, a: Dict) -> str:
        L = []
        meta = a['metadata']
        cn = self._safe_class_name(a, 'TradingStrategy')
        hints = a.get('filename_hints', {})
        ex4h = a.get('ex4_header', {})
        stats = a.get('statistics', {})

        L.append('"""')
        L.append(f"Converted from MT4 {meta['type']}: {a.get('filename', 'unknown')}")
        L.append(f"Type:       {hints.get('possible_type', meta['type'])}")
        L.append(f"Version:    {meta['version']}")
        L.append(f"Format:     EX4 {ex4h.get('format_version', 'Unknown')}")
        if ex4h.get('is_encrypted'):
            L.append("Encrypted:  Yes - structure inferred from binary analysis")
        L.append(f"File Size:  {stats.get('file_size_kb', 0)} KB")
        L.append(f"Entropy:    {stats.get('entropy', 0)}")
        strat = a.get('trading_strategy', {})
        if strat.get('type', 'Unknown') != 'Unknown':
            L.append(f"Strategy:   {strat['type']}")
        if strat.get('indicators_used'):
            L.append(f"Indicators: {', '.join(strat['indicators_used'])}")
        if meta.get('copyright', 'Unknown') != 'Unknown':
            L.append(f"Copyright:  {meta['copyright']}")
        L.append('"""')
        L.append('')
        L.append('import numpy as np')
        L.append('import pandas as pd')
        L.append('from datetime import datetime')
        L.append('from typing import Dict, List, Optional')
        L.append('')
        L.append('')
        L.append(f'class {cn}:')
        L.append(f'    """MT4 {hints.get("possible_type", meta["type"])} converted to Python."""')
        L.append('')

        params = a.get('input_parameters', [])
        if params:
            args = ', '.join(
                f"{p['name'].lower()}: {'float' if p['type'] == 'double' else 'int'} = {p['default']}"
                for p in params)
            L.append(f"    def __init__(self, {args}):")
        else:
            L.append("    def __init__(self, period: int = 14, shift: int = 0, deviation: float = 2.0):")

        L.append("        self.data: pd.DataFrame = pd.DataFrame()")
        L.append("        self.indicators: Dict[str, pd.Series] = {}")
        if params:
            for p in params:
                L.append(f"        self.{p['name'].lower()} = {p['name'].lower()}")
        else:
            L.append("        self.period = period")
            L.append("        self.shift = shift")
            L.append("        self.deviation = deviation")
        L.append('')

        L.append("    def initialize(self, data: pd.DataFrame) -> bool:")
        L.append('        """Load OHLCV data and compute indicators."""')
        L.append("        if data.empty:")
        L.append("            return False")
        L.append("        self.data = data.copy()")
        L.append("        self._calculate_indicators()")
        L.append("        return True")
        L.append('')

        L.append("    def _calculate_indicators(self) -> None:")
        L.append('        """Compute technical indicators from OHLCV data."""')
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
            L.append("        # No specific indicators detected - using defaults")
            L.append("        period = getattr(self, 'period', 14)")
            L.append("        self.indicators['sma'] = self.data['close'].rolling(window=period).mean()")
            L.append("        self.indicators['ema'] = self.data['close'].ewm(span=period).mean()")
        L.append('')

        if meta['type'] == 'Expert Advisor':
            L.append("    def on_tick(self, tick_data: Dict) -> Optional[Dict]:")
            L.append('        """Process a new tick and return trading signal."""')
            L.append("        self._calculate_indicators()")
            L.append("        signal = {'action': None, 'price': self.data['close'].iloc[-1]}")
            L.append("        return signal")
        else:
            L.append("    def calculate(self, rates_total: int = 0) -> pd.DataFrame:")
            L.append('        """Calculate indicator values for all bars."""')
            L.append("        self._calculate_indicators()")
            L.append("        result = pd.DataFrame(self.indicators)")
            L.append("        return result")
        L.append('')

        # Risk management section
        rm = a.get('risk_management', {})
        if rm.get('features') or meta['type'] == 'Expert Advisor':
            L.append("    def check_risk(self, price: float, lots: float = 0.1) -> Dict:")
            L.append('        """Evaluate risk parameters for a potential trade."""')
            L.append("        return {")
            L.append("            'allowed': True,")
            L.append("            'lots': lots,")
            L.append("            'stop_loss': price * 0.99,")
            L.append("            'take_profit': price * 1.02,")
            L.append("        }")

        return '\n'.join(L)

    # -- C --------------------------------------------------------------------

    def _c(self, a: Dict) -> str:
        L = []
        meta = a['metadata']
        cn = self._safe_class_name(a, 'ex4_program')
        hints = a.get('filename_hints', {})
        ex4h = a.get('ex4_header', {})
        stats = a.get('statistics', {})

        L.append(f'/* Converted from MT4 {meta["type"]}: {a.get("filename", "unknown")} */')
        L.append(f'/* Type:     {hints.get("possible_type", meta["type"])} */')
        L.append(f'/* Version:  {meta["version"]} */')
        L.append(f'/* Format:   EX4 {ex4h.get("format_version", "Unknown")} */')
        L.append(f'/* Size:     {stats.get("file_size_kb", 0)} KB  Entropy: {stats.get("entropy", 0)} */')
        if meta.get('is_encrypted'):
            L.append('/* Note:     Encrypted EX4 - structure inferred */')
        L.append('')
        L.append('#include <stdio.h>')
        L.append('#include <stdlib.h>')
        L.append('#include <string.h>')
        L.append('#include <math.h>')
        L.append('')

        L.append('/* OHLCV Bar data structure */')
        L.append('typedef struct {')
        L.append('    double open, high, low, close;')
        L.append('    long   volume;')
        L.append('    long   time;')
        L.append('} Bar;')
        L.append('')

        L.append('/* Indicator result structure */')
        L.append('typedef struct {')
        L.append('    double *buffer1;')
        L.append('    double *buffer2;')
        L.append('    int     size;')
        L.append(f'}} {cn}_Result;')
        L.append('')

        L.append('/* Parameters */')
        if a.get('input_parameters'):
            for p in a['input_parameters']:
                ctype = 'double' if p['type'] == 'double' else 'int'
                L.append(f"{ctype} {p['name']} = {p['default']};")
        else:
            L.append('int    inp_period    = 14;')
            L.append('int    inp_shift     = 0;')
            L.append('double inp_deviation = 2.0;')
        L.append('')

        L.append(f'int {cn}_init(void) {{')
        L.append(f'    printf("{cn} initialized\\n");')
        L.append('    return 1;')
        L.append('}')
        L.append('')

        L.append(f'void {cn}_deinit(void) {{')
        L.append(f'    printf("{cn} deinitialized\\n");')
        L.append('}')
        L.append('')

        # Indicator calculation functions
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

        if not a.get('indicators_detected'):
            L.append('double calc_sma(Bar *bars, int n, int period) {')
            L.append('    if (n < period) return 0.0;')
            L.append('    double sum = 0;')
            L.append('    for (int i = n - period; i < n; i++) sum += bars[i].close;')
            L.append('    return sum / period;')
            L.append('}')
            L.append('')

        L.append(f'int {cn}_calculate(Bar *bars, int rates_total,')
        L.append(f'    int prev_calculated, {cn}_Result *result)')
        L.append('{')
        L.append('    if (rates_total < 1) return 0;')
        L.append('    int limit = rates_total - prev_calculated;')
        L.append('    if (prev_calculated > 0) limit++;')
        L.append('')
        L.append('    for (int i = rates_total - limit; i < rates_total; i++) {')
        for ind in a.get('indicators_detected', []):
            n = ind['name']
            if n == 'iMA':
                L.append('        result->buffer1[i] = calc_ma(bars, i + 1, 14);')
            elif n == 'iRSI':
                L.append('        result->buffer1[i] = calc_rsi(bars, i + 1, 14);')
        if not a.get('indicators_detected'):
            L.append('        result->buffer1[i] = calc_sma(bars, i + 1, inp_period);')
        L.append('    }')
        L.append('    return rates_total;')
        L.append('}')
        return '\n'.join(L)

    # -- R --------------------------------------------------------------------

    def _r(self, a: Dict) -> str:
        L = []
        meta = a['metadata']
        cn = self._safe_class_name(a, 'trading_strategy')
        hints = a.get('filename_hints', {})
        ex4h = a.get('ex4_header', {})
        stats = a.get('statistics', {})

        L.append(f'# Converted from MT4 {meta["type"]}: {a.get("filename", "unknown")}')
        L.append(f'# Type:     {hints.get("possible_type", meta["type"])}')
        L.append(f'# Version:  {meta["version"]}')
        L.append(f'# Format:   EX4 {ex4h.get("format_version", "Unknown")}')
        L.append(f'# Size:     {stats.get("file_size_kb", 0)} KB')
        if meta.get('is_encrypted'):
            L.append('# Note:     Encrypted EX4 - structure inferred')
        L.append('')
        L.append('library(quantmod)')
        L.append('library(TTR)')
        L.append('library(xts)')
        L.append('')

        L.append(f'{cn} <- function(data, period = 14, shift = 0, deviation = 2.0) {{')
        for p in a.get('input_parameters', []):
            L.append(f"    {p['name']} <- {p['default']}")
        L.append('')
        L.append('    # Validate input data')
        L.append('    if (is.null(data) || nrow(data) < period) {')
        L.append('        stop("Insufficient data for calculation")')
        L.append('    }')
        L.append('')
        L.append('    indicators <- list()')
        L.append('')

        has_indicators = False
        for ind in a.get('indicators_detected', []):
            has_indicators = True
            n = ind['name']
            if n == 'iMA':
                L.append('    # Moving Average')
                L.append('    indicators$sma <- SMA(Cl(data), n = period)')
                L.append('    indicators$ema <- EMA(Cl(data), n = period)')
            elif n == 'iRSI':
                L.append('    # Relative Strength Index')
                L.append('    indicators$rsi <- RSI(Cl(data), n = period)')
            elif n == 'iMACD':
                L.append('    # MACD')
                L.append('    indicators$macd <- MACD(Cl(data), nFast = 12, nSlow = 26, nSig = 9)')
            elif n == 'iBands':
                L.append('    # Bollinger Bands')
                L.append('    indicators$bbands <- BBands(HLC(data), n = 20)')
            elif n == 'iATR':
                L.append('    # Average True Range')
                L.append('    indicators$atr <- ATR(HLC(data), n = period)')

        if not has_indicators:
            L.append('    # Default indicators (no specific indicators detected)')
            L.append('    indicators$sma <- SMA(Cl(data), n = period)')
            L.append('    indicators$ema <- EMA(Cl(data), n = period)')
            L.append('    indicators$rsi <- RSI(Cl(data), n = period)')
        L.append('')

        L.append('    # Combine results')
        L.append('    result <- list(')
        L.append('        indicators = indicators,')
        L.append(f'        name = "{cn}",')
        L.append(f'        type = "{hints.get("possible_type", meta["type"])}",')
        L.append('        period = period')
        L.append('    )')
        L.append('')
        L.append('    return(result)')
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

        L.append('=' * W)
        L.append('EX4 FILE ANALYSIS REPORT'.center(W))
        L.append('=' * W)
        L.append('')
        L.append('FILE INFORMATION')
        L.append('-' * W)
        L.append(f"  Filename:      {a.get('filename', 'N/A')}")
        L.append(f"  Type:          {meta['type']}")
        L.append(f"  Version:       {meta['version']}")
        if meta.get('creation_date', 'Unknown') != 'Unknown':
            L.append(f"  Created:       {meta['creation_date']}")
        if meta.get('copyright', 'Unknown') != 'Unknown':
            L.append(f"  Copyright:     {meta['copyright']}")
        if meta.get('author', 'Unknown') != 'Unknown':
            L.append(f"  Author:        {meta['author']}")
        L.append(f"  Size:          {stats.get('file_size_kb', 0)} KB")
        L.append(f"  Entropy:       {stats.get('entropy', 0)}")
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

# Color palette
BG_PRIMARY = "#FAF3E1"        # Light cream - main background
BG_SECONDARY = "#F5E7C6"      # Warm beige - cards/surfaces/sidebar
ACCENT = "#FA8112"             # Orange - accent/buttons
ACCENT_HOVER = "#E0720F"       # Darker orange for hover
TEXT_PRIMARY = "#222222"        # Dark text
TEXT_SECONDARY = "#555555"      # Medium gray text
CODE_BG = "#2B2B2B"            # Dark code background
CODE_FG = "#E0E0E0"            # Light code text
SUCCESS = "#2ed573"
WARNING = "#FA8112"


class SidebarButton(ctk.CTkButton):
    """Custom sidebar navigation button."""

    def __init__(self, master, text, icon="", command=None, **kw):
        super().__init__(
            master, text=f"  {icon}  {text}", command=command,
            fg_color="transparent", text_color=TEXT_SECONDARY,
            hover_color=ACCENT, anchor="w",
            font=ctk.CTkFont(size=14), height=44, corner_radius=8, **kw)


class EX4StudioApp(ctk.CTk):
    """Main application window."""

    WIDTH = 1360
    HEIGHT = 820

    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

        self.title("EX4 Studio")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.minsize(1024, 680)

        self.engine = EX4AnalysisEngine()
        self.codegen = CodeGenerator()
        self.current_analysis: Optional[Dict] = None
        self.current_code: Optional[str] = None
        self.raw_data: Optional[bytes] = None

        self._build_ui()

    # -- UI construction ------------------------------------------------------

    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self._build_sidebar()

        # Main content area
        self.main_frame = ctk.CTkFrame(self, fg_color=BG_PRIMARY, corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        # Header
        self._build_header()

        # Content notebook area
        self.content = ctk.CTkFrame(self.main_frame, fg_color=BG_PRIMARY)
        self.content.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 8))
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        # Tab view
        self.tabview = ctk.CTkTabview(
            self.content, fg_color=BG_SECONDARY,
            segmented_button_fg_color=BG_SECONDARY,
            segmented_button_selected_color=ACCENT,
            segmented_button_unselected_color=BG_SECONDARY,
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
        sidebar = ctk.CTkFrame(self, width=220, fg_color=BG_SECONDARY,
                               corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        # Logo area
        logo_frame = ctk.CTkFrame(sidebar, fg_color="transparent", height=80)
        logo_frame.pack(fill="x", padx=12, pady=(20, 8))
        logo_frame.pack_propagate(False)

        ctk.CTkLabel(logo_frame, text="EX4 Studio",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=ACCENT).pack(pady=(8, 0))
        ctk.CTkLabel(logo_frame, text="Binary Analyzer",
                     font=ctk.CTkFont(size=11),
                     text_color=TEXT_SECONDARY).pack()

        ctk.CTkFrame(sidebar, height=1, fg_color=ACCENT).pack(
            fill="x", padx=16, pady=12)

        # Navigation buttons
        SidebarButton(sidebar, "Open File", icon="\U0001F4C2",
                      command=self.open_file).pack(fill="x", padx=12, pady=2)
        SidebarButton(sidebar, "Analyze", icon="\U0001F50D",
                      command=self._run_analysis).pack(fill="x", padx=12, pady=2)

        ctk.CTkFrame(sidebar, height=1, fg_color=ACCENT).pack(
            fill="x", padx=16, pady=12)

        # Language selector
        ctk.CTkLabel(sidebar, text="Target Language",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=TEXT_SECONDARY).pack(padx=16, anchor="w")
        self.lang_var = ctk.StringVar(value="MQL4")
        self.lang_menu = ctk.CTkOptionMenu(
            sidebar, values=["MQL4", "MQL5", "Python", "C", "R", "Text"],
            variable=self.lang_var, command=self._on_language_change,
            fg_color=BG_PRIMARY, button_color=ACCENT,
            button_hover_color=ACCENT_HOVER, width=180)
        self.lang_menu.pack(padx=16, pady=(4, 12))

        ctk.CTkFrame(sidebar, height=1, fg_color=ACCENT).pack(
            fill="x", padx=16, pady=4)

        # Export buttons
        SidebarButton(sidebar, "Export Code", icon="\U0001F4BE",
                      command=self._export_code).pack(fill="x", padx=12, pady=2)
        SidebarButton(sidebar, "Export JSON", icon="\U0001F4CB",
                      command=self._export_json).pack(fill="x", padx=12, pady=2)

        # Spacer
        ctk.CTkFrame(sidebar, fg_color="transparent").pack(fill="both",
                                                           expand=True)

        # Version
        ctk.CTkLabel(sidebar, text="v2.0.0",
                     font=ctk.CTkFont(size=10),
                     text_color=TEXT_SECONDARY).pack(pady=8)

    def _build_header(self):
        header = ctk.CTkFrame(self.main_frame, fg_color=BG_SECONDARY,
                              height=64, corner_radius=0)
        header.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header.grid_propagate(False)
        header.grid_columnconfigure(1, weight=1)

        self.file_label = ctk.CTkLabel(
            header, text="No file loaded",
            font=ctk.CTkFont(size=14), text_color=TEXT_PRIMARY)
        self.file_label.grid(row=0, column=0, padx=20, pady=16, sticky="w")

        self.info_label = ctk.CTkLabel(
            header, text="",
            font=ctk.CTkFont(size=12), text_color=TEXT_SECONDARY)
        self.info_label.grid(row=0, column=1, padx=20, pady=16, sticky="e")

    def _build_overview_tab(self):
        tab = self.tabview.tab("Overview")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        self.overview_text = ctk.CTkTextbox(
            tab, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=CODE_BG, text_color=CODE_FG, corner_radius=8,
            wrap="word")
        self.overview_text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

    def _build_code_tab(self):
        tab = self.tabview.tab("Generated Code")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        self.code_text = ctk.CTkTextbox(
            tab, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=CODE_BG, text_color=CODE_FG, corner_radius=8,
            wrap="none")
        self.code_text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

    def _build_disasm_tab(self):
        tab = self.tabview.tab("Disassembly")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        self.disasm_text = ctk.CTkTextbox(
            tab, font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=CODE_BG, text_color="#7ee787", corner_radius=8,
            wrap="none")
        self.disasm_text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

    def _build_strings_tab(self):
        tab = self.tabview.tab("Strings")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        self.strings_text = ctk.CTkTextbox(
            tab, font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=CODE_BG, text_color="#ffa657", corner_radius=8,
            wrap="word")
        self.strings_text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

    def _build_hex_tab(self):
        tab = self.tabview.tab("Hex View")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        self.hex_text = ctk.CTkTextbox(
            tab, font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=CODE_BG, text_color="#d2a8ff", corner_radius=8,
            wrap="none")
        self.hex_text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

    def _build_log_tab(self):
        tab = self.tabview.tab("Log")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        self.log_text = ctk.CTkTextbox(
            tab, font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=CODE_BG, text_color="#8b949e", corner_radius=8,
            wrap="word")
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
        bar = ctk.CTkFrame(self.main_frame, height=32, fg_color=BG_SECONDARY,
                           corner_radius=0)
        bar.grid(row=2, column=0, sticky="ew")
        bar.grid_propagate(False)
        self.status_label = ctk.CTkLabel(
            bar, text="Ready", font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY)
        self.status_label.pack(side="left", padx=16)

    # -- Welcome screen -------------------------------------------------------

    def _show_welcome(self):
        welcome = (
            "╔══════════════════════════════════════════════════════════════╗\n"
            "║                  EX4 STUDIO  v2.0                          ║\n"
            "╠══════════════════════════════════════════════════════════════╣\n"
            "║                                                            ║\n"
            "║  Features:                                                 ║\n"
            "║  • EX4 header parsing (v400 & v500+ formats)               ║\n"
            "║  • Binary pattern recognition (60+ patterns)               ║\n"
            "║  • x86 disassembly via Capstone engine                     ║\n"
            "║  • PE header analysis                                      ║\n"
            "║  • ASCII + UTF-16LE string extraction                      ║\n"
            "║  • Trading strategy & indicator detection                  ║\n"
            "║  • Risk management analysis                                ║\n"
            "║  • Multi-language code generation:                         ║\n"
            "║      MQL4 · MQL5 · Python · C · R · Text                  ║\n"
            "║  • Hex viewer for binary inspection                        ║\n"
            "║  • JSON export for further processing                      ║\n"
            "║                                                            ║\n"
            "║  Click 'Open File' in the sidebar to begin.                ║\n"
            "╚══════════════════════════════════════════════════════════════╝\n"
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
                text=f"\U0001F4C4  {os.path.basename(path)}",
                text_color=TEXT_PRIMARY)
            size_kb = round(len(self.raw_data) / 1024, 1)
            self.info_label.configure(text=f"{size_kb} KB")
            self._filepath = path
            self._set_status(f"Loaded {os.path.basename(path)} – click Analyze")
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
        ex4h = a.get('ex4_header', {})
        hints = a.get('filename_hints', {})

        lines = []
        lines.append(f"{'═' * 60}")
        lines.append(f"  FILE: {a.get('filename', 'N/A')}")
        lines.append(f"{'═' * 60}")
        lines.append("")

        lines.append("  EX4 FORMAT")
        lines.append(f"  ├─ Format:       {ex4h.get('format_version', 'Unknown')}")
        lines.append(f"  ├─ Encrypted:    {'Yes' if ex4h.get('is_encrypted') else 'No'}")
        if ex4h.get('build_number'):
            lines.append(f"  ├─ Build:        {ex4h['build_number']}")
        if ex4h.get('header_hash'):
            lines.append(f"  └─ Hash:         {ex4h['header_hash']}")
        else:
            if ex4h.get('header_size'):
                lines.append(f"  └─ Header Size:  {ex4h['header_size']}")
        lines.append("")

        lines.append("  FILE INFO")
        lines.append(f"  ├─ Type:         {meta['type']}")
        if hints.get('possible_type') and hints['possible_type'] != meta['type']:
            lines.append(f"  ├─ Hint:         {hints['possible_type']} (from filename)")
        lines.append(f"  ├─ Version:      {meta['version']}")
        lines.append(f"  ├─ Size:         {stats.get('file_size_kb', 0)} KB")
        lines.append(f"  ├─ Entropy:      {stats.get('entropy', 0)}")
        if meta.get('copyright', 'Unknown') != 'Unknown':
            lines.append(f"  ├─ Copyright:    {meta['copyright']}")
        if meta.get('author', 'Unknown') != 'Unknown':
            lines.append(f"  ├─ Author:       {meta['author']}")
        if meta.get('link', 'Unknown') != 'Unknown':
            lines.append(f"  └─ Link:         {meta['link']}")
        lines.append("")

        lines.append("  BYTE ANALYSIS")
        lines.append(f"  ├─ Printable:    {stats.get('printable_pct', 0)}%")
        lines.append(f"  ├─ High bytes:   {stats.get('high_byte_pct', 0)}%")
        lines.append(f"  └─ Null bytes:   {stats.get('null_byte_pct', 0)}%")
        lines.append("")

        if pe.get('valid_pe'):
            lines.append("  PE HEADER")
            lines.append(f"  ├─ Machine:      {pe.get('machine', 'N/A')}")
            if pe.get('timestamp'):
                lines.append(f"  ├─ Compiled:     {pe['timestamp']}")
            if pe.get('num_sections'):
                lines.append(f"  └─ Sections:     {pe['num_sections']}")
            lines.append("")

        if strat.get('type', 'Unknown') != 'Unknown':
            lines.append(f"  STRATEGY: {strat['type']}")
            if strat.get('indicators_used'):
                lines.append(f"  ├─ Indicators:   {', '.join(strat['indicators_used'])}")
            if strat.get('timeframes'):
                lines.append(f"  ├─ Timeframes:   {', '.join(strat['timeframes'])}")
            if strat.get('entry_patterns'):
                lines.append(f"  ├─ Entry:        {', '.join(strat['entry_patterns'])}")
            if strat.get('exit_patterns'):
                lines.append(f"  └─ Exit:         {', '.join(strat['exit_patterns'])}")
            lines.append("")

        if risk.get('features'):
            lines.append("  RISK MANAGEMENT")
            for i, f in enumerate(risk['features']):
                prefix = "  └─" if i == len(risk['features']) - 1 else "  ├─"
                lines.append(f"{prefix} {f}")
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

        lines.append("  ANALYSIS RESULTS")
        all_str_count = a.get('all_strings_count', stats.get('total_strings', 0))
        quality_count = len(a.get('strings', []))
        lines.append(f"  ├─ Patterns:     {len(a.get('patterns', []))}")
        lines.append(f"  ├─ Strings:      {all_str_count} extracted, {quality_count} quality")
        lines.append(f"  ├─ Handlers:     {len(handlers)}")
        lines.append(f"  ├─ Indicators:   {len(inds)}")
        lines.append(f"  └─ Trading fns:  {len(tfuncs)}")
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
        if dis.get('error'):
            self.disasm_text.insert("end", f"[!] {dis['error']}\n\n")

        funcs = dis.get('functions', [])
        if funcs:
            for fn in funcs:
                self.disasm_text.insert(
                    "end",
                    f"\n{'─' * 50}\n"
                    f"Function @ {fn['start']} – {fn['end']}  "
                    f"({fn['size']} bytes)\n"
                    f"{'─' * 50}\n")
                for ins in fn['instructions']:
                    self.disasm_text.insert("end", f"  {ins}\n")
        else:
            ex4h = a.get('ex4_header', {})
            stats = a.get('statistics', {})
            lines = []
            lines.append("╔══════════════════════════════════════════════════╗")
            lines.append("║           BINARY STRUCTURE ANALYSIS              ║")
            lines.append("╚══════════════════════════════════════════════════╝")
            lines.append("")

            if ex4h.get('is_encrypted'):
                lines.append("[i] File uses encrypted EX4 format (v500+)")
                lines.append("    Standard x86 disassembly is not applicable.")
                lines.append("    The bytecode is protected with MT4's encryption.")
                lines.append("")

            lines.append("EX4 HEADER ANALYSIS")
            lines.append("─" * 50)
            lines.append(f"  Magic Bytes:     {ex4h.get('format_version', 'N/A')}")
            if ex4h.get('build_number'):
                lines.append(f"  MT4 Build:       {ex4h['build_number']}")
            if ex4h.get('header_hash'):
                lines.append(f"  Header Hash:     {ex4h['header_hash']}")
            if ex4h.get('program_type_flags'):
                lines.append(f"  Type Flags:      0x{ex4h['program_type_flags']:08x}")
            lines.append("")

            lines.append("BYTE FREQUENCY ANALYSIS")
            lines.append("─" * 50)
            entropy = stats.get('entropy', 0)
            lines.append(f"  File Entropy:    {entropy} bits/byte")
            if entropy > 7.5:
                lines.append("  Assessment:      High entropy - encrypted/compressed data")
            elif entropy > 6.0:
                lines.append("  Assessment:      Moderate entropy - mixed code/data")
            else:
                lines.append("  Assessment:      Low entropy - mostly code/text")
            lines.append(f"  Printable:       {stats.get('printable_pct', 0)}%")
            lines.append(f"  High bytes:      {stats.get('high_byte_pct', 0)}%")
            lines.append(f"  Null bytes:      {stats.get('null_byte_pct', 0)}%")
            lines.append("")

            lines.append("FILE STRUCTURE")
            lines.append("─" * 50)
            lines.append(f"  Total Size:      {stats.get('file_size_bytes', 0)} bytes")
            lines.append(f"  MZ Header:       {'Present' if stats.get('has_mz_header') else 'Not present'}")
            lines.append(f"  EX4 Header:      {'Present' if stats.get('has_ex4_header') else 'Not present'}")

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
            ex4h = a.get('ex4_header', {})
            lines = []
            if ex4h.get('is_encrypted'):
                lines.append("╔══════════════════════════════════════════════╗")
                lines.append("║     ENCRYPTED EX4 - LIMITED STRING DATA      ║")
                lines.append("╚══════════════════════════════════════════════╝")
                lines.append("")
                lines.append("This file uses MT4's protected EX4 format.")
                lines.append("String data is encrypted and cannot be fully extracted.")
                lines.append("")

            all_strings = a.get('strings', [])
            if all_strings:
                lines.append(f"EXTRACTED STRINGS ({len(all_strings)} found)")
                lines.append("─" * 40)
                for s in all_strings[:200]:
                    lines.append(f"  {s}")
            else:
                lines.append("No meaningful strings could be extracted.")

            self.strings_text.insert("end", "\n".join(lines))

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
