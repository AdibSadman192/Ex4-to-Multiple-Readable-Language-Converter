#!/usr/bin/env python3
"""
EX4 Converter Studio
A comprehensive GUI application for decompiling MetaTrader 4 EX4 binary files
into multiple readable programming languages.

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

        strings = self._extract_strings(data)
        categories = self._categorize_strings(strings)

        result = {
            'filepath': filepath,
            'filename': os.path.basename(filepath),
            'metadata': self._extract_metadata(data),
            'pe_info': self._parse_pe_header(data),
            'patterns': self._find_patterns(data),
            'strings': strings,
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
        }
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
            'format': 'Unknown', 'build': 'Unknown',
        }

        # Detect EX4 format
        if data[:4] == b'EX4\x00':
            meta['format'] = 'EX4 Legacy (Build <600)'
            meta['type'] = 'Indicator'
            # Copyright at offset 0x0C, 64 bytes ASCII
            copyright_raw = data[12:76]
            copyright_str = copyright_raw.split(b'\x00')[0].decode('latin-1', errors='ignore').strip()
            if copyright_str:
                meta['copyright'] = copyright_str
        elif data[:2] == b'EX' and len(data) > 0x2B0:
            fmt_byte = data[2]
            sub_byte = data[3]  # format sub-version
            meta['format'] = f'EX4 Build 600+ (0x{fmt_byte:02x}.{sub_byte:02x})'
            # Build number at offset 0x06
            build = struct.unpack('<H', data[6:8])[0]
            meta['build'] = str(build)
            # Type from byte at 0x40: 0x07 = Indicator, 0x66 = Expert Advisor
            type_byte = data[0x40] if len(data) > 0x40 else 0
            if type_byte == 0x07 or (type_byte & 0x07) == 0x07:
                meta['type'] = 'Indicator'
            elif type_byte == 0x66 or (type_byte & 0x0F) == 0x06:
                meta['type'] = 'Expert Advisor'
            else:
                meta['type'] = 'Indicator'
            # Copyright from UTF-16LE at offset 0xA8 (256 bytes)
            try:
                copyright_raw = data[0xA8:0x1A8]
                copyright_str = copyright_raw.decode('utf-16-le', errors='ignore').split('\x00')[0].strip()
                if copyright_str and len(copyright_str) >= 3:
                    meta['copyright'] = copyright_str
            except Exception:
                pass
            # Link from UTF-16LE at offset 0x1A8 (256 bytes)
            try:
                link_raw = data[0x1A8:0x2A8]
                link_str = link_raw.decode('utf-16-le', errors='ignore').split('\x00')[0].strip()
                if link_str and len(link_str) >= 3:
                    meta['link'] = link_str
            except Exception:
                pass
            # Version from UTF-16LE at offset 0x2A8
            try:
                ver_raw = data[0x2A8:0x2C8]
                ver_str = ver_raw.decode('utf-16-le', errors='ignore').split('\x00')[0].strip()
                if ver_str and len(ver_str) >= 1:
                    meta['version'] = ver_str
            except Exception:
                pass

        # Fallback: try to detect type from raw bytes if still unknown
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

        # Fallback version from raw bytes
        if meta['version'] == 'Unknown':
            for pat in [
                rb'version[\s=:]+([\d]+\.[\d]+(?:\.[\d]+)?)',
                rb'v[\s]*([\d]+\.[\d]+(?:\.[\d]+)?)',
            ]:
                m = re.search(pat, data, re.IGNORECASE)
                if m:
                    meta['version'] = m.group(1).decode('ascii', errors='ignore')
                    break

        # Fallback copyright/author/link from raw bytes
        if meta['copyright'] == 'Unknown':
            for field, regex in [
                ('copyright', rb'copyright[\s]*[:(\s]*([^\x00]{3,50})'),
                ('description', rb'description[\s]*[:(\s]*([^\x00]{3,100})'),
                ('author', rb'author[\s]*[:(\s]*([^\x00]{3,50})'),
            ]:
                m = re.search(regex, data, re.IGNORECASE)
                if m:
                    meta[field] = m.group(1).decode('ascii', errors='ignore').strip()

        if meta['link'] == 'Unknown':
            m = re.search(rb'(https?://[^\x00\s]{3,100})', data)
            if m:
                meta['link'] = m.group(1).decode('ascii', errors='ignore').strip()

        # Extract author from copyright if present
        if meta['author'] == 'Unknown' and meta['copyright'] != 'Unknown':
            cr = meta['copyright']
            m = re.search(r'(?:copyright|©|\(c\))\s*(?:\d{4}[,\s]*)?\s*(.*)', cr, re.IGNORECASE)
            if m:
                author = m.group(1).strip().rstrip('.')
                if author:
                    meta['author'] = author

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
        return {
            'file_size_bytes': len(data),
            'file_size_kb': round(len(data) / 1024, 2),
            'total_strings': len(strings),
            'unique_strings': len(set(strings)),
            'has_mz_header': data[:2] == b'MZ',
            'entropy': round(entropy, 4),
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
        L += self._header_box(f"Decompiled MQL4 – {meta['type']}")
        L.append(f"// Version:   {meta['version']}")
        if meta.get('creation_date', 'Unknown') != 'Unknown':
            L.append(f"// Created:   {meta['creation_date']}")
        if meta.get('copyright', 'Unknown') != 'Unknown':
            L.append(f"// Copyright: {meta['copyright']}")
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
        L += self._header_box(f"Decompiled MQL5 – {meta['type']}")
        L.append(f"// Version: {meta['version']}")
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

        L.append('"""')
        L.append(f"Converted from MT4 {meta['type']}")
        L.append(f"Version: {meta['version']}")
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
        L.append(f'/* Converted from MT4 {meta["type"]} */')
        L.append(f'/* Version: {meta["version"]} */')
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
        L.append(f'# Converted from MT4 {meta["type"]}')
        L.append(f'# Version: {meta["version"]}')
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

        L.append('=' * W)
        L.append('EX4 FILE ANALYSIS REPORT'.center(W))
        L.append('=' * W)
        L.append('')
        L.append('FILE INFORMATION')
        L.append('-' * W)
        L.append(f"  Filename:      {a.get('filename', 'N/A')}")
        L.append(f"  Type:          {meta['type']}")
        L.append(f"  Version:       {meta['version']}")
        if meta.get('format', 'Unknown') != 'Unknown':
            L.append(f"  Format:        {meta['format']}")
        if meta.get('build', 'Unknown') != 'Unknown':
            L.append(f"  Build:         {meta['build']}")
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
# Color palette: #FAF3E1, #F5E7C6, #FA8112, #222222
DARK_BG = "#222222"
DARK_SURFACE = "#2a2a2a"
DARK_CARD = "#333333"
ACCENT = "#FA8112"
ACCENT_HOVER = "#fb9a3e"
TEXT_PRIMARY = "#FAF3E1"
TEXT_SECONDARY = "#F5E7C6"
SUCCESS = "#2ed573"
WARNING = "#ffa502"
CODE_BG = "#1a1a1a"
CODE_FG = "#FAF3E1"
SIDEBAR_BG = "#1a1a1a"
SIDEBAR_ACTIVE = "#333333"


class SidebarButton(ctk.CTkButton):
    """Custom sidebar navigation button."""

    def __init__(self, master, text, icon="", command=None, **kw):
        super().__init__(
            master, text=f"  {icon}  {text}", command=command,
            fg_color="transparent", text_color=TEXT_SECONDARY,
            hover_color=SIDEBAR_ACTIVE, anchor="w",
            font=ctk.CTkFont(size=14), height=44, corner_radius=8, **kw)


class EX4StudioApp(ctk.CTk):
    """Main application window."""

    WIDTH = 1360
    HEIGHT = 820

    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("EX4 Converter Studio")
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
        self.main_frame = ctk.CTkFrame(self, fg_color=DARK_BG, corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        # Header
        self._build_header()

        # Content notebook area
        self.content = ctk.CTkFrame(self.main_frame, fg_color=DARK_BG)
        self.content.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 8))
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        # Tab view
        self.tabview = ctk.CTkTabview(
            self.content, fg_color=DARK_SURFACE,
            segmented_button_fg_color=DARK_CARD,
            segmented_button_selected_color=ACCENT,
            segmented_button_unselected_color=DARK_CARD,
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
        sidebar = ctk.CTkFrame(self, width=220, fg_color=SIDEBAR_BG,
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
        ctk.CTkLabel(logo_frame, text="File Converter",
                     font=ctk.CTkFont(size=11),
                     text_color=TEXT_SECONDARY).pack()

        ctk.CTkFrame(sidebar, height=1, fg_color=DARK_CARD).pack(
            fill="x", padx=16, pady=12)

        # Navigation buttons
        SidebarButton(sidebar, "Open File", icon="\U0001F4C2",
                      command=self.open_file).pack(fill="x", padx=12, pady=2)
        SidebarButton(sidebar, "Analyze", icon="\U0001F50D",
                      command=self._run_analysis).pack(fill="x", padx=12, pady=2)

        ctk.CTkFrame(sidebar, height=1, fg_color=DARK_CARD).pack(
            fill="x", padx=16, pady=12)

        # Language selector
        ctk.CTkLabel(sidebar, text="Target Language",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=TEXT_SECONDARY).pack(padx=16, anchor="w")
        self.lang_var = ctk.StringVar(value="MQL4")
        self.lang_menu = ctk.CTkOptionMenu(
            sidebar, values=["MQL4", "MQL5", "Python", "C", "R", "Text"],
            variable=self.lang_var, command=self._on_language_change,
            fg_color=DARK_CARD, button_color=ACCENT,
            button_hover_color=ACCENT_HOVER, width=180)
        self.lang_menu.pack(padx=16, pady=(4, 12))

        ctk.CTkFrame(sidebar, height=1, fg_color=DARK_CARD).pack(
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
        header = ctk.CTkFrame(self.main_frame, fg_color=DARK_SURFACE,
                              height=64, corner_radius=0)
        header.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header.grid_propagate(False)
        header.grid_columnconfigure(1, weight=1)

        self.file_label = ctk.CTkLabel(
            header, text="No file loaded",
            font=ctk.CTkFont(size=14), text_color=TEXT_SECONDARY)
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
        bar = ctk.CTkFrame(self.main_frame, height=32, fg_color=DARK_CARD,
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
            "║              EX4 CONVERTER STUDIO  v2.0                    ║\n"
            "╠══════════════════════════════════════════════════════════════╣\n"
            "║                                                            ║\n"
            "║  Features:                                                 ║\n"
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

        lines = []
        lines.append(f"{'═' * 60}")
        lines.append(f"  FILE: {a.get('filename', 'N/A')}")
        lines.append(f"{'═' * 60}")
        lines.append("")
        lines.append(f"  Type:         {meta['type']}")
        if meta.get('format', 'Unknown') != 'Unknown':
            lines.append(f"  Format:       {meta['format']}")
        if meta.get('build', 'Unknown') != 'Unknown':
            lines.append(f"  Build:        {meta['build']}")
        lines.append(f"  Version:      {meta['version']}")
        lines.append(f"  Size:         {stats.get('file_size_kb', 0)} KB")
        lines.append(f"  Entropy:      {stats.get('entropy', 0)}")
        if meta.get('copyright', 'Unknown') != 'Unknown':
            lines.append(f"  Copyright:    {meta['copyright']}")
        if meta.get('author', 'Unknown') != 'Unknown':
            lines.append(f"  Author:       {meta['author']}")
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
        if dis.get('error'):
            self.disasm_text.insert("end", f"[!] {dis['error']}\n")
            return
        funcs = dis.get('functions', [])
        if not funcs:
            self.disasm_text.insert("end", "[i] No function prologues detected\n")
            self.disasm_text.insert("end", "\n  This is common for EX4 files compiled with Build 600+\n")
            self.disasm_text.insert("end", "  which use encrypted/obfuscated bytecode.\n\n")
            # Show raw hex bytes around potential code regions
            if self.raw_data:
                self.disasm_text.insert("end", "  Raw binary sections (first 512 bytes after header):\n")
                self.disasm_text.insert("end", "  " + "─" * 48 + "\n")
                # Skip past EX4 header (~0x300 bytes) to code region
                start_offset = 0x300 if len(self.raw_data) > 0x300 else 0
                end_offset = min(start_offset + 512, len(self.raw_data))
                for offset in range(start_offset, end_offset, 16):
                    chunk = self.raw_data[offset:offset + 16]
                    hex_part = ' '.join(f'{b:02x}' for b in chunk)
                    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                    self.disasm_text.insert("end", f"  {offset:08x}  {hex_part:<48s}  |{ascii_part}|\n")
            return
        for fn in funcs:
            self.disasm_text.insert(
                "end",
                f"\n{'─' * 50}\n"
                f"Function @ {fn['start']} – {fn['end']}  "
                f"({fn['size']} bytes)\n"
                f"{'─' * 50}\n")
            for ins in fn['instructions']:
                self.disasm_text.insert("end", f"  {ins}\n")

    def _populate_strings(self, a: Dict):
        self.strings_text.delete("0.0", "end")
        cats = a.get('string_categories', {})
        for cat_name, items in cats.items():
            if items:
                self.strings_text.insert(
                    "end", f"\n{'─' * 40}\n  {cat_name.upper()} "
                           f"({len(items)})\n{'─' * 40}\n")
                for s in items:
                    self.strings_text.insert("end", f"  {s}\n")

        # If no categorized strings shown, show all raw strings
        all_strings = a.get('strings', [])
        if not any(items for items in cats.values()):
            if all_strings:
                self.strings_text.insert("end", f"\n{'─' * 40}\n  ALL STRINGS ({len(all_strings)})\n{'─' * 40}\n")
                for s in all_strings[:200]:
                    self.strings_text.insert("end", f"  {s}\n")
            else:
                self.strings_text.insert("end", "  No readable strings found in this file.\n")

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
