#!/usr/bin/env python3
"""EX4 REA Engine - Reverse Engineering Assistant.

Advanced analysis layer that adds REA-grade capabilities to the EX4
decompiler: PE section/import/resource parsing, MQL4 VM bytecode
disassembly, control-flow graphs, call graphs, data-flow analysis,
string deobfuscation, API resolution, and function-boundary detection.
"""
import os
import re
import struct
import math
import logging
import binascii
import hashlib
import hmac
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional, Set

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

logger = logging.getLogger("EX4REA")
logger.setLevel(logging.DEBUG)


# ---------------------------------------------------------------------------
# MQL4 API function database (base + expanded patterns)
# ---------------------------------------------------------------------------

MT4_FUNCTIONS = {
    # Trading
    1: "OrderSend", 2: "OrderClose", 3: "OrderModify", 4: "OrderDelete",
    5: "OrderCloseBy", 6: "OrdersTotal", 7: "OrderSelect", 8: "OrderTicket",
    9: "OrderSymbol", 10: "OrderType", 11: "OrderLots", 12: "OrderOpenPrice",
    13: "OrderStopLoss", 14: "OrderTakeProfit", 15: "OrderOpenTime",
    16: "OrderExpiration", 17: "OrderType", 18: "OrderMagicNumber",
    19: "OrderComment", 20: "OrderCommission", 21: "OrderSwap",
    22: "OrderProfit", 23: "OrdersHistoryTotal", 24: "OrderCloseTime",
    # Account info
    100: "AccountInfoInteger", 101: "AccountInfoDouble", 102: "AccountInfoString",
    103: "AccountName", 104: "AccountNumber", 105: "AccountCompany",
    106: "AccountBalance", 107: "AccountEquity", 108: "AccountMargin",
    109: "AccountMarginLevel", 110: "AccountFreeMargin", 111: "AccountLeverage",
    112: "AccountStopoutLevel", 113: "AccountStopoutMode", 114: "AccountCurrency",
    # Market info
    200: "MarketInfo", 201: "SymbolInfoTick", 202: "SymbolInfoDouble",
    203: "SymbolInfoInteger", 204: "SymbolInfoString", 205: "SymbolSelect",
    206: "Symbol", 207: "Digits", 208: "Point", 209: "Ask", 210: "Bid",
    211: "LastError", 212: "RefreshRates", 213: "Rets", 214: "Volume",
    # Indicators
    300: "iMA", 301: "iRSI", 302: "iATR", 303: "iMACD", 304: "iBands",
    305: "iStochastic", 306: "iCCI", 307: "iADX", 308: "iIchimoku",
    309: "iFractals", 310: "iAlligator", 311: "iSAR", 312: "iCustom",
    313: "iBearsPower", 314: "iBullsPower", 315: "iDeMarker", 316: "iForceIndex",
    317: "iMomentum", 318: "iOBV", 319: "iStandardDeviation", 320: "iVolumes",
    321: "iAD", 322: "iWPR", 323: "iBWMFI", 324: "iGator", 325: "iEnvelopes",
    # Chart objects
    400: "ObjectCreate", 401: "ObjectDelete", 402: "ObjectSet", 403: "ObjectGet",
    404: "ObjectsTotal", 405: "ObjectName", 406: "ObjectType", 407: "ObjectMove",
    408: "ObjectSetInteger", 409: "ObjectSetDouble", 410: "ObjectSetString",
    # Time
    500: "TimeCurrent", 501: "TimeLocal", 502: "TimeGMT", 503: "TimeToStruct",
    504: "TimeToString", 505: "StringToTime", 506: "Year", 507: "Month",
    508: "Day", 509: "DayOfWeek", 510: "Hour", 511: "Minute", 512: "Seconds",
    # String functions
    600: "StringFind", 601: "StringGetCharacter", 602: "StringSetCharacter",
    603: "StringLen", 604: "StringToLower", 605: "StringToUpper",
    606: "StringTrimLeft", 607: "StringTrimRight", 608: "StringConcatenate",
    609: "StringCompare", 610: "StringFormat", 611: "CharToStr",
    612: "StrToChar", 613: "StrToDouble", 614: "StrToInteger",
    # Math
    700: "MathAbs", 701: "MathArccos", 702: "MathArcsin", 703: "MathArctan",
    704: "MathCeil", 705: "MathCos", 706: "MathExp", 707: "MathFloor",
    708: "MathLog", 709: "MathMax", 710: "MathMin", 711: "MathMod",
    712: "MathPow", 713: "MathRand", 714: "MathRound", 715: "MathSin",
    716: "MathSqrt", 717: "MathSrand", 718: "MathTan",
    # Array / Series
    800: "ArraySetAsSeries", 801: "ArrayGetAsSeries", 802: "ArrayInitialize",
    803: "ArrayCopy", 804: "ArrayCopyRates", 805: "ArrayCopySeries",
    806: "ArrayDimension", 807: "ArrayRange", 808: "ArrayResize",
    809: "ArraySize", 810: "ArrayFree", 811: "ArraySort", 812: "ArrayMinimum",
    813: "ArrayMaximum", 814: "SeriesInfoInteger", 815: "SeriesInfoDouble",
    816: "CopyOpen", 817: "CopyHigh", 818: "CopyLow", 819: "CopyClose",
    820: "CopyTime", 821: "CopyVolume", 822: "CopyTicks", 823: "CopyTicksRange",
    # Normalize / price
    900: "NormalizeDouble", 901: "PriceClose", 902: "PriceOpen",
    903: "PriceHigh", 904: "PriceLow", 905: "Close", 906: "Open",
    907: "High", 908: "Low", 909: "Time", 910: "Volume", 911: "iHigh",
    912: "iLow", 913: "iClose", 914: "iOpen", 915: "iTime", 916: "iVolume",
    # File / Misc
    1000: "FileOpen", 1001: "FileClose", 1002: "FileReadString",
    1003: "FileReadInteger", 1004: "FileReadDouble", 1005: "FileWriteString",
    1006: "FileWriteInteger", 1007: "FileWriteDouble", 1008: "FileSeek",
    1009: "FileIsEnding", 1010: "FileIsLineEnding", 1011: "FileSize",
    1012: "FileDelete", 1013: "FileMove", 1014: "FileCopy",
    # Alert / Mail / FTP
    1100: "Alert", 1101: "PlaySound", 1102: "SendMail", 1103: "SendFTP",
    1104: "Comment", 1105: "Print", 1106: "PlaySound",
    # Global variables
    1200: "GlobalVariableSet", 1201: "GlobalVariableGet", 1202: "GlobalVariableDel",
    1203: "GlobalVariableSetOnCondition", 1204: "GlobalVariableCheck",
    1205: "GlobalVariableTime", 1206: "GlobalVariablesTotal",
    # Error handling
    1300: "GetLastError", 1301: "IsError",
    # Terminal
    1400: "TerminalInfoInteger", 1401: "TerminalInfoDouble", 1402: "TerminalInfoString",
    # On functions (event handlers)
    1500: "OnInit", 1501: "OnDeinit", 1502: "OnStart", 1503: "OnTick",
    1504: "OnCalculate", 1505: "OnChartEvent", 1506: "OnTester",
    # Constants
    2000: "OP_BUY", 2001: "OP_SELL", 2002: "OP_BUYLIMIT", 2003: "OP_SELLLIMIT",
    2004: "OP_BUYSTOP", 2005: "OP_SELLSTOP",
    2010: "MODE_SMA", 2011: "MODE_EMA", 2012: "MODE_SMMA", 2013: "MODE_LWMA",
    2020: "PRICE_CLOSE", 2021: "PRICE_OPEN", 2022: "PRICE_HIGH", 2023: "PRICE_LOW",
    2024: "PRICE_MEDIAN", 2025: "PRICE_TYPICAL", 2026: "PRICE_WEIGHTED",
    2030: "MODE_MAIN", 2031: "MODE_SIGNAL", 2032: "MODE_UPPER", 2033: "MODE_LOWER",
    2040: "clrRed", 2041: "clrGreen", 2042: "clrBlue",
}

MT4_INDICATORS = {
    "iMA": "Moving Average", "iRSI": "Relative Strength Index",
    "iATR": "Average True Range", "iMACD": "MACD", "iBands": "Bollinger Bands",
    "iStochastic": "Stochastic Oscillator", "iCCI": "Commodity Channel Index",
    "iADX": "Average Directional Index", "iIchimoku": "Ichimoku Kinko Hyo",
    "iFractals": "Fractals", "iAlligator": "Alligator", "iSAR": "Parabolic SAR",
    "iCustom": "Custom Indicator", "iBearsPower": "Bears Power",
    "iBullsPower": "Bulls Power", "iDeMarker": "DeMarker",
    "iForceIndex": "Force Index", "iMomentum": "Momentum",
    "iOBV": "On Balance Volume", "iStandardDeviation": "Standard Deviation",
    "iVolumes": "Volumes", "iAD": "Accumulation/Distribution",
    "iWPR": "Williams' Percent Range", "iBWMFI": "Bill Williams' Market Facilitation Index",
    "iGator": "Gator Oscillator", "iEnvelopes": "Envelopes",
}

MT4_TRADING_CONSTANTS = {
    "OP_BUY": 0, "OP_SELL": 1, "OP_BUYLIMIT": 2, "OP_SELLLIMIT": 3,
    "OP_BUYSTOP": 4, "OP_SELLSTOP": 5,
}

# Known MQL4 strings used to derive XOR keys
KNOWN_MQL4_STRINGS = [
    b"OrderSend", b"OrderClose", b"OrderModify", b"OrderDelete",
    b"iMA", b"iRSI", b"iMACD", b"iBands", b"iStochastic", b"iCCI",
    b"iADX", b"iATR", b"Symbol", b"Period", b"Close", b"Open",
    b"High", b"Low", b"Ask", b"Bid", b"Point", b"Digits",
    b"Alert", b"Print", b"Comment", b"PlaySound",
    b"OnInit", b"OnDeinit", b"OnStart", b"OnTick", b"OnCalculate",
    b"Copyright", b"Link", b"Description", b"Author",
    b"MagicNumber", b"StopLoss", b"TakeProfit", b"LotSize",
    b"Slippage", b"TrailingStop", b"Martingale", b"Grid",
]


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def safe_int(val, default=0):
    try:
        return int(val)
    except Exception:
        return default


def entropy_of(data):
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            ent -= p * math.log2(p)
    return round(ent, 4)


# ---------------------------------------------------------------------------
# PEAnalyzer
# ---------------------------------------------------------------------------

class PEAnalyzer:
    """Parse PE headers: sections, imports, exports, resources, overlay, timestamp."""

    def __init__(self):
        self.sections = []
        self.imports = []
        self.exports = []
        self.resources = []
        self.overlay = b""
        self.timestamp = 0
        self.machine = 0
        self.subsystem = 0
        self.characteristics = 0
        self.entry_point = 0
        self.image_base = 0
        self.size_of_code = 0
        self.size_of_image = 0
        self.valid = False

    def analyze(self, data):
        """Analyze PE structure from raw bytes. Returns dict of findings."""
        try:
            result = {
                "valid": False,
                "machine": 0,
                "subsystem": 0,
                "timestamp": 0,
                "entry_point": 0,
                "image_base": 0,
                "size_of_code": 0,
                "size_of_image": 0,
                "sections": [],
                "imports": [],
                "exports": [],
                "resources": [],
                "overlay_size": 0,
                "entropy": {},
                "confidence": 0.0,
            }
            if len(data) < 64:
                return result
            if data[:2] != b"MZ":
                return result

            pe_offset = safe_int(struct.unpack_from("<I", data, 0x3C)[0])
            if pe_offset + 24 > len(data):
                return result
            if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return result

            self.valid = True
            result["valid"] = True

            # COFF header
            coff = pe_offset + 4
            self.machine = safe_int(struct.unpack_from("<H", data, coff)[0])
            num_sections = safe_int(struct.unpack_from("<H", data, coff + 2)[0])
            self.timestamp = safe_int(struct.unpack_from("<I", data, coff + 8)[0])
            self.characteristics = safe_int(struct.unpack_from("<H", data, coff + 16)[0])

            result["machine"] = self.machine
            result["timestamp"] = self.timestamp
            result["characteristics"] = self.characteristics

            # Optional header
            opt = coff + 20
            magic = safe_int(struct.unpack_from("<H", data, opt)[0])
            is_pe32 = magic == 0x10B
            if not is_pe32 and magic != 0x20B:
                return result

            if is_pe32:
                self.entry_point = safe_int(struct.unpack_from("<I", data, opt + 28)[0])
                self.image_base = safe_int(struct.unpack_from("<I", data, opt + 28 + 4)[0])
                self.size_of_code = safe_int(struct.unpack_from("<I", data, opt + 28 + 8)[0])
                self.size_of_image = safe_int(struct.unpack_from("<I", data, opt + 28 + 16)[0])
                num_rva_sizes = safe_int(struct.unpack_from("<H", data, opt + 92)[0])
                data_dir_off = opt + 96
                subsystem_off = opt + 68
            else:
                self.entry_point = safe_int(struct.unpack_from("<I", data, opt + 28)[0])
                self.image_base = safe_int(struct.unpack_from("<Q", data, opt + 28)[0])
                self.size_of_code = safe_int(struct.unpack_from("<I", data, opt + 28 + 8)[0])
                self.size_of_image = safe_int(struct.unpack_from("<I", data, opt + 28 + 16)[0])
                num_rva_sizes = safe_int(struct.unpack_from("<H", data, opt + 108)[0])
                data_dir_off = opt + 112
                subsystem_off = opt + 68

            self.subsystem = safe_int(struct.unpack_from("<H", data, subsystem_off)[0])
            result["subsystem"] = self.subsystem
            result["entry_point"] = self.entry_point
            result["image_base"] = self.image_base
            result["size_of_code"] = self.size_of_code
            result["size_of_image"] = self.size_of_image

            # Section table
            sec_table_off = opt + (224 if is_pe32 else 240)
            for i in range(num_sections):
                soff = sec_table_off + i * 40
                if soff + 40 > len(data):
                    break
                name = data[soff:soff + 8].rstrip(b"\x00").decode("ascii", errors="ignore")
                vsize = safe_int(struct.unpack_from("<I", data, soff + 8)[0])
                vaddr = safe_int(struct.unpack_from("<I", data, soff + 12)[0])
                psize = safe_int(struct.unpack_from("<I", data, soff + 16)[0])
                poff = safe_int(struct.unpack_from("<I", data, soff + 20)[0])
                chars = safe_int(struct.unpack_from("<I", data, soff + 36)[0])
                sec_data = b""
                if poff and psize and poff + psize <= len(data):
                    sec_data = data[poff:poff + min(psize, len(data) - poff)]
                section = {
                    "name": name,
                    "virtual_address": vaddr,
                    "virtual_size": vsize,
                    "physical_size": psize,
                    "physical_offset": poff,
                    "characteristics": chars,
                    "entropy": round(entropy_of(sec_data), 4),
                }
                self.sections.append(section)
                result["sections"].append(section)
                result["entropy"][name] = section["entropy"]

            # Data directories
            dd_import = None
            dd_export = None
            dd_resource = None
            if num_rva_sizes > 1 and data_dir_off + 16 <= len(data):
                dd_import_off = data_dir_off + 1 * 8
                if dd_import_off + 8 <= len(data):
                    dd_import = struct.unpack_from("<II", data, dd_import_off)
                dd_export_off = data_dir_off + 0 * 8
                if dd_export_off + 8 <= len(data):
                    dd_export = struct.unpack_from("<II", data, dd_export_off)
                dd_resource_off = data_dir_off + 2 * 8
                if dd_resource_off + 8 <= len(data):
                    dd_resource = struct.unpack_from("<II", data, dd_resource_off)

            # Imports
            if dd_import and dd_import[0] and dd_import[1]:
                imp_rva, imp_name_rva = dd_import
                imp_off = self._rva_to_offset(imp_rva)
                name_off = self._rva_to_offset(imp_name_rva)
                dll_name = b""
                if name_off and name_off < len(data):
                    end = data.find(b"\x00", name_off)
                    if end == -1:
                        end = len(data)
                    dll_name = data[name_off:end].decode("ascii", errors="ignore")
                i = 0
                while imp_off and imp_off + 20 <= len(data):
                    entry = struct.unpack_from("<IIIII", data, imp_off)
                    if entry[0] == 0 and entry[1] == 0 and entry[2] == 0 and entry[3] == 0 and entry[4] == 0:
                        break
                    thunk_rva = entry[0]
                    func_off = self._rva_to_offset(thunk_rva)
                    func_name = ""
                    if func_off and func_off + 2 <= len(data):
                        if data[func_off] == 0:
                            func_name = "ordinal_%d" % safe_int(struct.unpack_from("<H", data, func_off + 2)[0])
                        else:
                            end = data.find(b"\x00", func_off + 2)
                            if end == -1:
                                end = len(data)
                            func_name = data[func_off + 2:end].decode("ascii", errors="ignore")
                    self.imports.append({"dll": dll_name, "function": func_name, "hint": entry[1] if len(entry) > 1 else 0})
                    result["imports"].append(self.imports[-1])
                    imp_off += 20
                    i += 1
                    if i > 4096:
                        break

            # Exports
            if dd_export and dd_export[0] and dd_export[1]:
                exp_rva, exp_name_rva = dd_export
                exp_off = self._rva_to_offset(exp_rva)
                if exp_off and exp_off + 40 <= len(data):
                    num_names = safe_int(struct.unpack_from("<I", data, exp_off + 24)[0])
                    addr_of_names_rva = safe_int(struct.unpack_from("<I", data, exp_off + 32)[0])
                    addr_of_names_off = self._rva_to_offset(addr_of_names_rva)
                    for j in range(min(num_names, 1024)):
                        name_rva_off = addr_of_names_off + j * 4
                        if name_rva_off + 4 > len(data):
                            break
                        name_rva = safe_int(struct.unpack_from("<I", data, name_rva_off)[0])
                        name_ptr = self._rva_to_offset(name_rva)
                        if name_ptr and name_ptr < len(data):
                            end = data.find(b"\x00", name_ptr)
                            if end == -1:
                                end = len(data)
                            fname = data[name_ptr:end].decode("ascii", errors="ignore")
                            self.exports.append({"name": fname, "ordinal": j + 1})
                            result["exports"].append(self.exports[-1])

            # Resources
            if dd_resource and dd_resource[0] and dd_resource[1]:
                res_rva = dd_resource[0]
                res_off = self._rva_to_offset(res_rva)
                if res_off and res_off + 16 <= len(data):
                    self._parse_resource_dir(data, res_off, result["resources"])

            # Overlay
            last_raw_end = 0
            for sec in self.sections:
                end = sec["physical_offset"] + sec["physical_size"]
                if end > last_raw_end:
                    last_raw_end = end
            if last_raw_end < len(data):
                self.overlay = data[last_raw_end:]
                result["overlay_size"] = len(self.overlay)

            result["confidence"] = 0.9 if self.valid else 0.0
            return result

        except Exception as e:
            logger.debug("PEAnalyzer error: %s", e)
            return {
                "valid": False, "machine": 0, "subsystem": 0, "timestamp": 0,
                "entry_point": 0, "image_base": 0, "size_of_code": 0,
                "size_of_image": 0, "sections": [], "imports": [],
                "exports": [], "resources": [], "overlay_size": 0,
                "entropy": {}, "confidence": 0.0,
            }

    def _rva_to_offset(self, rva):
        if not self.sections:
            return rva
        for sec in self.sections:
            if sec["virtual_address"] <= rva < sec["virtual_address"] + sec["virtual_size"]:
                return sec["physical_offset"] + (rva - sec["virtual_address"])
        return None

    def _parse_resource_dir(self, data, off, out, depth=0):
        try:
            if depth > 4 or off + 16 > len(data):
                return
            num_named = safe_int(struct.unpack_from("<H", data, off + 12)[0])
            num_id = safe_int(struct.unpack_from("<H", data, off + 14)[0])
            total_entries = num_named + num_id
            entry_off = off + 16
            for _ in range(min(total_entries, 256)):
                if entry_off + 8 > len(data):
                    break
                name_or_id = safe_int(struct.unpack_from("<I", data, entry_off)[0])
                data_or_dir = safe_int(struct.unpack_from("<I", data, entry_off + 4)[0])
                is_dir = (data_or_dir & 0x80000000) != 0
                if is_dir:
                    dir_off = data_or_dir & 0x7FFFFFFF
                    self._parse_resource_dir(data, dir_off, out, depth + 1)
                else:
                    res_data_off = self._rva_to_offset(data_or_dir)
                    if res_data_off and res_data_off + 16 <= len(data):
                        size = safe_int(struct.unpack_from("<I", data, res_data_off + 4)[0])
                        rdata_rva = safe_int(struct.unpack_from("<I", data, res_data_off + 8)[0])
                        rdata_off = self._rva_to_offset(rdata_rva)
                        rdata = b""
                        if rdata_off and rdata_off + size <= len(data):
                            rdata = data[rdata_off:rdata_off + size]
                        out.append({
                            "id": name_or_id,
                            "size": size,
                            "depth": depth,
                            "entropy": round(entropy_of(rdata), 4),
                        })
                entry_off += 8
        except Exception:
            pass


# ---------------------------------------------------------------------------
# AES-256 (pure Python, ECB encrypt only) + CFB mode for modern EX4 decryption
# ---------------------------------------------------------------------------

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
]


def _sub_word(word):
    return [(SBOX[b] & 0xFF) for b in word]


def _rot_word(word):
    return word[1:] + word[:1]


def _xor_words(a, b):
    return [x ^ y for x, y in zip(a, b)]


def _key_expansion(key):
    """Expand a 32-byte AES-256 key into 60 round keys (4 bytes each)."""
    nk = 8  # 256-bit key = 8 words
    nr = 14  # 14 rounds
    total_words = 4 * (nr + 1)  # 60 words
    w = []
    for i in range(nk):
        w.append(list(key[4 * i:4 * i + 4]))
    i = nk
    while i < total_words:
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= RCON[(i // nk) - 1]
        elif i % nk == 4:
            temp = _sub_word(temp)
        w.append(_xor_words(w[i - nk], temp))
        i += 1
    return w  # list of 60 4-byte words


def _add_round_key(state, round_key):
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]


def _sub_bytes(state):
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def _shift_rows(state):
    return [
        state[0],
        state[1][1:] + state[1][:1],
        state[2][2:] + state[2][:2],
        state[3][3:] + state[3][:3],
    ]


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def _mix_single_column(col):
    t = col[0] ^ col[1] ^ col[2] ^ col[3]
    u = col[0]
    col[0] ^= t ^ _xtime(col[0] ^ col[1])
    col[1] ^= t ^ _xtime(col[1] ^ col[2])
    col[2] ^= t ^ _xtime(col[2] ^ col[3])
    col[3] ^= t ^ _xtime(col[3] ^ u)
    return col


def _mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        col = _mix_single_column(col)
        for r in range(4):
            state[r][c] = col[r]
    return state


def _bytes_to_state(block):
    return [[block[c * 4 + r] for c in range(4)] for r in range(4)]


def _state_to_bytes(state):
    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[c * 4 + r] = state[r][c]
    return bytes(out)


def aes_256_encrypt(key, block):
    """AES-256 ECB encrypt of a single 16-byte block. key: 32 bytes, block: 16 bytes."""
    if len(key) != 32 or len(block) != 16:
        raise ValueError("AES-256 requires 32-byte key and 16-byte block")
    round_keys = _key_expansion(key)
    nr = 14
    state = _bytes_to_state(block)
    state = _add_round_key(state, _words_to_state(round_keys[0:4]))
    for round_idx in range(1, nr):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, _words_to_state(round_keys[4 * round_idx:4 * round_idx + 4]))
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, _words_to_state(round_keys[4 * nr:4 * nr + 4]))
    return _state_to_bytes(state)


def _words_to_state(words):
    return [[words[c][r] for c in range(4)] for r in range(4)]


class CFBCipher:
    """Cipher Feedback (CFB) mode. Same operation for encrypt and decrypt (XOR keystream)."""

    def __init__(self, key, iv, segment_size=128):
        if len(key) != 32:
            raise ValueError("CFB AES-256 requires a 32-byte key")
        if len(iv) != 16:
            raise ValueError("CFB requires a 16-byte IV")
        self.key = key
        self.iv = iv
        self.segment_size = segment_size  # bits; full-block CFB = 128

    def _keystream_block(self, feedback):
        return aes_256_encrypt(self.key, feedback)

    def process(self, data, decrypt=False):
        """XOR data with CFB keystream. Same operation for enc/dec; feedback is always the
        ciphertext block (input block when decrypting, output block when encrypting)."""
        out = bytearray()
        feedback = bytearray(self.iv)
        for i in range(0, len(data), 16):
            ks = self._keystream_block(bytes(feedback))
            block = data[i:i + 16]
            crypt_block = bytes(b ^ k for b, k in zip(block, ks[:len(block)]))
            out.extend(crypt_block)
            feedback = bytearray(block if decrypt else crypt_block)
        return bytes(out)


# ---------------------------------------------------------------------------
# Modern EX4 (build 600+) format detection and CFB decryption
# ---------------------------------------------------------------------------

class ModernEX4Decryptor:
    """Detects and attempts CFB decryption of modern (build 600+) EX4 files.

    Modern EX4 files (MetaTrader 4 build 600+, Feb 2014+) are protected with
    RSA-1024 + an AES-256-CFB stream cipher + MD5 integrity, using 128-byte
    key tables embedded in the file. The RSA private key tables needed to
    recover the session key live inside MetaEditor/terminal and are not publicly
    available. Without them, exact decryption is impossible.

    This class:
      * detects modern encrypted EX4 files,
      * extracts the visible key-table material and structure,
      * implements the AES-256-CFB decryption algorithm parameterized by a
        session key + IV (so decryption works if the session key is supplied),
      * honestly reports decryption impossibility when no key is available.
    """

    # Magic / markers for modern EX4
    EX4_MAGIC = b"EX4"
    MODERN_SECTION_MARKERS = (b".cod0", b".dat0", b".rsrc")

    def __init__(self):
        self.is_modern = False
        self.build_estimate = None
        self.key_tables = []
        self.session_key_enc = None
        self.md5_digest = None
        self.decrypted_payload = None
        self.decryption_error = None
        self.decryption_possible = False

    def analyze(self, data):
        """Analyze data for modern EX4 encryption. Returns a findings dict."""
        result = {
            "is_modern_ex4": False,
            "build_estimate": None,
            "encrypted": False,
            "decryptable": False,
            "decryption_error": None,
            "key_table_count": 0,
            "payload_size": 0,
            "decrypted_size": 0,
        }
        try:
            # Basic EX4 sanity: must start with MZ (PE wrapper) then EX4 sections
            if len(data) < 64 or data[:2] != b"MZ":
                return result

            # Look for modern section markers in overlay/resource area
            pe_off = safe_int(struct.unpack_from("<I", data, 0x3C)[0])
            if pe_off + 24 > len(data):
                return result
            if data[pe_off:pe_off + 4] != b"PE\x00\x00":
                return result

            # Estimate build from timestamp: build 600+ = after ~2014-02
            coff = pe_off + 4
            timestamp = safe_int(struct.unpack_from("<I", data, coff + 8)[0])
            # Rough heuristic: timestamps > ~1390000000 (Jan 2014) suggest build 600+
            build_600_epoch = 1390000000
            if timestamp > build_600_epoch:
                self.is_modern = True
                result["is_modern_ex4"] = True
                result["build_estimate"] = "600+ (post-2014)"

            # Scan for .cod0 / .dat0 section names and key-table-like 128-byte blocks
            cod0_off = data.find(b".cod0")
            if cod0_off != -1:
                self.is_modern = True
                result["is_modern_ex4"] = True

            # Look for 128-byte aligned key tables (high entropy, repeating structure)
            key_tables = []
            scan_end = min(len(data), len(data) - 128)
            for off in range(0, scan_end, 1):
                chunk = data[off:off + 128]
                if len(chunk) < 128:
                    break
                # Heuristic: key tables are 128 bytes with high entropy but not all zeros/FF
                nonzero = sum(1 for b in chunk if b != 0)
                if 64 <= nonzero <= 128:
                    key_tables.append({"offset": off, "entropy": round(entropy_of(chunk), 4)})
                    if len(key_tables) >= 8:
                        break
            self.key_tables = key_tables
            result["key_table_count"] = len(key_tables)

            # Detect RSA-encrypted session key (256 bytes for RSA-1024)
            # Look for a 256-byte block near key tables with high entropy
            if key_tables:
                result["encrypted"] = True
                result["decryptable"] = False  # default: no key available
                result["decryption_error"] = (
                    "Modern EX4 (build 600+) requires MetaQuotes RSA-1024 private key "
                    "tables (inside MetaEditor/terminal) to recover the session key. "
                    "Not publicly available. Supply session_key via decrypt() to attempt."
                )
                result["payload_size"] = len(data)

            return result
        except Exception as e:
            logger.debug("ModernEX4Decryptor.analyze error: %s", e)
            result["decryption_error"] = str(e)
            return result

    def decrypt(self, session_key, iv=None):
        """Attempt AES-256-CFB decryption of the payload.

        session_key: 32-byte AES key (recovered from MetaQuotes RSA private key).
        iv: 16-byte initialization vector (16 zero bytes if unknown).

        Returns dict with decrypted payload or error.
        """
        result = {
            "success": False,
            "decrypted": None,
            "error": None,
        }
        try:
            if self.decrypted_payload is not None:
                result["success"] = True
                result["decrypted"] = self.decrypted_payload
                return result

            if len(session_key) != 32:
                result["error"] = "session_key must be 32 bytes (AES-256)"
                return result

            if iv is None:
                iv = b"\x00" * 16
            elif len(iv) != 16:
                result["error"] = "iv must be 16 bytes"
                return result

            # The payload to decrypt: everything after the PE header/sections,
            # typically the overlay or the .cod0 section content.
            payload = self._extract_payload()
            if not payload:
                result["error"] = "No payload to decrypt found"
                return result

            cipher = CFBCipher(session_key, iv)
            decrypted = cipher.process(payload, decrypt=True)
            self.decrypted_payload = decrypted
            self.decryption_possible = True
            result["success"] = True
            result["decrypted"] = decrypted
            return result
        except Exception as e:
            result["error"] = str(e)
            self.decryption_error = str(e)
            return result

    def _extract_payload(self):
        """Extract the encrypted payload region from the EX4 file."""
        # Prefer overlay (data after last PE section)
        if self.pe_overlay():
            return self.pe_overlay()
        # Fallback: data after PE header
        return b""

    def pe_overlay(self):
        """Return overlay bytes if a PEAnalyzer result is attached, else b''."""
        # We don't hold a PEAnalyzer here; caller may set .overlay externally.
        return getattr(self, "_overlay", b"")

    def set_overlay(self, overlay):
        """Attach overlay bytes extracted by PEAnalyzer."""
        self._overlay = overlay


# ---------------------------------------------------------------------------
# MQL4VMDisassembler
# ---------------------------------------------------------------------------

class MQL4VMDisassembler:
    """Decode MQL4 VM bytecode into structured instructions."""

    OPCODES = {
        0x00: "NOP", 0x01: "PUSH", 0x02: "POP", 0x03: "CALL",
        0x04: "RET", 0x05: "JMP", 0x06: "JZ", 0x07: "JNZ",
        0x08: "EQ", 0x09: "NE", 0x0A: "GT", 0x0B: "LT",
        0x0C: "ADD", 0x0D: "SUB", 0x0E: "MUL", 0x0F: "DIV",
        0x10: "LOAD", 0x11: "STORE", 0x12: "SYS",
    }

    def __init__(self):
        self.instructions = []
        self.bytecode = b""

    def disassemble(self, data, start=0, max_ins=4096):
        """Decode bytecode starting at offset. Returns list of instruction dicts."""
        self.instructions = []
        self.bytecode = data[start:]
        try:
            pc = start
            count = 0
            while pc < len(data) and count < max_ins:
                opcode = data[pc]
                mnemonic = self.OPCODES.get(opcode, "UNKNOWN(%02x)" % opcode)
                ins = {"address": pc, "opcode": opcode, "mnemonic": mnemonic, "operands": []}
                pc += 1
                if opcode in (0x01,):  # PUSH imm32
                    if pc + 4 <= len(data):
                        imm = struct.unpack_from("<I", data, pc)[0]
                        ins["operands"].append({"type": "imm32", "value": imm})
                        pc += 4
                elif opcode in (0x03,):  # CALL imm32
                    if pc + 4 <= len(data):
                        target = struct.unpack_from("<I", data, pc)[0]
                        ins["operands"].append({"type": "imm32", "value": target})
                        pc += 4
                elif opcode in (0x05, 0x06, 0x07):  # JMP/JZ/JNZ imm32
                    if pc + 4 <= len(data):
                        target = struct.unpack_from("<I", data, pc)[0]
                        ins["operands"].append({"type": "imm32", "value": target})
                        pc += 4
                elif opcode in (0x10, 0x11):  # LOAD/STORE reg8
                    if pc + 1 <= len(data):
                        reg = data[pc]
                        ins["operands"].append({"type": "reg8", "value": reg})
                        pc += 1
                elif opcode == 0x12:  # SYS imm32
                    if pc + 4 <= len(data):
                        sysnum = struct.unpack_from("<I", data, pc)[0]
                        ins["operands"].append({"type": "imm32", "value": sysnum})
                        pc += 4
                self.instructions.append(ins)
                count += 1
            return self.instructions
        except Exception as e:
            logger.debug("MQL4VMDisassembler error: %s", e)
            return self.instructions

    def find_bytecode_section(self, data):
        """Heuristically locate an MQL4 bytecode blob inside data."""
        try:
            scan = data[:4194304]  # first 4 MB only
            best = None
            best_score = 0
            for start in range(0, len(scan) - 64, 8):
                score = 0
                for i in range(start, min(start + 256, len(scan) - 1)):
                    op = scan[i]
                    if op in self.OPCODES:
                        score += 1
                if score > best_score and score > 8:
                    best_score = score
                    best = start
            return best
        except Exception:
            return None


# ---------------------------------------------------------------------------
# CFGBuilder
# ---------------------------------------------------------------------------

class CFGBuilder:
    """Build control-flow graph using networkx.DiGraph."""

    def __init__(self):
        self.graph = None
        self.blocks = []
        self.entry_block = None
        self.exit_blocks = []
        self.loops = []

    def build(self, instructions, entry_address=0):
        """Build CFG from instruction list. Returns adjacency list dict."""
        try:
            self.graph = nx.DiGraph() if HAS_NETWORKX else None
            self.blocks = []
            self.entry_block = None
            self.exit_blocks = []
            self.loops = []

            if not instructions:
                return {}

            addrs = [ins["address"] for ins in instructions]
            ins_map = {ins["address"]: ins for ins in instructions}

            # Identify jump targets
            jump_targets = set()
            for ins in instructions:
                for op in ins.get("operands", []):
                    if op.get("type") == "imm32":
                        jump_targets.add(op["value"])

            # Split into basic blocks at jump targets and after terminators
            terminators = {"RET", "JMP", "JZ", "JNZ", "CALL"}
            sorted_ins = sorted(instructions, key=lambda x: x["address"])
            blocks = []
            current = []
            prev_addr = None

            target_set = set(jump_targets)
            for ins in sorted_ins:
                addr = ins["address"]
                mnemonic = ins["mnemonic"]
                is_target = addr in target_set
                is_terminator = mnemonic in terminators
                if current and (is_target or (prev_addr is not None and
                       any(p.get("mnemonic") in ("JMP", "RET") for p in current))):
                    blocks.append(current)
                    current = []
                current.append(ins)
                prev_addr = addr
                if is_terminator:
                    blocks.append(current)
                    current = []
            if current:
                blocks.append(current)

            self.blocks = blocks
            if blocks:
                self.entry_block = blocks[0][0]["address"]

            # Build edges
            adjacency = defaultdict(list)
            if self.graph:
                for bi, block in enumerate(blocks):
                    last = block[-1]
                    la = last["address"]
                    lm = last["mnemonic"]
                    self.graph.add_node(la)
                    # fall-through
                    next_block_addr = None
                    for bj, b2 in enumerate(blocks):
                        if bj > bi:
                            next_block_addr = b2[0]["address"]
                            break
                    if lm not in ("RET", "JMP"):
                        if next_block_addr is not None:
                            adjacency[la].append(next_block_addr)
                            self.graph.add_edge(la, next_block_addr, type="fallthrough")
                    # explicit jumps
                    for op in last.get("operands", []):
                        if op.get("type") == "imm32":
                            tgt = op["value"]
                            adjacency[la].append(tgt)
                            self.graph.add_edge(la, tgt, type="jump")
                            # find block containing target
                            for b2 in blocks:
                                if b2[0]["address"] == tgt:
                                    break

            # Detect exit blocks (end with RET)
            for block in blocks:
                if block[-1]["mnemonic"] == "RET":
                    self.exit_blocks.append(block[0]["address"])

            # Detect loops via networkx cycles
            if self.graph:
                try:
                    self.loops = list(nx.simple_cycles(self.graph))
                except Exception:
                    self.loops = []

            result = {}
            for k, v in adjacency.items():
                result[k] = v
            result["_entry"] = self.entry_block
            result["_exits"] = self.exit_blocks
            result["_loops"] = [list(c) for c in self.loops]
            result["confidence"] = 0.7 if blocks else 0.0
            return result
        except Exception as e:
            logger.debug("CFGBuilder error: %s", e)
            return {"confidence": 0.0}

    def to_dict(self):
        if self.graph is None:
            return {}
        return {
            "nodes": list(self.graph.nodes()),
            "edges": [(u, v, d.get("type", "")) for u, v, d in self.graph.edges(data=True)],
            "entry": self.entry_block,
            "exits": self.exit_blocks,
            "loops": [list(c) for c in self.loops],
        }


# ---------------------------------------------------------------------------
# CallGraphBuilder
# ---------------------------------------------------------------------------

class CallGraphBuilder:
    """Build call graph from CALL instructions and function boundaries."""

    def __init__(self):
        self.graph = None
        self.calls = []
        self.recursive = []
        self.call_depth = {}
        self.leaf_functions = []

    def build(self, functions, instructions):
        """Build call graph. Returns adjacency dict {caller: [callees]}."""
        try:
            self.graph = nx.DiGraph() if HAS_NETWORKX else None
            self.calls = []
            func_addrs = [f["start"] for f in functions]
            ins_map = {ins["address"]: ins for ins in instructions}

            adjacency = defaultdict(list)
            for ins in instructions:
                if ins["mnemonic"] == "CALL":
                    for op in ins.get("operands", []):
                        if op.get("type") == "imm32":
                            target = op["value"]
                            caller = self._containing_func(ins["address"], functions)
                            if caller is not None:
                                self.calls.append({"from": caller, "to": target, "at": ins["address"]})
                                adjacency[caller].append(target)
                                if self.graph:
                                    self.graph.add_edge(caller, target)

            # Deduplicate
            dedup = defaultdict(set)
            for k, v in adjacency.items():
                dedup[k] = list(set(v))
            adjacency = {k: v for k, v in dedup.items()}

            # Detect recursion (self-loops and cycles)
            self.recursive = []
            if self.graph:
                try:
                    for cycle in nx.simple_cycles(self.graph):
                        if len(cycle) >= 1:
                            self.recursive.append(list(cycle))
                except Exception:
                    pass
                # self recursion
                for f in functions:
                    if f["start"] in adjacency.get(f["start"], []):
                        self.recursive.append([f["start"], f["start"]])

            # Leaf functions = functions that call nothing
            called_set = set()
            for v in adjacency.values():
                for t in v:
                    called_set.add(t)
            self.leaf_functions = [f["start"] for f in functions if f["start"] not in called_set]

            # Call depth via longest path approximation
            self.call_depth = {}
            for f in functions:
                self.call_depth[f["start"]] = self._depth(f["start"], adjacency, set())

            result = dict(adjacency)
            result["_recursive"] = self.recursive
            result["_leaf_functions"] = self.leaf_functions
            result["_call_depth"] = self.call_depth
            result["confidence"] = 0.65 if functions else 0.0
            return result
        except Exception as e:
            logger.debug("CallGraphBuilder error: %s", e)
            return {"confidence": 0.0}

    def _containing_func(self, addr, functions):
        best = None
        for f in functions:
            if f["start"] <= addr <= f.get("end", f["start"]):
                if best is None or f["start"] > best["start"]:
                    best = f
        return best["start"] if best else None

    def _depth(self, node, adjacency, visited):
        if node in visited:
            return 0
        visited = visited | {node}
        max_d = 0
        for child in adjacency.get(node, []):
            max_d = max(max_d, 1 + self._depth(child, adjacency, visited))
        return max_d


# ---------------------------------------------------------------------------
# DataFlowAnalyzer
# ---------------------------------------------------------------------------

class DataFlowAnalyzer:
    """Simple def-use analysis with taint tracking."""

    def __init__(self):
        self.defs = defaultdict(list)   # var -> [(addr, ins)]
        self.uses = defaultdict(list)   # var -> [(addr, ins)]
        self.tainted_sources = []
        self.tainted_sinks = []
        self.taint_flow = []

    def analyze(self, instructions, functions):
        """Run def-use and taint analysis. Returns dict of results."""
        try:
            self.defs = defaultdict(list)
            self.uses = defaultdict(list)
            self.tainted_sources = []
            self.tainted_sinks = []
            self.taint_flow = []

            source_patterns = [
                b"FileRead", b"FileOpen", b"iCustom", b"MarketInfo",
                b"SymbolInfoTick", b"AccountInfo", b"OrderSelect",
            ]
            sink_patterns = [
                b"OrderSend", b"OrderClose", b"OrderModify", b"OrderDelete",
                b"SendMail", b"SendFTP", b"Alert", b"FileWrite",
            ]

            for ins in instructions:
                mnemonic = ins["mnemonic"]
                addr = ins["address"]
                if mnemonic in ("STORE",):
                    for op in ins.get("operands", []):
                        if op.get("type") == "reg8":
                            self.defs[op["value"]].append(addr)
                if mnemonic in ("LOAD",):
                    for op in ins.get("operands", []):
                        if op.get("type") == "reg8":
                            self.uses[op["value"]].append(addr)
                if mnemonic == "SYS":
                    for op in ins.get("operands", []):
                        if op.get("type") == "imm32":
                            sysnum = op["value"]
                            fname = MT4_FUNCTIONS.get(sysnum, "sys_%d" % sysnum)
                            for sp in source_patterns:
                                if sp.lower() in fname.lower().encode():
                                    self.tainted_sources.append({"addr": addr, "function": fname, "sysnum": sysnum})
                                    break
                            for sk in sink_patterns:
                                if sk.lower() in fname.lower().encode():
                                    self.tainted_sinks.append({"addr": addr, "function": fname, "sysnum": sysnum})
                                    break
                            self.taint_flow.append({
                                "addr": addr, "function": fname,
                                "source": any(sp.lower() in fname.lower().encode() for sp in source_patterns),
                                "sink": any(sk.lower() in fname.lower().encode() for sk in sink_patterns),
                            })

            # Build def-use chains
            def_use = {}
            for var in set(list(self.defs.keys()) + list(self.uses.keys())):
                def_use[var] = {
                    "defs": self.defs.get(var, []),
                    "uses": self.uses.get(var, []),
                }

            result = {
                "def_use": {str(k): v for k, v in def_use.items()},
                "tainted_sources": self.tainted_sources,
                "tainted_sinks": self.tainted_sinks,
                "taint_flow": self.taint_flow,
                "num_tainted_sources": len(self.tainted_sources),
                "num_tainted_sinks": len(self.tainted_sinks),
                "confidence": 0.6 if instructions else 0.0,
            }
            return result
        except Exception as e:
            logger.debug("DataFlowAnalyzer error: %s", e)
            return {
                "def_use": {}, "tainted_sources": [], "tainted_sinks": [],
                "taint_flow": [], "num_tainted_sources": 0, "num_tainted_sinks": 0,
                "confidence": 0.0,
            }


# ---------------------------------------------------------------------------
# StringDeobfuscator
# ---------------------------------------------------------------------------

class StringDeobfuscator:
    """Detect and reverse XOR, ROT13, base64, reversed, stacked ciphers."""

    def __init__(self):
        self.results = []
        self.known_strings = KNOWN_MQL4_STRINGS

    def deobfuscate(self, data):
        """Scan data for obfuscated strings and attempt recovery."""
        self.results = []
        try:
            # Bound total work: cap data length and candidate count
            work_data = data[:262144]  # first 256 KB only
            candidates = self._extract_candidates(work_data)
            # Process only the most promising candidates first
            candidates.sort(key=len, reverse=True)
            for cand in candidates[:64]:
                self._try_candidates(cand)
            self.results.sort(key=lambda r: r["score"], reverse=True)
            return {
                "strings": self.results[:200],
                "count": len(self.results),
                "confidence": 0.6 if self.results else 0.0,
            }
        except Exception as e:
            logger.debug("StringDeobfuscator error: %s", e)
            return {"strings": [], "count": 0, "confidence": 0.0}

    def _extract_candidates(self, data):
        candidates = []
        n = len(data)
        i = 0
        while i < n - 4:
            if data[i] != 0:
                j = i
                while j < n and j < i + 64 and data[j] != 0:
                    j += 1
                run = data[i:j]
                if len(run) >= 4:
                    candidates.append(run)
                i = j
            else:
                i += 1
        return candidates[:256]

    def _try_candidates(self, data):
        methods = [
            ("xor_single", self._xor_single),
            ("rot13", self._rot13),
            ("reverse", self._reverse),
            ("base64", self._base64),
            ("plain", self._plain),
            ("xor_multi", self._xor_multi),
        ]
        seen = set()
        for name, fn in methods:
            try:
                for out, key, score in fn(data):
                    sig = (name, key, out)
                    if sig in seen:
                        continue
                    seen.add(sig)
                    if score > 0.5:
                        self.results.append({
                            "string": out,
                            "method": name,
                            "key": key,
                            "score": round(score, 3),
                        })
            except Exception:
                pass

    def _plain(self, data):
        out = []
        for b in data:
            if 32 <= b <= 126:
                out.append(chr(b))
            else:
                return [], 0
        s = "".join(out)
        if len(s) < 4:
            return [], 0
        score = self._readability(s)
        return [(s, "none", score)] if score > 0.6 else ([], 0)

    def _xor_single(self, data):
        results = []
        # Single-byte brute force (255 iterations - cheap)
        for key in range(1, 256):
            out = bytes(b ^ key for b in data)
            s = self._to_string(out)
            if s:
                score = self._readability(s)
                if score > 0.55:
                    results.append((s, key, score))
        # Known-plaintext key derivation at candidate start only
        for kstr in self.known_strings:
            if 1 <= len(kstr) <= len(data):
                key = data[0] ^ kstr[0]
                if 1 <= key <= 255:
                    out = bytes(b ^ key for b in data)
                    s = self._to_string(out)
                    if s and kstr.decode("ascii", errors="ignore") in s:
                        score = self._readability(s) + 0.2
                        results.append((s, key, min(score, 1.0)))
        return results

    def _xor_multi(self, data):
        results = []
        # Multi-byte XOR only via known-plaintext derivation at candidate start.
        # Avoids the 255^k brute-force explosion.
        for kstr in self.known_strings:
            klen = len(kstr)
            if klen < 2 or klen > 4 or klen > len(data):
                continue
            keys = tuple(data[i] ^ kstr[i] for i in range(klen))
            if any(k == 0 for k in keys):
                continue
            out = bytes(b ^ keys[i % klen] for i, b in enumerate(data))
            s = self._to_string(out)
            if s:
                ktext = kstr.decode("ascii", errors="ignore")
                if ktext in s:
                    score = self._readability(s) + 0.25
                    results.append((s, keys, min(score, 1.0)))
                    if len(results) >= 8:
                        return results
        return results

    def _rot13(self, data):
        results = []
        for shift in range(1, 26):
            out = bytearray()
            for b in data:
                if 65 <= b <= 90:
                    out.append(((b - 65 + shift) % 26) + 65)
                elif 97 <= b <= 122:
                    out.append(((b - 97 + shift) % 26) + 97)
                else:
                    out.append(b)
            s = self._to_string(out)
            if s:
                score = self._readability(s)
                if score > 0.6:
                    results.append((s, "rot%d" % shift, score))
        return results

    def _reverse(self, data):
        results = []
        out = data[::-1]
        s = self._to_string(out)
        if s:
            score = self._readability(s)
            if score > 0.6:
                results.append((s, "reverse", score))
        return results

    def _base64(self, data):
        results = []
        import base64
        try:
            # try raw
            dec = base64.b64decode(data, validate=False)
            s = self._to_string(dec)
            if s:
                score = self._readability(s)
                if score > 0.6:
                    results.append((s, "base64", score))
        except Exception:
            pass
        return results

    def _to_string(self, data):
        try:
            s = data.decode("ascii")
            if all(32 <= b <= 126 or b in (9, 10, 13) for b in data):
                return s
        except Exception:
            pass
        return None

    def _readability(self, s):
        if not s:
            return 0.0
        printable = sum(1 for c in s if 32 <= ord(c) <= 126)
        ratio = printable / len(s)
        # bonus for known MQL4 tokens
        bonus = 0.0
        for k in self.known_strings:
            if k.decode("ascii", errors="ignore") in s:
                bonus += 0.15
        return min(ratio + bonus, 1.0)


# ---------------------------------------------------------------------------
# APIResolver
# ---------------------------------------------------------------------------

class APIResolver:
    """Map syscall numbers and byte patterns to MQL4 API functions."""

    def __init__(self):
        self.functions = dict(MT4_FUNCTIONS)
        self.indicators = dict(MT4_INDICATORS)
        self.patterns = self._build_byte_patterns()

    def _build_byte_patterns(self):
        patterns = {}
        for name in MT4_FUNCTIONS.values():
            patterns[name.encode()] = name
        for name in MT4_INDICATORS.keys():
            patterns[name.encode()] = name
        return patterns

    def resolve_syscalls(self, syscalls):
        """Resolve list of syscall numbers to function names with confidence."""
        resolved = []
        for sc in syscalls:
            num = sc if isinstance(sc, int) else sc.get("sysnum", sc)
            name = self.functions.get(num, "sys_%d" % num)
            conf = 0.9 if num in self.functions else 0.3
            resolved.append({"sysnum": num, "function": name, "confidence": conf})
        return resolved

    def resolve_patterns(self, data):
        """Find API function names as byte patterns in data."""
        found = []
        for pat, name in self.patterns.items():
            idx = data.find(pat)
            while idx != -1:
                found.append({
                    "function": name,
                    "offset": idx,
                    "pattern": pat.decode("ascii", errors="ignore"),
                    "confidence": 0.85,
                })
                idx = data.find(pat, idx + 1)
                if len(found) > 512:
                    break
        return found

    def resolve_from_disassembly(self, instructions):
        """Resolve SYS instructions to API calls."""
        calls = []
        for ins in instructions:
            if ins["mnemonic"] == "SYS":
                for op in ins.get("operands", []):
                    if op.get("type") == "imm32":
                        num = op["value"]
                        name = self.functions.get(num, "sys_%d" % num)
                        conf = 0.9 if num in self.functions else 0.35
                        calls.append({
                            "address": ins["address"],
                            "sysnum": num,
                            "function": name,
                            "confidence": conf,
                        })
        return calls


# ---------------------------------------------------------------------------
# FunctionBoundaryDetector
# ---------------------------------------------------------------------------

class FunctionBoundaryDetector:
    """Detect function boundaries via x86 prologue/epilogue and call/jmp rel."""

    PROLOGUE = b"\x55\x89\xE5"      # push ebp; mov ebp, esp
    EPILOGUE = b"\x5D\xC3"          # pop ebp; ret
    SHORT_EPILOGUE = b"\xC3"        # ret

    def __init__(self):
        self.functions = []

    def detect(self, data):
        """Scan data for function boundaries. Returns list of function dicts."""
        self.functions = []
        try:
            starts = []
            # prologue starts
            for m in re.finditer(re.escape(self.PROLOGUE), data):
                starts.append(m.start())
            # also any address targeted by a call/jmp
            for m in re.finditer(b"\xE8", data):  # call rel32
                if m.start() + 5 <= len(data):
                    off = struct.unpack_from("<i", data, m.start() + 1)[0]
                    tgt = m.start() + 5 + off
                    if 0 <= tgt < len(data):
                        starts.append(tgt)
            for m in re.finditer(b"\xE9", data):  # jmp rel32
                if m.start() + 5 <= len(data):
                    off = struct.unpack_from("<i", data, m.start() + 1)[0]
                    tgt = m.start() + 5 + off
                    if 0 <= tgt < len(data):
                        starts.append(tgt)

            starts = sorted(set(s for s in starts if s < len(data)))
            for start in starts:
                end = self._find_end(data, start)
                if end is None or end <= start:
                    end = start + 1
                size = end - start
                # collect calls within
                called = []
                for m in re.finditer(b"\xE8", data, start, end):
                    if m.start() + 5 <= len(data):
                        off = struct.unpack_from("<i", data, m.start() + 1)[0]
                        tgt = m.start() + 5 + off
                        called.append(tgt)
                self.functions.append({
                    "start": start,
                    "end": end,
                    "size": size,
                    "called": sorted(set(called)),
                    "prologue": data[start:start + 3] == self.PROLOGUE,
                })

            # sort & dedupe overlapping
            self.functions.sort(key=lambda f: f["start"])
            return {
                "functions": self.functions,
                "count": len(self.functions),
                "confidence": 0.6 if self.functions else 0.0,
            }
        except Exception as e:
            logger.debug("FunctionBoundaryDetector error: %s", e)
            return {"functions": [], "count": 0, "confidence": 0.0}

    def _find_end(self, data, start):
        # search epilogue within reasonable range
        limit = min(start + 4096, len(data))
        idx = data.find(self.EPILOGUE, start, limit)
        if idx != -1:
            return idx + 2
        # short ret
        idx2 = data.find(self.SHORT_EPILOGUE, start, limit)
        if idx2 != -1:
            return idx2 + 1
        return None


# ---------------------------------------------------------------------------
# REAEngine
# ---------------------------------------------------------------------------

class REAEngine:
    """Main orchestrator. Runs all sub-analyzers and returns comprehensive dict."""

    def __init__(self):
        self.pe = PEAnalyzer()
        self.vd = MQL4VMDisassembler()
        self.cfg = CFGBuilder()
        self.cg = CallGraphBuilder()
        self.df = DataFlowAnalyzer()
        self.sd = StringDeobfuscator()
        self.ar = APIResolver()
        self.fbd = FunctionBoundaryDetector()
        self.modern = ModernEX4Decryptor()

    def analyze(self, filepath):
        """Run full REA analysis on a file. Returns dict with all findings."""
        result = {
            "pe_info": {},
            "disassembly": [],
            "functions": [],
            "cfg": {},
            "call_graph": {},
            "data_flow": {},
            "deobfuscated_strings": [],
            "api_calls": [],
            "bytecode": [],
            "entropy_map": {},
            "confidence": 0.0,
        }
        try:
            if not os.path.exists(filepath):
                return result
            with open(filepath, "rb") as f:
                data = f.read()

            # PE analysis
            pe_res = self.pe.analyze(data)
            result["pe_info"] = pe_res
            result["entropy_map"] = pe_res.get("entropy", {})

            # Modern EX4 (build 600+) detection + CFB decryption
            self.modern.set_overlay(self.pe.overlay)
            modern_res = self.modern.analyze(data)
            result["modern_ex4"] = modern_res
            if modern_res.get("is_modern_ex4"):
                result["entropy_map"]["modern_ex4_encrypted"] = 1.0

            # Function boundaries
            fb_res = self.fbd.detect(data)
            funcs = fb_res.get("functions", [])
            result["functions"] = funcs

            # x86 disassembly via capstone if available
            disasm = []
            code_section = None
            for sec in pe_res.get("sections", []):
                if sec.get("name", "").startswith(".text"):
                    code_section = sec
                    break
            if code_section and code_section.get("physical_offset") is not None:
                poff = code_section["physical_offset"]
                psize = code_section["physical_size"]
                code_data = data[poff:poff + psize]
                vaddr = code_section["virtual_address"]
            else:
                code_data = data
                vaddr = 0

            if HAS_CAPSTONE:
                try:
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                    for ins in md.disasm(code_data, vaddr):
                        disasm.append({
                            "address": ins.address,
                            "mnemonic": ins.mnemonic,
                            "op_str": ins.op_str,
                            "bytes": ins.bytes.hex(),
                            "size": ins.size,
                        })
                except Exception as e:
                    logger.debug("Capstone disasm error: %s", e)
            else:
                # fallback: raw opcode scan
                for i in range(0, min(len(code_data), 2048), 1):
                    disasm.append({
                        "address": vaddr + i,
                        "mnemonic": "db",
                        "op_str": "0x%02x" % code_data[i],
                        "bytes": "%02x" % code_data[i],
                        "size": 1,
                    })
            result["disassembly"] = disasm[:4096]

            # MQL4 bytecode
            bc_start = self.vd.find_bytecode_section(data)
            bytecode_ins = []
            syscalls = []
            if bc_start is not None:
                bytecode_ins = self.vd.disassemble(data, bc_start)
                for ins in bytecode_ins:
                    if ins["mnemonic"] == "SYS":
                        for op in ins.get("operands", []):
                            if op.get("type") == "imm32":
                                syscalls.append(op["value"])
            result["bytecode"] = bytecode_ins

            # CFG
            cfg_res = self.cfg.build(bytecode_ins if bytecode_ins else disasm)
            result["cfg"] = cfg_res

            # Call graph
            cg_res = self.cg.build(funcs, disasm)
            result["call_graph"] = cg_res

            # Data flow
            df_res = self.df.analyze(bytecode_ins if bytecode_ins else disasm, funcs)
            result["data_flow"] = df_res

            # API resolution from syscalls + disassembly
            api_calls = []
            api_calls.extend(self.ar.resolve_syscalls(syscalls))
            api_calls.extend(self.ar.resolve_from_disassembly(bytecode_ins if bytecode_ins else disasm))
            # dedupe by address/sysnum
            seen = set()
            deduped = []
            for c in api_calls:
                key = c.get("address", c.get("sysnum"))
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(c)
            result["api_calls"] = deduped

            # String deobfuscation
            sd_res = self.sd.deobfuscate(data)
            result["deobfuscated_strings"] = sd_res.get("strings", [])

            # imports from PE as api_calls too
            for imp in pe_res.get("imports", []):
                result["api_calls"].append({
                    "address": None,
                    "sysnum": None,
                    "function": imp.get("function", imp.get("dll", "")),
                    "confidence": 0.8,
                    "dll": imp.get("dll", ""),
                })

            # Overall confidence
            confs = []
            for key in ("pe_info", "cfg", "call_graph", "data_flow", "deobfuscated_strings", "api_calls"):
                v = result.get(key, {})
                if isinstance(v, dict) and "confidence" in v:
                    confs.append(v["confidence"])
                elif isinstance(v, list) and v:
                    confs.append(0.7)
            result["confidence"] = round(sum(confs) / len(confs), 3) if confs else 0.0

            return result

        except Exception as e:
            logger.debug("REAEngine.analyze error: %s", e)
            result["confidence"] = 0.0
            return result
