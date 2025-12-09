import os
import struct
import binascii
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import re
import json
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                   format='%(asctime)s - %(levelname)s - %(message)s')

class MT4Analyzer:
    def __init__(self):
        self.known_patterns = {
            # Common patterns
            b'indicator': 'Custom Indicator',
            b'expert': 'Expert Advisor',
            b'copyright': 'Copyright Information',
            b'property': 'Indicator Property',
            b'extern': 'External Variable',
            b'buffer': 'Indicator Buffer',
            
            # MQL4 specific patterns - Enhanced
            b'OrderSend': 'MQL4 Trading Function',
            b'OrderClose': 'MQL4 Order Close',
            b'OrderModify': 'MQL4 Order Modify',
            b'OrderDelete': 'MQL4 Order Delete',
            b'iCustom': 'MQL4 Custom Indicator',
            b'iMA': 'MQL4 Moving Average',
            b'iRSI': 'MQL4 RSI',
            b'iATR': 'MQL4 ATR',
            b'iMACD': 'MQL4 MACD',
            b'iBands': 'MQL4 Bollinger Bands',
            b'iStochastic': 'MQL4 Stochastic',
            b'iCCI': 'MQL4 CCI',
            b'iADX': 'MQL4 ADX',
            b'iIchimoku': 'MQL4 Ichimoku',
            b'iFractals': 'MQL4 Fractals',
            b'iAlligator': 'MQL4 Alligator',
            b'iSAR': 'MQL4 Parabolic SAR',
            
            # MQL5 specific patterns - Enhanced
            b'CTrade': 'MQL5 Trading Class',
            b'CCustomInd': 'MQL5 Custom Indicator',
            b'CiMA': 'MQL5 Moving Average',
            b'CiRSI': 'MQL5 RSI',
            b'CiATR': 'MQL5 ATR',
            b'CiMACD': 'MQL5 MACD',
            b'CiBands': 'MQL5 Bollinger Bands',
            b'CiStochastic': 'MQL5 Stochastic',
            
            # Trading Strategy Patterns - New
            b'Martingale': 'Martingale Strategy',
            b'Grid': 'Grid Trading Strategy',
            b'Hedg': 'Hedging Strategy',
            b'Scalp': 'Scalping Strategy',
            b'Breakout': 'Breakout Strategy',
            b'Trend': 'Trend Following Strategy',
            
            # Timeframe patterns - New
            b'PERIOD_M1': 'M1 Timeframe',
            b'PERIOD_M5': 'M5 Timeframe',
            b'PERIOD_M15': 'M15 Timeframe',
            b'PERIOD_M30': 'M30 Timeframe',
            b'PERIOD_H1': 'H1 Timeframe',
            b'PERIOD_H4': 'H4 Timeframe',
            b'PERIOD_D1': 'D1 Timeframe',
            b'PERIOD_W1': 'W1 Timeframe',
            
            # Risk Management - New
            b'StopLoss': 'Stop Loss Management',
            b'TakeProfit': 'Take Profit Management',
            b'TrailingStop': 'Trailing Stop',
            b'MoneyManagement': 'Money Management',
            b'RiskPercent': 'Risk Percentage',
        }

    def analyze_file(self, filepath):
        """Analyze an EX4 file with enhanced detailed error reporting"""
        try:
            logging.info(f"Starting analysis of {filepath}")
            
            with open(filepath, 'rb') as f:
                data = f.read()
                
            logging.info(f"Successfully read {len(data)} bytes from file")
            
            # Basic file validation
            if len(data) < 64:
                raise ValueError("File too small to be a valid EX4 file")
                
            # Check for MZ header (common in EX4 files)
            if not data.startswith(b'MZ'):
                logging.warning("File does not start with MZ header")
            
            # Extract strings first for categorization
            strings = self.extract_strings(data)
            string_categories = self.categorize_strings(strings)
            
            analysis = {
                'metadata': self.extract_metadata(data),
                'patterns': self.find_patterns(data),
                'strings': strings,
                'string_categories': string_categories,
                'functions': self.identify_functions(data),
                'input_parameters': self.extract_input_parameters(data, string_categories),
                'trading_strategy': self.analyze_trading_strategy(data),
                'risk_management': self.analyze_risk_management(data),
                'statistics': self.generate_statistics(data, strings)
            }
            
            logging.info("Analysis completed successfully")
            return analysis
            
        except Exception as e:
            logging.error(f"Error during analysis: {str(e)}", exc_info=True)
            return {
                'error': str(e),
                'metadata': {'type': 'Unknown', 'version': 'Unknown'},
                'patterns': [],
                'strings': [],
                'string_categories': {},
                'functions': [],
                'input_parameters': [],
                'trading_strategy': {},
                'risk_management': {},
                'statistics': {}
            }

    def extract_metadata(self, data):
        """Extract enhanced metadata with better timestamp and details"""
        try:
            metadata = {
                'type': 'Unknown',
                'version': 'Unknown',
                'creation_date': 'Unknown',
                'file_size': len(data),
                'copyright': 'Unknown',
                'description': 'Unknown',
                'author': 'Unknown',
                'link': 'Unknown'
            }
            
            # Determine type with priority order
            if b'indicator' in data.lower():
                metadata['type'] = 'Indicator'
            elif b'expert' in data.lower() or b'EA' in data:
                metadata['type'] = 'Expert Advisor'
            elif b'script' in data.lower():
                metadata['type'] = 'Script'
                
            # Look for version information - enhanced patterns
            version_patterns = [
                b'version[\\s=:]+(\\d+\\.\\d+(?:\\.\\d+)?)',
                b'v[\\s]*(\\d+\\.\\d+(?:\\.\\d+)?)',
                b'ver[\\s]*(\\d+\\.\\d+(?:\\.\\d+)?)'
            ]
            for pattern in version_patterns:
                version_match = re.search(pattern, data, re.IGNORECASE)
                if version_match:
                    metadata['version'] = version_match.group(1).decode('ascii', errors='ignore')
                    break
            
            # Extract PE timestamp if available (Enhanced)
            if data.startswith(b'MZ') and len(data) > 0x3C:
                try:
                    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
                    if pe_offset < len(data) - 8 and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                        timestamp = struct.unpack('<I', data[pe_offset+8:pe_offset+12])[0]
                        if timestamp > 0:
                            creation_time = datetime.fromtimestamp(timestamp)
                            metadata['creation_date'] = creation_time.strftime('%Y-%m-%d %H:%M:%S')
                except Exception as e:
                    logging.debug(f"Could not extract PE timestamp: {e}")
            
            # Extract copyright information
            copyright_match = re.search(b'copyright[\\s]*[:\\(]?[\\s]*([^\x00]{3,50})', data, re.IGNORECASE)
            if copyright_match:
                metadata['copyright'] = copyright_match.group(1).decode('ascii', errors='ignore').strip()
            
            # Extract description
            desc_match = re.search(b'description[\\s]*[:\\(]?[\\s]*([^\x00]{3,100})', data, re.IGNORECASE)
            if desc_match:
                metadata['description'] = desc_match.group(1).decode('ascii', errors='ignore').strip()
            
            # Extract author
            author_match = re.search(b'author[\\s]*[:\\(]?[\\s]*([^\x00]{3,50})', data, re.IGNORECASE)
            if author_match:
                metadata['author'] = author_match.group(1).decode('ascii', errors='ignore').strip()
            
            # Extract link/URL
            link_match = re.search(b'(https?://[^\x00\\s]{3,100})', data, re.IGNORECASE)
            if link_match:
                metadata['link'] = link_match.group(1).decode('ascii', errors='ignore').strip()
                
            logging.info(f"Extracted metadata: {metadata}")
            return metadata
            
        except Exception as e:
            logging.error(f"Error extracting metadata: {str(e)}", exc_info=True)
            return {'type': 'Unknown', 'version': 'Unknown', 'error': str(e)}

    def find_patterns(self, data):
        """Find known patterns in the binary data"""
        try:
            patterns = []
            for pattern, description in self.known_patterns.items():
                if pattern in data:
                    patterns.append({
                        'type': description,
                        'count': data.count(pattern)
                    })
            
            logging.info(f"Found {len(patterns)} patterns")
            return patterns
            
        except Exception as e:
            logging.error(f"Error finding patterns: {str(e)}", exc_info=True)
            return []

    def extract_strings(self, data):
        """Extract readable strings with Unicode support and categorization"""
        try:
            strings = []
            current = ''
            
            # ASCII string extraction
            for byte in data:
                if 32 <= byte <= 126:  # printable ASCII
                    current += chr(byte)
                elif current:
                    if len(current) > 3:  # minimum length
                        strings.append(current)
                    current = ''
            
            # Add last string if exists
            if current and len(current) > 3:
                strings.append(current)
            
            # Try to extract Unicode strings (UTF-16LE is common in Windows binaries)
            try:
                i = 0
                while i < len(data) - 1:
                    # Look for potential UTF-16LE strings
                    if data[i] != 0 and data[i+1] == 0:  # Potential start of UTF-16LE
                        unicode_str = bytearray()
                        j = i
                        while j < len(data) - 1 and j < i + 200:  # Limit length
                            if data[j] == 0 and data[j+1] == 0:  # End of string
                                break
                            if data[j] != 0 and data[j+1] == 0 and 32 <= data[j] <= 126:
                                unicode_str.append(data[j])
                                j += 2
                            else:
                                break
                        
                        if len(unicode_str) > 3:
                            try:
                                decoded = unicode_str.decode('ascii', errors='ignore')
                                if decoded and decoded not in strings:
                                    strings.append(decoded)
                            except:
                                pass
                        i = j
                    i += 1
            except Exception as e:
                logging.debug(f"Unicode extraction error: {e}")
            
            # Remove duplicates while preserving order
            seen = set()
            unique_strings = []
            for s in strings:
                if s not in seen:
                    seen.add(s)
                    unique_strings.append(s)
                    
            logging.info(f"Extracted {len(unique_strings)} unique strings")
            return unique_strings
            
        except Exception as e:
            logging.error(f"Error extracting strings: {str(e)}", exc_info=True)
            return []
    
    def categorize_strings(self, strings):
        """Categorize extracted strings for better analysis"""
        categories = {
            'functions': [],
            'variables': [],
            'indicators': [],
            'symbols': [],
            'parameters': [],
            'comments': [],
            'other': []
        }
        
        # Function-like patterns
        function_patterns = [
            'OnInit', 'OnDeinit', 'OnTick', 'OnCalculate', 'OnStart',
            'OrderSend', 'OrderClose', 'OrderModify', 'iMA', 'iRSI',
            'SetIndexBuffer', 'SetIndexStyle'
        ]
        
        # Variable/parameter patterns
        param_patterns = ['period', 'shift', 'method', 'price', 'lot', 'stop', 'take']
        
        # Indicator patterns
        indicator_patterns = ['MA', 'RSI', 'MACD', 'ATR', 'Bollinger', 'Stochastic']
        
        for s in strings:
            categorized = False
            s_lower = s.lower()
            
            # Check functions
            for pattern in function_patterns:
                if pattern.lower() in s_lower:
                    categories['functions'].append(s)
                    categorized = True
                    break
            
            if not categorized:
                # Check parameters
                for pattern in param_patterns:
                    if pattern in s_lower:
                        categories['parameters'].append(s)
                        categorized = True
                        break
            
            if not categorized:
                # Check indicators
                for pattern in indicator_patterns:
                    if pattern.lower() in s_lower:
                        categories['indicators'].append(s)
                        categorized = True
                        break
            
            if not categorized:
                # Check if it looks like a symbol (e.g., EURUSD, GBPUSD)
                if len(s) == 6 and s.isalpha() and s.isupper():
                    categories['symbols'].append(s)
                elif '#' in s or '//' in s:
                    categories['comments'].append(s)
                else:
                    categories['other'].append(s)
        
        return categories

    def identify_functions(self, data):
        """Identify potential functions in the binary"""
        try:
            functions = []
            
            # Common function markers in MT4
            markers = [
                b'OnInit',
                b'OnDeinit',
                b'OnStart',
                b'OnTick',
                b'OnCalculate'
            ]
            
            for marker in markers:
                if marker in data:
                    functions.append(marker.decode('ascii', errors='ignore'))
                    
            logging.info(f"Identified {len(functions)} functions")
            return functions
            
        except Exception as e:
            logging.error(f"Error identifying functions: {str(e)}", exc_info=True)
            return []
    
    def extract_input_parameters(self, data, string_categories):
        """Extract input parameters with type inference"""
        try:
            parameters = []
            param_strings = string_categories.get('parameters', [])
            
            # Common parameter patterns with type hints
            type_keywords = {
                'period': ('int', 14),
                'shift': ('int', 0),
                'lot': ('double', 0.1),
                'lots': ('double', 0.1),
                'stoploss': ('int', 50),
                'takeprofit': ('int', 100),
                'maxlots': ('double', 1.0),
                'slippage': ('int', 3),
                'magic': ('int', 12345),
                'risk': ('double', 1.0),
                'percent': ('double', 2.0),
            }
            
            for param in param_strings:
                param_lower = param.lower()
                param_type = 'int'
                default_value = 0
                
                # Infer type from common patterns
                for keyword, (typ, default) in type_keywords.items():
                    if keyword in param_lower:
                        param_type = typ
                        default_value = default
                        break
                
                parameters.append({
                    'name': param,
                    'type': param_type,
                    'default': default_value
                })
            
            return parameters
        except Exception as e:
            logging.error(f"Error extracting parameters: {e}")
            return []
    
    def analyze_trading_strategy(self, data):
        """Analyze and identify trading strategy patterns"""
        try:
            strategy = {
                'type': 'Unknown',
                'indicators_used': [],
                'entry_patterns': [],
                'exit_patterns': [],
                'timeframes': []
            }
            
            # Detect strategy type
            if b'Martingale' in data or b'martingale' in data:
                strategy['type'] = 'Martingale'
            elif b'Grid' in data or b'grid' in data:
                strategy['type'] = 'Grid Trading'
            elif b'Scalp' in data or b'scalp' in data:
                strategy['type'] = 'Scalping'
            elif b'Breakout' in data or b'breakout' in data:
                strategy['type'] = 'Breakout'
            elif b'Trend' in data or b'trend' in data:
                strategy['type'] = 'Trend Following'
            elif b'Hedg' in data:
                strategy['type'] = 'Hedging'
            
            # Detect indicators used
            indicator_list = [
                (b'iMA', 'Moving Average'),
                (b'iRSI', 'RSI'),
                (b'iMACD', 'MACD'),
                (b'iATR', 'ATR'),
                (b'iBands', 'Bollinger Bands'),
                (b'iStochastic', 'Stochastic'),
                (b'iCCI', 'CCI'),
                (b'iADX', 'ADX'),
            ]
            
            for pattern, name in indicator_list:
                if pattern in data:
                    strategy['indicators_used'].append(name)
            
            # Detect timeframes
            timeframes = [
                (b'PERIOD_M1', 'M1'),
                (b'PERIOD_M5', 'M5'),
                (b'PERIOD_M15', 'M15'),
                (b'PERIOD_M30', 'M30'),
                (b'PERIOD_H1', 'H1'),
                (b'PERIOD_H4', 'H4'),
                (b'PERIOD_D1', 'D1'),
            ]
            
            for pattern, name in timeframes:
                if pattern in data:
                    strategy['timeframes'].append(name)
            
            # Detect entry patterns
            if b'Buy' in data and b'Signal' in data:
                strategy['entry_patterns'].append('Buy Signal Based')
            if b'Sell' in data and b'Signal' in data:
                strategy['entry_patterns'].append('Sell Signal Based')
            if b'Cross' in data or b'cross' in data:
                strategy['entry_patterns'].append('Indicator Crossover')
            
            # Detect exit patterns
            if b'StopLoss' in data or b'SL' in data:
                strategy['exit_patterns'].append('Stop Loss')
            if b'TakeProfit' in data or b'TP' in data:
                strategy['exit_patterns'].append('Take Profit')
            if b'TrailingStop' in data:
                strategy['exit_patterns'].append('Trailing Stop')
            
            return strategy
        except Exception as e:
            logging.error(f"Error analyzing strategy: {e}")
            return {}
    
    def analyze_risk_management(self, data):
        """Analyze risk management features"""
        try:
            risk_mgmt = {
                'has_stop_loss': b'StopLoss' in data or b'SL' in data,
                'has_take_profit': b'TakeProfit' in data or b'TP' in data,
                'has_trailing_stop': b'TrailingStop' in data,
                'has_money_management': b'MoneyManagement' in data or b'MM' in data,
                'has_risk_percent': b'RiskPercent' in data or b'Risk' in data,
                'has_max_lots': b'MaxLots' in data or b'MaxLot' in data,
                'has_max_orders': b'MaxOrders' in data or b'MaxTrades' in data,
                'features': []
            }
            
            # Build features list
            if risk_mgmt['has_stop_loss']:
                risk_mgmt['features'].append('Stop Loss Protection')
            if risk_mgmt['has_take_profit']:
                risk_mgmt['features'].append('Take Profit Targets')
            if risk_mgmt['has_trailing_stop']:
                risk_mgmt['features'].append('Trailing Stop')
            if risk_mgmt['has_money_management']:
                risk_mgmt['features'].append('Money Management')
            if risk_mgmt['has_risk_percent']:
                risk_mgmt['features'].append('Risk Percentage Based')
            if risk_mgmt['has_max_lots']:
                risk_mgmt['features'].append('Maximum Lot Size Limit')
            if risk_mgmt['has_max_orders']:
                risk_mgmt['features'].append('Maximum Order Limit')
            
            return risk_mgmt
        except Exception as e:
            logging.error(f"Error analyzing risk management: {e}")
            return {}
    
    def generate_statistics(self, data, strings):
        """Generate statistics about the analysis"""
        try:
            stats = {
                'file_size_bytes': len(data),
                'file_size_kb': round(len(data) / 1024, 2),
                'total_strings': len(strings),
                'unique_strings': len(set(strings)),
                'has_mz_header': data.startswith(b'MZ'),
                'entropy': self.calculate_entropy(data)
            }
            return stats
        except Exception as e:
            logging.error(f"Error generating statistics: {e}")
            return {}
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of the data"""
        try:
            from collections import Counter
            import math
            
            if not data:
                return 0
            
            # Count byte frequencies
            counts = Counter(data)
            total = len(data)
            
            # Calculate entropy
            entropy = 0
            for count in counts.values():
                probability = count / total
                entropy -= probability * math.log2(probability)
            
            return round(entropy, 4)
        except Exception as e:
            logging.debug(f"Entropy calculation error: {e}")
            return 0

    def generate_pseudocode(self, analysis, language='MQL4'):
        """Generate pseudocode in the specified language format"""
        try:
            generators = {
                'MQL4': self.generate_mql4_code,
                'MQL5': self.generate_mql5_code,
                'Python': self.generate_python_code,
                'C': self.generate_c_code,
                'R': self.generate_r_code,
                'Text': self.generate_text_description
            }
            
            if language in generators:
                return generators[language](analysis)
            else:
                return f"// Error: Unsupported language {language}"
                
        except Exception as e:
            logging.error(f"Error generating {language} pseudocode: {str(e)}", exc_info=True)
            return f"// Error generating {language} pseudocode: {str(e)}"

    def generate_mql4_code(self, analysis):
        """Generate enhanced MQL4 pseudocode with better context"""
        code_lines = []
        
        # Add header with more metadata
        code_lines.append("//+------------------------------------------------------------------+")
        code_lines.append("//|                    Decompiled MQL4 Program                       |")
        code_lines.append("//|                    Type: " + analysis['metadata']['type'].ljust(41) + "|")
        code_lines.append("//|                    Version: " + str(analysis['metadata']['version']).ljust(39) + "|")
        if analysis['metadata'].get('creation_date', 'Unknown') != 'Unknown':
            code_lines.append("//|                    Created: " + str(analysis['metadata']['creation_date']).ljust(38) + "|")
        if analysis['metadata'].get('copyright', 'Unknown') != 'Unknown':
            code_lines.append("//|                    Copyright: " + str(analysis['metadata']['copyright'])[:37].ljust(37) + "|")
        code_lines.append("//+------------------------------------------------------------------+")
        code_lines.append("")
        
        # Add trading strategy comment if detected
        if analysis.get('trading_strategy', {}).get('type', 'Unknown') != 'Unknown':
            code_lines.append(f"// Trading Strategy: {analysis['trading_strategy']['type']}")
            if analysis['trading_strategy'].get('indicators_used'):
                code_lines.append(f"// Indicators: {', '.join(analysis['trading_strategy']['indicators_used'])}")
            code_lines.append("")
        
        # Properties
        if analysis['metadata']['type'] == 'Indicator':
            code_lines.append("#property indicator_separate_window")
            code_lines.append("#property indicator_buffers 1")
            code_lines.append("")
        
        # External parameters - use extracted parameters
        input_params = analysis.get('input_parameters', [])
        if input_params:
            code_lines.append("// Input Parameters (inferred from analysis)")
            for param in input_params:
                code_lines.append(f"extern {param['type']} {param['name']} = {param['default']};")
            code_lines.append("")
        elif 'period' in str(analysis['strings']).lower():
            # Fallback to old method if new extraction didn't work
            code_lines.append("// Input Parameters")
            for string in analysis['strings']:
                if 'period' in string.lower() or 'shift' in string.lower() or 'price' in string.lower():
                    code_lines.append(f"extern int {string} = 0;")
            code_lines.append("")
        
        # Global variables
        if analysis['metadata']['type'] == 'Indicator':
            code_lines.append("// Indicator Buffers")
            code_lines.append("double Buffer1[];")
            code_lines.append("")
        
        # Functions
        code_lines.append("//+------------------------------------------------------------------+")
        code_lines.append("//| Initialization function                                          |")
        code_lines.append("//+------------------------------------------------------------------+")
        code_lines.append("int init()")
        code_lines.append("{")
        if analysis['metadata']['type'] == 'Indicator':
            code_lines.append("    // Setup indicator buffers")
            code_lines.append("    SetIndexStyle(0, DRAW_LINE);")
            code_lines.append("    SetIndexBuffer(0, Buffer1);")
            code_lines.append("    SetIndexLabel(0, \"Main Buffer\");")
        code_lines.append("    return(0);")
        code_lines.append("}")
        code_lines.append("")
        
        code_lines.append("//+------------------------------------------------------------------+")
        code_lines.append("//| Deinitialization function                                        |")
        code_lines.append("//+------------------------------------------------------------------+")
        code_lines.append("int deinit()")
        code_lines.append("{")
        code_lines.append("    return(0);")
        code_lines.append("}")
        code_lines.append("")
        
        # Main function with enhanced pattern detection
        code_lines.append("//+------------------------------------------------------------------+")
        if analysis['metadata']['type'] == 'Expert Advisor':
            code_lines.append("//| Expert tick function (called on every tick)                     |")
            code_lines.append("//+------------------------------------------------------------------+")
            code_lines.append("void OnTick()")
        else:
            code_lines.append("//| Custom indicator iteration function                              |")
            code_lines.append("//+------------------------------------------------------------------+")
            code_lines.append("int start()")
        code_lines.append("{")
        
        # Add detected indicators calculations
        indicators_used = analysis.get('trading_strategy', {}).get('indicators_used', [])
        if 'Moving Average' in indicators_used:
            code_lines.append("    // Moving Average calculation (detected)")
            code_lines.append("    double ma = iMA(Symbol(), Period(), 14, 0, MODE_SMA, PRICE_CLOSE, 0);")
        if 'RSI' in indicators_used:
            code_lines.append("    // RSI calculation (detected)")
            code_lines.append("    double rsi = iRSI(Symbol(), Period(), 14, PRICE_CLOSE, 0);")
        if 'MACD' in indicators_used:
            code_lines.append("    // MACD calculation (detected)")
            code_lines.append("    double macd = iMACD(Symbol(), Period(), 12, 26, 9, PRICE_CLOSE, MODE_MAIN, 0);")
        if 'ATR' in indicators_used:
            code_lines.append("    // ATR calculation (detected)")
            code_lines.append("    double atr = iATR(Symbol(), Period(), 14, 0);")
        if 'Bollinger Bands' in indicators_used:
            code_lines.append("    // Bollinger Bands calculation (detected)")
            code_lines.append("    double bb_upper = iBands(Symbol(), Period(), 20, 2, 0, PRICE_CLOSE, MODE_UPPER, 0);")
            code_lines.append("    double bb_lower = iBands(Symbol(), Period(), 20, 2, 0, PRICE_CLOSE, MODE_LOWER, 0);")
        
        # Add trading logic for EA
        if analysis['metadata']['type'] == 'Expert Advisor':
            code_lines.append("")
            code_lines.append("    // Trading logic (pattern detected)")
            
            # Check risk management
            risk_mgmt = analysis.get('risk_management', {})
            if risk_mgmt.get('has_stop_loss') or risk_mgmt.get('has_take_profit'):
                code_lines.append("    // Risk management parameters")
                if risk_mgmt.get('has_stop_loss'):
                    code_lines.append("    double stopLoss = 50 * Point;  // Adjust as needed")
                if risk_mgmt.get('has_take_profit'):
                    code_lines.append("    double takeProfit = 100 * Point;  // Adjust as needed")
            
            code_lines.append("    ")
            code_lines.append("    // Check for entry conditions")
            code_lines.append("    if(OrdersTotal() < 1) {")
            code_lines.append("        // Entry logic based on detected strategy")
            
            for pattern in analysis['patterns']:
                if 'Trading Function' in pattern['type']:
                    code_lines.append("        int ticket = OrderSend(Symbol(), OP_BUY, 0.1, Ask, 3, 0, 0, \"Auto Trade\", 0, 0, clrGreen);")
                    code_lines.append("        if(ticket > 0) {")
                    code_lines.append("            Print(\"Order opened successfully: \", ticket);")
                    code_lines.append("        }")
                    break
            
            code_lines.append("    }")
        
        if analysis['metadata']['type'] != 'Expert Advisor':
            code_lines.append("    return(0);")
        code_lines.append("}")
        
        return "\n".join(code_lines)

    def generate_mql5_code(self, analysis):
        """Generate MQL5 pseudocode"""
        code_lines = []
        
        # Add header
        code_lines.append("//+------------------------------------------------------------------+")
        code_lines.append("//|                    Decompiled MQL5 Program                       |")
        code_lines.append("//|                    Type: " + analysis['metadata']['type'].ljust(41) + "|")
        code_lines.append("//|                    Version: " + str(analysis['metadata']['version']).ljust(39) + "|")
        code_lines.append("//+------------------------------------------------------------------+")
        code_lines.append("")
        
        # Include necessary files
        code_lines.append("#include <Trade/Trade.mqh>")
        code_lines.append("#include <Indicators/Indicators.mqh>")
        code_lines.append("")
        
        # Class definition
        class_name = os.path.splitext(os.path.basename(analysis.get('filepath', 'Unknown')))[0]
        if analysis['metadata']['type'] == 'Expert Advisor':
            code_lines.append(f"class {class_name} : public CExpertAdvisor")
        else:
            code_lines.append(f"class {class_name} : public CIndicator")
        code_lines.append("{")
        code_lines.append("private:")
        code_lines.append("    CTrade  m_trade;      // Trading object")
        
        # Add detected indicators as members
        for pattern in analysis['patterns']:
            if 'MQL5' in pattern['type']:
                if 'Moving Average' in pattern['type']:
                    code_lines.append("    CiMA    m_ma;         // Moving Average indicator")
                elif 'RSI' in pattern['type']:
                    code_lines.append("    CiRSI   m_rsi;        // RSI indicator")
        
        code_lines.append("")
        code_lines.append("public:")
        
        # Input parameters
        externals_found = False
        for string in analysis['strings']:
            if 'period' in string.lower() or 'shift' in string.lower() or 'price' in string.lower():
                if not externals_found:
                    code_lines.append("    // Input Parameters")
                    externals_found = True
                code_lines.append(f"    input int {string} = 0;")
        
        if externals_found:
            code_lines.append("")
        
        # Constructor
        code_lines.append(f"    {class_name}(void);")
        code_lines.append(f"    ~{class_name}(void);")
        code_lines.append("")
        
        # Virtual functions
        code_lines.append("    virtual bool      Init(void);")
        code_lines.append("    virtual void      Deinit(void);")
        if analysis['metadata']['type'] == 'Expert Advisor':
            code_lines.append("    virtual void      OnTick(void);")
        else:
            code_lines.append("    virtual int       Calculate(const int rates_total,")
            code_lines.append("                               const int prev_calculated,")
            code_lines.append("                               const datetime &time[],")
            code_lines.append("                               const double &open[],")
            code_lines.append("                               const double &high[],")
            code_lines.append("                               const double &low[],")
            code_lines.append("                               const double &close[],")
            code_lines.append("                               const long &tick_volume[],")
            code_lines.append("                               const long &volume[],")
            code_lines.append("                               const int &spread[]);")
        
        code_lines.append("};")
        code_lines.append("")
        
        # Implementation
        code_lines.append(f"{class_name}::{class_name}(void)")
        code_lines.append("{")
        code_lines.append("}")
        code_lines.append("")
        
        code_lines.append(f"{class_name}::~{class_name}(void)")
        code_lines.append("{")
        code_lines.append("}")
        code_lines.append("")
        
        code_lines.append(f"bool {class_name}::Init(void)")
        code_lines.append("{")
        # Initialize detected indicators
        for pattern in analysis['patterns']:
            if 'MQL5' in pattern['type']:
                if 'Moving Average' in pattern['type']:
                    code_lines.append("    if(!m_ma.Create(_Symbol, PERIOD_CURRENT, 14, 0, MODE_SMA, PRICE_CLOSE))")
                    code_lines.append("        return(false);")
                elif 'RSI' in pattern['type']:
                    code_lines.append("    if(!m_rsi.Create(_Symbol, PERIOD_CURRENT, 14, PRICE_CLOSE))")
                    code_lines.append("        return(false);")
        code_lines.append("    return(true);")
        code_lines.append("}")
        code_lines.append("")
        
        code_lines.append(f"void {class_name}::Deinit(void)")
        code_lines.append("{")
        code_lines.append("}")
        code_lines.append("")
        
        # Main function
        if analysis['metadata']['type'] == 'Expert Advisor':
            code_lines.append(f"void {class_name}::OnTick(void)")
            code_lines.append("{")
            
            # Add detected trading patterns
            for pattern in analysis['patterns']:
                if 'MQL5' in pattern['type'] and 'Trading' in pattern['type']:
                    code_lines.append("    if(PositionsTotal() < 1) {")
                    code_lines.append("        m_trade.Buy(0.1, _Symbol);")
                    code_lines.append("    }")
            
            code_lines.append("}")
        else:
            code_lines.append(f"int {class_name}::Calculate(const int rates_total,")
            code_lines.append("                          const int prev_calculated,")
            code_lines.append("                          const datetime &time[],")
            code_lines.append("                          const double &open[],")
            code_lines.append("                          const double &high[],")
            code_lines.append("                          const double &low[],")
            code_lines.append("                          const double &close[],")
            code_lines.append("                          const long &tick_volume[],")
            code_lines.append("                          const long &volume[],")
            code_lines.append("                          const int &spread[])")
            code_lines.append("{")
            code_lines.append("    if(rates_total < 1)")
            code_lines.append("        return(0);")
            code_lines.append("")
            code_lines.append("    return(rates_total);")
            code_lines.append("}")
        
        return "\n".join(code_lines)

    def generate_python_code(self, analysis):
        """Generate enhanced Python equivalent code"""
        code_lines = []
        
        # Add header with more metadata
        code_lines.append('"""')
        code_lines.append(f"Converted from MT4/MT5 {analysis['metadata']['type']}")
        code_lines.append(f"Version: {analysis['metadata']['version']}")
        if analysis['metadata'].get('creation_date', 'Unknown') != 'Unknown':
            code_lines.append(f"Created: {analysis['metadata']['creation_date']}")
        if analysis['metadata'].get('copyright', 'Unknown') != 'Unknown':
            code_lines.append(f"Copyright: {analysis['metadata']['copyright']}")
        
        # Add strategy info
        strategy = analysis.get('trading_strategy', {})
        if strategy.get('type', 'Unknown') != 'Unknown':
            code_lines.append(f"\nTrading Strategy: {strategy['type']}")
        if strategy.get('indicators_used'):
            code_lines.append(f"Indicators: {', '.join(strategy['indicators_used'])}")
        
        code_lines.append('"""')
        code_lines.append("")
        
        # Imports - enhanced
        code_lines.append("import numpy as np")
        code_lines.append("import pandas as pd")
        code_lines.append("from datetime import datetime")
        code_lines.append("from typing import Dict, List, Optional")
        code_lines.append("")
        
        # Class definition
        class_name = 'TradingIndicator' if analysis['metadata']['type'] == 'Indicator' else 'TradingExpert'
        if analysis.get('filepath'):
            class_name = os.path.splitext(os.path.basename(analysis['filepath']))[0]
        
        code_lines.append(f"class {class_name}:")
        code_lines.append(f'    """')
        code_lines.append(f'    {analysis["metadata"]["type"]} implementation in Python')
        code_lines.append(f'    """')
        code_lines.append("")
        
        # Constructor with parameters
        code_lines.append("    def __init__(self,")
        
        # Add input parameters
        input_params = analysis.get('input_parameters', [])
        if input_params:
            for i, param in enumerate(input_params):
                param_type = 'float' if param['type'] == 'double' else 'int'
                comma = ',' if i < len(input_params) - 1 else ''
                code_lines.append(f"                 {param['name'].lower()}: {param_type} = {param['default']}{comma}")
        else:
            code_lines[-1] = "    def __init__(self):"
        
        if input_params:
            code_lines.append("                 ):")
        
        code_lines.append("        # Initialize data storage")
        code_lines.append("        self.data: pd.DataFrame = pd.DataFrame()")
        code_lines.append("        self.indicators: Dict[str, pd.Series] = {}")
        code_lines.append("        ")
        code_lines.append("        # Store parameters")
        
        if input_params:
            for param in input_params:
                code_lines.append(f"        self.{param['name'].lower()} = {param['name'].lower()}")
        else:
            code_lines.append("        # No parameters detected")
        
        code_lines.append("")
        
        # Initialize method
        code_lines.append("    def initialize(self, data: pd.DataFrame) -> bool:")
        code_lines.append('        """Initialize with historical price data"""')
        code_lines.append("        if data.empty:")
        code_lines.append("            return False")
        code_lines.append("        ")
        code_lines.append("        self.data = data")
        code_lines.append("        self.calculate_indicators()")
        code_lines.append("        return True")
        code_lines.append("")
        
        # Calculate indicators - enhanced
        code_lines.append("    def calculate_indicators(self) -> None:")
        code_lines.append('        """Calculate all technical indicators"""')
        
        indicators_used = analysis.get('trading_strategy', {}).get('indicators_used', [])
        if 'Moving Average' in indicators_used:
            code_lines.append("        # Moving Average (detected)")
            code_lines.append("        if 'close' in self.data.columns:")
            code_lines.append("            period = getattr(self, 'period', 14)")
            code_lines.append("            self.indicators['ma'] = self.data['close'].rolling(window=period).mean()")
            code_lines.append("")
        
        if 'RSI' in indicators_used:
            code_lines.append("        # Relative Strength Index (detected)")
            code_lines.append("        if 'close' in self.data.columns:")
            code_lines.append("            period = getattr(self, 'period', 14)")
            code_lines.append("            delta = self.data['close'].diff()")
            code_lines.append("            gain = (delta.where(delta > 0, 0)).rolling(window=period).mean()")
            code_lines.append("            loss = (-delta.where(delta < 0, 0)).rolling(window=period).mean()")
            code_lines.append("            rs = gain / loss")
            code_lines.append("            self.indicators['rsi'] = 100 - (100 / (1 + rs))")
            code_lines.append("")
        
        if 'MACD' in indicators_used:
            code_lines.append("        # MACD (detected)")
            code_lines.append("        if 'close' in self.data.columns:")
            code_lines.append("            exp1 = self.data['close'].ewm(span=12, adjust=False).mean()")
            code_lines.append("            exp2 = self.data['close'].ewm(span=26, adjust=False).mean()")
            code_lines.append("            self.indicators['macd'] = exp1 - exp2")
            code_lines.append("            self.indicators['macd_signal'] = self.indicators['macd'].ewm(span=9, adjust=False).mean()")
            code_lines.append("")
        
        if 'ATR' in indicators_used:
            code_lines.append("        # Average True Range (detected)")
            code_lines.append("        if all(col in self.data.columns for col in ['high', 'low', 'close']):")
            code_lines.append("            high_low = self.data['high'] - self.data['low']")
            code_lines.append("            high_close = np.abs(self.data['high'] - self.data['close'].shift())")
            code_lines.append("            low_close = np.abs(self.data['low'] - self.data['close'].shift())")
            code_lines.append("            true_range = pd.concat([high_low, high_close, low_close], axis=1).max(axis=1)")
            code_lines.append("            period = getattr(self, 'period', 14)")
            code_lines.append("            self.indicators['atr'] = true_range.rolling(window=period).mean()")
            code_lines.append("")
        
        if 'Bollinger Bands' in indicators_used:
            code_lines.append("        # Bollinger Bands (detected)")
            code_lines.append("        if 'close' in self.data.columns:")
            code_lines.append("            period = getattr(self, 'period', 20)")
            code_lines.append("            sma = self.data['close'].rolling(window=period).mean()")
            code_lines.append("            std = self.data['close'].rolling(window=period).std()")
            code_lines.append("            self.indicators['bb_upper'] = sma + (std * 2)")
            code_lines.append("            self.indicators['bb_middle'] = sma")
            code_lines.append("            self.indicators['bb_lower'] = sma - (std * 2)")
            code_lines.append("")
        
        if not indicators_used:
            code_lines.append("        # No specific indicators detected")
            code_lines.append("        pass")
        
        code_lines.append("")
        
        # Main processing method
        if analysis['metadata']['type'] == 'Expert Advisor':
            code_lines.append("    def on_tick(self) -> Optional[Dict]:")
            code_lines.append('        """Process each new price tick"""')
            code_lines.append("        if self.data.empty:")
            code_lines.append("            return None")
            code_lines.append("        ")
            code_lines.append("        # Update indicators")
            code_lines.append("        self.calculate_indicators()")
            code_lines.append("        ")
            code_lines.append("        # Trading logic (customize based on your strategy)")
            code_lines.append("        signal = {")
            code_lines.append("            'action': None,  # 'buy', 'sell', or None")
            code_lines.append("            'price': self.data['close'].iloc[-1],")
            code_lines.append("            'timestamp': datetime.now()")
            code_lines.append("        }")
            code_lines.append("        ")
            code_lines.append("        # Example: Simple MA crossover logic")
            code_lines.append("        if 'ma' in self.indicators and len(self.indicators['ma']) > 1:")
            code_lines.append("            # Add your trading logic here")
            code_lines.append("            pass")
            code_lines.append("        ")
            code_lines.append("        return signal")
        else:
            code_lines.append("    def calculate(self) -> pd.DataFrame:")
            code_lines.append('        """Calculate indicator values"""')
            code_lines.append("        self.calculate_indicators()")
            code_lines.append("        return pd.DataFrame(self.indicators)")
        
        code_lines.append("")
        code_lines.append("    def get_latest_values(self) -> Dict:")
        code_lines.append('        """Get the latest indicator values"""')
        code_lines.append("        return {name: values.iloc[-1] if not values.empty else None")
        code_lines.append("                for name, values in self.indicators.items()}")
        
        return "\n".join(code_lines)

    def generate_c_code(self, analysis):
        """Generate C equivalent code"""
        code_lines = []
        
        # Add header
        code_lines.append("/*")
        code_lines.append(f" * Converted from MT4/MT5 {analysis['metadata']['type']}")
        code_lines.append(f" * Version: {analysis['metadata']['version']}")
        code_lines.append(" */")
        code_lines.append("")
        
        # Includes
        code_lines.append("#include <stdio.h>")
        code_lines.append("#include <stdlib.h>")
        code_lines.append("#include <string.h>")
        code_lines.append("#include <math.h>")
        code_lines.append("")
        
        # Structs
        code_lines.append("typedef struct {")
        code_lines.append("    double open;")
        code_lines.append("    double high;")
        code_lines.append("    double low;")
        code_lines.append("    double close;")
        code_lines.append("    long volume;")
        code_lines.append("} PRICE_BAR;")
        code_lines.append("")
        
        # Input parameters
        for string in analysis['strings']:
            if 'period' in string.lower() or 'shift' in string.lower() or 'price' in string.lower():
                code_lines.append(f"int {string} = 0;")
        
        code_lines.append("")
        
        # Function prototypes
        code_lines.append("int initialize(void);")
        code_lines.append("int process_tick(PRICE_BAR *bars, int total_bars);")
        code_lines.append("double calculate_ma(PRICE_BAR *bars, int total_bars, int period);")
        code_lines.append("double calculate_rsi(PRICE_BAR *bars, int total_bars, int period);")
        code_lines.append("")
        
        # Initialize function
        code_lines.append("int initialize(void) {")
        code_lines.append("    return 1;")
        code_lines.append("}")
        code_lines.append("")
        
        # Main processing function
        code_lines.append("int process_tick(PRICE_BAR *bars, int total_bars) {")
        code_lines.append("    if (total_bars < 1) return 0;")
        code_lines.append("")
        
        # Add detected patterns
        for pattern in analysis['patterns']:
            if 'Moving Average' in pattern['type']:
                code_lines.append("    // Calculate Moving Average")
                code_lines.append("    double ma = calculate_ma(bars, total_bars, 14);")
            elif 'RSI' in pattern['type']:
                code_lines.append("    // Calculate RSI")
                code_lines.append("    double rsi = calculate_rsi(bars, total_bars, 14);")
        
        code_lines.append("    return 1;")
        code_lines.append("}")
        
        return "\n".join(code_lines)

    def generate_r_code(self, analysis):
        """Generate R equivalent code"""
        code_lines = []
        
        # Add header comments
        code_lines.append("# Converted from MT4/MT5 {analysis['metadata']['type']}")
        code_lines.append(f"# Version: {analysis['metadata']['version']}")
        code_lines.append("")
        
        # Required libraries
        code_lines.append("library(quantmod)")
        code_lines.append("library(TTR)")
        code_lines.append("library(xts)")
        code_lines.append("")
        
        # Create main function
        class_name = os.path.splitext(os.path.basename(analysis.get('filepath', 'Unknown')))[0]
        code_lines.append(f"{class_name} <- function(data) {{")
        
        # Input parameters
        params_found = False
        for string in analysis['strings']:
            if 'period' in string.lower() or 'shift' in string.lower() or 'price' in string.lower():
                if not params_found:
                    code_lines.append("    # Input Parameters")
                    params_found = True
                code_lines.append(f"    {string} <- 0")
        
        code_lines.append("")
        code_lines.append("    # Initialize indicators list")
        code_lines.append("    indicators <- list()")
        code_lines.append("")
        
        # Calculate indicators
        code_lines.append("    # Calculate indicators")
        for pattern in analysis['patterns']:
            if 'Moving Average' in pattern['type']:
                code_lines.append("    # Moving Average")
                code_lines.append("    indicators$ma <- SMA(Cl(data), n=14)")
            elif 'RSI' in pattern['type']:
                code_lines.append("    # RSI")
                code_lines.append("    indicators$rsi <- RSI(Cl(data), n=14)")
        
        code_lines.append("")
        code_lines.append("    # Return results")
        code_lines.append("    return(indicators)")
        code_lines.append("}")
        code_lines.append("")
        
        # Add usage example
        code_lines.append("# Usage example:")
        code_lines.append("# data <- getSymbols('AAPL', auto.assign=FALSE)")
        code_lines.append(f"# results <- {class_name}(data)")
        
        return "\n".join(code_lines)

    def generate_text_description(self, analysis):
        """Generate comprehensive plain text description of the trading logic"""
        text_lines = []
        
        # Header with file information
        text_lines.append("=" * 70)
        text_lines.append("EX4 FILE ANALYSIS REPORT".center(70))
        text_lines.append("=" * 70)
        text_lines.append("")
        
        # Metadata section
        text_lines.append("FILE INFORMATION")
        text_lines.append("-" * 70)
        text_lines.append(f"Type:           {analysis['metadata']['type']}")
        text_lines.append(f"Version:        {analysis['metadata']['version']}")
        if analysis['metadata'].get('creation_date', 'Unknown') != 'Unknown':
            text_lines.append(f"Created:        {analysis['metadata']['creation_date']}")
        if analysis['metadata'].get('copyright', 'Unknown') != 'Unknown':
            text_lines.append(f"Copyright:      {analysis['metadata']['copyright']}")
        if analysis['metadata'].get('author', 'Unknown') != 'Unknown':
            text_lines.append(f"Author:         {analysis['metadata']['author']}")
        
        # File statistics
        stats = analysis.get('statistics', {})
        if stats:
            text_lines.append(f"File Size:      {stats.get('file_size_kb', 0)} KB ({stats.get('file_size_bytes', 0)} bytes)")
            text_lines.append(f"Entropy:        {stats.get('entropy', 0)} (complexity measure)")
        
        text_lines.append("")
        
        # Strategy information
        strategy = analysis.get('trading_strategy', {})
        if strategy and strategy.get('type', 'Unknown') != 'Unknown':
            text_lines.append("TRADING STRATEGY")
            text_lines.append("-" * 70)
            text_lines.append(f"Strategy Type:  {strategy['type']}")
            
            if strategy.get('timeframes'):
                text_lines.append(f"Timeframes:     {', '.join(strategy['timeframes'])}")
            
            text_lines.append("")
        
        # Input parameters section
        input_params = analysis.get('input_parameters', [])
        if input_params:
            text_lines.append("INPUT PARAMETERS")
            text_lines.append("-" * 70)
            for param in input_params:
                text_lines.append(f"  • {param['name']:<20} ({param['type']}, default: {param['default']})")
            text_lines.append("")
        
        # Technical indicators section
        indicators_used = strategy.get('indicators_used', []) if strategy else []
        if indicators_used:
            text_lines.append("TECHNICAL INDICATORS")
            text_lines.append("-" * 70)
            for indicator in indicators_used:
                text_lines.append(f"  • {indicator}")
                
                # Add descriptions for each indicator
                if 'Moving Average' in indicator:
                    text_lines.append("    Purpose: Identifies trend direction and support/resistance levels")
                elif 'RSI' in indicator:
                    text_lines.append("    Purpose: Measures overbought/oversold conditions (0-100 scale)")
                elif 'MACD' in indicator:
                    text_lines.append("    Purpose: Momentum and trend-following indicator")
                elif 'ATR' in indicator:
                    text_lines.append("    Purpose: Volatility measurement for stop-loss placement")
                elif 'Bollinger Bands' in indicator:
                    text_lines.append("    Purpose: Price volatility and potential reversal zones")
                elif 'Stochastic' in indicator:
                    text_lines.append("    Purpose: Momentum indicator comparing closing price to range")
            
            text_lines.append("")
        
        # Risk management section
        risk_mgmt = analysis.get('risk_management', {})
        if risk_mgmt and risk_mgmt.get('features'):
            text_lines.append("RISK MANAGEMENT")
            text_lines.append("-" * 70)
            for feature in risk_mgmt['features']:
                text_lines.append(f"  ✓ {feature}")
            text_lines.append("")
        
        # Entry and exit patterns
        if strategy:
            if strategy.get('entry_patterns'):
                text_lines.append("ENTRY PATTERNS")
                text_lines.append("-" * 70)
                for pattern in strategy['entry_patterns']:
                    text_lines.append(f"  • {pattern}")
                text_lines.append("")
            
            if strategy.get('exit_patterns'):
                text_lines.append("EXIT PATTERNS")
                text_lines.append("-" * 70)
                for pattern in strategy['exit_patterns']:
                    text_lines.append(f"  • {pattern}")
                text_lines.append("")
        
        # Functions detected
        functions = analysis.get('functions', [])
        if functions:
            text_lines.append("DETECTED FUNCTIONS")
            text_lines.append("-" * 70)
            for func in functions:
                text_lines.append(f"  • {func}()")
            text_lines.append("")
        
        # Operation logic
        text_lines.append("OPERATIONAL LOGIC")
        text_lines.append("-" * 70)
        if analysis['metadata']['type'] == 'Expert Advisor':
            text_lines.append("This Expert Advisor operates as follows:")
            text_lines.append("")
            text_lines.append("1. INITIALIZATION (OnInit)")
            text_lines.append("   - Sets up input parameters")
            if indicators_used:
                text_lines.append("   - Initializes technical indicators:")
                for ind in indicators_used[:3]:  # Show first 3
                    text_lines.append(f"     * {ind}")
            if risk_mgmt.get('features'):
                text_lines.append("   - Configures risk management:")
                for feat in risk_mgmt['features'][:2]:  # Show first 2
                    text_lines.append(f"     * {feat}")
            text_lines.append("")
            
            text_lines.append("2. TICK PROCESSING (OnTick)")
            text_lines.append("   - Updates all indicator values")
            text_lines.append("   - Analyzes current market conditions")
            if strategy.get('entry_patterns'):
                text_lines.append("   - Checks entry conditions")
            if strategy.get('exit_patterns'):
                text_lines.append("   - Manages existing positions")
            text_lines.append("   - Executes trading decisions")
            text_lines.append("")
            
            text_lines.append("3. CLEANUP (OnDeinit)")
            text_lines.append("   - Releases resources")
            text_lines.append("   - Saves final state")
        else:
            text_lines.append("This Indicator operates as follows:")
            text_lines.append("")
            text_lines.append("1. INITIALIZATION")
            text_lines.append("   - Sets up indicator buffers")
            text_lines.append("   - Configures drawing styles")
            text_lines.append("")
            text_lines.append("2. CALCULATION")
            text_lines.append("   - Processes historical price data")
            if indicators_used:
                text_lines.append("   - Calculates indicator values")
            text_lines.append("   - Updates display buffers")
            text_lines.append("")
            text_lines.append("3. VISUALIZATION")
            text_lines.append("   - Draws indicator lines on chart")
            text_lines.append("   - Updates in real-time with new price data")
        
        text_lines.append("")
        
        # Analysis summary
        text_lines.append("ANALYSIS SUMMARY")
        text_lines.append("-" * 70)
        text_lines.append(f"Total Patterns Found:     {len(analysis.get('patterns', []))}")
        text_lines.append(f"String Extracted:         {stats.get('total_strings', 0)}")
        text_lines.append(f"Functions Identified:     {len(functions)}")
        text_lines.append(f"Indicators Used:          {len(indicators_used)}")
        text_lines.append("")
        
        # Limitations notice
        text_lines.append("IMPORTANT NOTES")
        text_lines.append("-" * 70)
        text_lines.append("• This analysis is based on pattern recognition and may not be 100% accurate")
        text_lines.append("• Original variable names and comments cannot be recovered")
        text_lines.append("• Generated code templates require manual review and adjustment")
        text_lines.append("• Always test thoroughly before using in live trading")
        text_lines.append("")
        text_lines.append("=" * 70)
        
        return "\n".join(text_lines)

class DebugDecompilerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("EX4 Multi-Language Trading Code Converter")
        self.root.geometry("1280x850")
        self.root.minsize(1024, 700)
        
        self.analyzer = MT4Analyzer()
        self.setup_styles()
        self.setup_gui()
        
    def setup_styles(self):
        """Configure modern ttk styles"""
        style = ttk.Style()
        
        # Configure colors - Modern blue theme
        bg_color = '#f0f0f0'
        accent_color = '#0078d4'
        hover_color = '#106ebe'
        
        # Configure button style
        style.configure('Modern.TButton',
                       padding=(15, 8),
                       relief='flat',
                       borderwidth=0,
                       font=('Segoe UI', 10))
        
        # Configure label style
        style.configure('Title.TLabel',
                       font=('Segoe UI', 16, 'bold'),
                       padding=10)
        
        style.configure('Subtitle.TLabel',
                       font=('Segoe UI', 10),
                       foreground='#666666',
                       padding=(5, 2))
        
        style.configure('Status.TLabel',
                       font=('Segoe UI', 9),
                       padding=(10, 5),
                       background='#e8e8e8')
        
        # Configure frame styles
        style.configure('Header.TFrame',
                       background='white',
                       relief='flat')
        
        style.configure('Control.TFrame',
                       background='#f8f8f8',
                       padding=10,
                       relief='solid',
                       borderwidth=1)
        
    def setup_gui(self):
        # Configure grid weights for responsiveness
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="0")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Header section
        header_frame = ttk.Frame(main_frame, style='Header.TFrame')
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=0, pady=0)
        
        title_label = ttk.Label(header_frame, 
                               text="EX4 Multi-Language Converter",
                               style='Title.TLabel')
        title_label.pack(pady=(15, 5))
        
        subtitle_label = ttk.Label(header_frame,
                                   text="Convert MetaTrader 4 EX4 files to MQL4, MQL5, Python, C, R, or readable text",
                                   style='Subtitle.TLabel')
        subtitle_label.pack(pady=(0, 15))
        
        # Control panel
        control_frame = ttk.Frame(main_frame, style='Control.TFrame')
        control_frame.grid(row=1, column=0, pady=(10, 5), padx=15, sticky=(tk.W, tk.E))
        
        # Language selection with label
        lang_container = ttk.Frame(control_frame)
        lang_container.pack(side=tk.LEFT, padx=(0, 15))
        
        ttk.Label(lang_container, text="Target Language:", 
                 font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=(0, 8))
        
        self.language_var = tk.StringVar(value="MQL4")
        language_combo = ttk.Combobox(lang_container, 
                                     textvariable=self.language_var, 
                                     values=["MQL4", "MQL5", "Python", "C", "R", "Text"], 
                                     state="readonly",
                                     width=12,
                                     font=('Segoe UI', 10))
        language_combo.pack(side=tk.LEFT)
        language_combo.bind('<<ComboboxSelected>>', self.on_language_change)
        
        # Buttons with modern styling
        btn_container = ttk.Frame(control_frame)
        btn_container.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.open_btn = ttk.Button(btn_container, 
                                   text="Select EX4 File", 
                                   command=self.select_file,
                                   style='Modern.TButton')
        self.open_btn.pack(side=tk.LEFT, padx=5)
        
        self.save_analysis_btn = ttk.Button(btn_container, 
                                           text="Save Analysis", 
                                           command=self.save_analysis,
                                           style='Modern.TButton')
        self.save_analysis_btn.pack(side=tk.LEFT, padx=5)
        self.save_analysis_btn.state(['disabled'])
        
        self.save_code_btn = ttk.Button(btn_container, 
                                       text="Save Code", 
                                       command=self.save_pseudocode,
                                       style='Modern.TButton')
        self.save_code_btn.pack(side=tk.LEFT, padx=5)
        self.save_code_btn.state(['disabled'])

        # Content area with notebook
        content_frame = ttk.Frame(main_frame)
        content_frame.grid(row=2, column=0, pady=(5, 0), padx=15, sticky=(tk.W, tk.E, tk.N, tk.S))
        content_frame.columnconfigure(0, weight=1)
        content_frame.rowconfigure(0, weight=1)
        
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Analysis tab with better formatting
        self.analysis_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.analysis_frame, text="Analysis")
        
        self.analysis_text = scrolledtext.ScrolledText(
            self.analysis_frame, 
            width=100, 
            height=35,
            font=('Consolas', 10),
            wrap=tk.WORD,
            background='#ffffff',
            padx=10,
            pady=10
        )
        self.analysis_text.pack(expand=True, fill='both')
        
        # Pseudocode tab
        self.pseudo_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.pseudo_frame, text="Generated Code")
        
        self.pseudo_text = scrolledtext.ScrolledText(
            self.pseudo_frame, 
            width=100, 
            height=35,
            font=('Consolas', 10),
            wrap=tk.NONE,
            background='#ffffff',
            padx=10,
            pady=10
        )
        self.pseudo_text.pack(expand=True, fill='both')
        
        # Debug log tab
        self.debug_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.debug_frame, text="Debug Log")
        
        self.debug_text = scrolledtext.ScrolledText(
            self.debug_frame, 
            width=100, 
            height=35,
            font=('Consolas', 9),
            wrap=tk.WORD,
            background='#1e1e1e',
            foreground='#d4d4d4',
            padx=10,
            pady=10
        )
        self.debug_text.pack(expand=True, fill='both')
        
        # Status bar with modern styling
        status_frame = ttk.Frame(main_frame, style='Status.TLabel')
        status_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), padx=0, pady=0)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - Select an EX4 file to begin")
        
        status_bar = ttk.Label(status_frame, 
                              textvariable=self.status_var,
                              style='Status.TLabel')
        status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.current_analysis = None
        self.current_pseudocode = None
        
        # Configure logging to GUI
        self.setup_logging()
        
    def on_language_change(self, event=None):
        """Handle language selection change"""
        if self.current_analysis:
            self.status_var.set(f"⏳ Regenerating code in {self.language_var.get()}...")
            self.root.update()
            
            try:
                self.current_pseudocode = self.analyzer.generate_pseudocode(
                    self.current_analysis, 
                    self.language_var.get()
                )
                self.pseudo_text.delete(1.0, tk.END)
                self.pseudo_text.insert(tk.END, self.current_pseudocode)
                self.status_var.set(f"✓ Code regenerated in {self.language_var.get()}")
            except Exception as e:
                logging.error(f"Error regenerating code: {str(e)}", exc_info=True)
                self.status_var.set(f"✗ Error regenerating code: {str(e)}")

    def setup_logging(self):
        class TextHandler(logging.Handler):
            def __init__(self, text_widget):
                logging.Handler.__init__(self)
                self.text_widget = text_widget
                
            def emit(self, record):
                msg = self.format(record) + '\n'
                self.text_widget.insert(tk.END, msg)
                self.text_widget.see(tk.END)
                
        handler = TextHandler(self.debug_text)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(handler)
        
    def select_file(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("EX4 files", "*.ex4"), ("All files", "*.*")]
        )
        if filepath:
            self.analyze_file(filepath)
            
    def analyze_file(self, filepath):
        self.status_var.set(f"⏳ Analyzing {os.path.basename(filepath)}...")
        self.root.update()
        
        try:
            # Clear previous content
            self.analysis_text.delete(1.0, tk.END)
            self.pseudo_text.delete(1.0, tk.END)
            self.debug_text.delete(1.0, tk.END)
            
            # Perform analysis
            logging.info(f"Starting analysis of {filepath}")
            analysis = self.analyzer.analyze_file(filepath)
            analysis['filepath'] = filepath  # Add filepath for MQL5 class name
            
            # Store current analysis
            self.current_analysis = analysis
            
            # Generate and store pseudocode
            self.current_pseudocode = self.analyzer.generate_pseudocode(analysis, self.language_var.get())
            
            # Display results
            self.analysis_text.insert(tk.END, json.dumps(analysis, indent=2))
            self.pseudo_text.insert(tk.END, self.current_pseudocode)
            
            # Enable save buttons
            self.save_analysis_btn.state(['!disabled'])
            self.save_code_btn.state(['!disabled'])
            
            self.status_var.set(f"✓ Analysis complete - {os.path.basename(filepath)}")
            
        except Exception as e:
            error_msg = f"Error during analysis: {str(e)}"
            logging.error(error_msg, exc_info=True)
            self.status_var.set(f"✗ {error_msg}")

    def save_pseudocode(self):
        if not self.current_pseudocode:
            self.status_var.set("⚠ No code to save")
            return
            
        # Define file extensions for each language
        extensions = {
            'MQL4': '.mq4',
            'MQL5': '.mq5',
            'Python': '.py',
            'C': '.c',
            'R': '.R',
            'Text': '.txt'
        }
        
        # Get current language and extension
        current_lang = self.language_var.get()
        extension = extensions.get(current_lang, '.txt')
        
        # Create file type list for dialog
        filetypes = [
            ("MQL4 files", "*.mq4"),
            ("MQL5 files", "*.mq5"),
            ("Python files", "*.py"),
            ("C files", "*.c"),
            ("R files", "*.R"),
            ("Text files", "*.txt"),
            ("All files", "*.*")
        ]
        
        filepath = filedialog.asksaveasfilename(
            title=f"Save {current_lang} Code",
            defaultextension=extension,
            filetypes=filetypes
        )
        
        if filepath:
            try:
                with open(filepath, 'w') as f:
                    f.write(self.current_pseudocode)
                self.status_var.set(f"✓ Code saved to {os.path.basename(filepath)}")
            except Exception as e:
                error_msg = f"Error saving file: {str(e)}"
                logging.error(error_msg, exc_info=True)
                self.status_var.set(f"✗ {error_msg}")
                
    def save_analysis(self):
        if not self.current_analysis:
            self.status_var.set("⚠ No analysis to save")
            return
            
        filepath = filedialog.asksaveasfilename(
            title="Save Analysis as JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filepath:
            try:
                with open(filepath, 'w') as f:
                    json.dump(self.current_analysis, f, indent=2)
                self.status_var.set(f"✓ Analysis saved to {os.path.basename(filepath)}")
            except Exception as e:
                error_msg = f"Error saving analysis: {str(e)}"
                logging.error(error_msg)
                self.status_var.set(f"✗ {error_msg}")

def main():
    root = tk.Tk()
    app = DebugDecompilerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
