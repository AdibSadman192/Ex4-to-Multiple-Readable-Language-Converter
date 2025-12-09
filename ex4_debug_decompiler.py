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
            
            # MQL4 specific patterns
            b'OrderSend': 'MQL4 Trading Function',
            b'iCustom': 'MQL4 Custom Indicator',
            b'iMA': 'MQL4 Moving Average',
            b'iRSI': 'MQL4 RSI',
            b'iATR': 'MQL4 ATR',
            
            # MQL5 specific patterns
            b'CTrade': 'MQL5 Trading Class',
            b'CCustomInd': 'MQL5 Custom Indicator',
            b'CiMA': 'MQL5 Moving Average',
            b'CiRSI': 'MQL5 RSI',
            b'CiATR': 'MQL5 ATR'
        }

    def analyze_file(self, filepath):
        """Analyze an EX4 file with detailed error reporting"""
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
            
            analysis = {
                'metadata': self.extract_metadata(data),
                'patterns': self.find_patterns(data),
                'strings': self.extract_strings(data),
                'functions': self.identify_functions(data)
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
                'functions': []
            }

    def extract_metadata(self, data):
        """Extract basic metadata with error handling"""
        try:
            metadata = {
                'type': 'Unknown',
                'version': 'Unknown',
                'creation_date': 'Unknown'
            }
            
            # Determine type
            if b'indicator' in data.lower():
                metadata['type'] = 'Indicator'
            elif b'expert' in data.lower():
                metadata['type'] = 'Expert Advisor'
            elif b'script' in data.lower():
                metadata['type'] = 'Script'
                
            # Look for version information
            version_match = re.search(b'version[\\s=]+(\\d+\\.\\d+)', data, re.IGNORECASE)
            if version_match:
                metadata['version'] = version_match.group(1).decode('ascii', errors='ignore')
                
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
        """Extract readable strings from the binary"""
        try:
            strings = []
            current = ''
            for byte in data:
                if 32 <= byte <= 126:  # printable ASCII
                    current += chr(byte)
                elif current:
                    if len(current) > 3:  # minimum length
                        strings.append(current)
                    current = ''
                    
            logging.info(f"Extracted {len(strings)} strings")
            return strings
            
        except Exception as e:
            logging.error(f"Error extracting strings: {str(e)}", exc_info=True)
            return []

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
        """Generate MQL4 pseudocode"""
        code_lines = []
        
        # Add header
        code_lines.append("//+------------------------------------------------------------------+")
        code_lines.append("//|                    Decompiled MQL4 Program                       |")
        code_lines.append("//|                    Type: " + analysis['metadata']['type'].ljust(41) + "|")
        code_lines.append("//|                    Version: " + str(analysis['metadata']['version']).ljust(39) + "|")
        code_lines.append("//+------------------------------------------------------------------+")
        code_lines.append("")
        
        # Properties
        if analysis['metadata']['type'] == 'Indicator':
            code_lines.append("#property indicator_separate_window")
            code_lines.append("#property indicator_buffers 1")
            code_lines.append("")
        
        # External parameters
        externals_found = False
        for string in analysis['strings']:
            if 'period' in string.lower() or 'shift' in string.lower() or 'price' in string.lower():
                if not externals_found:
                    code_lines.append("// Input Parameters")
                    externals_found = True
                code_lines.append(f"extern int {string} = 0;")
        
        if externals_found:
            code_lines.append("")
        
        # Global variables
        if analysis['metadata']['type'] == 'Indicator':
            code_lines.append("// Indicator Buffers")
            code_lines.append("double Buffer1[];")
            code_lines.append("")
        
        # Functions
        code_lines.append("int init()")
        code_lines.append("{")
        if analysis['metadata']['type'] == 'Indicator':
            code_lines.append("    SetIndexStyle(0, DRAW_LINE);")
            code_lines.append("    SetIndexBuffer(0, Buffer1);")
        code_lines.append("    return(0);")
        code_lines.append("}")
        code_lines.append("")
        
        code_lines.append("int deinit()")
        code_lines.append("{")
        code_lines.append("    return(0);")
        code_lines.append("}")
        code_lines.append("")
        
        # Main function
        if analysis['metadata']['type'] == 'Expert Advisor':
            code_lines.append("void OnTick()")
        else:
            code_lines.append("int start()")
        code_lines.append("{")
        
        # Add detected patterns
        for pattern in analysis['patterns']:
            if 'MQL4' in pattern['type']:
                if 'Moving Average' in pattern['type']:
                    code_lines.append("    double ma = iMA(Symbol(), Period(), 14, 0, MODE_SMA, PRICE_CLOSE, 0);")
                elif 'RSI' in pattern['type']:
                    code_lines.append("    double rsi = iRSI(Symbol(), Period(), 14, PRICE_CLOSE, 0);")
                elif 'Trading Function' in pattern['type']:
                    code_lines.append("    if(OrdersTotal() < 1) {")
                    code_lines.append("        OrderSend(Symbol(), OP_BUY, 0.1, Ask, 3, 0, 0);")
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
        """Generate Python equivalent code"""
        code_lines = []
        
        # Add header
        code_lines.append('"""')
        code_lines.append(f"Converted from MT4/MT5 {analysis['metadata']['type']}")
        code_lines.append(f"Version: {analysis['metadata']['version']}")
        code_lines.append('"""')
        code_lines.append("")
        
        # Imports
        code_lines.append("import numpy as np")
        code_lines.append("import pandas as pd")
        code_lines.append("from datetime import datetime")
        code_lines.append("")
        
        # Class definition
        class_name = os.path.splitext(os.path.basename(analysis.get('filepath', 'Unknown')))[0]
        code_lines.append(f"class {class_name}:")
        
        # Constructor
        code_lines.append("    def __init__(self):")
        code_lines.append("        self.data = pd.DataFrame()")
        code_lines.append("        self.indicators = {}")
        code_lines.append("")
        
        # Input parameters
        params_found = False
        for string in analysis['strings']:
            if 'period' in string.lower() or 'shift' in string.lower() or 'price' in string.lower():
                if not params_found:
                    code_lines.append("        # Input Parameters")
                    params_found = True
                code_lines.append(f"        self.{string} = 0")
        
        code_lines.append("")
        
        # Initialize method
        code_lines.append("    def initialize(self, data):")
        code_lines.append("        self.data = data")
        code_lines.append("        return True")
        code_lines.append("")
        
        # Calculate indicators
        code_lines.append("    def calculate_indicators(self):")
        
        # Add detected patterns
        for pattern in analysis['patterns']:
            if 'Moving Average' in pattern['type']:
                code_lines.append("        # Calculate Moving Average")
                code_lines.append("        self.indicators['ma'] = self.data['close'].rolling(window=14).mean()")
            elif 'RSI' in pattern['type']:
                code_lines.append("        # Calculate RSI")
                code_lines.append("        delta = self.data['close'].diff()")
                code_lines.append("        gain = (delta.where(delta > 0, 0)).rolling(window=14).mean()")
                code_lines.append("        loss = (-delta.where(delta < 0, 0)).rolling(window=14).mean()")
                code_lines.append("        rs = gain / loss")
                code_lines.append("        self.indicators['rsi'] = 100 - (100 / (1 + rs))")
        
        code_lines.append("        return True")
        code_lines.append("")
        
        # Main processing method
        code_lines.append("    def process_tick(self):")
        code_lines.append("        self.calculate_indicators()")
        
        if analysis['metadata']['type'] == 'Expert Advisor':
            code_lines.append("        # Trading logic")
            code_lines.append("        if len(self.data) > 0:")
            code_lines.append("            last_close = self.data['close'].iloc[-1]")
            code_lines.append("            # Add your trading conditions here")
        
        code_lines.append("        return True")
        
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
        """Generate plain text description of the trading logic"""
        text_lines = []
        
        # Header
        text_lines.append("=== Trading Strategy Description ===")
        text_lines.append(f"Type: {analysis['metadata']['type']}")
        text_lines.append(f"Version: {analysis['metadata']['version']}")
        text_lines.append("")
        
        # Parameters
        params_found = False
        for string in analysis['strings']:
            if 'period' in string.lower() or 'shift' in string.lower() or 'price' in string.lower():
                if not params_found:
                    text_lines.append("Input Parameters:")
                    params_found = True
                text_lines.append(f"- {string}")
        
        if params_found:
            text_lines.append("")
        
        # Indicators and patterns
        text_lines.append("Technical Indicators Used:")
        for pattern in analysis['patterns']:
            if 'Moving Average' in pattern['type']:
                text_lines.append("- Moving Average (Period: 14)")
                text_lines.append("  Used for trend direction analysis")
            elif 'RSI' in pattern['type']:
                text_lines.append("- Relative Strength Index (Period: 14)")
                text_lines.append("  Used for overbought/oversold conditions")
            elif 'Trading' in pattern['type']:
                text_lines.append("- Trading Functions Detected")
                text_lines.append("  Implements order execution logic")
        
        text_lines.append("")
        text_lines.append("Strategy Logic:")
        if analysis['metadata']['type'] == 'Expert Advisor':
            text_lines.append("1. Initializes technical indicators")
            text_lines.append("2. On each tick:")
            text_lines.append("   - Updates indicator values")
            text_lines.append("   - Checks trading conditions")
            text_lines.append("   - Executes trades if conditions are met")
        else:
            text_lines.append("1. Calculates indicator values")
            text_lines.append("2. Displays results on the chart")
        
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
                                   text="📂 Select EX4 File", 
                                   command=self.select_file,
                                   style='Modern.TButton')
        self.open_btn.pack(side=tk.LEFT, padx=5)
        
        self.save_analysis_btn = ttk.Button(btn_container, 
                                           text="💾 Save Analysis", 
                                           command=self.save_analysis,
                                           style='Modern.TButton')
        self.save_analysis_btn.pack(side=tk.LEFT, padx=5)
        self.save_analysis_btn.state(['disabled'])
        
        self.save_code_btn = ttk.Button(btn_container, 
                                       text="💾 Save Code", 
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
        self.notebook.add(self.analysis_frame, text="📊 Analysis")
        
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
        self.notebook.add(self.pseudo_frame, text="📝 Generated Code")
        
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
        self.notebook.add(self.debug_frame, text="🔍 Debug Log")
        
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
            self.status_var.set(f"Regenerating code in {self.language_var.get()}...")
            self.root.update()
            self.current_pseudocode = self.analyzer.generate_pseudocode(
                self.current_analysis, 
                self.language_var.get()
            )
            self.pseudo_text.delete(1.0, tk.END)
            self.pseudo_text.insert(tk.END, self.current_pseudocode)
            self.status_var.set(f"Code regenerated in {self.language_var.get()}")

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
