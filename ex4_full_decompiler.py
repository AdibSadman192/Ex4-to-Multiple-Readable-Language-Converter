import os
import struct
import binascii
from collections import defaultdict
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import re
import json
from datetime import datetime
import capstone  # For disassembly
import networkx as nx  # For control flow analysis
import numpy as np
from typing import List, Dict, Set, Tuple
import logging

class MT4Constants:
    """MetaTrader 4 Constants and Structures"""
    INDICATOR_BUFFERS = {
        0: 'MODE_MAIN',
        1: 'MODE_SIGNAL',
        2: 'MODE_UPPER',
        3: 'MODE_LOWER'
    }
    
    PRICE_CONSTANTS = {
        0: 'PRICE_CLOSE',
        1: 'PRICE_OPEN',
        2: 'PRICE_HIGH',
        3: 'PRICE_LOW',
        4: 'PRICE_MEDIAN',
        5: 'PRICE_TYPICAL',
        6: 'PRICE_WEIGHTED'
    }
    
    MA_METHODS = {
        0: 'MODE_SMA',
        1: 'MODE_EMA',
        2: 'MODE_SMMA',
        3: 'MODE_LWMA'
    }

class BinaryAnalyzer:
    """Analyzes binary structure and patterns"""
    def __init__(self):
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        
    def find_functions(self, data: bytes) -> List[Tuple[int, int]]:
        """Find function boundaries in binary data"""
        functions = []
        current_start = None
        
        # Look for common function prologue/epilogue
        for i in range(len(data) - 3):
            # Function prologue (push ebp; mov ebp, esp)
            if data[i:i+3] == b'\x55\x89\xE5':
                if current_start is not None:
                    functions.append((current_start, i))
                current_start = i
            # Function epilogue (pop ebp; ret)
            elif data[i:i+2] == b'\x5D\xC3' and current_start is not None:
                functions.append((current_start, i + 2))
                current_start = None
                
        return functions

    def disassemble_function(self, data: bytes, start: int, end: int) -> List[str]:
        """Disassemble a function's instructions"""
        try:
            instructions = list(self.cs.disasm(data[start:end], start))
            return [f"{i.mnemonic} {i.op_str}" for i in instructions]
        except Exception as e:
            logging.error(f"Disassembly error: {str(e)}")
            return []

class MT4Decompiler:
    """Main decompiler class"""
    def __init__(self):
        self.binary_analyzer = BinaryAnalyzer()
        self.setup_patterns()
        
    def setup_patterns(self):
        """Setup pattern matching for MT4 specific features"""
        self.mt4_functions = {
            b'iCustom': 'Custom Indicator',
            b'iMA': 'Moving Average',
            b'iRSI': 'Relative Strength Index',
            b'iATR': 'Average True Range',
            b'iBands': 'Bollinger Bands',
            b'iStochastic': 'Stochastic',
            b'iMACD': 'MACD',
            b'OrderSend': 'Order Send',
            b'OrderClose': 'Order Close',
            b'OrderModify': 'Order Modify'
        }
        
        self.indicator_patterns = {
            b'SetIndexBuffer': 'Buffer Setup',
            b'SetIndexStyle': 'Style Setup',
            b'SetIndexLabel': 'Label Setup',
            b'SetIndexDrawBegin': 'Draw Setup'
        }

    def analyze_file(self, filepath: str) -> Dict:
        """Perform full analysis of an ex4 file"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                
            result = {
                'metadata': self.extract_metadata(data),
                'functions': self.analyze_functions(data),
                'strings': self.extract_strings(data),
                'indicators': self.analyze_indicators(data),
                'trading_logic': self.analyze_trading_logic(data)
            }
            
            return result
        except Exception as e:
            logging.error(f"Analysis error: {str(e)}")
            return None

    def extract_metadata(self, data: bytes) -> Dict:
        """Extract metadata from ex4 file"""
        metadata = {
            'type': self.determine_type(data),
            'version': self.extract_version(data),
            'copyright': self.extract_copyright(data),
            'description': self.extract_description(data)
        }
        return metadata

    def determine_type(self, data: bytes) -> str:
        """Determine if file is indicator, expert advisor, or script"""
        if b'indicator' in data.lower():
            return 'Indicator'
        elif b'expert' in data.lower():
            return 'Expert Advisor'
        elif b'script' in data.lower():
            return 'Script'
        return 'Unknown'

    def extract_version(self, data: bytes) -> str:
        """Extract version information"""
        version_pattern = re.compile(b'version\\s*[\\d\\.]+', re.IGNORECASE)
        match = version_pattern.search(data)
        return match.group().decode('ascii', errors='ignore') if match else 'Unknown'

    def analyze_functions(self, data: bytes) -> List[Dict]:
        """Analyze functions in the binary"""
        functions = []
        for start, end in self.binary_analyzer.find_functions(data):
            instructions = self.binary_analyzer.disassemble_function(data, start, end)
            function_info = {
                'start': start,
                'end': end,
                'size': end - start,
                'instructions': instructions,
                'calls': self.analyze_function_calls(instructions)
            }
            functions.append(function_info)
        return functions

    def analyze_function_calls(self, instructions: List[str]) -> List[str]:
        """Analyze function calls within instructions"""
        calls = []
        for inst in instructions:
            if inst.startswith('call'):
                calls.append(inst)
        return calls

    def extract_strings(self, data: bytes) -> List[str]:
        """Extract readable strings from binary"""
        strings = []
        current = ''
        for byte in data:
            if 32 <= byte <= 126:  # printable ASCII
                current += chr(byte)
            elif current:
                if len(current) > 3:  # minimum length
                    strings.append(current)
                current = ''
        return strings

    def analyze_indicators(self, data: bytes) -> Dict:
        """Analyze indicator-specific features"""
        indicators = {
            'buffers': [],
            'parameters': [],
            'styles': []
        }
        
        # Look for buffer setup
        buffer_pattern = re.compile(b'SetIndexBuffer\\s*\\(\\s*\\d+\\s*,', re.IGNORECASE)
        for match in buffer_pattern.finditer(data):
            indicators['buffers'].append(match.group().decode('ascii', errors='ignore'))
            
        return indicators

    def analyze_trading_logic(self, data: bytes) -> Dict:
        """Analyze trading-related logic"""
        trading = {
            'order_functions': [],
            'price_checks': [],
            'conditions': []
        }
        
        # Look for trading functions
        for func, desc in self.mt4_functions.items():
            if func in data:
                trading['order_functions'].append(desc)
                
        return trading

    def generate_pseudocode(self, analysis: Dict) -> str:
        """Generate pseudocode from analysis results"""
        code = []
        
        # Add header
        code.append(f"// {analysis['metadata']['type']}")
        code.append(f"// Version: {analysis['metadata']['version']}")
        code.append("")
        
        # Add indicator properties if applicable
        if analysis['metadata']['type'] == 'Indicator':
            code.append("#property indicator_separate_window")
            code.append("#property indicator_buffers 1")
            code.append("")
        
        # Add external parameters
        code.append("// Input Parameters")
        for param in analysis.get('parameters', []):
            code.append(f"extern {param};")
        code.append("")
        
        # Add initialization function
        code.append("int init()")
        code.append("{")
        for buffer in analysis['indicators']['buffers']:
            code.append(f"    {buffer};")
        code.append("    return(0);")
        code.append("}")
        code.append("")
        
        # Add main calculation function
        code.append("int start()")
        code.append("{")
        
        # Add trading logic if present
        for func in analysis['trading_logic']['order_functions']:
            code.append(f"    // {func} implementation")
            code.append(f"    // TODO: Add specific {func} logic")
            
        code.append("    return(0);")
        code.append("}")
        
        return "\n".join(code)

class DecompilerGUI:
    """GUI for the decompiler"""
    def __init__(self, root):
        self.root = root
        self.root.title("MT4 Full Decompiler")
        self.root.geometry("1200x800")
        
        self.decompiler = MT4Decompiler()
        self.setup_gui()
        
    def setup_gui(self):
        """Setup GUI components"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=0, column=0, pady=5, sticky=(tk.W, tk.E))
        
        ttk.Button(button_frame, text="Select EX4 File", command=self.select_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save Analysis", command=self.save_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save Pseudocode", command=self.save_pseudocode).pack(side=tk.LEFT, padx=5)
        
        # Notebook for different views
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Analysis tab
        self.analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.analysis_frame, text="Analysis")
        
        self.analysis_text = scrolledtext.ScrolledText(self.analysis_frame, width=120, height=30)
        self.analysis_text.pack(expand=True, fill='both')
        
        # Pseudocode tab
        self.pseudo_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.pseudo_frame, text="Pseudocode")
        
        self.pseudo_text = scrolledtext.ScrolledText(self.pseudo_frame, width=120, height=30)
        self.pseudo_text.pack(expand=True, fill='both')
        
        # Disassembly tab
        self.disasm_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.disasm_frame, text="Disassembly")
        
        self.disasm_text = scrolledtext.ScrolledText(self.disasm_frame, width=120, height=30)
        self.disasm_text.pack(expand=True, fill='both')
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var)
        status_bar.grid(row=2, column=0, pady=5)
        
        self.current_analysis = None
        self.current_pseudocode = None
        
    def select_file(self):
        """Handle file selection"""
        filepath = filedialog.askopenfilename(
            filetypes=[("EX4 files", "*.ex4"), ("All files", "*.*")]
        )
        if filepath:
            self.analyze_file(filepath)
            
    def analyze_file(self, filepath):
        """Perform analysis on selected file"""
        self.status_var.set(f"Analyzing {os.path.basename(filepath)}...")
        self.root.update()
        
        try:
            # Perform analysis
            analysis = self.decompiler.analyze_file(filepath)
            if not analysis:
                self.status_var.set("Analysis failed")
                return
                
            self.current_analysis = analysis
            
            # Display analysis results
            self.analysis_text.delete(1.0, tk.END)
            self.analysis_text.insert(tk.END, json.dumps(analysis, indent=2))
            
            # Generate and display pseudocode
            pseudocode = self.decompiler.generate_pseudocode(analysis)
            self.current_pseudocode = pseudocode
            self.pseudo_text.delete(1.0, tk.END)
            self.pseudo_text.insert(tk.END, pseudocode)
            
            # Display disassembly
            self.disasm_text.delete(1.0, tk.END)
            for func in analysis['functions']:
                self.disasm_text.insert(tk.END, f"\nFunction at {hex(func['start'])}:\n")
                for inst in func['instructions']:
                    self.disasm_text.insert(tk.END, f"  {inst}\n")
            
            self.status_var.set("Analysis complete")
            
        except Exception as e:
            self.status_var.set(f"Error during analysis: {str(e)}")
            logging.error(f"Analysis error: {str(e)}")
            
    def save_analysis(self):
        """Save analysis results"""
        if not self.current_analysis:
            self.status_var.set("No analysis to save")
            return
            
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filepath:
            try:
                with open(filepath, 'w') as f:
                    json.dump(self.current_analysis, f, indent=2)
                self.status_var.set(f"Analysis saved to {filepath}")
            except Exception as e:
                self.status_var.set(f"Error saving analysis: {str(e)}")
                
    def save_pseudocode(self):
        """Save generated pseudocode"""
        if not self.current_pseudocode:
            self.status_var.set("No pseudocode to save")
            return
            
        filepath = filedialog.asksaveasfilename(
            defaultextension=".mq4",
            filetypes=[("MQL4 files", "*.mq4"), ("All files", "*.*")]
        )
        if filepath:
            try:
                with open(filepath, 'w') as f:
                    f.write(self.current_pseudocode)
                self.status_var.set(f"Pseudocode saved to {filepath}")
            except Exception as e:
                self.status_var.set(f"Error saving pseudocode: {str(e)}")

def main():
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Create and run GUI
    root = tk.Tk()
    app = DecompilerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
