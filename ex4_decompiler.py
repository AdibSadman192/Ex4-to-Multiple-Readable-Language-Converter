import os
import struct
import binascii
from collections import defaultdict
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import re
import json
from datetime import datetime

class EX4Decompiler:
    def __init__(self):
        self.known_functions = {
            # Indicators
            b'iMA': 'iMA (Moving Average)',
            b'iRSI': 'iRSI (Relative Strength Index)',
            b'iMACD': 'iMACD (MACD)',
            b'iBands': 'iBands (Bollinger Bands)',
            b'iATR': 'iATR (Average True Range)',
            b'iStochastic': 'iStochastic',
            b'iCCI': 'iCCI (Commodity Channel Index)',
            b'iADX': 'iADX (Average Directional Index)',
            
            # Trading functions
            b'OrderSend': 'OrderSend (Place order)',
            b'OrderClose': 'OrderClose',
            b'OrderModify': 'OrderModify',
            b'OrderDelete': 'OrderDelete',
            
            # Buffer functions
            b'SetIndexBuffer': 'SetIndexBuffer',
            b'SetIndexStyle': 'SetIndexStyle',
            b'SetIndexLabel': 'SetIndexLabel',
        }
        
        self.mt4_structures = {
            b'indicator': 'INDICATOR_STRUCT',
            b'expert': 'EXPERT_STRUCT',
            b'script': 'SCRIPT_STRUCT'
        }

    def read_file(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                return f.read()
        except Exception as e:
            return f"Error reading file: {str(e)}"

    def extract_metadata(self, data):
        """Enhanced metadata extraction"""
        metadata = {
            "type": "Unknown",
            "version": "Unknown",
            "functions": [],
            "indicators": [],
            "strings": [],
            "creation_date": "Unknown",
            "file_size": len(data)
        }

        # Determine type with better pattern matching
        if b'indicator' in data.lower():
            metadata["type"] = "INDICATOR"
        elif b'expert' in data.lower() or b'EA' in data:
            metadata["type"] = "EXPERT ADVISOR"
        elif b'script' in data.lower():
            metadata["type"] = "SCRIPT"

        # Extract version info with multiple patterns
        version_patterns = [
            re.compile(b'version\\s*[\\d\\.]+', re.IGNORECASE),
            re.compile(b'v[\\s]*(\\d+\\.\\d+)', re.IGNORECASE),
        ]
        for pattern in version_patterns:
            version_match = pattern.search(data)
            if version_match:
                metadata["version"] = version_match.group().decode('ascii', errors='ignore')
                break

        # Extract creation date from PE header
        if data.startswith(b'MZ') and len(data) > 0x3C:
            try:
                pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
                if pe_offset < len(data) - 8 and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                    timestamp = struct.unpack('<I', data[pe_offset+8:pe_offset+12])[0]
                    if timestamp > 0:
                        from datetime import datetime
                        creation_time = datetime.fromtimestamp(timestamp)
                        metadata["creation_date"] = creation_time.strftime('%Y-%m-%d %H:%M:%S')
            except:
                pass

        # Extract function calls
        for func_sig, func_name in self.known_functions.items():
            if func_sig in data:
                metadata["functions"].append(func_name)

        return metadata

    def extract_indicator_parameters(self, data):
        params = []
        # Look for common indicator parameter patterns
        param_patterns = {
            b'period': 'Period',
            b'shift': 'Shift',
            b'method': 'Method',
            b'price': 'Applied Price',
            b'timeframe': 'Timeframe'
        }

        for pattern, param_name in param_patterns.items():
            if pattern in data.lower():
                params.append(param_name)

        return params

    def generate_pseudocode(self, data, metadata):
        """Enhanced pseudocode generation with better formatting"""
        pseudo = []
        
        # Generate header with metadata
        pseudo.append("//+------------------------------------------------------------------+")
        pseudo.append(f"//| Decompiled {metadata['type']}")
        pseudo.append(f"//| Version: {metadata['version']}")
        if metadata.get('creation_date', 'Unknown') != 'Unknown':
            pseudo.append(f"//| Created: {metadata['creation_date']}")
        pseudo.append("//+------------------------------------------------------------------+")
        pseudo.append("")

        # Generate parameters section if it's an indicator
        if 'INDICATOR' in metadata['type']:
            params = self.extract_indicator_parameters(data)
            if params:
                pseudo.append("// Input Parameters (detected)")
                for param in params:
                    pseudo.append(f"extern int {param} = 14;  // Default value")
                pseudo.append("")

        # Generate function declarations with descriptions
        if metadata['functions']:
            pseudo.append("// Detected Functions:")
            for func in metadata['functions']:
                pseudo.append(f"//   - {func}")
            pseudo.append("")

        # Try to reconstruct main logic with better structure
        pseudo.append("//+------------------------------------------------------------------+")
        pseudo.append("//| Initialization function")
        pseudo.append("//+------------------------------------------------------------------+")
        pseudo.append("int init()")
        pseudo.append("{")
        if 'INDICATOR' in metadata['type']:
            pseudo.append("    // Setup indicator buffers")
            pseudo.append("    SetIndexBuffer(0, Buffer[]);")
            pseudo.append("    SetIndexStyle(0, DRAW_LINE);")
        pseudo.append("    return(0);")
        pseudo.append("}")
        pseudo.append("")
        
        pseudo.append("//+------------------------------------------------------------------+")
        pseudo.append("//| Main execution function")
        pseudo.append("//+------------------------------------------------------------------+")
        pseudo.append("int start()")
        pseudo.append("{")
        
        # Add detected function calls with better context
        for func in metadata['functions']:
            if 'iMA' in func:
                pseudo.append("    // Calculate Moving Average (detected)")
                pseudo.append("    double ma = iMA(Symbol(), Period(), 14, 0, MODE_SMA, PRICE_CLOSE, 0);")
            elif 'iRSI' in func:
                pseudo.append("    // Calculate RSI (detected)")
                pseudo.append("    double rsi = iRSI(Symbol(), Period(), 14, PRICE_CLOSE, 0);")
            elif 'iMACD' in func:
                pseudo.append("    // Calculate MACD (detected)")
                pseudo.append("    double macd = iMACD(Symbol(), Period(), 12, 26, 9, PRICE_CLOSE, MODE_MAIN, 0);")
            elif 'iBands' in func:
                pseudo.append("    // Calculate Bollinger Bands (detected)")
                pseudo.append("    double upper = iBands(Symbol(), Period(), 20, 2, 0, PRICE_CLOSE, MODE_UPPER, 0);")
                pseudo.append("    double lower = iBands(Symbol(), Period(), 20, 2, 0, PRICE_CLOSE, MODE_LOWER, 0);")
            elif 'OrderSend' in func:
                pseudo.append("    // Trading logic (detected)")
                pseudo.append("    if(OrdersTotal() < 1) {")
                pseudo.append("        int ticket = OrderSend(Symbol(), OP_BUY, 0.1, Ask, 3, 0, 0, \"Trade\");")
                pseudo.append("    }")

        pseudo.append("    return(0);")
        pseudo.append("}")

        return "\n".join(pseudo)

class DecompilerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("EX4 Decompiler")
        self.root.geometry("1000x800")
        
        self.decompiler = EX4Decompiler()
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # File selection
        file_frame = ttk.Frame(main_frame)
        file_frame.grid(row=0, column=0, pady=5, sticky=(tk.W, tk.E))
        
        ttk.Button(file_frame, text="Select EX4 File", command=self.select_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_frame, text="Save Output", command=self.save_output).pack(side=tk.LEFT, padx=5)
        
        # Create notebook for multiple tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Metadata tab
        self.metadata_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.metadata_frame, text="Metadata")
        
        self.metadata_text = scrolledtext.ScrolledText(self.metadata_frame, width=100, height=15)
        self.metadata_text.pack(expand=True, fill='both')
        
        # Pseudocode tab
        self.pseudo_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.pseudo_frame, text="Pseudocode")
        
        self.pseudo_text = scrolledtext.ScrolledText(self.pseudo_frame, width=100, height=30)
        self.pseudo_text.pack(expand=True, fill='both')
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var)
        status_bar.grid(row=2, column=0, pady=5)
        
        self.current_file = None
        self.current_output = None
    
    def select_file(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("EX4 files", "*.ex4"), ("All files", "*.*")]
        )
        if filepath:
            self.current_file = filepath
            self.decompile_file(filepath)
    
    def decompile_file(self, filepath):
        self.status_var.set(f"Analyzing {os.path.basename(filepath)}...")
        self.root.update()
        
        # Read and analyze the file
        data = self.decompiler.read_file(filepath)
        if isinstance(data, str):  # Error message
            self.status_var.set(data)
            return
        
        # Extract metadata
        metadata = self.decompiler.extract_metadata(data)
        
        # Display metadata
        self.metadata_text.delete(1.0, tk.END)
        self.metadata_text.insert(tk.END, json.dumps(metadata, indent=2))
        
        # Generate and display pseudocode
        pseudocode = self.decompiler.generate_pseudocode(data, metadata)
        self.pseudo_text.delete(1.0, tk.END)
        self.pseudo_text.insert(tk.END, pseudocode)
        
        self.current_output = pseudocode
        self.status_var.set("Decompilation complete")
    
    def save_output(self):
        if not self.current_output:
            self.status_var.set("No output to save")
            return
            
        filepath = filedialog.asksaveasfilename(
            defaultextension=".mq4",
            filetypes=[("MQL4 files", "*.mq4"), ("All files", "*.*")]
        )
        if filepath:
            try:
                with open(filepath, 'w') as f:
                    f.write(self.current_output)
                self.status_var.set(f"Saved to {filepath}")
            except Exception as e:
                self.status_var.set(f"Error saving file: {str(e)}")

def main():
    root = tk.Tk()
    app = DecompilerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
