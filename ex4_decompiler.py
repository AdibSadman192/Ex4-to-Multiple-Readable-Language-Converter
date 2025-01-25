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
            b'\x4D\x41\x5F': 'MovingAverage',
            b'\x52\x53\x49': 'RSI',
            b'\x42\x42\x5F': 'BollingerBands',
            b'\x4D\x41\x43\x44': 'MACD',
            b'\x69\x4D\x41': 'iMA',
            b'\x69\x52\x53\x49': 'iRSI',
            b'\x69\x42\x42': 'iBands',
            b'\x4F\x72\x64': 'OrderSend'
        }
        
        self.mt4_structures = {
            b'\x69\x6E\x64\x69\x63\x61\x74\x6F\x72': 'INDICATOR_STRUCT',
            b'\x65\x78\x70\x65\x72\x74': 'EXPERT_STRUCT',
            b'\x73\x63\x72\x69\x70\x74': 'SCRIPT_STRUCT'
        }

    def read_file(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                return f.read()
        except Exception as e:
            return f"Error reading file: {str(e)}"

    def extract_metadata(self, data):
        metadata = {
            "type": "Unknown",
            "version": "Unknown",
            "functions": [],
            "indicators": [],
            "strings": []
        }

        # Determine type
        for marker, type_name in self.mt4_structures.items():
            if marker in data:
                metadata["type"] = type_name
                break

        # Extract version info
        version_pattern = re.compile(b'version\\s*[\\d\\.]+', re.IGNORECASE)
        version_match = version_pattern.search(data)
        if version_match:
            metadata["version"] = version_match.group().decode('ascii', errors='ignore')

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
        pseudo = []
        
        # Generate header
        pseudo.append(f"// {metadata['type']} Implementation")
        pseudo.append(f"// Version: {metadata['version']}")
        pseudo.append("")

        # Generate parameters section if it's an indicator
        if metadata['type'] == 'INDICATOR_STRUCT':
            params = self.extract_indicator_parameters(data)
            if params:
                pseudo.append("// Input Parameters")
                for param in params:
                    pseudo.append(f"extern int {param} = 0;")
                pseudo.append("")

        # Generate function declarations
        if metadata['functions']:
            pseudo.append("// Function Calls Detected")
            for func in metadata['functions']:
                pseudo.append(f"// Uses {func}()")
            pseudo.append("")

        # Try to reconstruct main logic
        pseudo.append("int start()")
        pseudo.append("{")
        
        # Add detected function calls
        for func in metadata['functions']:
            if 'MA' in func:
                pseudo.append(f"    double ma = {func}(/* parameters */);")
            elif 'RSI' in func:
                pseudo.append(f"    double rsi = {func}(/* parameters */);")
            elif 'BB' in func:
                pseudo.append(f"    double bands = {func}(/* parameters */);")
            elif 'Order' in func:
                pseudo.append(f"    // Trading function: {func}")
                pseudo.append(f"    {func}(/* trading parameters */);")

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
