import os
import struct
import binascii
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext
from tkinter import filedialog

class EX4Analyzer:
    def __init__(self):
        self.magic_bytes = b'\x4D\x5A'  # MZ header
        self.known_patterns = {
            b'\x00\x00\x00\x00\x00\x00\x00\x00': 'Null padding',
            b'\x55\x8B\xEC': 'Function prologue',
            b'\x68': 'Push instruction',
            b'\xE8': 'Call instruction',
            b'\xC3': 'Return instruction'
        }

    def read_file(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                return f.read()
        except Exception as e:
            return f"Error reading file: {str(e)}"

    def analyze_header(self, data):
        result = []
        if data.startswith(self.magic_bytes):
            result.append("Valid MZ executable header found")
            
            # Try to extract creation timestamp if available
            if len(data) > 0x3C:
                pe_pointer = struct.unpack('<I', data[0x3C:0x40])[0]
                if len(data) > pe_pointer + 8:
                    timestamp = struct.unpack('<I', data[pe_pointer+8:pe_pointer+12])[0]
                    creation_time = datetime.fromtimestamp(timestamp)
                    result.append(f"Creation Time: {creation_time}")

        # Look for MT4 specific markers
        mt4_markers = {
            b'copyright': 'Copyright information found',
            b'MetaQuotes': 'MetaQuotes signature found',
            b'expert': 'Expert Advisor identifier found',
            b'indicator': 'Indicator identifier found'
        }

        for marker, desc in mt4_markers.items():
            if marker in data:
                result.append(desc)

        return result

    def find_patterns(self, data):
        results = []
        for pattern, desc in self.known_patterns.items():
            count = data.count(pattern)
            if count > 0:
                results.append(f"Found {count} instances of {desc}")
        return results

    def extract_strings(self, data):
        strings = []
        current_string = ""
        for byte in data:
            if 32 <= byte <= 126:  # printable ASCII characters
                current_string += chr(byte)
            elif current_string:
                if len(current_string) > 3:  # only keep strings longer than 3 characters
                    strings.append(current_string)
                current_string = ""
        return strings

class EX4AnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("EX4 File Analyzer")
        self.root.geometry("800x600")
        
        self.analyzer = EX4Analyzer()
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # File selection
        ttk.Button(main_frame, text="Select EX4 File", command=self.select_file).grid(row=0, column=0, pady=5)
        
        # Results area
        self.results_text = scrolledtext.ScrolledText(main_frame, width=80, height=30)
        self.results_text.grid(row=1, column=0, pady=5)
        
    def select_file(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("EX4 files", "*.ex4"), ("All files", "*.*")]
        )
        if filepath:
            self.analyze_file(filepath)
    
    def analyze_file(self, filepath):
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Analyzing: {filepath}\n\n")
        
        # Read and analyze the file
        data = self.analyzer.read_file(filepath)
        if isinstance(data, str):  # Error message
            self.results_text.insert(tk.END, data)
            return
            
        # Analyze header
        self.results_text.insert(tk.END, "=== Header Analysis ===\n")
        header_results = self.analyzer.analyze_header(data)
        for result in header_results:
            self.results_text.insert(tk.END, f"{result}\n")
            
        # Find patterns
        self.results_text.insert(tk.END, "\n=== Pattern Analysis ===\n")
        pattern_results = self.analyzer.find_patterns(data)
        for result in pattern_results:
            self.results_text.insert(tk.END, f"{result}\n")
            
        # Extract strings
        self.results_text.insert(tk.END, "\n=== Extracted Strings ===\n")
        strings = self.analyzer.extract_strings(data)
        for string in strings:
            if any(keyword in string.lower() for keyword in ['function', 'indicator', 'expert', 'copyright', 'version']):
                self.results_text.insert(tk.END, f"{string}\n")

def main():
    root = tk.Tk()
    app = EX4AnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
