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
            # Assembly patterns
            b'\x00\x00\x00\x00\x00\x00\x00\x00': 'Null padding',
            b'\x55\x8B\xEC': 'Function prologue (push ebp; mov ebp, esp)',
            b'\x89\xE5': 'Function prologue alternative',
            b'\x68': 'Push instruction',
            b'\xE8': 'Call instruction',
            b'\xC3': 'Return instruction',
            b'\x5D\xC3': 'Function epilogue (pop ebp; ret)',
            b'\x8B\xE5': 'Restore stack pointer',
            
            # MT4 specific patterns
            b'OnInit': 'Initialization function',
            b'OnDeinit': 'Deinitialization function',
            b'OnTick': 'Expert tick function',
            b'OnCalculate': 'Indicator calculation function',
            b'OrderSend': 'Order placement function',
            b'OrderClose': 'Order close function',
            b'iMA': 'Moving Average indicator',
            b'iRSI': 'RSI indicator',
            b'iMACD': 'MACD indicator',
            b'iBands': 'Bollinger Bands indicator',
        }

    def read_file(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                return f.read()
        except Exception as e:
            return f"Error reading file: {str(e)}"

    def analyze_header(self, data):
        """Enhanced header analysis with more details"""
        result = []
        if data.startswith(self.magic_bytes):
            result.append("✓ Valid MZ executable header found")
            
            # Try to extract creation timestamp if available
            if len(data) > 0x3C:
                try:
                    pe_pointer = struct.unpack('<I', data[0x3C:0x40])[0]
                    if len(data) > pe_pointer + 12:
                        # Check for PE signature
                        if data[pe_pointer:pe_pointer+4] == b'PE\x00\x00':
                            result.append("✓ Valid PE (Portable Executable) signature found")
                            
                            # Extract timestamp
                            timestamp = struct.unpack('<I', data[pe_pointer+8:pe_pointer+12])[0]
                            if timestamp > 0:
                                creation_time = datetime.fromtimestamp(timestamp)
                                result.append(f"  Creation Time: {creation_time.strftime('%Y-%m-%d %H:%M:%S')}")
                            
                            # Get machine type
                            machine_type = struct.unpack('<H', data[pe_pointer+4:pe_pointer+6])[0]
                            machine_names = {
                                0x014c: "x86 (32-bit)",
                                0x8664: "x64 (64-bit)",
                                0x0200: "Intel Itanium"
                            }
                            if machine_type in machine_names:
                                result.append(f"  Machine Type: {machine_names[machine_type]}")
                except Exception as e:
                    result.append(f"⚠ Could not fully parse PE header: {str(e)}")

        # Look for MT4 specific markers with counts
        mt4_markers = {
            b'copyright': 'Copyright information',
            b'MetaQuotes': 'MetaQuotes Software signature',
            b'expert': 'Expert Advisor identifier',
            b'indicator': 'Indicator identifier',
            b'script': 'Script identifier',
            b'#property': 'Property directive'
        }

        for marker, desc in mt4_markers.items():
            count = data.count(marker)
            if count > 0:
                result.append(f"✓ {desc} found ({count} occurrence{'s' if count > 1 else ''})")

        return result

    def find_patterns(self, data):
        results = []
        for pattern, desc in self.known_patterns.items():
            count = data.count(pattern)
            if count > 0:
                results.append(f"Found {count} instances of {desc}")
        return results

    def extract_strings(self, data):
        """Enhanced string extraction with Unicode support"""
        strings = []
        current_string = ""
        
        # Extract ASCII strings
        for byte in data:
            if 32 <= byte <= 126:  # printable ASCII characters
                current_string += chr(byte)
            elif current_string:
                if len(current_string) > 3:  # only keep strings longer than 3 characters
                    strings.append(current_string)
                current_string = ""
        
        # Add last string if exists
        if current_string and len(current_string) > 3:
            strings.append(current_string)
        
        # Try Unicode (UTF-16LE) extraction for Windows binaries
        try:
            i = 0
            while i < len(data) - 1:
                if data[i] != 0 and data[i+1] == 0:  # Potential UTF-16LE
                    unicode_str = bytearray()
                    j = i
                    while j < len(data) - 1 and j < i + 200:
                        if data[j] == 0 and data[j+1] == 0:
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
        except Exception:
            pass
        
        # Remove duplicates while preserving order
        seen = set()
        unique_strings = []
        for s in strings:
            if s not in seen:
                seen.add(s)
                unique_strings.append(s)
        
        return unique_strings

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
