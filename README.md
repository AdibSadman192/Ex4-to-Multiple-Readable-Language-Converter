# EX4 Debug Decompiler

A powerful tool for analyzing and converting MetaTrader 4 (MT4) EX4 binary files into multiple readable programming languages.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [GUI Application](#gui-application)
- [CLI Usage](#cli-usage)
- [Limitations](#limitations)
- [Technical Details](#technical-details)
- [License](#license)

## Features

### Analysis Capabilities

- Metadata extraction from PE headers
- Pattern recognition for MT4/MT5 function structures
- String analysis with Unicode (UTF-16LE) support
- Function identification and indicator detection
- Trading logic analysis and strategy classification
- Control flow analysis via Capstone disassembly

### Supported Output Formats

| Format | Description                                       |
| ------ | ------------------------------------------------- |
| MQL4   | Original MT4 format with function-based structure |
| MQL5   | Modern class-based MQL5 structure                 |
| Python | Pandas/NumPy implementation with type hints       |
| C      | Structured programming with custom data types     |
| R      | Quantmod/TTR integration, functional style        |
| Text   | Human-readable strategy documentation             |

### Additional Features

- Trading strategy detection (Martingale, Grid, Hedging, Scalping, Breakout, Trend Following)
- Risk management pattern identification
- Timeframe usage pattern analysis
- Input parameter extraction with automatic type detection
- File statistics including entropy calculation
- String categorization for improved code generation

## Installation

### Prerequisites

- Python 3.10 or higher
- pip package manager

### Setup

1. Clone or download this repository:

```bash
git clone https://github.com/AdibSadman192/Ex4-to-Multiple-Readable-Language-Converter.git
cd Ex4-to-Multiple-Readable-Language-Converter
```

2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

The `requirements.txt` includes:

- `customtkinter==6.0.0` - Modern GUI framework
- `capstone==5.0.9` - Disassembly engine
- `networkx==3.6.1` - Control flow analysis
- `numpy>=2.0.0` - Numerical computing
- `pandas>=2.0.0` - Data analysis
- `darkdetect==0.8.0` - OS-level theme detection

## Usage

### GUI Application

EX4 Studio is the modern graphical interface for the decompiler.

**Launch the GUI:**

```bash
python ex4_gui_app.py
```

Or simply run the main entry point with no arguments:

```bash
python ex4_debug_decompiler.py
```

**Workflow:**

1. Launch the application. The GUI detects your OS theme automatically and applies it.
2. Select your target language from the sidebar dropdown (MQL4, MQL5, Python, C, R, Text).
3. Click **Open File** (folder icon) and choose your `.ex4` file.
4. Click **Analyze** (magnifying glass icon) to begin analysis.
5. Review results across six tabs:
   - **Overview** - Human-readable analysis summary
   - **Generated Code** - Code in your selected language
   - **Disassembly** - x86 disassembly output
   - **Strings** - Extracted strings from the binary
   - **Hex View** - Hexadecimal dump of the file
   - **Log** - Detailed processing log
6. Export results:
   - **Export Code** - Save generated code to disk
   - **Export JSON** - Save raw analysis data as JSON

**Theme switching:** Toggle the moon/sun switch in the sidebar to switch between dark and light themes. All widgets re-color instantly with no flicker.

### CLI Usage

You can also use the decompiler from the command line.

**Basic usage** - analyze an EX4 file and print results to the console:

```bash
python ex4_debug_decompiler.py "path/to/file.ex4"
```

**Specify output language:**

```bash
python ex4_debug_decompiler.py "path/to/file.ex4" --language Python
```

**Save output to a file:**

```bash
python ex4_debug_decompiler.py "path/to/file.ex4" --output output.py
```

**Generate in different languages:**

```bash
python ex4_debug_decompiler.py "path/to/file.ex4" --language MQL5
python ex4_debug_decompiler.py "path/to/file.ex4" --language C
python ex4_debug_decompiler.py "path/to/file.ex4" --language Text
```

#### CLI Options

| Option           | Description                                           |
| ---------------- | ----------------------------------------------------- |
| `filepath`       | Path to the EX4 file to analyze (positional argument) |
| `-l, --language` | Target output language (default: `MQL4`)              |
| `-o, --output`   | Output file path (default: print to console)          |
| `--no-gui`       | Run in CLI mode only, suppress GUI launch             |

**Note:** When you provide a file path as the first argument, the tool automatically runs in CLI mode and prints results to the console. Without any arguments, it launches the GUI.

## Limitations

### Inherent Limitations

- Original variable names cannot be recovered from compiled binaries
- Original source code cannot be exactly reconstructed
- Original comments are lost during compilation
- Compiler optimizations are permanent and cannot be reversed
- Complex logic may be simplified during decompilation
- Custom indicators cannot be fully reversed
- Proprietary functions remain obfuscated

### Best Efforts

- Generated code still requires manual review for edge cases
- Parameter names and types are inferred to help understand intent
- Deep nested functions may be flattened
- Custom indicator detection is improved but may not be fully reconstructed

## Technical Details

### Implementation Approach

1. **Binary Analysis**
   - Uses Capstone for x86 disassembly
   - Pattern matching for MT4 binary structures
   - String extraction and categorization

2. **Pattern Recognition**
   - Trading function detection
   - Indicator pattern matching
   - Control flow analysis

3. **Code Generation**
   - Template-based generation
   - Language-specific optimization
   - Best practices implementation

### Development Process

1. **Research Phase**
   - MT4/MT5 binary format analysis
   - Common trading patterns study
   - Multi-language conversion research

2. **Implementation**
   - Python-based GUI development with CustomTkinter
   - Modular code generation system
   - Extensive error handling

3. **Testing**
   - Multiple EX4 file testing
   - Cross-language verification
   - Pattern recognition validation

## License

This project is licensed under the [MIT License](./LICENSE) - free to use, modify, and distribute with attribution.

See the [LICENSE](./LICENSE) file for the full text.
