# EX4 Debug Decompiler

A powerful tool for analyzing and converting MetaTrader 4 (MT4) EX4 files into various programming languages.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [Limitations](#limitations)
- [Technical Details](#technical-details)

## Installation

### Prerequisites
- Python 3.12 or higher (Python 3.8+ supported)
- Required Python packages (see requirements.txt)

### Setup
1. Clone or download this repository
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

The requirements.txt includes:
- PyQt5 (5.15.11) - GUI framework
- pandas (2.3.3+) - Data analysis
- numpy (1.26.4+) - Numerical computing
- capstone (5.0.6) - Disassembly engine
- networkx (3.6.1) - Control flow analysis

3. Run the main decompiler:
```bash
python ex4_debug_decompiler.py
```

## Usage

1. Launch the application
2. Select your target language from the dropdown:
   - MQL4 (MetaTrader 4)
   - MQL5 (MetaTrader 5)
   - Python
   - C
   - R
   - Text (Plain description)

3. Click "Select EX4 File" and choose your .ex4 file
4. View results in three tabs:
   - Analysis: Raw analysis data in JSON format
   - Pseudocode: Generated code in selected language
   - Debug Log: Detailed analysis process and any errors

5. Save your results:
   - "Save Analysis": Saves the raw analysis as JSON
   - "Save Pseudocode": Saves the generated code in appropriate format

## Features

### Analysis Capabilities
- Metadata extraction
- Pattern recognition
- String analysis
- Function identification
- Trading logic analysis
- Indicator detection

### Supported Output Formats
1. **MQL4**
   - Original MT4 format
   - Function-based structure
   - Native indicator calls

2. **MQL5**
   - Modern class-based structure
   - Object-oriented approach
   - Built-in trading classes

3. **Python**
   - Pandas/Numpy implementation
   - Class-based design
   - Technical analysis functions

4. **C**
   - Structured programming
   - Custom data structures
   - Low-level implementation

5. **R**
   - Quantmod/TTR integration
   - Functional programming style
   - Statistical analysis focus

6. **Text**
   - Human-readable description
   - Strategy explanation
   - Technical documentation

## Limitations

### Current Limitations
1. **Decompilation Accuracy**
   - Cannot recover original variable names
   - Complex logic may be simplified
   - Custom indicators may not be fully reconstructed

2. **Pattern Recognition**
   - Limited to common trading patterns
   - May miss custom implementations
   - Complex strategies might be oversimplified

3. **Code Generation**
   - Generated code may require optimization
   - Some trading functions are templates only
   - Manual adjustment might be needed

4. **Analysis Depth**
   - Cannot recover compiler optimizations
   - Some binary patterns might be missed
   - Deep nested functions may be flattened

### What Cannot Be Done

1. **Full Source Recovery**
   - Original source code cannot be exactly reconstructed
   - Original comments are lost
   - Original code structure may differ

2. **Custom Features**
   - Custom indicators cannot be fully reversed
   - Proprietary functions remain obfuscated
   - Complex trading logic may be approximated

3. **Optimization Recovery**
   - Compiler optimizations are permanent
   - Original performance tweaks are lost
   - Memory management patterns are simplified

## Technical Details

### Implementation Approach

1. **Binary Analysis**
   - Uses Capstone for disassembly
   - Pattern matching for MT4 structures
   - String extraction and analysis

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
   - Python-based GUI development
   - Modular code generation system
   - Extensive error handling

3. **Testing**
   - Multiple EX4 file testing
   - Cross-language verification
   - Pattern recognition validation


<div align='center'><a href='https://www.websitecounterfree.com'><img src='https://www.websitecounterfree.com/c.php?d=9&id=65509&s=1' border='0' alt='Free Website Counter'></a></div>
