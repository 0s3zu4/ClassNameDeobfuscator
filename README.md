# ClassNameDeobfuscator 2.0

A powerful Android APK analysis tool that helps reverse engineers and security analysts understand obfuscated Android applications. This tool analyzes smali files (produced by apktool) to reveal original class names, identify suspicious patterns, and provide insights into the app's structure.

## 🌟 Key Features

- **Deobfuscation**: Recovers original class names from `.source` annotations
- **Deep Scanning**: Identifies potentially suspicious or malicious code patterns
- **Entry Point Detection**: Finds Activities, Services, and other Android entry points
- **Comprehensive Analysis**: Provides insights about large methods, suspicious patterns, and inner classes
- **Multiple Output Formats**: Supports text, JSON, and CSV output

## 📋 Requirements

- Python 3.7 or higher
- Apktool (or similar tool) to extract smali files from APK
- The target APK's smali files

## 🚀 Quick Start

1. **Extract the APK:**
```bash
apktool d target.apk
cd target/smali/     # IMPORTANT: You must run the tool from the smali directory
```

2. **Copy the Tool:**
```bash
# Copy ClassNameDeobfuscator.py to the smali directory
cp /path/to/ClassNameDeobfuscator.py .
```

3. **Run the Analysis:**
```bash
# Basic analysis
python ClassNameDeobfuscator.py com.example.app --summary --deep-scan

# Note: Replace 'com.example.app' with the actual package name of your target app
# You can usually find this in AndroidManifest.xml or by looking at the smali directory structure
```

⚠️ **Important Note**: The tool must be run from within the smali directory created by apktool. This is where it looks for the decompiled classes to analyze.

## 🛠️ Usage

```
usage: ClassNameDeobfuscator.py [-h] [-o OUTPUT] [--format {text,json,csv}] 
                               [--threads N] [--deep-scan] [--detect-obfuscator]
                               [--summary] [--only-first-party] [--ignore-libs]
                               [--dump-class CLASS_NAME] [-v] namespace

positional arguments:
  namespace             Base namespace to begin deobfuscating classes

Analysis Options:
  --deep-scan          Enable deep analysis of methods and patterns
  --detect-obfuscator  Try to identify which obfuscator was used
  --summary            Show detailed analysis dashboard
  
Filtering Options:
  --only-first-party   Focus on app-specific code (ignore common libraries)
  --ignore-libs        Skip known third-party library paths

Output Options:
  -o OUTPUT           Save results to file
  --format FORMAT     Output format: text, json, or csv
  --threads N         Number of parallel processing threads (default: 4)
  -v, --verbose      Enable verbose logging

Inspection Options:
  --dump-class CLASS  Show detailed information about a specific class

## 📖 Analysis Guide

### Basic Analysis
```bash
# Basic deobfuscation
python ClassNameDeobfuscator.py com.example.app

# Save results to a file
python ClassNameDeobfuscator.py com.example.app -o analysis.txt

# Get JSON output for further processing
python ClassNameDeobfuscator.py com.example.app --format json -o analysis.json
```

### Advanced Analysis
```bash
# Comprehensive analysis with method behavior heuristics
python ClassNameDeobfuscator.py com.example.app --summary --deep-scan --format json -o analysis.json

# Focus on app-specific code (automatically filters out common libraries)
python ClassNameDeobfuscator.py com.example.app --only-first-party --deep-scan --summary

# Combined analysis: app-specific code with behavior analysis
python ClassNameDeobfuscator.py com.example.app --only-first-party --deep-scan --detect-obfuscator --summary

# Examine specific suspicious classes with detailed method analysis
python ClassNameDeobfuscator.py com.example.app --dump-class com.example.app.a --deep-scan  # Analyze obfuscated class
python ClassNameDeobfuscator.py com.example.app --dump-class com.example.app.CryptoUtil     # Analyze specific class

# Export comprehensive JSON report with method scoring
python ClassNameDeobfuscator.py com.example.app --deep-scan --only-first-party --format json -o detailed_analysis.json
```

### Understanding the Results

The tool provides several key indicators:

1. **Entry Points** 🚪
   - Activities, Services, and BroadcastReceivers
   - These are the main interfaces between the app and the Android system

2. **Suspicious Methods** ⚠️
   - Method behavior analysis with suspicion scoring (0.0 to 1.0)
   - Detection of suspicious patterns:
     * Single-letter or obfuscated names (a(), b(), etc.)
     * Common suspicious names (invoke(), init(), run(), exec(), etc.)
     * Large methods (>200 lines)
     * Native method implementations
     * Generic/suspicious return types (Object, byte[], DexClassLoader)
   - Advanced pattern detection:
     * Reflection and dynamic code loading
     * Cryptographic operations
     * Process manipulation
     * Package queries and network operations
   - Comprehensive scoring system with categorized flags

3. **Library Filtering** 📚
   - Smart detection of common Android libraries and SDKs
   - Filters out:
     * Android framework classes (android.*, java.*, javax.*)
     * Common libraries (AndroidX, Google libraries, Firebase)
     * Popular networking libraries (OkHttp, Retrofit)
     * UI libraries (Material, Picasso, Glide)
     * Utility libraries (Apache, JSON, logging frameworks)
     * Social SDKs (Facebook, Twitter)
   - Focus on application-specific code for faster analysis

4. **Inner Classes** 📦
   - Anonymous classes
   - Nested implementation details

4. **Obfuscation Analysis** 🔒
   - Detected obfuscator type
   - Statistics about obfuscated names

## 🔍 Analysis Tips

### Common Patterns to Watch For

1. **Large Methods**
   - Methods over 200 lines may indicate complex logic or obfuscation
   - Could be hiding important business logic or security measures

2. **Reflection Usage**
   - Often used to hide sensitive API calls
   - Can indicate dynamic code loading or anti-analysis techniques

3. **Suspicious Return Types**
   - `byte[]` - Could indicate encryption/decryption or binary manipulation
   - `Object` - Generic type might hide actual functionality
   - `DexClassLoader` - Often used for dynamic code loading

4. **Entry Points**
   - Activities with minimal UI but complex logic
   - Services running in background
   - BroadcastReceivers handling sensitive intents

### Example Dashboard Output
```
=============================================================
                 DEOBFUSCATION DASHBOARD
=============================================================

📊 Basic Statistics:
  Total Files: 150
  Deobfuscated: 45
  Success Rate: 30.0%

🚪 Entry Points:
  • com.example.app.MainActivity
  • com.example.app.BackgroundService
  • com.example.app.StartupReceiver

⚠️ High-Risk Methods:
  • com.example.app.crypto.a()
    Score: 0.88
    Flags: ["single-letter", "large", "generic-return", "reflection"]
    Reasons: Single-letter method name, Large method (350 lines),
             Suspicious return type: Object, Uses reflection
  • com.example.app.network.b()
    Score: 0.75
    Flags: ["single-letter", "crypto", "native"]
    Reasons: Single-letter method name, Cryptographic operations,
             Native method implementation

📦 Inner Classes:
  Total: 15
  • com.example.app.MainActivity$1
  • com.example.app.CryptoUtil$KeyGenerator
```

## 🔬 Technical Details

### ProGuard Considerations

The tool's effectiveness depends on how the APK was obfuscated. Different ProGuard configurations affect what information is available:

1. **Default Configuration**
   - Most `.source` annotations are removed
   - Basic name obfuscation is applied

2. **Debug Configuration**
   - When `-keepattributes SourceFile,LineNumberTable` is used
   - Original class names may be preserved in `.source` lines

3. **Custom Rules**
   - Some apps may have custom ProGuard rules
   - Can lead to partial obfuscation

### Understanding Output Formats

1. **Text Format** (default)
   - Human-readable mapping of obfuscated to deobfuscated names
   - Good for quick analysis

2. **JSON Format**
   - Full structured data including all analysis results
   - Ideal for automated processing or integration with other tools

3. **CSV Format**
   - Simple mapping in spreadsheet format
   - Good for tracking large numbers of classes

## 🔐 Security Considerations

1. **For App Developers**
   - Be aware that keeping source attributes aids debugging but may help reverse engineers
   - Consider the trade-off between debugging capability and security

2. **For Analysts**
   - Results may be partial if the app uses advanced obfuscation
   - Combine this tool with other analysis methods for best results
   - Pay special attention to entry points and suspicious patterns

## 🤝 Contributing

Found a bug or have an improvement idea? We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## ❓ Troubleshooting

### Common Issues

1. **"Namespace not found" Error**
   - Make sure you're running the tool from the smali directory
   - Verify the package name matches the directory structure in smali/
   - Try using the full path: `smali/com/example/app`

2. **No Results Found**
   - Check if you're in the correct directory
   - Verify the APK was properly decompiled by apktool
   - Try running with `-v` flag for verbose output
   - The app might be using advanced obfuscation techniques

3. **Multiple smali Directories**
   - Some apps have `smali`, `smali_classes2`, etc.
   - Run the tool in each directory separately
   - Focus on `smali` first as it contains the main app code

4. **Large APKs**
   - Use `--threads` option to speed up analysis
   - Consider using `--only-first-party` to focus on app code
   - Split analysis into smaller chunks using specific namespaces

### Best Practices

1. Always start with basic analysis before deep scanning
2. Save output to a file for later reference
3. Use `--summary` to get an overview before diving deeper
4. Keep the original APK and decompiled files for reference

## 📝 License

This project is licensed under MIT License - see the LICENSE file for details.
