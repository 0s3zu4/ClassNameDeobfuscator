import argparse
import os
import logging
from pathlib import Path
from typing import Optional, List, Dict
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import re
from collections import Counter

__author__ = 'Osezua'
__version__ = '2.0.0'

# Analysis constants
LARGE_METHOD_THRESHOLD = 200  # Lines of code threshold for suspicious methods
SUSPICIOUS_RETURN_TYPES = {
    'Ljava/lang/Object;',
    '[B',  # byte[]
    '[Ljava/lang/Object;',
    'Ljava/lang/reflect/Method;',
    'Ldalvik/system/DexClassLoader;',
    'Ljavax/crypto/Cipher;'
}

COMMON_LIBRARY_PACKAGES = {
    # Android and Google libraries
    'androidx/',
    'com/google/',
    'com/android/',
    'android/support/',
    'org/chromium/',
    'com/google/firebase/',
    'com/google/android/gms/',
    'com/google/android/material/',
    
    # Kotlin
    'kotlin/',
    'kotlinx/',
    
    # Common networking libraries
    'okhttp3/',
    'retrofit2/',
    'com/squareup/okhttp/',
    'com/squareup/retrofit/',
    'com/squareup/moshi/',
    
    # Reactive programming
    'io/reactivex/',
    'io/reactivex/rxjava2/',
    'io/reactivex/rxjava3/',
    'io/reactivex/rxkotlin/',
    
    # Common utility libraries
    'org/json/',
    'com/fasterxml/',
    'org/slf4j/',
    'ch/qos/logback/',
    'org/apache/',
    'com/jakewharton/',
    
    # Social SDKs
    'com/facebook/',
    'com/twitter/',
    
    # Image loading
    'com/squareup/picasso/',
    'com/bumptech/glide/',
    'com/github/bumptech/',
    
    # Dependency Injection
    'dagger/',
    'javax/inject/',
    'com/google/inject/',
    
    # Analytics and crash reporting
    'com/crashlytics/',
    'io/fabric/',
    'com/google/firebase/analytics/',
    
    # Common event buses
    'org/greenrobot/eventbus/',
    'com/squareup/otto/'
}

# Modern Android package naming patterns and source file attributes
COMMON_OBFUSCATION_PATTERNS = {
    'proguard': r'^[a-z]{1,3}$',  # Common ProGuard pattern (a, aa, aaa)
    'r8': r'^[a-z]{1}[0-9]{1,2}[a]?$',  # Common R8 pattern (a1, a2b)
    'dexguard': r'^[A-Za-z]{1,3}\d{0,2}$',  # Common DexGuard pattern
    'inner_class': r'.*\$[a-zA-Z0-9]+$'  # Inner class pattern
}

IGNORED_SOURCE_FILES = {
    'SourceFile',  # Common ProGuard/R8 renamed source
    'Unknown',     # Common fallback name
    'Unknown Source', 
    'null'
}

def parse_args():
    parser = argparse.ArgumentParser(description='Execute in the smali directory of a disassembled APK')
    parser.add_argument('namespace', type=str, help='base namespace to begin deobfuscating classes')
    parser.add_argument('-o', dest='outfile', default=None, metavar='output.txt', 
                      help='output filename to save deobfusacted class mapping')
    parser.add_argument('--format', choices=['text', 'json', 'csv'], default='text',
                      help='Output format (default: text)')
    parser.add_argument('--threads', type=int, default=4,
                      help='Number of threads for parallel processing (default: 4)')
    
    # Analysis options
    parser.add_argument('--deep-scan', action='store_true',
                      help='Perform deep scanning for suspicious patterns and methods')
    parser.add_argument('--detect-obfuscator', action='store_true',
                      help='Try to detect which obfuscator was used')
    parser.add_argument('--summary', action='store_true',
                      help='Display summary dashboard with statistics and key findings')
    
    # Filtering options
    parser.add_argument('--only-first-party', action='store_true',
                      help='Focus on app-specific code by filtering out common libraries')
    parser.add_argument('--ignore-libs', action='store_true',
                      help='Ignore common third-party library paths')
    
    # Inspection options
    parser.add_argument('--dump-class', type=str, metavar='CLASS_NAME',
                      help='Dump detailed information about a specific class')
    parser.add_argument('--dump-format', choices=['smali', 'summary'], default='summary',
                      help='Format for class dump output (default: summary)')
    
    # Output options
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Enable verbose logging')
    return parser.parse_args()


@dataclass
class SmaliMethod:
    """Represents a method in a smali file."""
    name: str
    params: List[str]
    return_type: str
    modifiers: List[str]
    source_line: int
    code: List[str] = field(default_factory=list)

@dataclass
class SmaliFile:
    """A class to represent a Smali file with modern Android APK support."""
    
    filepath: str
    raw_lines: List[str] = field(default_factory=list)
    class_name: Optional[str] = None
    source_file: Optional[str] = None
    annotations: Dict[str, str] = field(default_factory=dict)
    methods: List[SmaliMethod] = field(default_factory=list)
    super_class: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)
    fields: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        self.read_smali_file()
        self.parse_basic_info()
    
    def read_smali_file(self) -> None:
        """Read smali file with proper error handling and encoding detection."""
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                self.raw_lines = f.readlines()
        except UnicodeDecodeError:
            # Some obfuscators might use different encodings
            try:
                with open(self.filepath, 'r', encoding='latin-1') as f:
                    self.raw_lines = f.readlines()
            except Exception as e:
                logging.error(f"Failed to read {self.filepath}: {e}")
                raise
    
    def parse_basic_info(self) -> None:
        """Extract basic information from the smali file."""
        in_annotation = False
        in_method = False
        annotation_buffer = []
        method_buffer = []
        current_line_num = 0
        
        for line in self.raw_lines:
            current_line_num += 1
            line = line.strip()
            
            if line.startswith('.class'):
                self.class_name = self._parse_class_name(line)
                self.class_modifiers = self._parse_class_modifiers(line)
                
            elif line.startswith('.super'):
                self.super_class = line.split(' ')[-1].strip('L;')
                
            elif line.startswith('.implements'):
                self.interfaces.append(line.split(' ')[-1].strip('L;'))
                
            elif line.startswith('.field'):
                self._parse_field(line)
                
            elif line.startswith('.method'):
                in_method = True
                method_buffer = [line]
                method_start_line = current_line_num
                
            elif line.startswith('.end method'):
                in_method = False
                method_buffer.append(line)
                self._parse_method(method_buffer, method_start_line)
                
            elif in_method:
                method_buffer.append(line)
                
            elif line.startswith('.source'):
                raw_source = self._parse_source_name(line)
                if raw_source not in IGNORED_SOURCE_FILES:
                    self.source_file = raw_source
                else:
                    self.source_file = self._derive_source_from_class()
                    
            elif line.startswith('.annotation'):
                in_annotation = True
                annotation_buffer = [line]
            elif in_annotation:
                annotation_buffer.append(line)
                if line.strip() == '.end annotation':
                    in_annotation = False
                    self._parse_annotation('\\n'.join(annotation_buffer))
    
    def _parse_class_name(self, line: str) -> str:
        """Parse the actual class name from .class line."""
        parts = line.split(' ')
        return parts[-1].strip('L;')
    
    def _parse_source_name(self, line: str) -> str:
        """Parse source file name with better error handling."""
        try:
            return line.split(' ')[1].strip().strip('"')
        except IndexError:
            return 'UNKNOWN_SOURCE'
    
    def _parse_class_modifiers(self, line: str) -> List[str]:
        """Parse class modifiers (public, final, etc)."""
        parts = line.split(' ')
        modifiers = []
        for part in parts[1:-1]:  # Skip .class and the final class name
            if part in ['public', 'final', 'abstract', 'interface']:
                modifiers.append(part)
        return modifiers

    def _derive_source_from_class(self) -> str:
        """Attempt to derive original source file name from class name."""
        if not self.class_name:
            return 'Unknown'
            
        # Handle inner classes
        if '$' in self.class_name:
            parts = self.class_name.split('$')
            base_class = parts[0].split('/')[-1]
            # If it's a numbered inner class, try to make it more readable
            if parts[1].isdigit():
                return f"{base_class}$Inner{parts[1]}"
            return f"{base_class}${parts[1]}"
            
        # Handle regular classes
        class_name = self.class_name.split('/')[-1]
        # If it's obfuscated (like 'a' or 'b'), keep the original name
        if len(class_name) <= 2 and class_name.isalpha():
            return class_name
        return class_name

    def _parse_method(self, method_lines: List[str], start_line: int) -> None:
        """Parse a method definition and its contents."""
        if not method_lines:
            return
            
        # Parse method signature
        signature_line = method_lines[0].strip()
        if not signature_line.startswith('.method'):
            return
            
        parts = signature_line.split(' ')
        modifiers = []
        method_name = ''
        params = []
        return_type = ''
        
        # Parse method signature components
        for part in parts[1:]:
            if part in ['public', 'private', 'protected', 'static', 'final', 'synthetic']:
                modifiers.append(part)
            elif '(' in part:  # This is the method name and signature
                method_part = part.split('(')
                method_name = method_part[0]
                sig_part = '('.join(method_part[1:])
                # Parse parameters and return type
                sig_match = re.match(r'([^)]*)\)(.*)', sig_part)
                if sig_match:
                    params = self._parse_method_params(sig_match.group(1))
                    return_type = sig_match.group(2)
        
        # Create SmaliMethod object
        method = SmaliMethod(
            name=method_name,
            params=params,
            return_type=return_type,
            modifiers=modifiers,
            source_line=start_line,
            code=method_lines[1:-1]  # Exclude .method and .end method lines
        )
        
        self.methods.append(method)

    def _parse_method_params(self, params_str: str) -> List[str]:
        """Parse method parameters from signature."""
        if not params_str:
            return []
            
        params = []
        current_param = ''
        array_depth = 0
        
        for char in params_str:
            if char == '[':
                array_depth += 1
            elif char in 'ZBCSIFJD':  # Primitive types
                params.append(f"{'[' * array_depth}{char}")
                array_depth = 0
            elif char == 'L':  # Start of class type
                current_param = f"{'[' * array_depth}L"
                array_depth = 0
            elif char == ';':  # End of class type
                if current_param:
                    params.append(f"{current_param};")
                    current_param = ''
            elif current_param:
                current_param += char
                
        return params
        
    def _parse_field(self, line: str) -> None:
        """Parse a field definition."""
        parts = line.split(' ')
        field_name = None
        field_type = None
        
        for part in parts:
            if ':' in part:  # This is the field type
                field_type = part.split(':')[1].strip()
            elif not part.startswith('.') and not part in ['public', 'private', 'protected', 'static', 'final']:
                field_name = part
                
        if field_name and field_type:
            self.fields[field_name] = field_type

    def _parse_annotation(self, content: str) -> None:
        """Parse annotations that might contain deobfuscation hints."""
        try:
            # Look for specific annotations that might contain mapping information
            if 'Ldalvik/annotation/MemberClasses;' in content:
                # Parse member classes information
                self.annotations['member_classes'] = self._extract_member_classes(content)
            elif 'Ldalvik/annotation/EnclosingClass;' in content:
                # Parse enclosing class information
                self.annotations['enclosing_class'] = self._extract_enclosing_class(content)
            elif 'Ldalvik/annotation/Signature;' in content:
                # Parse method/field signature information
                self.annotations['signature'] = self._extract_signature(content)
        except Exception as e:
            logging.debug(f"Error parsing annotation: {e}")
            
    def _extract_member_classes(self, content: str) -> List[str]:
        """Extract member classes from annotation."""
        classes = []
        for line in content.split('\\n'):
            if 'value =' in line:
                # Parse the class names from the value
                class_matches = re.findall(r'L[^;]+;', line)
                classes.extend([c.strip('L;') for c in class_matches])
        return classes

    def _extract_enclosing_class(self, content: str) -> Optional[str]:
        """Extract enclosing class from annotation."""
        for line in content.split('\\n'):
            if 'value =' in line:
                match = re.search(r'L([^;]+);', line)
                if match:
                    return match.group(1)
        return None
        
    def _extract_signature(self, content: str) -> Optional[str]:
        """Extract signature information from annotation."""
        signatures = []
        for line in content.split('\n'):
            if 'value =' in line:
                # Look for signature values in the format "value = [...]"
                sig_match = re.search(r'value\s*=\s*\[(.*?)\]', line)
                if sig_match:
                    signatures.extend(re.findall(r'"([^"]*)"', sig_match.group(1)))
        return signatures[0] if signatures else None
       


class ClassNameDeobfuscator:
    def __init__(self, namespace: str, outfilepath: Optional[str] = None):
        self.namespace = namespace
        self.outfilepath = outfilepath
        self.outfile = None
        self.results = []
        self.statistics = {
            'total_files': 0,
            'deobfuscated_files': 0,
            'obfuscator_detected': None,
            'patterns_found': {},
            'large_methods': [],
            'suspicious_methods': [],
            'inner_classes': [],
            'entry_points': [],  # Activities, Services, Receivers
            'suspicious_returns': [],
            'obfuscated_names': []
        }
        
        # Configure logging
        log_level = logging.DEBUG if args.verbose else logging.INFO
        logging.basicConfig(level=log_level, 
                          format='%(asctime)s - %(levelname)s - %(message)s')
        
        if self.outfilepath:
            self.outfile = open(self.outfilepath, 'w', encoding='utf-8')

    def out(self, message):
        if self.outfile:
            self.outfile.write(message + '\n')
        else:
            print(message)

    def namespace_to_path(self, namespace):
        return namespace.replace('.', os.path.sep)

    def path_to_namespace(self, path):
        return path.replace(os.path.sep, '.')

    def ensure_namespace_dir_exists(self, namespace_dir):
        return os.path.isdir(namespace_dir)

    def parse_classname_from_source_line(self, source_line):
        try:
            return source_line.split(' ')[1].strip().strip('"')
        except IndexError:
            return 'ERROR_WHILE_DEOBFUSCATING_CLASS_NAME'

    def deobfuscate_smali_file_class(self, namespace_path, filename):
        filepath = os.path.join(namespace_path, filename)
        smali_file = SmaliFile(filepath)
        for line in smali_file.raw_lines:
            if line.startswith('.source'):
                return self.parse_classname_from_source_line(line)

    def walk_namespace_dir(self, namespace_dir):
        self.out(' [*] Deobfuscating class names from namespace {0}...'.format(self.path_to_namespace(namespace_dir)))
        for dirpath, dirnames, filenames in os.walk(namespace_dir):
            namespace = self.path_to_namespace(dirpath)
            for file in filenames:
                if file.endswith('smali'):
                    obfuscated_full_namesapce = '{0}.{1}'.format(namespace, file)
                    deobfuscated_name = self.deobfuscate_smali_file_class(dirpath, file)
                    deobfuscated_full_namepsace = '{0}.{1}'.format(namespace, deobfuscated_name)
                    self.out('{0} => {1}'.format(obfuscated_full_namesapce, deobfuscated_full_namepsace))

    def detect_obfuscator(self, class_name: str) -> Optional[str]:
        """Detect which obfuscator was likely used based on naming patterns."""
        for obfuscator, pattern in COMMON_OBFUSCATION_PATTERNS.items():
            if re.match(pattern, class_name):
                self.statistics['patterns_found'][obfuscator] = self.statistics['patterns_found'].get(obfuscator, 0) + 1
                return obfuscator
        return None

    def analyze_method_suspiciousness(self, method: SmaliMethod, class_name: str) -> Dict:
        """Analyze a method for suspicious patterns."""
        suspicion_score = 0.0
        flags = []
        reasons = []
        
        # Check method name patterns
        suspicious_names = {'invoke', 'init', 'run', 'exec', 'load', 'native'}
        if method.name in suspicious_names:
            suspicion_score += 0.3
            flags.append("suspicious-name")
            reasons.append(f"Suspicious method name: {method.name}")
            
        # Check for single-letter or obfuscated names
        if len(method.name) <= 2:
            if method.name.isalpha():
                suspicion_score += 0.4
                flags.append("single-letter")
                reasons.append("Single-letter method name")
            elif method.name not in {'<init>', '<clinit>'}:  # Exclude legitimate short names
                suspicion_score += 0.3
                flags.append("short-name")
                reasons.append("Short obfuscated name")
                
        # Check method size
        if len(method.code) > LARGE_METHOD_THRESHOLD:
            size_score = min(0.5, len(method.code) / (LARGE_METHOD_THRESHOLD * 2))
            suspicion_score += size_score
            flags.append("large")
            reasons.append(f"Large method ({len(method.code)} lines)")
            
        # Check return type
        if method.return_type in SUSPICIOUS_RETURN_TYPES:
            suspicion_score += 0.4
            flags.append("generic-return")
            reasons.append(f"Suspicious return type: {method.return_type}")
            
        # Check for native methods
        if 'native' in method.modifiers:
            suspicion_score += 0.5
            flags.append("native")
            reasons.append("Native method implementation")
            
        # Check for reflection/dynamic loading patterns
        reflection_indicators = {
            'Ljava/lang/reflect/': 'reflection usage',
            'Ldalvik/system/DexClassLoader': 'dynamic code loading',
            'Ljavax/crypto/': 'cryptographic operations',
            'Landroid/app/ActivityManager;->killBackgroundProcesses': 'process manipulation',
            'Landroid/content/pm/PackageManager': 'package queries',
            'Landroid/net/ConnectivityManager': 'network operations'
        }
        
        method_code = ''.join(method.code)
        for indicator, description in reflection_indicators.items():
            if indicator in method_code:
                suspicion_score += 0.3
                flags.append(indicator.split('/')[-1].lower().rstrip(';'))
                reasons.append(description)
                
        # Calculate final normalized score (0.0 to 1.0)
        final_score = min(1.0, suspicion_score)
            
        return {
            'method_name': method.name,
            'class_name': class_name,
            'suspicious_score': round(final_score, 2),
            'flags': flags,
            'reasons': reasons,
            'code_size': len(method.code)
        }

    def is_entry_point(self, smali_file: SmaliFile) -> bool:
        """Check if the class is an Android entry point."""
        entry_point_superclasses = [
            'Landroid/app/Activity',
            'Landroid/app/Service',
            'Landroid/content/BroadcastReceiver',
            'Landroid/content/ContentProvider'
        ]
        return smali_file.super_class in entry_point_superclasses

    def process_smali_file(self, dirpath: str, filename: str) -> Optional[Dict]:
        """Process a single smali file with enhanced detection."""
        filepath = os.path.join(dirpath, filename)
        try:
            smali_file = SmaliFile(filepath)
            
            # Early return if it's a third-party library class and we're in first-party only mode
            if args.only_first_party:
                # Check if the class is from a common library package
                if any(lib in smali_file.class_name for lib in COMMON_LIBRARY_PACKAGES):
                    return None
                # Skip if it's an Android framework class
                if smali_file.class_name and (smali_file.class_name.startswith('android/') or 
                   smali_file.class_name.startswith('java/') or 
                   smali_file.class_name.startswith('javax/')):
                    return None
            
            self.statistics['total_files'] += 1
            
            namespace = self.path_to_namespace(dirpath)
            obfuscated_name = f"{namespace}.{filename}"
            class_name = smali_file.class_name or filename.replace('.smali', '')
            
            # Basic deobfuscation
            if smali_file.source_file:
                self.statistics['deobfuscated_files'] += 1
                deobfuscated_name = f"{namespace}.{smali_file.source_file}"
            else:
                deobfuscated_name = obfuscated_name
                
            # Deep scan analysis if requested
            if args.deep_scan:
                # Analyze methods
                for method in smali_file.methods:
                    analysis = self.analyze_method_suspiciousness(method, class_name)
                    
                    if analysis['suspicion_score'] > 0:
                        self.statistics['suspicious_methods'].append(analysis)
                    
                    if analysis['code_size'] > LARGE_METHOD_THRESHOLD:
                        self.statistics['large_methods'].append({
                            'class': class_name,
                            'method': method.name,
                            'size': analysis['code_size']
                        })
                        
                # Check for entry points
                if self.is_entry_point(smali_file):
                    self.statistics['entry_points'].append(class_name)
                    
                # Track inner classes
                if '$' in class_name:
                    self.statistics['inner_classes'].append(class_name)
                    
                # Track obfuscated names
                if len(filename.replace('.smali', '')) <= 2:
                    self.statistics['obfuscated_names'].append(class_name)
                
            # Detect obfuscator if requested
            if args.detect_obfuscator:
                obfuscator = self.detect_obfuscator(filename.replace('.smali', ''))
                if obfuscator and not self.statistics['obfuscator_detected']:
                    self.statistics['obfuscator_detected'] = obfuscator
            
            methods_info = []
            for method in smali_file.methods:
                methods_info.append({
                    'name': method.name,
                    'params': method.params,
                    'return_type': method.return_type,
                    'modifiers': method.modifiers,
                    'code_size': len(method.code)
                })
            
            return {
                'obfuscated': obfuscated_name,
                'deobfuscated': deobfuscated_name,
                'class_name': class_name,
                'source_file': smali_file.source_file,
                'super_class': smali_file.super_class,
                'interfaces': smali_file.interfaces,
                'methods': methods_info,
                'fields': smali_file.fields
            }
        except Exception as e:
            logging.error(f"Error processing {filepath}: {e}")
        return None

    def execute(self):
        """Execute the deobfuscation process with parallel processing."""
        namespace_dir = self.namespace_to_path(self.namespace)
        if not self.ensure_namespace_dir_exists(namespace_dir):
            logging.error(f"Could not find directory {namespace_dir} for namespace {self.namespace}")
            return

        logging.info(f"Starting deobfuscation for namespace: {self.namespace}")
        
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            for dirpath, _, filenames in os.walk(namespace_dir):
                # Skip common library paths if requested
                if args.ignore_libs and any(lib in dirpath for lib in ['androidx', 'com.google', 'kotlin']):
                    continue
                    
                # Process smali files
                smali_files = [f for f in filenames if f.endswith('.smali')]
                futures = [executor.submit(self.process_smali_file, dirpath, f) for f in smali_files]
                
                for future in futures:
                    result = future.result()
                    if result:
                        self.results.append(result)
                        if args.format == 'text':
                            self.out(f"{result['obfuscated']} => {result['deobfuscated']}")

        self._save_results()
        self._print_statistics()

    def _save_results(self):
        """Save results in the specified format."""
        if not self.outfilepath:
            return

        with open(self.outfilepath, 'w', encoding='utf-8') as f:
            if args.format == 'json':
                # Process results to match the desired format
                formatted_results = []
                for r in self.results:
                    # Add .smali extension to obfuscated name if not present
                    obf_name = r['obfuscated']
                    if not obf_name.endswith('.smali'):
                        obf_name += '.smali'
                    
                    formatted_result = {
                        'obfuscated': obf_name,
                        'deobfuscated': r['deobfuscated'],
                        'class_name': r['class_name'].replace('.', '/'),  # Ensure proper format
                        'source_file': r['source_file'],
                        'super_class': r['super_class'],
                        'interfaces': r['interfaces'],
                        'methods': [{
                            'name': m['name'],
                            'params': m['params'],
                            'return_type': m['return_type'],
                            'modifiers': m['modifiers'],
                            'code_size': m['code_size']
                        } for m in r['methods']],
                        'fields': r['fields']
                    }
                    formatted_results.append(formatted_result)
                
                json.dump({'results': formatted_results}, f, indent=2)
            elif args.format == 'csv':
                f.write("obfuscated,deobfuscated,class_name,source_file\n")
                for r in self.results:
                    f.write(f"{r['obfuscated']},{r['deobfuscated']},{r['class_name']},{r['source_file']}\n")
            else:
                for r in self.results:
                    f.write(f"{r['obfuscated']} => {r['deobfuscated']}\n")

    def _print_statistics(self):
        """Print deobfuscation statistics and summary dashboard."""
        if args.summary:
            self._print_summary_dashboard()
        else:
            logging.info("=== Deobfuscation Statistics ===")
            logging.info(f"Total files processed: {self.statistics['total_files']}")
            logging.info(f"Successfully deobfuscated: {self.statistics['deobfuscated_files']}")
            if self.statistics['obfuscator_detected']:
                logging.info(f"Detected obfuscator: {self.statistics['obfuscator_detected']}")
            if self.statistics['patterns_found']:
                logging.info("Pattern matches found:")
                for obfuscator, count in self.statistics['patterns_found'].items():
                    logging.info(f"  {obfuscator}: {count}")
                    
    def _print_summary_dashboard(self):
        """Print detailed summary dashboard."""
        print("\n" + "="*60)
        print(" "*20 + "DEOBFUSCATION DASHBOARD")
        print("="*60)
        
        # Basic Statistics
        print("\n📊 Basic Statistics:")
        print(f"  Total Files: {self.statistics['total_files']}")
        print(f"  Deobfuscated: {self.statistics['deobfuscated_files']}")
        print(f"  Success Rate: {(self.statistics['deobfuscated_files']/self.statistics['total_files']*100):.1f}%")
        
        # Entry Points
        if self.statistics['entry_points']:
            print("\n🚪 Entry Points:")
            for entry in sorted(self.statistics['entry_points'])[:5]:
                print(f"  • {entry}")
            if len(self.statistics['entry_points']) > 5:
                print(f"  ... and {len(self.statistics['entry_points'])-5} more")
        
        # Large Methods
        if self.statistics['large_methods']:
            print("\n📏 Large Methods (>200 lines):")
            for method in sorted(self.statistics['large_methods'], 
                              key=lambda x: x['size'], reverse=True)[:5]:
                print(f"  • {method['class']}.{method['method']} ({method['size']} lines)")
            if len(self.statistics['large_methods']) > 5:
                print(f"  ... and {len(self.statistics['large_methods'])-5} more")
        
        # Suspicious Methods
        if self.statistics['suspicious_methods']:
            print("\n⚠️ High-Risk Methods:")
            for method in sorted(self.statistics['suspicious_methods'], 
                              key=lambda x: x['suspicion_score'], reverse=True)[:5]:
                print(f"  • {method['class_name']}.{method['method_name']}")
                print(f"    Reasons: {', '.join(method['reasons'])}")
            if len(self.statistics['suspicious_methods']) > 5:
                print(f"  ... and {len(self.statistics['suspicious_methods'])-5} more")
        
        # Inner Classes
        if self.statistics['inner_classes']:
            print("\n📦 Inner Classes:")
            print(f"  Total: {len(self.statistics['inner_classes'])}")
            for inner in sorted(self.statistics['inner_classes'])[:3]:
                print(f"  • {inner}")
            if len(self.statistics['inner_classes']) > 3:
                print(f"  ... and {len(self.statistics['inner_classes'])-3} more")
        
        # Obfuscation Info
        if self.statistics['obfuscator_detected'] or self.statistics['obfuscated_names']:
            print("\n🔒 Obfuscation Analysis:")
            if self.statistics['obfuscator_detected']:
                print(f"  Detected Obfuscator: {self.statistics['obfuscator_detected']}")
            print(f"  Obfuscated Names: {len(self.statistics['obfuscated_names'])}")
        
        print("\n" + "="*60)
        
    def dump_class(self, class_name: str):
        """Dump detailed information about a specific class."""
        matches = []
        for result in self.results:
            if class_name in (result['obfuscated'], result['deobfuscated'], result['class_name']):
                matches.append(result)
        
        if not matches:
            logging.error(f"Class '{class_name}' not found")
            return
        
        for match in matches:
            print("\n" + "="*60)
            print(f"Class Details: {match['class_name']}")
            print("="*60)
            
            print(f"\nObfuscated Name: {match['obfuscated']}")
            print(f"Deobfuscated Name: {match['deobfuscated']}")
            print(f"Source File: {match['source_file']}")
            print(f"Super Class: {match['super_class']}")
            
            if match['interfaces']:
                print("\nInterfaces:")
                for interface in match['interfaces']:
                    print(f"  • {interface}")
            
            print("\nMethods:")
            for method in match['methods']:
                print(f"\n  {' '.join(method['modifiers'])} {method['name']}")
                print(f"    Parameters: {', '.join(method['params'])}")
                print(f"    Returns: {method['return_type']}")
                print(f"    Code Size: {method['code_size']} lines")
            
            if match['fields']:
                print("\nFields:")
                for name, type_ in match['fields'].items():
                    print(f"  • {name}: {type_}")


def main():
    global args
    args = parse_args()
    try:
        deobfuscator = ClassNameDeobfuscator(args.namespace, args.outfile)
        deobfuscator.execute()
    except KeyboardInterrupt:
        logging.info("\nDeobfuscation interrupted by user")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    main()