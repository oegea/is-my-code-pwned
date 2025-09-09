const fs = require('fs');
const path = require('path');

class CLIHandler {
  constructor() {
    this.options = {};
  }

  printBanner() {
    console.log('');
    console.log('🔍 is-my-code-pwned v2.0.0');
    console.log('   🛡️  Advanced Security Scanner for npm Packages');
    console.log('   🔎 Comprehensive malware detection & vulnerability analysis');
    console.log('');
  }

  printUsage() {
    this.printBanner();
    console.log('USAGE:');
    console.log('  is-my-code-pwned [OPTIONS] [PATH]');
    console.log('');
    console.log('OPTIONS:');
    console.log('  -h, --help              Show this help');
    console.log('  -v, --verbose           Show detailed scan log');
    console.log('  --json                  JSON output format');
    console.log('  --log-file FILE         Save detailed report to file');
    console.log('  --scan-caches           Include package manager caches in scan');
    console.log('  --deep-scan             Maximum depth scanning (slower but thorough)');
    console.log('  --config-only           Only analyze configuration files');
    console.log('');
    console.log('EXAMPLES:');
    console.log('  is-my-code-pwned                              # Quick scan current directory');
    console.log('  is-my-code-pwned -v /path/to/project          # Verbose scan specific path');
    console.log('  is-my-code-pwned --deep-scan --scan-caches    # Maximum security scan');
    console.log('  is-my-code-pwned --json --log-file report.json');
    console.log('  is-my-code-pwned --config-only                # Fast config check only');
    console.log('');
    console.log('SECURITY FEATURES:');
    console.log('  ✓ Detects known malicious npm packages');
    console.log('  ✓ Scans nested node_modules recursively');
    console.log('  ✓ Checks global packages across all managers');
    console.log('  ✓ Analyzes package.json for vulnerable ranges');
    console.log('  ✓ Validates lock files and integrity');
    console.log('  ✓ Scans .npmrc and configuration files');
    console.log('  ✓ Checks package manager caches');
    console.log('  ✓ Provides actionable security recommendations');
    console.log('');
  }

  parseArgs() {
    const args = process.argv.slice(2);
    const options = {
      help: false,
      verbose: false,
      json: false,
      logFile: null,
      scanCaches: false,
      deepScan: false,
      configOnly: false,
      targetPath: process.cwd()
    };

    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      
      switch (arg) {
        case '-h':
        case '--help':
          options.help = true;
          break;
        case '-v':
        case '--verbose':
          options.verbose = true;
          break;
        case '--json':
          options.json = true;
          break;
        case '--log-file':
          options.logFile = args[++i];
          if (!options.logFile) {
            console.error('❌ --log-file requires a filename');
            process.exit(1);
          }
          break;
        case '--scan-caches':
          options.scanCaches = true;
          break;
        case '--deep-scan':
          options.deepScan = true;
          options.scanCaches = true; // Deep scan includes caches
          break;
        case '--config-only':
          options.configOnly = true;
          break;
        default:
          if (!arg.startsWith('-')) {
            const resolvedPath = path.resolve(arg);
            if (fs.existsSync(resolvedPath)) {
              options.targetPath = resolvedPath;
            } else {
              console.error(`❌ Path does not exist: ${resolvedPath}`);
              process.exit(1);
            }
          } else {
            console.error(`❌ Unknown option: ${arg}`);
            console.error('Use --help for usage information');
            process.exit(1);
          }
          break;
      }
    }

    this.options = options;
    return options;
  }

  validateOptions() {
    // Validar path de destino
    if (!fs.existsSync(this.options.targetPath)) {
      console.error(`❌ Path does not exist: ${this.options.targetPath}`);
      process.exit(1);
    }

    if (!fs.statSync(this.options.targetPath).isDirectory()) {
      console.error(`❌ Path is not a directory: ${this.options.targetPath}`);
      process.exit(1);
    }

    // Validar archivo de log
    if (this.options.logFile) {
      const logDir = path.dirname(path.resolve(this.options.logFile));
      if (!fs.existsSync(logDir)) {
        console.error(`❌ Log file directory does not exist: ${logDir}`);
        process.exit(1);
      }
    }

    return true;
  }

  showScanStartMessage() {
    if (!this.options.json) {
      console.log(`🔍 Starting ${this.options.deepScan ? 'deep ' : ''}security scan...`);
      console.log(`📁 Target: ${this.options.targetPath}`);
      
      if (this.options.configOnly) {
        console.log('⚡ Mode: Configuration analysis only (fast)');
      } else if (this.options.deepScan) {
        console.log('🔬 Mode: Deep scan (comprehensive, may take longer)');
      } else {
        console.log('⚡ Mode: Standard scan (balanced speed and coverage)');
      }
      
      if (this.options.scanCaches) {
        console.log('💾 Cache scanning: Enabled');
      }
      
      console.log('');
    }
  }

  getExitCode(summary) {
    if (summary.maliciousPackages > 0) {
      return 2; // Malicious packages found
    }
    
    if (summary.risks.critical > 0) {
      return 1; // Critical risks
    }
    
    if (summary.risks.high > 0) {
      return 1; // High risks
    }
    
    return 0; // Safe
  }

  printSecurityAdvice() {
    if (!this.options.json && !this.options.help) {
      console.log('💡 SECURITY TIPS:');
      console.log('   • Run this scanner regularly in your CI/CD pipeline');
      console.log('   • Use --deep-scan for thorough pre-production checks');
      console.log('   • Keep the malicious package database updated');
      console.log('   • Report new malicious packages to the community');
      console.log('');
    }
  }
}

module.exports = CLIHandler;