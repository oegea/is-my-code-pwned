#!/usr/bin/env node

const path = require('path');
const fs = require('fs');

// Ensure we can find our modules relative to the installed package
const moduleDir = path.dirname(__filename);
const srcDir = path.join(moduleDir, 'src');

// Verify our modules exist
if (!fs.existsSync(srcDir)) {
  console.error('❌ Installation error: Required modules not found');
  console.error('Please reinstall: npm install -g is-my-code-pwned');
  process.exit(3);
}

const MaliciousPackageDatabase = require(path.join(srcDir, 'database'));
const Logger = require(path.join(srcDir, 'logger'));
const PackageScanner = require(path.join(srcDir, 'scanner'));
const RiskAnalyzer = require(path.join(srcDir, 'risk-analyzer'));
const SecurityReporter = require(path.join(srcDir, 'reporter'));
const CLIHandler = require(path.join(srcDir, 'cli'));

class EnhancedSecurityScanner {
  constructor() {
    this.db = new MaliciousPackageDatabase();
    this.logger = new Logger();
    this.scanner = new PackageScanner(this.db, this.logger);
    this.riskAnalyzer = new RiskAnalyzer(this.db, this.logger);
    this.reporter = new SecurityReporter(this.logger);
    this.cli = new CLIHandler();
  }

  async performComprehensiveScan(options) {
    const startTime = Date.now();
    this.logger.clear();
    this.logger.setCurrentPath(options.targetPath);
    
    this.logger.info(`Starting comprehensive security scan of ${options.targetPath}`);
    
    let maliciousPackages = [];
    let cacheResults = [];
    let risks = [];

    try {
      // Análisis de configuración (siempre se ejecuta)
      this.logger.info('Analyzing configuration files and security settings...');
      risks = this.riskAnalyzer.analyzeVulnerabilityRisks(options.targetPath);
      
      if (!options.configOnly) {
        // Escaneo de paquetes maliciosos locales
        this.logger.info('Scanning for malicious packages in node_modules...');
        maliciousPackages = this.scanner.scanForMaliciousPackages(options.targetPath);
        
        // Escaneo de paquetes globales
        this.logger.info('Checking global packages...');
        const globalMalicious = this.scanner.checkGlobalPackages();
        maliciousPackages.push(...globalMalicious);
        
        // Escaneo de caches si está habilitado
        if (options.scanCaches) {
          this.logger.info('Scanning package manager caches...');
          cacheResults = this.scanner.scanPackageCaches();
        }
      }

      const endTime = Date.now();
      const scanTime = endTime - startTime;
      
      // Generar resumen
      const summary = this.reporter.generateSummary(maliciousPackages, risks, cacheResults, scanTime);
      
      // Mostrar resultados
      if (options.json) {
        this.reporter.printJsonOutput(summary, maliciousPackages, risks, cacheResults);
      } else {
        this.reporter.printSummary(summary, maliciousPackages, risks, cacheResults, options);
      }
      
      return summary;
      
    } catch (error) {
      this.logger.error('Scan failed', { error: error.message, stack: error.stack });
      
      if (options.json) {
        console.log(JSON.stringify({
          safe: false,
          status: 'ERROR',
          error: error.message,
          scanTime: Date.now() - startTime
        }, null, 2));
      } else {
        console.error(`\n❌ Scan failed: ${error.message}`);
        if (options.verbose) {
          console.error(error.stack);
        }
      }
      
      return { safe: false, status: 'ERROR' };
    }
  }

  async run() {
    const options = this.cli.parseArgs();
    
    if (options.help) {
      this.cli.printUsage();
      process.exit(0);
    }
    
    // Validar opciones
    this.cli.validateOptions();
    
    // Mostrar banner y información de inicio
    if (!options.json) {
      this.cli.printBanner();
    }
    
    this.cli.showScanStartMessage();
    
    // Realizar el escaneo
    const summary = await this.performComprehensiveScan(options);
    
    // Mostrar consejos de seguridad
    this.cli.printSecurityAdvice();
    
    // Salir con código apropiado
    const exitCode = this.cli.getExitCode(summary);
    process.exit(exitCode);
  }
}

// Manejar errores no capturados
process.on('uncaughtException', (error) => {
  console.error('🚨 Fatal error:', error.message);
  process.exit(3);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('🚨 Unhandled rejection at:', promise, 'reason:', reason);
  process.exit(3);
});

// Ejecutar si es el módulo principal
if (require.main === module) {
  const scanner = new EnhancedSecurityScanner();
  scanner.run();
}

module.exports = EnhancedSecurityScanner;