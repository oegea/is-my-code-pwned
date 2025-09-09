const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class RiskAnalyzer {
  constructor(database, logger) {
    this.db = database;
    this.logger = logger;
  }

  analyzeVulnerabilityRisks(targetPath) {
    const risks = [];
    this.logger.info('Analyzing vulnerability risks');

    // Análisis exhaustivo de todos los archivos de configuración
    this.analyzePackageJson(targetPath, risks);
    this.analyzeLockFiles(targetPath, risks);
    this.analyzeNpmConfig(targetPath, risks);
    this.analyzeEnvironment(risks);
    this.analyzePackageManagerVersions(risks);
    this.analyzeRegistryConfiguration(risks);
    this.checkForUnsafeConfigurations(targetPath, risks);

    return risks;
  }

  analyzePackageJson(targetPath, risks) {
    const packageJsonPath = path.join(targetPath, 'package.json');
    
    if (!fs.existsSync(packageJsonPath)) {
      risks.push({
        type: 'no-package-json',
        severity: 'medium',
        message: 'No package.json found - not a Node.js project or missing configuration',
        recommendation: 'Ensure this is a Node.js project with proper package.json'
      });
      return;
    }

    try {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
      
      // Verificar dependencias con rangos peligrosos
      this.checkDependencyRanges(packageJson.dependencies, 'dependencies', risks);
      this.checkDependencyRanges(packageJson.devDependencies, 'devDependencies', risks);
      this.checkDependencyRanges(packageJson.peerDependencies, 'peerDependencies', risks);
      this.checkDependencyRanges(packageJson.optionalDependencies, 'optionalDependencies', risks);
      
      // Verificar scripts peligrosos
      this.analyzePackageScripts(packageJson.scripts, risks);
      
      // Verificar configuración de engine
      this.analyzeEngineRequirements(packageJson.engines, risks);
      
      // Verificar repositorio y autor
      this.analyzePackageMetadata(packageJson, risks);

    } catch (error) {
      risks.push({
        type: 'invalid-package-json',
        severity: 'high',
        message: `Invalid package.json: ${error.message}`,
        recommendation: 'Fix package.json syntax errors'
      });
    }
  }

  checkDependencyRanges(deps, depType, risks) {
    if (!deps) return;
    
    for (const [packageName, version] of Object.entries(deps)) {
      // Verificar si es un paquete malicioso conocido
      if (this.db.getMaliciousVersion(packageName)) {
        const maliciousVersion = this.db.getMaliciousVersion(packageName);
        
        if (this.versionRangeCouldInclude(version, maliciousVersion)) {
          risks.push({
            type: 'vulnerable-range',
            severity: 'critical',
            message: `${packageName} uses range "${version}" which could install malicious version ${maliciousVersion}`,
            package: packageName,
            currentRange: version,
            maliciousVersion: maliciousVersion,
            dependencyType: depType,
            recommendation: `Pin to safe version (not ${maliciousVersion}): "${packageName}": "SAFE_VERSION"`
          });
        }
      }
      
      // Verificar rangos muy amplios
      if (this.isVeryLooseRange(version)) {
        risks.push({
          type: 'loose-dependency',
          severity: version === '*' ? 'high' : 'medium',
          message: `${packageName} uses very loose version "${version}"`,
          package: packageName,
          version: version,
          dependencyType: depType,
          recommendation: 'Pin to specific version to avoid unexpected updates'
        });
      }
      
      // Verificar protocolos de fuente sospechosos
      this.checkSuspiciousSourceProtocol(packageName, version, depType, risks);
    }
  }

  versionRangeCouldInclude(range, targetVersion) {
    // Rangos que podrían incluir versiones peligrosas
    return range.includes('^') || 
           range.includes('~') || 
           range === '*' || 
           range.includes('x') ||
           range.includes('latest') ||
           range.includes('>') ||
           range.includes('<') ||
           range.includes('>=') ||
           range.includes('<=');
  }

  isVeryLooseRange(version) {
    return version === '*' || 
           version.includes('x') || 
           version === 'latest' ||
           version === '>0.0.0' ||
           /^\^0\./.test(version) || // ^0.x es muy peligroso
           /^~0\./.test(version);    // ~0.x también
  }

  checkSuspiciousSourceProtocol(packageName, version, depType, risks) {
    // Verificar fuentes sospechosas
    const suspiciousPatterns = [
      'git+http://',    // HTTP no seguro
      'file://',        // Archivos locales
      'ftp://',         // FTP
      'git+ssh://',     // SSH sin verificación
    ];

    for (const pattern of suspiciousPatterns) {
      if (version.includes(pattern)) {
        risks.push({
          type: 'suspicious-source',
          severity: 'high',
          message: `${packageName} uses suspicious source: ${version}`,
          package: packageName,
          source: version,
          dependencyType: depType,
          recommendation: 'Use official npm registry or verify source security'
        });
      }
    }
  }

  analyzePackageScripts(scripts, risks) {
    if (!scripts) return;

    const dangerousCommands = [
      'rm -rf',
      'sudo ',
      'curl | sh',
      'wget | sh',
      'eval(',
      '$((',
      'chmod +x',
      '> /dev/',
      'dd if=',
      'format ',
      'fdisk'
    ];

    for (const [scriptName, command] of Object.entries(scripts)) {
      for (const dangerous of dangerousCommands) {
        if (command.includes(dangerous)) {
          risks.push({
            type: 'dangerous-script',
            severity: 'critical',
            message: `Script "${scriptName}" contains potentially dangerous command: ${dangerous}`,
            script: scriptName,
            command: command,
            recommendation: 'Review and verify script safety before execution'
          });
        }
      }

      // Verificar descarga de archivos externos
      if (command.includes('http://') || (command.includes('curl') && command.includes('http'))) {
        risks.push({
          type: 'external-download-script',
          severity: 'high',
          message: `Script "${scriptName}" downloads external content over HTTP`,
          script: scriptName,
          recommendation: 'Use HTTPS and verify downloaded content integrity'
        });
      }
    }
  }

  analyzeEngineRequirements(engines, risks) {
    if (!engines) return;

    if (engines.node) {
      try {
        const currentNodeVersion = process.version;
        if (engines.node.includes('<') && !engines.node.includes('>=')) {
          risks.push({
            type: 'outdated-node-requirement',
            severity: 'medium',
            message: `Package requires old Node.js version: ${engines.node}`,
            requirement: engines.node,
            current: currentNodeVersion,
            recommendation: 'Consider updating to support newer Node.js versions'
          });
        }
      } catch (error) {
        this.logger.debug('Could not analyze Node version requirement');
      }
    }
  }

  analyzePackageMetadata(packageJson, risks) {
    // Verificar repositorio
    if (!packageJson.repository) {
      risks.push({
        type: 'no-repository',
        severity: 'low',
        message: 'Package has no repository information',
        recommendation: 'Verify package legitimacy through other means'
      });
    }

    // Verificar autor
    if (!packageJson.author && !packageJson.contributors) {
      risks.push({
        type: 'no-author',
        severity: 'low',
        message: 'Package has no author information',
        recommendation: 'Be cautious with anonymous packages'
      });
    }

    // Verificar homepage sospechosa
    if (packageJson.homepage) {
      if (packageJson.homepage.includes('bit.ly') || 
          packageJson.homepage.includes('tinyurl') ||
          !packageJson.homepage.startsWith('https://')) {
        risks.push({
          type: 'suspicious-homepage',
          severity: 'medium',
          message: `Suspicious homepage URL: ${packageJson.homepage}`,
          url: packageJson.homepage,
          recommendation: 'Verify package legitimacy'
        });
      }
    }
  }

  analyzeLockFiles(targetPath, risks) {
    const lockFiles = [
      { file: 'package-lock.json', type: 'npm' },
      { file: 'yarn.lock', type: 'yarn' },
      { file: 'pnpm-lock.yaml', type: 'pnpm' },
      { file: 'npm-shrinkwrap.json', type: 'npm-shrinkwrap' }
    ];

    const existingLockFiles = lockFiles.filter(({ file }) => 
      fs.existsSync(path.join(targetPath, file))
    );

    if (existingLockFiles.length === 0) {
      risks.push({
        type: 'no-lock-file',
        severity: 'critical',
        message: 'No lock file found - versions are not pinned, exposing to supply chain attacks',
        recommendation: 'Run npm install, yarn install, or pnpm install to generate lock file'
      });
    } else if (existingLockFiles.length > 1) {
      risks.push({
        type: 'multiple-lock-files',
        severity: 'high',
        message: `Multiple lock files found: ${existingLockFiles.map(f => f.file).join(', ')}`,
        files: existingLockFiles.map(f => f.file),
        recommendation: 'Use only one package manager to avoid conflicts'
      });
    }

    // Analizar contenido de lock files
    for (const { file, type } of existingLockFiles) {
      this.analyzeLockFileContent(path.join(targetPath, file), type, risks);
    }
  }

  analyzeLockFileContent(lockFilePath, type, risks) {
    try {
      const content = fs.readFileSync(lockFilePath, 'utf8');
      
      // Verificar registros sospechosos en lock files - solo si no son registros configurados legítimamente
      const suspiciousPatterns = [
        'http://registry',  // HTTP no seguro
        'localhost:',       // Registro local
        '127.0.0.1:',      // Registro local
        '192.168.',        // Red interna
        '10.',             // Red interna
      ];

      // Obtener registros configurados legítimamente
      const configuredRegistries = this.getConfiguredRegistries();
      
      for (const pattern of suspiciousPatterns) {
        if (content.includes(pattern)) {
          // Extraer la URL completa del registro
          const registryMatch = content.match(new RegExp(`https?://[^"'\\s]+`));
          const fullRegistry = registryMatch ? registryMatch[0] : pattern;
          
          // Solo marcar como sospechoso si no está en la configuración de npm
          if (!configuredRegistries.some(reg => fullRegistry.includes(reg))) {
            risks.push({
              type: 'suspicious-registry-in-lock',
              severity: 'high',
              message: `Lock file contains unconfigured registry: ${fullRegistry}`,
              lockFile: path.basename(lockFilePath),
              registry: fullRegistry,
              recommendation: 'Verify this registry is intended and properly configured'
            });
          } else {
            // Si está configurado, solo advertir si es HTTP
            if (fullRegistry.startsWith('http://')) {
              risks.push({
                type: 'insecure-configured-registry',
                severity: 'medium',
                message: `Configured registry uses HTTP: ${fullRegistry}`,
                lockFile: path.basename(lockFilePath),
                registry: fullRegistry,
                recommendation: 'Switch to HTTPS version of your private registry'
              });
            }
          }
        }
      }

      // Verificar integridad
      if (type === 'npm' && !content.includes('"integrity":')) {
        risks.push({
          type: 'no-integrity-hashes',
          severity: 'high',
          message: 'npm lock file lacks integrity hashes',
          lockFile: path.basename(lockFilePath),
          recommendation: 'Update npm and regenerate lock file for integrity protection'
        });
      }

    } catch (error) {
      risks.push({
        type: 'invalid-lock-file',
        severity: 'high',
        message: `Cannot read or parse lock file: ${error.message}`,
        lockFile: path.basename(lockFilePath),
        recommendation: 'Regenerate lock file'
      });
    }
  }

  getConfiguredRegistries() {
    const registries = [];
    
    try {
      // Obtener registro por defecto
      const defaultRegistry = execSync('npm config get registry', { encoding: 'utf8', stderr: 'ignore' }).trim();
      if (defaultRegistry) registries.push(defaultRegistry);
      
      // Obtener registros con scope
      const configList = execSync('npm config list', { encoding: 'utf8', stderr: 'ignore' });
      const scopedMatches = configList.match(/@[^:]+:registry\s*=\s*([^\s]+)/g);
      if (scopedMatches) {
        for (const match of scopedMatches) {
          const registry = match.split('=')[1].trim();
          registries.push(registry);
        }
      }
    } catch (error) {
      this.logger.debug('Could not get configured registries');
    }
    
    return registries;
  }

  analyzeNpmConfig(targetPath, risks) {
    // Verificar .npmrc local (esto SÍ es importante)
    const npmrcPath = path.join(targetPath, '.npmrc');
    if (fs.existsSync(npmrcPath)) {
      this.analyzeNpmrcFile(npmrcPath, 'project', risks, targetPath);
    }

    // Solo verificar .npmrc global para ciertas configuraciones peligrosas, NO para tokens
    try {
      const globalNpmrc = path.join(require('os').homedir(), '.npmrc');
      if (fs.existsSync(globalNpmrc)) {
        this.analyzeGlobalNpmrcFile(globalNpmrc, risks);
      }
    } catch (error) {
      this.logger.debug('Could not check global .npmrc');
    }
  }

  analyzeNpmrcFile(npmrcPath, scope, risks, projectPath) {
    try {
      const content = fs.readFileSync(npmrcPath, 'utf8');
      const lines = content.split('\n').filter(line => line.trim() && !line.startsWith('#'));

      for (const line of lines) {
        // Verificar registros no seguros
        if (line.includes('registry=http://')) {
          risks.push({
            type: 'insecure-registry',
            severity: 'critical',
            message: `${scope} .npmrc uses insecure HTTP registry`,
            file: npmrcPath,
            line: line.trim(),
            recommendation: 'Use HTTPS registry only'
          });
        }

        // Verificar configuraciones peligrosas
        if (line.includes('ignore-scripts=false')) {
          risks.push({
            type: 'scripts-enabled',
            severity: 'high',
            message: `${scope} .npmrc explicitly enables package scripts`,
            file: npmrcPath,
            recommendation: 'Consider disabling scripts for security'
          });
        }

        if (line.includes('audit=false') || line.includes('audit-level=none')) {
          risks.push({
            type: 'audit-disabled',
            severity: 'medium',
            message: `${scope} .npmrc disables security auditing`,
            file: npmrcPath,
            recommendation: 'Enable npm audit for security checks'
          });
        }

        // SOLO verificar tokens en .npmrc del proyecto (no global)
        if (line.includes('_authToken=') && !line.includes('${') && scope === 'project') {
          const isIgnored = this.isFileIgnoredByGit(npmrcPath);
          risks.push({
            type: 'exposed-auth-token',
            severity: 'critical',
            message: `Project .npmrc contains exposed authentication token`,
            file: npmrcPath,
            gitIgnored: isIgnored,
            recommendation: isIgnored 
              ? 'Token is git-ignored but still visible in filesystem - use environment variables'
              : 'URGENT: Token will be committed to git! Use environment variables and add .npmrc to .gitignore'
          });
        }
      }
    } catch (error) {
      this.logger.warning(`Could not analyze .npmrc: ${error.message}`, { path: npmrcPath });
    }
  }

  analyzeGlobalNpmrcFile(globalNpmrcPath, risks) {
    try {
      const content = fs.readFileSync(globalNpmrcPath, 'utf8');
      const lines = content.split('\n').filter(line => line.trim() && !line.startsWith('#'));

      for (const line of lines) {
        // Solo verificar configuraciones que afectan a todos los proyectos
        if (line.includes('registry=http://')) {
          risks.push({
            type: 'insecure-global-registry',
            severity: 'high',
            message: 'Global npm config uses insecure HTTP registry',
            file: globalNpmrcPath,
            line: line.trim(),
            recommendation: 'Change global registry to HTTPS: npm config set registry https://registry.npmjs.org/'
          });
        }

        // TLS deshabilitado globalmente es muy peligroso
        if (line.includes('strict-ssl=false')) {
          risks.push({
            type: 'global-tls-disabled',
            severity: 'critical',
            message: 'Global npm config disables SSL verification',
            file: globalNpmrcPath,
            recommendation: 'Enable SSL: npm config set strict-ssl true'
          });
        }
        
        // NO reportar tokens globales - es normal tenerlos
      }
    } catch (error) {
      this.logger.debug(`Could not analyze global .npmrc: ${error.message}`);
    }
  }

  analyzeEnvironment(risks) {
    // Verificar variables de entorno peligrosas
    const dangerousEnvVars = [
      'NPM_CONFIG_REGISTRY',
      'npm_config_registry',
      'YARN_REGISTRY',
      'NODE_TLS_REJECT_UNAUTHORIZED'
    ];

    for (const envVar of dangerousEnvVars) {
      if (process.env[envVar]) {
        const value = process.env[envVar];
        
        if (envVar.includes('REGISTRY') && value.startsWith('http://')) {
          risks.push({
            type: 'insecure-registry-env',
            severity: 'critical',
            message: `Environment variable ${envVar} uses insecure HTTP registry`,
            variable: envVar,
            value: value,
            recommendation: 'Use HTTPS registry or remove environment override'
          });
        }
        
        if (envVar === 'NODE_TLS_REJECT_UNAUTHORIZED' && value === '0') {
          risks.push({
            type: 'tls-disabled',
            severity: 'critical',
            message: 'TLS certificate verification is disabled',
            variable: envVar,
            recommendation: 'Remove NODE_TLS_REJECT_UNAUTHORIZED=0 for security'
          });
        }
      }
    }
  }

  analyzePackageManagerVersions(risks) {
    const packageManagers = [
      { cmd: 'npm --version', name: 'npm', minSecureVersion: '8.0.0' },
      { cmd: 'yarn --version', name: 'yarn', minSecureVersion: '1.22.0' },
      { cmd: 'pnpm --version', name: 'pnpm', minSecureVersion: '7.0.0' }
    ];

    for (const pm of packageManagers) {
      try {
        const version = execSync(pm.cmd, { encoding: 'utf8', stderr: 'ignore' }).trim();
        
        if (this.isVersionOutdated(version, pm.minSecureVersion)) {
          risks.push({
            type: 'outdated-package-manager',
            severity: 'medium',
            message: `${pm.name} v${version} is outdated (recommend v${pm.minSecureVersion}+)`,
            packageManager: pm.name,
            currentVersion: version,
            recommendedVersion: pm.minSecureVersion,
            recommendation: `Update ${pm.name} to latest version for security fixes`
          });
        }
      } catch (error) {
        this.logger.debug(`Could not check ${pm.name} version`);
      }
    }
  }

  analyzeRegistryConfiguration(risks) {
    try {
      // Verificar configuración actual del registro
      const registry = execSync('npm config get registry', { encoding: 'utf8', stderr: 'ignore' }).trim();
      
      if (registry && registry.startsWith('http://')) {
        risks.push({
          type: 'insecure-default-registry',
          severity: 'critical',
          message: `Default npm registry uses insecure HTTP: ${registry}`,
          registry: registry,
          recommendation: 'Configure secure HTTPS registry: npm config set registry https://registry.npmjs.org/'
        });
      }

      // Verificar registros con scope configurados
      const scopedRegistries = execSync('npm config list', { encoding: 'utf8', stderr: 'ignore' });
      const lines = scopedRegistries.split('\n');
      
      for (const line of lines) {
        if (line.includes(':registry = http://')) {
          risks.push({
            type: 'insecure-scoped-registry',
            severity: 'high',
            message: `Scoped registry uses insecure HTTP: ${line.trim()}`,
            config: line.trim(),
            recommendation: 'Configure scoped registries to use HTTPS'
          });
        }
      }
    } catch (error) {
      this.logger.debug('Could not check registry configuration');
    }
  }

  checkForUnsafeConfigurations(targetPath, risks) {
    // Verificar archivos de configuración adicionales que podrían ser peligrosos
    const configFiles = [
      '.yarnrc',
      '.yarnrc.yml', 
      '.pnpmfile.cjs',
      'pnpm-workspace.yaml',
      'lerna.json'
    ];

    for (const configFile of configFiles) {
      const filePath = path.join(targetPath, configFile);
      if (fs.existsSync(filePath)) {
        this.analyzeConfigFile(filePath, risks);
      }
    }
  }

  analyzeConfigFile(filePath, risks) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const fileName = path.basename(filePath);
      
      // Verificar URLs HTTP en archivos de configuración
      if (content.includes('http://')) {
        risks.push({
          type: 'insecure-config-url',
          severity: 'high',
          message: `Configuration file ${fileName} contains insecure HTTP URLs`,
          file: filePath,
          recommendation: 'Replace HTTP URLs with HTTPS equivalents'
        });
      }

      // Verificar configuraciones específicas por tipo de archivo
      if (fileName.includes('.yarnrc')) {
        this.analyzeYarnrcContent(content, filePath, risks);
      }
    } catch (error) {
      this.logger.debug(`Could not analyze config file: ${filePath}`);
    }
  }

  analyzeYarnrcContent(content, filePath, risks) {
    if (content.includes('ignore-scripts false')) {
      risks.push({
        type: 'yarn-scripts-enabled',
        severity: 'high',
        message: 'Yarn configuration enables package scripts',
        file: filePath,
        recommendation: 'Consider setting ignore-scripts true for security'
      });
    }

    if (content.includes('disable-self-update-check true')) {
      risks.push({
        type: 'yarn-update-disabled',
        severity: 'low',
        message: 'Yarn self-update check is disabled',
        file: filePath,
        recommendation: 'Enable update checks to stay current with security fixes'
      });
    }
  }

  isVersionOutdated(current, minimum) {
    try {
      const currentParts = current.split('.').map(Number);
      const minimumParts = minimum.split('.').map(Number);
      
      for (let i = 0; i < Math.max(currentParts.length, minimumParts.length); i++) {
        const currentPart = currentParts[i] || 0;
        const minimumPart = minimumParts[i] || 0;
        
        if (currentPart < minimumPart) return true;
        if (currentPart > minimumPart) return false;
      }
      
      return false;
    } catch (error) {
      return false;
    }
  }

  isFileIgnoredByGit(filePath) {
    try {
      const projectRoot = this.findProjectRoot(filePath);
      const gitignorePath = path.join(projectRoot, '.gitignore');
      
      if (!fs.existsSync(gitignorePath)) {
        return false; // No .gitignore means file is not ignored
      }
      
      const gitignoreContent = fs.readFileSync(gitignorePath, 'utf8');
      const relativePath = path.relative(projectRoot, filePath);
      
      // Simple gitignore pattern matching (basic implementation)
      const patterns = gitignoreContent
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
      
      for (const pattern of patterns) {
        if (this.matchesGitignorePattern(relativePath, pattern)) {
          return true;
        }
      }
      
      return false;
    } catch (error) {
      this.logger.debug(`Could not check gitignore status for ${filePath}: ${error.message}`);
      return false;
    }
  }

  findProjectRoot(startPath) {
    let currentPath = path.dirname(startPath);
    
    while (currentPath !== path.dirname(currentPath)) {
      if (fs.existsSync(path.join(currentPath, 'package.json')) || 
          fs.existsSync(path.join(currentPath, '.git'))) {
        return currentPath;
      }
      currentPath = path.dirname(currentPath);
    }
    
    return path.dirname(startPath); // Fallback to file's directory
  }

  matchesGitignorePattern(filePath, pattern) {
    // Basic gitignore pattern matching
    if (pattern === filePath) return true;
    if (pattern === path.basename(filePath)) return true;
    
    // Handle wildcards (very basic)
    if (pattern.includes('*')) {
      const regexPattern = pattern.replace(/\*/g, '.*');
      const regex = new RegExp(`^${regexPattern}$`);
      return regex.test(filePath) || regex.test(path.basename(filePath));
    }
    
    // Handle directory patterns
    if (pattern.endsWith('/')) {
      return filePath.startsWith(pattern) || 
             filePath.includes(`/${pattern.slice(0, -1)}/`);
    }
    
    return false;
  }
}

module.exports = RiskAnalyzer;