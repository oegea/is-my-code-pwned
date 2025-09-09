const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const os = require('os');

class PackageScanner {
  constructor(database, logger) {
    this.db = database;
    this.logger = logger;
  }

  // Encuentra TODOS los directorios node_modules de manera exhaustiva
  findAllNodeModules(startDir) {
    const nodeModulesPaths = [];
    const visited = new Set();
    
    const searchRecursive = (dir, depth = 0) => {
      if (depth > 15) return; // Aumentamos profundidad máxima
      
      try {
        const realPath = fs.realpathSync(dir);
        if (visited.has(realPath)) return;
        visited.add(realPath);

        const items = fs.readdirSync(dir, { withFileTypes: true });
        
        for (const item of items) {
          if (item.isDirectory()) {
            const itemPath = path.join(dir, item.name);
            
            if (item.name === 'node_modules') {
              nodeModulesPaths.push(itemPath);
              this.logger.debug('Found node_modules', { path: itemPath, depth });
              
              // CRÍTICO: También buscar node_modules DENTRO de node_modules
              this.searchNestedNodeModules(itemPath, nodeModulesPaths, visited, depth + 1);
            } else if (this.shouldExploreDirectory(item.name)) {
              searchRecursive(itemPath, depth + 1);
            }
          }
        }
      } catch (error) {
        this.logger.warning(`Cannot access directory: ${error.message}`, { path: dir });
      }
    };
    
    searchRecursive(startDir);
    this.logger.info(`Found ${nodeModulesPaths.length} node_modules directories`);
    return nodeModulesPaths;
  }

  // Busca node_modules anidados dentro de otros node_modules
  searchNestedNodeModules(nodeModulesPath, foundPaths, visited, depth) {
    if (depth > 15) return;
    
    try {
      const packages = fs.readdirSync(nodeModulesPath, { withFileTypes: true });
      
      for (const pkg of packages) {
        if (pkg.isDirectory()) {
          const packagePath = path.join(nodeModulesPath, pkg.name);
          
          // Buscar node_modules dentro de cada paquete
          const nestedNodeModules = path.join(packagePath, 'node_modules');
          if (fs.existsSync(nestedNodeModules)) {
            const realPath = fs.realpathSync(nestedNodeModules);
            if (!visited.has(realPath)) {
              visited.add(realPath);
              foundPaths.push(nestedNodeModules);
              this.logger.debug('Found nested node_modules', { path: nestedNodeModules, parent: pkg.name });
              
              // Recursivamente buscar más niveles
              this.searchNestedNodeModules(nestedNodeModules, foundPaths, visited, depth + 1);
            }
          }
          
          // Para paquetes con scope (@org/package)
          if (pkg.name.startsWith('@')) {
            try {
              const scopedPackages = fs.readdirSync(packagePath, { withFileTypes: true });
              for (const scopedPkg of scopedPackages) {
                if (scopedPkg.isDirectory()) {
                  const scopedPackagePath = path.join(packagePath, scopedPkg.name);
                  const scopedNestedNodeModules = path.join(scopedPackagePath, 'node_modules');
                  if (fs.existsSync(scopedNestedNodeModules)) {
                    const realPath = fs.realpathSync(scopedNestedNodeModules);
                    if (!visited.has(realPath)) {
                      visited.add(realPath);
                      foundPaths.push(scopedNestedNodeModules);
                      this.logger.debug('Found nested scoped node_modules', { 
                        path: scopedNestedNodeModules, 
                        package: `${pkg.name}/${scopedPkg.name}` 
                      });
                    }
                  }
                }
              }
            } catch (error) {
              this.logger.warning(`Error scanning scoped package: ${error.message}`, { package: pkg.name });
            }
          }
        }
      }
    } catch (error) {
      this.logger.warning(`Error scanning nested node_modules: ${error.message}`, { path: nodeModulesPath });
    }
  }

  shouldExploreDirectory(dirName) {
    const skipDirs = new Set([
      '.git', '.svn', '.hg',
      'dist', 'build', 'coverage', 'tmp', 'temp',
      '.next', '.nuxt', '.cache',
      'logs', 'log',
      '.DS_Store', 'Thumbs.db'
    ]);
    
    return !dirName.startsWith('.') || !skipDirs.has(dirName);
  }

  getPackageVersion(packagePath) {
    try {
      const packageJsonPath = path.join(packagePath, 'package.json');
      if (fs.existsSync(packageJsonPath)) {
        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        return packageJson.version;
      }
    } catch (error) {
      this.logger.warning('Cannot read package.json', { path: packagePath, error: error.message });
    }
    return null;
  }

  // Escaneo EXHAUSTIVO de paquetes maliciosos
  scanForMaliciousPackages(targetPath) {
    const nodeModulesPaths = this.findAllNodeModules(targetPath);
    const foundMalicious = [];
    const checkedPackages = new Set();
    
    for (const nodeModulesPath of nodeModulesPaths) {
      this.logger.setCurrentPath(nodeModulesPath);
      
      try {
        const packages = fs.readdirSync(nodeModulesPath, { withFileTypes: true });
        
        for (const pkg of packages) {
          if (pkg.isDirectory()) {
            this.scanPackageDirectory(nodeModulesPath, pkg.name, foundMalicious, checkedPackages);
          }
        }
      } catch (error) {
        this.logger.error(`Error scanning ${nodeModulesPath}: ${error.message}`);
      }
    }
    
    return foundMalicious;
  }

  scanPackageDirectory(nodeModulesPath, packageName, foundMalicious, checkedPackages) {
    if (packageName.startsWith('@')) {
      // Manejar paquetes con scope
      try {
        const scopedPackages = fs.readdirSync(path.join(nodeModulesPath, packageName), { withFileTypes: true });
        for (const scopedPkg of scopedPackages) {
          if (scopedPkg.isDirectory()) {
            const fullPackageName = `${packageName}/${scopedPkg.name}`;
            this.checkSinglePackage(nodeModulesPath, fullPackageName, foundMalicious, checkedPackages);
          }
        }
      } catch (error) {
        this.logger.warning('Error reading scoped package directory', { package: packageName, error: error.message });
      }
    } else {
      // Paquetes regulares
      this.checkSinglePackage(nodeModulesPath, packageName, foundMalicious, checkedPackages);
    }
  }

  checkSinglePackage(nodeModulesPath, packageName, foundMalicious, checkedPackages) {
    if (this.db.getMaliciousVersion(packageName)) {
      const packagePath = packageName.includes('/') 
        ? path.join(nodeModulesPath, ...packageName.split('/'))
        : path.join(nodeModulesPath, packageName);
      
      const version = this.getPackageVersion(packagePath);
      const packageKey = `${packageName}@${version}@${packagePath}`;
      
      if (!checkedPackages.has(packageKey) && version) {
        checkedPackages.add(packageKey);
        this.logger.debug('Checking package', { package: packageName, version, path: packagePath });
        
        if (this.db.isMalicious(packageName, version)) {
          foundMalicious.push({
            name: packageName,
            version: version,
            path: packagePath,
            type: 'local'
          });
          this.logger.critical('MALICIOUS PACKAGE FOUND', { package: packageName, version, path: packagePath });
        }
      }
    }
  }

  // Verificación de paquetes globales MÁS exhaustiva
  checkGlobalPackages() {
    this.logger.info('Checking global packages');
    const foundMalicious = [];
    
    // Verificar múltiples ubicaciones globales
    const globalLocations = this.getGlobalPackageLocations();
    
    for (const location of globalLocations) {
      try {
        if (fs.existsSync(location)) {
          this.logger.debug('Scanning global location', { path: location });
          this.scanGlobalLocation(location, foundMalicious);
        }
      } catch (error) {
        this.logger.warning(`Error checking global location: ${error.message}`, { path: location });
      }
    }
    
    return foundMalicious;
  }

  getGlobalPackageLocations() {
    const locations = [];
    
    try {
      // npm global
      const npmPrefix = execSync('npm config get prefix', { encoding: 'utf8', stderr: 'ignore' }).trim();
      locations.push(path.join(npmPrefix, 'lib', 'node_modules'));
      locations.push(path.join(npmPrefix, 'node_modules'));
    } catch (error) {
      this.logger.debug('Could not get npm prefix');
    }
    
    try {
      // yarn global
      const yarnGlobalDir = execSync('yarn global dir', { encoding: 'utf8', stderr: 'ignore' }).trim();
      locations.push(path.join(yarnGlobalDir, 'node_modules'));
    } catch (error) {
      this.logger.debug('Could not get yarn global dir');
    }
    
    try {
      // pnpm global
      const pnpmGlobalDir = execSync('pnpm root -g', { encoding: 'utf8', stderr: 'ignore' }).trim();
      locations.push(pnpmGlobalDir);
    } catch (error) {
      this.logger.debug('Could not get pnpm global dir');
    }
    
    // Ubicaciones adicionales comunes
    const homeDir = os.homedir();
    locations.push(path.join(homeDir, '.npm-global', 'lib', 'node_modules'));
    locations.push(path.join('/usr/local/lib/node_modules'));
    locations.push(path.join('/usr/lib/node_modules'));
    
    return [...new Set(locations)]; // Eliminar duplicados
  }

  scanGlobalLocation(globalPath, foundMalicious) {
    try {
      const packages = fs.readdirSync(globalPath, { withFileTypes: true });
      
      for (const pkg of packages) {
        if (pkg.isDirectory() && this.db.getMaliciousVersion(pkg.name)) {
          const packagePath = path.join(globalPath, pkg.name);
          const version = this.getPackageVersion(packagePath);
          
          this.logger.debug('Checking global package', { package: pkg.name, version, path: packagePath });
          
          if (version && this.db.isMalicious(pkg.name, version)) {
            foundMalicious.push({
              name: pkg.name,
              version: version,
              path: packagePath,
              type: 'global'
            });
            this.logger.critical('GLOBAL MALICIOUS PACKAGE FOUND', { package: pkg.name, version, path: packagePath });
          }
        }
      }
    } catch (error) {
      this.logger.warning(`Error scanning global location: ${error.message}`, { path: globalPath });
    }
  }

  // Escaneo de CACHES de paquetes
  scanPackageCaches() {
    this.logger.info('Scanning package caches');
    const foundMalicious = [];
    
    const cacheLocations = this.getPackageCacheLocations();
    
    for (const { type, path: cachePath } of cacheLocations) {
      try {
        if (fs.existsSync(cachePath)) {
          this.logger.debug(`Scanning ${type} cache`, { path: cachePath });
          this.scanCacheLocation(cachePath, type, foundMalicious);
        }
      } catch (error) {
        this.logger.warning(`Error scanning ${type} cache: ${error.message}`, { path: cachePath });
      }
    }
    
    return foundMalicious;
  }

  getPackageCacheLocations() {
    const locations = [];
    const homeDir = os.homedir();
    
    // npm cache
    try {
      const npmCache = execSync('npm config get cache', { encoding: 'utf8', stderr: 'ignore' }).trim();
      locations.push({ type: 'npm', path: npmCache });
    } catch (error) {
      locations.push({ type: 'npm', path: path.join(homeDir, '.npm') });
    }
    
    // yarn cache
    try {
      const yarnCache = execSync('yarn cache dir', { encoding: 'utf8', stderr: 'ignore' }).trim();
      locations.push({ type: 'yarn', path: yarnCache });
    } catch (error) {
      locations.push({ type: 'yarn', path: path.join(homeDir, '.yarn', 'cache') });
      locations.push({ type: 'yarn', path: path.join(homeDir, '.cache', 'yarn') });
    }
    
    // pnpm cache
    try {
      const pnpmStore = execSync('pnpm store path', { encoding: 'utf8', stderr: 'ignore' }).trim();
      locations.push({ type: 'pnpm', path: pnpmStore });
    } catch (error) {
      locations.push({ type: 'pnpm', path: path.join(homeDir, '.pnpm-store') });
    }
    
    return locations;
  }

  scanCacheLocation(cachePath, cacheType, foundMalicious) {
    // Esta es una implementación simplificada - las estructuras de cache son complejas
    // pero podemos al menos detectar algunos patrones
    try {
      this.scanDirectoryForMaliciousPackageNames(cachePath, cacheType, foundMalicious, 3);
    } catch (error) {
      this.logger.warning(`Error scanning cache directory: ${error.message}`, { type: cacheType, path: cachePath });
    }
  }

  scanDirectoryForMaliciousPackageNames(dir, type, foundMalicious, maxDepth) {
    if (maxDepth <= 0) return;
    
    try {
      const items = fs.readdirSync(dir, { withFileTypes: true });
      
      for (const item of items) {
        if (item.isDirectory()) {
          const itemPath = path.join(dir, item.name);
          
          // Buscar nombres de paquetes maliciosos en la estructura
          for (const maliciousPackage of this.db.getAllPackageNames()) {
            if (item.name.includes(maliciousPackage)) {
              this.logger.warning(`Possible malicious package in ${type} cache`, { 
                package: maliciousPackage, 
                found: item.name, 
                path: itemPath 
              });
              // No añadimos a foundMalicious porque en cache es más complejo verificar
            }
          }
          
          // Recursivamente escanear
          this.scanDirectoryForMaliciousPackageNames(itemPath, type, foundMalicious, maxDepth - 1);
        }
      }
    } catch (error) {
      // Silenciar errores de permisos en caches
    }
  }
}

module.exports = PackageScanner;