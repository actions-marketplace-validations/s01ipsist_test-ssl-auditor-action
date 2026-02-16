import { loadRulesConfig, validateRulesConfig, DEFAULT_RULES } from './rules-config';
import { writeFile, unlink } from 'fs/promises';
import { join } from 'path';

describe('loadRulesConfig', () => {
  const testConfigPath = join(__dirname, 'test-config.json');

  afterEach(async () => {
    try {
      await unlink(testConfigPath);
    } catch {
      // File may not exist
    }
  });

  it('should return default rules when config file does not exist', async () => {
    const config = await loadRulesConfig('/nonexistent/path.json');
    expect(config).toEqual(DEFAULT_RULES);
  });

  it('should load and parse valid config file', async () => {
    const testConfig = {
      rules: {
        minTlsVersion: '1.3',
        blockedCiphers: ['RC4']
      }
    };

    await writeFile(testConfigPath, JSON.stringify(testConfig));
    const config = await loadRulesConfig(testConfigPath);

    expect(config.rules.minTlsVersion).toBe('1.3');
    expect(config.rules.blockedCiphers).toEqual(['RC4']);
  });

  it('should not merge with default rules when config file is provided', async () => {
    const testConfig = {
      rules: {
        minTlsVersion: '1.3'
      }
    };

    await writeFile(testConfigPath, JSON.stringify(testConfig));
    const config = await loadRulesConfig(testConfigPath);

    expect(config.rules.minTlsVersion).toBe('1.3');
    // Other rules should be undefined when not specified in the config
    expect(config.rules.requireForwardSecrecy).toBeUndefined();
    expect(config.rules.blockedCiphers).toBeUndefined();
  });

  it('should only include configured rules from the file (issue example)', async () => {
    const testConfig = {
      rules: {
        minGrade: 'B'
      }
    };

    await writeFile(testConfigPath, JSON.stringify(testConfig));
    const config = await loadRulesConfig(testConfigPath);

    // Only minGrade should be set
    expect(config.rules.minGrade).toBe('B');
    // All other rules should be undefined
    expect(config.rules.minTlsVersion).toBeUndefined();
    expect(config.rules.requireForwardSecrecy).toBeUndefined();
    expect(config.rules.blockedCiphers).toBeUndefined();
    expect(config.rules.maxCertificateExpiry).toBeUndefined();
  });

  it('should reject invalid minGrade at load time', async () => {
    const testConfig = { rules: { minGrade: 'X' } };
    await writeFile(testConfigPath, JSON.stringify(testConfig));
    await expect(loadRulesConfig(testConfigPath)).rejects.toThrow('Invalid minGrade "X"');
  });

  it('should reject invalid minTlsVersion at load time', async () => {
    const testConfig = { rules: { minTlsVersion: 'abc' } };
    await writeFile(testConfigPath, JSON.stringify(testConfig));
    await expect(loadRulesConfig(testConfigPath)).rejects.toThrow('Invalid minTlsVersion "abc"');
  });

  it('should reject negative maxCertificateExpiry at load time', async () => {
    const testConfig = { rules: { maxCertificateExpiry: -5 } };
    await writeFile(testConfigPath, JSON.stringify(testConfig));
    await expect(loadRulesConfig(testConfigPath)).rejects.toThrow('Invalid maxCertificateExpiry');
  });
});

describe('validateRulesConfig', () => {
  it('should accept all valid grades', () => {
    const validGrades = ['A+', 'A', 'A-', 'B', 'C', 'D', 'E', 'F', 'T'];
    for (const grade of validGrades) {
      expect(() => validateRulesConfig({ rules: { minGrade: grade } })).not.toThrow();
    }
  });

  it('should accept valid TLS versions', () => {
    expect(() => validateRulesConfig({ rules: { minTlsVersion: '1.2' } })).not.toThrow();
    expect(() => validateRulesConfig({ rules: { minTlsVersion: '1.3' } })).not.toThrow();
  });

  it('should reject TLS versions without dot notation', () => {
    expect(() => validateRulesConfig({ rules: { minTlsVersion: '12' } })).toThrow(
      'Invalid minTlsVersion'
    );
  });

  it('should accept zero maxCertificateExpiry', () => {
    expect(() => validateRulesConfig({ rules: { maxCertificateExpiry: 0 } })).not.toThrow();
  });

  it('should accept config with no rules set', () => {
    expect(() => validateRulesConfig({ rules: {} })).not.toThrow();
  });
});
