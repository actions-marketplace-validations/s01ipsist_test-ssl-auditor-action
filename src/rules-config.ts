import { readFile } from 'fs/promises';
import { existsSync } from 'fs';

/**
 * Configuration for audit rules
 */
export interface RulesConfig {
  rules: {
    minTlsVersion?: string;
    blockedCiphers?: string[];
    requireForwardSecrecy?: boolean;
    maxCertificateExpiry?: number; // days
    minGrade?: string; // Minimum overall grade (A+, A, A-, B, C, D, E, F, T)
  };
}

const VALID_GRADES = ['A+', 'A', 'A-', 'B', 'C', 'D', 'E', 'F', 'T'];
const VALID_TLS_VERSION = /^\d+\.\d+$/;

/**
 * Validate a rules configuration and throw on invalid values
 */
export function validateRulesConfig(config: RulesConfig): void {
  const { rules } = config;

  if (rules.minGrade !== undefined && !VALID_GRADES.includes(rules.minGrade)) {
    throw new Error(
      `Invalid minGrade "${rules.minGrade}". Must be one of: ${VALID_GRADES.join(', ')}`
    );
  }

  if (rules.minTlsVersion !== undefined && !VALID_TLS_VERSION.test(rules.minTlsVersion)) {
    throw new Error(
      `Invalid minTlsVersion "${rules.minTlsVersion}". Must be in format "X.Y" (e.g., "1.2", "1.3")`
    );
  }

  if (rules.maxCertificateExpiry !== undefined) {
    if (!Number.isFinite(rules.maxCertificateExpiry) || rules.maxCertificateExpiry < 0) {
      throw new Error(
        `Invalid maxCertificateExpiry "${rules.maxCertificateExpiry}". Must be a non-negative number`
      );
    }
  }
}

/**
 * Default rules configuration - used only when no config file is provided
 */
export const DEFAULT_RULES: RulesConfig = {
  rules: {
    minTlsVersion: '1.2',
    blockedCiphers: ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon'],
    requireForwardSecrecy: true,
    maxCertificateExpiry: 14,
    minGrade: undefined // No grade requirement by default
  }
};

/**
 * Load rules configuration from a file
 * @param configPath Path to the configuration file
 * @returns Parsed rules configuration
 */
export async function loadRulesConfig(configPath: string): Promise<RulesConfig> {
  if (!configPath || !existsSync(configPath)) {
    return DEFAULT_RULES;
  }

  const content = await readFile(configPath, 'utf-8');
  const config = JSON.parse(content) as RulesConfig;

  validateRulesConfig(config);

  // Return the loaded config without merging with defaults
  // If a config is provided, only the rules specified in it should be tested
  return config;
}
