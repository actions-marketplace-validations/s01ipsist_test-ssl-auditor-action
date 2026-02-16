/**
 * Configuration for audit rules
 */
export interface RulesConfig {
  rules: {
    minTlsVersion?: string;
    blockedCiphers?: string[];
    requireForwardSecrecy?: boolean;
    maxCertificateExpiry?: number;
    minGrade?: string;
  };
}
/**
 * Validate a rules configuration and throw on invalid values
 */
export declare function validateRulesConfig(config: RulesConfig): void;
/**
 * Default rules configuration - used only when no config file is provided
 */
export declare const DEFAULT_RULES: RulesConfig;
/**
 * Load rules configuration from a file
 * @param configPath Path to the configuration file
 * @returns Parsed rules configuration
 */
export declare function loadRulesConfig(configPath: string): Promise<RulesConfig>;
