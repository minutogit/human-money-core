import { useEffect, useState, useCallback } from 'react';
import initWasm, {
  generate_mnemonic,
  validate_mnemonic,
  derive_issuer_id,
  validate_cel_expression,
  to_toml_preview,
  sign_standard,
  verify_standard,
  parse_and_diagnose_standard,
  sanitize_markdown_toml,
} from 'human_money_wasm';
import {
  VoucherStandardDefinition,
  SignResult,
  VerifyResult,
  StandardDiagnosticResult,
} from '../types/standard';

export interface WasmBridge {
  isReady: boolean;
  error: string | null;
  generateMnemonic: (wordCount?: number) => Promise<string>;
  validateMnemonic: (phrase: string) => Promise<boolean>;
  deriveIssuerId: (mnemonic: string, prefix?: string) => Promise<string>;
  validateCelExpression: (expression: string) => { valid: boolean; error?: string };
  toTomlPreview: (standard: VoucherStandardDefinition) => Promise<string>;
  signStandard: (standard: VoucherStandardDefinition, mnemonic: string, prefix?: string) => Promise<SignResult>;
  verifyStandard: (tomlContent: string) => Promise<VerifyResult>;
  parseAndDiagnoseStandard: (rawInput: string) => Promise<StandardDiagnosticResult>;
  sanitizeMarkdownToml: (rawInput: string) => string;
}

export function useWasmBridge(): WasmBridge {
  const [isReady, setIsReady] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    async function load() {
      try {
        await initWasm();
        if (isMounted) {
          setIsReady(true);
        }
      } catch (err: any) {
        if (isMounted) {
          console.error('Failed to initialize WASM module:', err);
          setError(err?.message || 'Failed to initialize WASM module');
        }
      }
    }
    load();
    return () => {
      isMounted = false;
    };
  }, []);

  const generateMnemonic = useCallback(
    async (wordCount = 12): Promise<string> => {
      if (!isReady) throw new Error('WASM module not ready');
      return generate_mnemonic(wordCount);
    },
    [isReady]
  );

  const validateMnemonic = useCallback(
    async (phrase: string): Promise<boolean> => {
      if (!isReady) throw new Error('WASM module not ready');
      try {
        return validate_mnemonic(phrase);
      } catch {
        return false;
      }
    },
    [isReady]
  );

  const deriveIssuerId = useCallback(
    async (mnemonic: string, prefix = '0'): Promise<string> => {
      if (!isReady) throw new Error('WASM module not ready');
      return derive_issuer_id(mnemonic, prefix);
    },
    [isReady]
  );

  const validateCelExpression = useCallback(
    (expression: string): { valid: boolean; error?: string } => {
      if (!isReady) return { valid: false, error: 'WASM loading...' };
      try {
        validate_cel_expression(expression);
        return { valid: true };
      } catch (err: any) {
        return { valid: false, error: err?.message || 'Invalid expression' };
      }
    },
    [isReady]
  );

  const toTomlPreview = useCallback(
    async (standard: VoucherStandardDefinition): Promise<string> => {
      if (!isReady) throw new Error('WASM module not ready');
      const json = JSON.stringify(standard);
      return to_toml_preview(json);
    },
    [isReady]
  );

  const signStandard = useCallback(
    async (standard: VoucherStandardDefinition, mnemonic: string, prefix = '0'): Promise<SignResult> => {
      if (!isReady) throw new Error('WASM module not ready');
      const json = JSON.stringify(standard);
      const resJson = sign_standard(json, mnemonic, prefix);
      return JSON.parse(resJson) as SignResult;
    },
    [isReady]
  );

  const verifyStandard = useCallback(
    async (tomlContent: string): Promise<VerifyResult> => {
      if (!isReady) throw new Error('WASM module not ready');
      const resJson = verify_standard(tomlContent);
      return JSON.parse(resJson) as VerifyResult;
    },
    [isReady]
  );

  const parseAndDiagnoseStandard = useCallback(
    async (rawInput: string): Promise<StandardDiagnosticResult> => {
      if (!isReady) {
        return {
          valid: false,
          clean_toml: '',
          is_signed: false,
          cel_diagnostics: [],
          errors: ['WASM module is still loading...'],
          warnings: [],
        };
      }
      try {
        const resJson = parse_and_diagnose_standard(rawInput);
        return JSON.parse(resJson) as StandardDiagnosticResult;
      } catch (err: any) {
        return {
          valid: false,
          clean_toml: '',
          is_signed: false,
          cel_diagnostics: [],
          errors: [err?.message || 'Failed to diagnose standard'],
          warnings: [],
        };
      }
    },
    [isReady]
  );

  const sanitizeMarkdownToml = useCallback(
    (rawInput: string): string => {
      if (!isReady) return rawInput;
      return sanitize_markdown_toml(rawInput);
    },
    [isReady]
  );

  return {
    isReady,
    error,
    generateMnemonic,
    validateMnemonic,
    deriveIssuerId,
    validateCelExpression,
    toTomlPreview,
    signStandard,
    verifyStandard,
    parseAndDiagnoseStandard,
    sanitizeMarkdownToml,
  };
}
