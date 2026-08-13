import React, { useState, useEffect } from 'react';
import {
  KeyRound,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Download,
  Copy,
  Check,
  FileCheck,
  Fingerprint,
  ArrowLeft,
  ChevronDown,
  RefreshCw,
} from 'lucide-react';
import { WasmBridge } from '../hooks/useWasmBridge';
import {
  VoucherStandardDefinition,
  StandardDiagnosticResult,
  SignResult,
} from '../types/standard';
import { SeedVault } from './SeedVault';
import { useLanguage } from '../i18n/LanguageContext';
import { FieldTooltip } from './FieldTooltip';

interface SigningViewProps {
  wasm: WasmBridge;
  standard: VoucherStandardDefinition;
  diagnostic: StandardDiagnosticResult | null;
  signResult: SignResult | null;
  onSigned: (res: SignResult) => void;
  onNavigateToEdit: () => void;
}

export const SigningView: React.FC<SigningViewProps> = ({
  wasm,
  standard,
  diagnostic,
  signResult,
  onSigned,
  onNavigateToEdit,
}) => {
  const { t } = useLanguage();
  const [mnemonic, setMnemonic] = useState<string>('');
  const [prefix, setPrefix] = useState<string>('0');
  const [derivedIssuerId, setDerivedIssuerId] = useState<string>('');
  const [isSigning, setIsSigning] = useState<boolean>(false);
  const [signError, setSignError] = useState<string | null>(null);

  // Verification & Copy Feedback
  const [copiedToml, setCopiedToml] = useState<boolean>(false);
  const [copiedIssuer, setCopiedIssuer] = useState<boolean>(false);
  const [verifyStatus, setVerifyStatus] = useState<{ valid: boolean; error?: string } | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [showSignedToml, setShowSignedToml] = useState<boolean>(true);

  // Derive Issuer DID from mnemonic
  useEffect(() => {
    let active = true;
    async function updateIdentity() {
      if (!wasm.isReady) return;

      const trimmed = mnemonic.trim();
      if (!trimmed) {
        if (active) setDerivedIssuerId('');
        return;
      }

      try {
        const isValid = await wasm.validateMnemonic(trimmed);
        if (isValid) {
          const id = await wasm.deriveIssuerId(trimmed, prefix.trim() || '0');
          if (active) {
            setDerivedIssuerId(id);
            setSignError(null);
          }
        } else {
          if (active) setDerivedIssuerId('');
        }
      } catch {
        if (active) setDerivedIssuerId('');
      }
    }

    updateIdentity();
    return () => {
      active = false;
    };
  }, [mnemonic, prefix, wasm]);

  const handleSign = async () => {
    if (!mnemonic.trim()) {
      setSignError(t.vaultStatusIdle);
      return;
    }

    try {
      setIsSigning(true);
      setSignError(null);

      const isMnemonicValid = await wasm.validateMnemonic(mnemonic.trim());
      if (!isMnemonicValid) {
        setSignError(t.vaultStatusInvalid(mnemonic.trim().split(/\s+/).length));
        setIsSigning(false);
        return;
      }

      const res = await wasm.signStandard(standard, mnemonic.trim(), prefix.trim() || '0');
      onSigned(res);

      // Trigger automatic download of signed standard.toml
      triggerDownload(res.toml);
    } catch (err: any) {
      console.error('Signing failed:', err);
      setSignError(err?.message || t.verifyFailed);
    } finally {
      setIsSigning(false);
    }
  };

  const triggerDownload = (tomlContent: string) => {
    const blob = new Blob([tomlContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    const abbreviation = standard.immutable.identity.abbreviation?.toLowerCase() || 'voucher';
    link.download = `${abbreviation}_standard.toml`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleCopyToml = async () => {
    if (!signResult?.toml) return;
    try {
      await navigator.clipboard.writeText(signResult.toml);
      setCopiedToml(true);
      setTimeout(() => setCopiedToml(false), 2000);
    } catch (err) {
      console.error('Failed to copy signed TOML:', err);
    }
  };

  const handleCopyIssuer = async () => {
    if (!derivedIssuerId && !signResult?.issuer_id) return;
    const toCopy = signResult?.issuer_id || derivedIssuerId;
    try {
      await navigator.clipboard.writeText(toCopy);
      setCopiedIssuer(true);
      setTimeout(() => setCopiedIssuer(false), 2000);
    } catch (err) {
      console.error('Failed to copy Issuer DID:', err);
    }
  };

  const handleVerify = async () => {
    if (!signResult?.toml) return;
    try {
      setIsVerifying(true);
      const res = await wasm.verifyStandard(signResult.toml);
      if (res.valid) {
        setVerifyStatus({ valid: true });
      } else {
        setVerifyStatus({ valid: false, error: t.verifyFailed });
      }
    } catch (err: any) {
      setVerifyStatus({ valid: false, error: err?.message || t.verifyFailed });
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="signing-view">
      {/* Header Banner */}
      <div className="signing-header-banner card">
        <div className="signing-header-left">
          <div className="icon-badge-pulse" style={{ background: 'rgba(16, 185, 129, 0.15)', borderColor: 'rgba(16, 185, 129, 0.3)' }}>
            <KeyRound size={22} color="var(--accent-emerald)" />
          </div>
          <div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 600, margin: 0 }}>
              {t.phase3Title}
            </h2>
            <p style={{ margin: '0.2rem 0 0', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              {t.phase3Subtitle}
            </p>
          </div>
        </div>

        <button
          type="button"
          className="btn btn-secondary"
          onClick={onNavigateToEdit}
        >
          <ArrowLeft size={16} />
          <span>{t.btnBackToEdit}</span>
        </button>
      </div>

      {/* Security Alert Banner */}
      <div className="security-notice-alert">
        <ShieldAlert size={20} color="var(--accent-amber)" />
        <div>
          {t.securityNoticeText}
        </div>
      </div>

      <div className="signing-grid">
        {/* Left / Main Column: Configuration & Seed Vault */}
        <div className="signing-main-col">
          {/* 1. Issuer Prefix */}
          <div className="card prefix-card">
            <div className="form-group">
              <label>
                <span>{t.fieldIssuerPrefix.label}</span>
                <FieldTooltip explanation={t.fieldIssuerPrefix} zone="crypto" />
                <span className="help-text-inline">— {t.fieldIssuerPrefix.placeholder}</span>
              </label>
              <input
                type="text"
                value={prefix}
                onChange={(e) => setPrefix(e.target.value)}
                placeholder={t.fieldIssuerPrefix.placeholder}
                maxLength={4}
                style={{ width: '120px', fontFamily: 'var(--font-mono)' }}
              />
              <span className="help-text">
                {t.fieldIssuerPrefix.helpText}
              </span>
            </div>
          </div>

          {/* 2. Seed Vault */}
          <div className="card seed-vault-card">
            <SeedVault
              wasm={wasm}
              mnemonic={mnemonic}
              onMnemonicChange={setMnemonic}
            />
          </div>

          {/* 3. Derived Identity Info Card */}
          <div className="card identity-card">
            <div className="identity-header-row">
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600, margin: 0, display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-secondary)' }}>
                <Fingerprint size={16} color="var(--accent-cyan)" />
                {t.identityCardTitle}
              </h3>
            </div>

            <div className="identity-rows" style={{ marginTop: '0.65rem' }}>
              <div className="identity-row">
                <div className="identity-label">
                  <KeyRound size={14} />
                  <span>{t.labelIssuerDid}</span>
                </div>
                <div className="identity-val-wrap">
                  <code className="identity-code">
                    {derivedIssuerId || signResult?.issuer_id || t.derivedDidPlaceholder}
                  </code>
                  {(derivedIssuerId || signResult?.issuer_id) && (
                    <button
                      type="button"
                      className="btn-icon"
                      onClick={handleCopyIssuer}
                      title={t.btnCopyDid}
                    >
                      {copiedIssuer ? <Check size={13} color="var(--accent-emerald)" /> : <Copy size={13} />}
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Signing Error Notice */}
          {signError && (
            <div className="sign-error-box">
              <AlertTriangle size={18} />
              <span>{signError}</span>
            </div>
          )}

          {/* Primary Action Button: Sign & Export */}
          <button
            type="button"
            className="btn btn-emerald btn-lg sign-submit-btn"
            onClick={handleSign}
            disabled={isSigning || !mnemonic.trim()}
          >
            {isSigning ? (
              <>
                <RefreshCw size={20} className="spin" />
                <span>{t.signingInProgress}</span>
              </>
            ) : (
              <>
                <Download size={20} />
                <span>{t.btnSignAndExport}</span>
              </>
            )}
          </button>
        </div>

        {/* Right Column / Bottom Panel: Success and Verification Result */}
        {signResult && (
          <div className="signing-result-col">
            <div className="card sign-success-panel">
              <div className="success-header">
                <div className="success-icon-badge">
                  <CheckCircle2 size={24} color="var(--accent-emerald)" />
                </div>
                <div>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--accent-emerald)', margin: 0 }}>
                    {t.successTitle}
                  </h3>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: '0.2rem 0 0' }}>
                    {t.successSubtitle(`${standard.immutable.identity.abbreviation?.toLowerCase() || 'voucher'}_standard.toml`)}
                  </p>
                </div>
              </div>

              {/* Signature Fingerprint */}
              <div className="signature-info-box">
                <div className="sig-field">
                  <span className="sig-label">{t.sigLabelSignature}</span>
                  <code className="sig-code">{signResult.signature}</code>
                </div>
                <div className="sig-field">
                  <span className="sig-label">{t.sigLabelIssuer}</span>
                  <code className="sig-code">{signResult.issuer_id}</code>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="success-actions">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={handleCopyToml}
                >
                  {copiedToml ? <Check size={15} color="var(--accent-emerald)" /> : <Copy size={15} />}
                  <span>{copiedToml ? t.btnCopied : t.btnCopyToml}</span>
                </button>

                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => triggerDownload(signResult.toml)}
                >
                  <Download size={15} />
                  <span>{t.btnDownloadAgain}</span>
                </button>

                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={handleVerify}
                  disabled={isVerifying}
                >
                  <ShieldCheck size={15} color="var(--accent-emerald)" />
                  <span>{isVerifying ? t.verifyingInProgress : t.btnVerifySignature}</span>
                </button>
              </div>

              {/* Verification Feedback Alert */}
              {verifyStatus && (
                <div className={`verification-feedback ${verifyStatus.valid ? 'success' : 'error'}`}>
                  {verifyStatus.valid ? (
                    <>
                      <CheckCircle2 size={16} />
                      <span>{t.verifySuccess(signResult.issuer_id)}</span>
                    </>
                  ) : (
                    <>
                      <AlertTriangle size={16} />
                      <span>{verifyStatus.error}</span>
                    </>
                  )}
                </div>
              )}

              {/* Collapsible Signed TOML View */}
              <div className="signed-toml-accordion">
                <button
                  type="button"
                  className="accordion-header"
                  onClick={() => setShowSignedToml((prev) => !prev)}
                >
                  <div className="accordion-header-left">
                    <FileCheck size={16} color="var(--accent-emerald)" />
                    <span className="accordion-title" style={{ fontSize: '0.85rem' }}>
                      {t.accordionSignedToml(signResult.toml.split('\n').length)}
                    </span>
                  </div>
                  <ChevronDown
                    size={16}
                    className={`accordion-chevron ${showSignedToml ? 'rotated' : ''}`}
                  />
                </button>

                {showSignedToml && (
                  <div className="signed-toml-body">
                    <pre className="code-preview">
                      <code>{signResult.toml}</code>
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
