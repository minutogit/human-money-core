import React, { useState, useEffect } from 'react';
import {
  RefreshCw,
  Eye,
  EyeOff,
  Copy,
  CheckCircle2,
  AlertCircle,
  LayoutGrid,
  FileText,
  KeyRound,
  ClipboardPaste,
  Trash2,
  Sparkles,
} from 'lucide-react';
import { WasmBridge } from '../hooks/useWasmBridge';
import { useLanguage } from '../i18n/LanguageContext';
import { FieldTooltip } from './FieldTooltip';

interface SeedVaultProps {
  wasm: WasmBridge;
  mnemonic: string;
  onMnemonicChange: (phrase: string) => void;
  className?: string;
}

export const SeedVault: React.FC<SeedVaultProps> = ({
  wasm,
  mnemonic,
  onMnemonicChange,
  className = '',
}) => {
  const { t } = useLanguage();
  const [viewMode, setViewMode] = useState<'chips' | 'freetext'>('chips');
  const [isVisible, setIsVisible] = useState<boolean>(true);
  const [copied, setCopied] = useState<boolean>(false);
  const [pastedFeedback, setPastedFeedback] = useState<boolean>(false);
  const [isValid, setIsValid] = useState<boolean | null>(null);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [genWordCount, setGenWordCount] = useState<12 | 24>(12);

  const words = mnemonic.trim().split(/\s+/).filter(Boolean);

  // Validate whenever mnemonic or wasm changes
  useEffect(() => {
    let active = true;
    async function validate() {
      const trimmed = mnemonic.trim();
      if (!trimmed || !wasm.isReady) {
        if (active) setIsValid(null);
        return;
      }
      try {
        const valid = await wasm.validateMnemonic(trimmed);
        if (active) setIsValid(valid);
      } catch {
        if (active) setIsValid(false);
      }
    }
    validate();
    return () => {
      active = false;
    };
  }, [mnemonic, wasm]);

  const handleGenerate = async (wordCount: 12 | 24) => {
    try {
      setIsGenerating(true);
      setGenWordCount(wordCount);
      const generated = await wasm.generateMnemonic(wordCount);
      onMnemonicChange(generated);
      setViewMode('chips');
      setIsVisible(true);
    } catch (err) {
      console.error('Failed to generate mnemonic:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleCopy = async () => {
    if (!mnemonic.trim()) return;
    try {
      await navigator.clipboard.writeText(mnemonic.trim());
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy mnemonic:', err);
    }
  };

  const handlePasteFromClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text && text.trim()) {
        onMnemonicChange(text.trim());
        setPastedFeedback(true);
        setIsVisible(true);
        setTimeout(() => setPastedFeedback(false), 2000);
      }
    } catch (err) {
      console.error('Failed to read clipboard:', err);
    }
  };

  const handleClear = () => {
    onMnemonicChange('');
    setViewMode('freetext');
  };

  return (
    <div className={`seed-vault ${className}`}>
      {/* Vault Toolbar */}
      <div className="seed-vault-toolbar">
        <div className="vault-header-title">
          <KeyRound size={16} color="var(--accent-emerald)" />
          <span className="vault-title-text">{t.vaultTitle}</span>
          <FieldTooltip explanation={t.fieldMnemonicSeed} zone="crypto" />
          {words.length > 0 && (
            <span className="vault-word-count">
              {t.vaultWordCount(words.length)}
            </span>
          )}
        </div>

        <div className="vault-toolbar-actions">
          {/* View mode toggle */}
          <div className="vault-mode-switch">
            <button
              type="button"
              className={`vault-mode-btn ${viewMode === 'chips' ? 'active' : ''}`}
              onClick={() => setViewMode('chips')}
              title={t.vaultModeChips}
            >
              <LayoutGrid size={13} />
              <span>{t.vaultModeChips}</span>
            </button>
            <button
              type="button"
              className={`vault-mode-btn ${viewMode === 'freetext' ? 'active' : ''}`}
              onClick={() => setViewMode('freetext')}
              title={t.vaultModeFreetext}
            >
              <FileText size={13} />
              <span>{t.vaultModeFreetext}</span>
            </button>
          </div>

          {/* Paste button */}
          <button
            type="button"
            className="btn-icon"
            onClick={handlePasteFromClipboard}
            title={t.vaultPasteSeed}
          >
            {pastedFeedback ? (
              <CheckCircle2 size={14} color="var(--accent-emerald)" />
            ) : (
              <ClipboardPaste size={14} />
            )}
            <span>{pastedFeedback ? t.btnPasted : t.vaultPasteSeed}</span>
          </button>

          {/* Visibility toggle */}
          <button
            type="button"
            className="btn-icon"
            onClick={() => setIsVisible((prev) => !prev)}
            title={isVisible ? t.vaultHide : t.vaultShow}
          >
            {isVisible ? <EyeOff size={14} /> : <Eye size={14} />}
            <span>{isVisible ? t.vaultHide : t.vaultShow}</span>
          </button>

          {/* Copy button */}
          <button
            type="button"
            className="btn-icon"
            onClick={handleCopy}
            disabled={!mnemonic.trim()}
            title={t.btnCopy}
          >
            {copied ? <CheckCircle2 size={14} color="var(--accent-emerald)" /> : <Copy size={14} />}
            <span>{copied ? t.btnCopied : t.btnCopy}</span>
          </button>

          {/* Clear button */}
          {mnemonic.trim() && (
            <button
              type="button"
              className="btn-icon text-muted"
              onClick={handleClear}
              title={t.vaultClearTitle}
            >
              <Trash2 size={14} />
            </button>
          )}

          {/* Generate Button Group */}
          <div className="vault-generate-group">
            <button
              type="button"
              className="btn btn-secondary vault-generate-btn"
              onClick={() => handleGenerate(12)}
              disabled={isGenerating || !wasm.isReady}
              title={t.vaultGen12}
            >
              <RefreshCw size={13} className={isGenerating && genWordCount === 12 ? 'spin' : ''} />
              <span>{t.vaultGen12}</span>
            </button>
            <button
              type="button"
              className="btn btn-secondary vault-generate-btn"
              onClick={() => handleGenerate(24)}
              disabled={isGenerating || !wasm.isReady}
              title={t.vaultGen24}
            >
              <Sparkles size={13} className={isGenerating && genWordCount === 24 ? 'spin' : ''} />
              <span>{t.vaultGen24}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Seed Display Area */}
      <div className="vault-body">
        {viewMode === 'chips' ? (
          words.length > 0 ? (
            <div className="seed-chips-container">
              <div className={`seed-grid ${words.length > 12 ? 'grid-24' : 'grid-12'}`}>
                {words.map((word, index) => (
                  <div key={index} className="seed-chip">
                    <span className="seed-chip-number">{index + 1}</span>
                    <span className="seed-chip-word">
                      {isVisible ? word : '••••••'}
                    </span>
                  </div>
                ))}
              </div>
              <div className="seed-chips-footer">
                <button
                  type="button"
                  className="btn-link"
                  onClick={() => setViewMode('freetext')}
                >
                  <FileText size={13} />
                  <span>{t.vaultEditAsTextLink}</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="seed-empty-state">
              <p>{t.vaultEmptyTitle}</p>
              <div className="seed-empty-actions">
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={handlePasteFromClipboard}
                >
                  <ClipboardPaste size={14} />
                  <span>{t.vaultPasteSeed}</span>
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => handleGenerate(12)}
                  disabled={!wasm.isReady}
                >
                  <RefreshCw size={14} />
                  <span>{t.vaultGen12}</span>
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => handleGenerate(24)}
                  disabled={!wasm.isReady}
                >
                  <Sparkles size={14} />
                  <span>{t.vaultGen24}</span>
                </button>
              </div>
            </div>
          )
        ) : (
          <div className="seed-textarea-wrap">
            <textarea
              className="seed-textarea"
              rows={4}
              placeholder={t.vaultFreetextPlaceholder}
              value={isVisible ? mnemonic : mnemonic.replace(/[^\s]/g, '•')}
              onChange={(e) => {
                if (isVisible) {
                  onMnemonicChange(e.target.value);
                }
              }}
              spellCheck={false}
              autoComplete="off"
            />
            <span className="help-text" style={{ marginTop: '0.4rem', display: 'block' }}>
              {t.vaultFreetextTip}
            </span>
          </div>
        )}
      </div>

      {/* Validation Status Footer */}
      <div className="vault-footer">
        {mnemonic.trim() ? (
          isValid === true ? (
            <div className="seed-status valid">
              <CheckCircle2 size={15} />
              <span>
                {t.vaultStatusValid(words.length, words.length === 12 || words.length === 24)}
              </span>
            </div>
          ) : isValid === false ? (
            <div className="seed-status invalid">
              <AlertCircle size={15} />
              <span>
                {t.vaultStatusInvalid(words.length)}
              </span>
            </div>
          ) : (
            <div className="seed-status checking">
              <RefreshCw size={12} className="spin" />
              <span>{t.vaultStatusChecking}</span>
            </div>
          )
        ) : (
          <div className="seed-status idle">
            <span>{t.vaultStatusIdle}</span>
          </div>
        )}
      </div>
    </div>
  );
};
