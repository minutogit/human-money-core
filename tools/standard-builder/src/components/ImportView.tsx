import React, { useState, useEffect, useRef } from 'react';
import {
  Sparkles,
  Copy,
  Download,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  FileCode,
  Shield,
  ArrowRight,
  RefreshCw,
  ClipboardPaste,
  Trash2,
} from 'lucide-react';
import { WasmBridge } from '../hooks/useWasmBridge';
import {
  VoucherStandardDefinition,
  StandardDiagnosticResult,
  ARCHETYPES,
} from '../types/standard';
import { VOUCHER_STANDARD_SKILL_MD } from '../constants/skill';
import { useLanguage } from '../i18n/LanguageContext';

interface ImportViewProps {
  wasm: WasmBridge;
  standard: VoucherStandardDefinition;
  onStandardChange: (updated: VoucherStandardDefinition) => void;
  diagnostic: StandardDiagnosticResult | null;
  onDiagnosticChange: (diag: StandardDiagnosticResult | null) => void;
  onNavigateToEdit: () => void;
}

export const ImportView: React.FC<ImportViewProps> = ({
  wasm,
  standard,
  onStandardChange,
  diagnostic,
  onDiagnosticChange,
  onNavigateToEdit,
}) => {
  const { t, language } = useLanguage();

  // Input raw TOML text
  const [rawInput, setRawInput] = useState<string>(ARCHETYPES[0].toml);
  const [isValidating, setIsValidating] = useState<boolean>(false);

  // Feedback notifications
  const [copiedAction, setCopiedAction] = useState<string | null>(null);
  const [isDragOver, setIsDragOver] = useState<boolean>(false);

  const debounceTimeoutRef = useRef<number | null>(null);

  // Run diagnosis whenever rawInput or wasm readiness changes
  useEffect(() => {
    if (!wasm.isReady) return;

    if (debounceTimeoutRef.current) {
      window.clearTimeout(debounceTimeoutRef.current);
    }

    setIsValidating(true);
    debounceTimeoutRef.current = window.setTimeout(async () => {
      try {
        const res = await wasm.parseAndDiagnoseStandard(rawInput);
        onDiagnosticChange(res);
        if (res.valid && res.standard) {
          onStandardChange(res.standard);
        }
      } catch (err) {
        console.error('Diagnosis error:', err);
      } finally {
        setIsValidating(false);
      }
    }, 250);

    return () => {
      if (debounceTimeoutRef.current) {
        window.clearTimeout(debounceTimeoutRef.current);
      }
    };
  }, [rawInput, wasm.isReady]);

  const showToast = (action: string) => {
    setCopiedAction(action);
    setTimeout(() => {
      setCopiedAction(null);
    }, 2500);
  };

  // Copy AI Skill Prompt
  const handleCopyPrompt = async () => {
    try {
      await navigator.clipboard.writeText(VOUCHER_STANDARD_SKILL_MD);
      showToast('prompt');
    } catch (err) {
      console.error('Clipboard copy failed:', err);
    }
  };

  // Download Skill File
  const handleDownloadSkillFile = () => {
    const blob = new Blob([VOUCHER_STANDARD_SKILL_MD], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'voucher-standard-designer.md';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showToast('skill-download');
  };

  // Copy Error Report for AI
  const handleCopyAiErrorReport = async () => {
    if (!diagnostic || diagnostic.errors.length === 0) return;

    const errorList = diagnostic.errors.map((e, idx) => `${idx + 1}. ${e}`).join('\n');
    const promptForAi = language === 'de'
      ? `Hallo! Ich habe eine standard.toml für das human_money_core Gutschein-System entworfen.
Die Rust-WASM-Tiefenvalidierung hat folgende Fehler festgestellt:

FEHLERMELDUNGEN:
${errorList}

MEIN AKTUELLER TOML-CODE:
\`\`\`toml
${diagnostic.clean_toml || rawInput}
\`\`\`

Bitte korrigiere die Fehler und gib mir die vollständige, fehlerfreie standard.toml im \`\`\`toml Codeblock zurück.`
      : `Hello! I drafted a standard.toml for the human_money_core voucher system.
The Rust-WASM deep validation detected the following errors:

ERROR MESSAGES:
${errorList}

MY CURRENT TOML CODE:
\`\`\`toml
${diagnostic.clean_toml || rawInput}
\`\`\`

Please fix these errors and provide the complete, valid standard.toml inside a \`\`\`toml code block.`;

    try {
      await navigator.clipboard.writeText(promptForAi);
      showToast('ai-error');
    } catch (err) {
      console.error('Clipboard copy failed:', err);
    }
  };

  // Quick Archetype Loading
  const handleLoadArchetype = (toml: string) => {
    setRawInput(toml);
  };

  // Paste from clipboard
  const handlePasteFromClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setRawInput(text);
      }
    } catch (err) {
      console.error('Failed to read clipboard:', err);
    }
  };

  // Drag & drop handling
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      const file = files[0];
      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target?.result as string;
        if (content) {
          setRawInput(content);
        }
      };
      reader.readAsText(file);
    }
  };

  return (
    <div className="import-view">
      {/* 1. Skill & Prompt Header Toolbar */}
      <section className="import-toolbar card">
        <div className="toolbar-header">
          <div className="toolbar-title-group">
            <div className="icon-badge-pulse">
              <Sparkles size={20} color="var(--accent-emerald)" />
            </div>
            <div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 600, margin: 0 }}>
                {t.phase1Title}
              </h2>
              <p style={{ margin: '0.2rem 0 0', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                {t.phase1Subtitle}
              </p>
            </div>
          </div>

          <div className="toolbar-actions">
            <button
              className="btn btn-secondary"
              onClick={handleCopyPrompt}
              title={t.copyPromptBtn}
            >
              {copiedAction === 'prompt' ? (
                <>
                  <CheckCircle2 size={16} color="var(--accent-emerald)" />
                  <span>{t.copyPromptDone}</span>
                </>
              ) : (
                <>
                  <Copy size={16} />
                  <span>{t.copyPromptBtn}</span>
                </>
              )}
            </button>

            <button
              className="btn btn-secondary"
              onClick={handleDownloadSkillFile}
              title={t.downloadSkillBtn}
            >
              {copiedAction === 'skill-download' ? (
                <>
                  <CheckCircle2 size={16} color="var(--accent-emerald)" />
                  <span>{t.downloadSkillDone}</span>
                </>
              ) : (
                <>
                  <Download size={16} />
                  <span>{t.downloadSkillBtn}</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Archetypes quick buttons */}
        <div className="archetypes-row">
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 500 }}>
            {t.quickTemplates}
          </span>
          <div className="archetype-chips">
            {ARCHETYPES.map((arch) => (
              <button
                key={arch.id}
                className="chip-btn"
                onClick={() => handleLoadArchetype(arch.toml)}
                title={arch.description}
              >
                <span className="chip-name">{arch.name}</span>
                <span className="chip-badge">{arch.badge}</span>
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* 2. Main Two-Column Grid: Smart Paste Box + Live Inspection */}
      <div className="import-grid">
        {/* Left Column: Smart Paste Box */}
        <section className="card paste-section">
          <div className="section-header-row">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FileCode size={18} color="var(--accent-blue)" />
              <h3 style={{ fontSize: '1rem', fontWeight: 600, margin: 0 }}>
                {t.smartImportTitle}
              </h3>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <button
                className="btn-icon"
                onClick={handlePasteFromClipboard}
                title={t.btnPaste}
              >
                <ClipboardPaste size={14} />
                <span>{t.btnPaste}</span>
              </button>
              <button
                className="btn-icon text-muted"
                onClick={() => setRawInput('')}
                title={t.btnClear}
              >
                <Trash2 size={14} />
              </button>
            </div>
          </div>

          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: '0.4rem 0 0.75rem' }}>
            {t.smartImportDesc}
          </p>

          <div
            className={`textarea-wrapper ${isDragOver ? 'drag-over' : ''}`}
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragOver(true);
            }}
            onDragLeave={() => setIsDragOver(false)}
            onDrop={handleDrop}
          >
            <textarea
              className="code-textarea"
              value={rawInput}
              onChange={(e) => setRawInput(e.target.value)}
              placeholder={t.pastePlaceholder}
              spellCheck={false}
              rows={22}
            />
            {isDragOver && (
              <div className="drag-overlay">
                <FileCode size={32} />
                <span>{t.dropFileNotice}</span>
              </div>
            )}
          </div>

          <div className="textarea-footer">
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              {t.linesAndChars(rawInput.split('\n').length, rawInput.length)}
            </span>
            {isValidating && (
              <span style={{ fontSize: '0.75rem', color: 'var(--accent-amber)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <RefreshCw size={12} className="spin" /> {t.validationRunning}
              </span>
            )}
          </div>
        </section>

        {/* Right Column: Live Status & Inspection */}
        <section className="card inspection-section">
          <div className="section-header-row">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Shield size={18} color={diagnostic?.valid ? 'var(--accent-emerald)' : 'var(--accent-amber)'} />
              <h3 style={{ fontSize: '1rem', fontWeight: 600, margin: 0 }}>
                {t.liveInspectionTitle}
              </h3>
            </div>

            {diagnostic && (
              <div className={`status-pill ${diagnostic.valid ? 'valid' : 'invalid'}`}>
                {diagnostic.valid ? (
                  <>
                    <CheckCircle2 size={14} />
                    <span>{t.statusValid}</span>
                  </>
                ) : (
                  <>
                    <XCircle size={14} />
                    <span>{t.statusInvalid(diagnostic.errors.length)}</span>
                  </>
                )}
              </div>
            )}
          </div>

          {/* Error View & AI Error Copier */}
          {diagnostic && !diagnostic.valid && (
            <div className="error-alert-box">
              <div className="error-alert-header">
                <AlertTriangle size={18} color="var(--accent-red)" />
                <h4 style={{ margin: 0, fontSize: '0.9rem', color: 'var(--accent-red)', fontWeight: 600 }}>
                  {t.validationFailed}
                </h4>
              </div>
              <ul className="error-list">
                {diagnostic.errors.map((err, idx) => (
                  <li key={idx}>{err}</li>
                ))}
              </ul>
              <button
                className="btn btn-ai-error"
                onClick={handleCopyAiErrorReport}
                title={t.copyAiErrorBtn}
              >
                {copiedAction === 'ai-error' ? (
                  <>
                    <CheckCircle2 size={15} />
                    <span>{t.copyAiErrorDone}</span>
                  </>
                ) : (
                  <>
                    <Copy size={15} />
                    <span>{t.copyAiErrorBtn}</span>
                  </>
                )}
              </button>
            </div>
          )}

          {/* Valid Summary Cards */}
          {diagnostic?.valid && diagnostic.summary && (
            <div className="summary-details">
              <div className="summary-grid">
                <div className="summary-card">
                  <span className="summary-label">{t.summaryTitleName}</span>
                  <span className="summary-value">
                    {diagnostic.summary.name} (<strong>{diagnostic.summary.abbreviation}</strong>)
                  </span>
                </div>
                <div className="summary-card">
                  <span className="summary-label">{t.summaryTitleUnit}</span>
                  <span className="summary-value">
                    {diagnostic.summary.unit} ({diagnostic.summary.amount_decimal_places} {t.fieldDecimalPlaces.label})
                  </span>
                </div>
                <div className="summary-card">
                  <span className="summary-label">{t.summaryTitleRedemption}</span>
                  <span className="summary-value badge-val">
                    {diagnostic.summary.primary_redemption_type}
                  </span>
                </div>
                <div className="summary-card">
                  <span className="summary-label">{t.summaryTitleCollateral}</span>
                  <span className="summary-value badge-val">
                    {diagnostic.summary.collateral_type}
                  </span>
                </div>
                <div className="summary-card">
                  <span className="summary-label">{t.summaryTitlePrivacy}</span>
                  <span className="summary-value badge-val">
                    {diagnostic.summary.privacy_mode}
                  </span>
                </div>
                <div className="summary-card">
                  <span className="summary-label">{t.summaryTitleSignaturesLabel}</span>
                  <span className="summary-value">
                    {t.summaryTitleSignatures(
                      diagnostic.summary.additional_signatures_range[0],
                      diagnostic.summary.additional_signatures_range[1]
                    )}
                  </span>
                </div>
              </div>

              {/* CEL Rules Inspection */}
              <div className="cel-rules-inspection">
                <h4 style={{ fontSize: '0.85rem', fontWeight: 600, margin: '0.75rem 0 0.4rem', color: 'var(--text-secondary)' }}>
                  {t.celRulesCount(diagnostic.cel_diagnostics.length)}
                </h4>
                {diagnostic.cel_diagnostics.length === 0 ? (
                  <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: 0 }}>
                    {t.celRulesEmpty}
                  </p>
                ) : (
                  <div className="cel-list">
                    {diagnostic.cel_diagnostics.map((cel) => (
                      <div key={cel.rule_id} className={`cel-item ${cel.valid ? 'valid' : 'invalid'}`}>
                        <div className="cel-header">
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            {cel.valid ? (
                              <CheckCircle2 size={14} color="var(--accent-emerald)" />
                            ) : (
                              <XCircle size={14} color="var(--accent-red)" />
                            )}
                            <span className="cel-name">{cel.rule_id}</span>
                          </div>
                          <span className="cel-msg">{cel.message}</span>
                        </div>
                        <code className="cel-code">{cel.expression}</code>
                        {cel.error && <span className="cel-error-text">{cel.error}</span>}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Prominent CTA Transition to Edit Phase */}
              <div className="cta-banner">
                <div className="cta-info">
                  <CheckCircle2 size={20} color="var(--accent-emerald)" />
                  <div>
                    <strong style={{ fontSize: '0.95rem', color: 'var(--text-primary)' }}>
                      {t.ctaStandardValid}
                    </strong>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: '0.15rem 0 0' }}>
                      {t.ctaStandardValidDesc}
                    </p>
                  </div>
                </div>
                <button
                  className="btn btn-primary cta-btn"
                  onClick={onNavigateToEdit}
                >
                  <span>{t.ctaEditNow}</span>
                  <ArrowRight size={16} />
                </button>
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
