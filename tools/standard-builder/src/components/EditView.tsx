import React, { useState, useEffect } from 'react';
import {
  Fingerprint,
  Sliders,
  Code,
  Globe,
  FileCode,
  KeyRound,
  ArrowRight,
  Copy,
  Check,
  CheckCircle2,
} from 'lucide-react';
import { WasmBridge } from '../hooks/useWasmBridge';
import { VoucherStandardDefinition } from '../types/standard';
import { AccordionSection } from './AccordionSection';
import { ImmutableZoneForm } from './ImmutableZoneForm';
import { FeaturesIssuanceForm } from './FeaturesIssuanceForm';
import { CelRulesForm } from './CelRulesForm';
import { MutableZoneForm } from './MutableZoneForm';
import { useLanguage } from '../i18n/LanguageContext';

interface EditViewProps {
  wasm: WasmBridge;
  standard: VoucherStandardDefinition;
  onStandardChange: (updated: VoucherStandardDefinition) => void;
  onNavigateToSign: () => void;
}

export const EditView: React.FC<EditViewProps> = ({
  wasm,
  standard,
  onStandardChange,
  onNavigateToSign,
}) => {
  const { t } = useLanguage();
  const [tomlPreview, setTomlPreview] = useState<string>('');
  const [copiedToml, setCopiedToml] = useState<boolean>(false);
  const [isGeneratingPreview, setIsGeneratingPreview] = useState<boolean>(false);

  // Generate TOML preview when requested or when standard changes
  useEffect(() => {
    let active = true;
    async function updatePreview() {
      if (!wasm.isReady) return;
      setIsGeneratingPreview(true);
      try {
        const preview = await wasm.toTomlPreview(standard);
        if (active) setTomlPreview(preview);
      } catch (err) {
        console.error('Failed to generate TOML preview:', err);
      } finally {
        if (active) setIsGeneratingPreview(false);
      }
    }
    updatePreview();
    return () => {
      active = false;
    };
  }, [standard, wasm]);

  const handleCopyToml = async () => {
    if (!tomlPreview) return;
    try {
      await navigator.clipboard.writeText(tomlPreview);
      setCopiedToml(true);
      setTimeout(() => setCopiedToml(false), 2000);
    } catch (err) {
      console.error('Failed to copy TOML:', err);
    }
  };

  const celRulesCount = Object.keys(standard.immutable.custom_rules || {}).length;

  return (
    <div className="edit-view">
      {/* Header Banner */}
      <div className="edit-view-header card">
        <div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 600, margin: 0 }}>
            {t.phase2Title}
          </h2>
          <p style={{ margin: '0.2rem 0 0', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            {t.phase2Subtitle}
          </p>
        </div>
        <button
          className="btn btn-primary"
          onClick={onNavigateToSign}
        >
          <KeyRound size={16} />
          <span>{t.btnProceedToSign}</span>
          <ArrowRight size={16} />
        </button>
      </div>

      {/* Accordion Sections Stack */}
      <div className="accordion-stack">
        {/* Sektion 1: Identität & Blueprint */}
        <AccordionSection
          title={t.sec1Title}
          subtitle={`${standard.immutable.identity.name || '---'} (${standard.immutable.identity.abbreviation || '---'}) • ${t.fieldUnit.label}: ${standard.immutable.blueprint.unit || '---'}`}
          icon={<Fingerprint size={20} color="var(--accent-primary)" />}
          defaultOpen={true}
        >
          <ImmutableZoneForm
            standard={standard}
            onChange={onStandardChange}
          />
        </AccordionSection>

        {/* Sektion 2: Features & Issuance Rules */}
        <AccordionSection
          title={t.sec2Title}
          subtitle={`Privacy: ${standard.immutable.features.privacy_mode} • ${standard.immutable.features.amount_decimal_places} Decimals • ${standard.immutable.issuance.additional_signatures_range[0]}-${standard.immutable.issuance.additional_signatures_range[1]} Signatures`}
          icon={<Sliders size={20} color="var(--accent-blue)" />}
          defaultOpen={false}
        >
          <FeaturesIssuanceForm
            standard={standard}
            onChange={onStandardChange}
          />
        </AccordionSection>

        {/* Sektion 3: CEL Custom Rules */}
        <AccordionSection
          title={t.sec3Title}
          subtitle={t.celRulesCount(celRulesCount)}
          icon={<Code size={20} color="var(--accent-emerald)" />}
          defaultOpen={false}
        >
          <CelRulesForm
            standard={standard}
            wasm={wasm}
            onChange={onStandardChange}
          />
        </AccordionSection>

        {/* Sektion 4: Metadaten & Sprachen (i18n) */}
        <AccordionSection
          title={t.sec4Title}
          subtitle={`${t.fieldIssuerName.label}: ${standard.mutable.metadata.issuer_name || '---'} • i18n: ${Object.keys(standard.mutable.i18n.descriptions || {}).join(', ') || 'de'}`}
          icon={<Globe size={20} color="var(--accent-cyan)" />}
          defaultOpen={false}
        >
          <MutableZoneForm
            standard={standard}
            onChange={onStandardChange}
          />
        </AccordionSection>

        {/* Sektion 5: TOML-Code Live-Vorschau */}
        <AccordionSection
          title={t.sec5Title}
          subtitle={t.sec5Subtitle}
          icon={<FileCode size={20} color="var(--accent-amber)" />}
          defaultOpen={false}
        >
          <div className="toml-preview-container">
            <div className="preview-toolbar">
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                {t.sec5Desc}
              </span>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={handleCopyToml}
              >
                {copiedToml ? <Check size={14} color="var(--accent-emerald)" /> : <Copy size={14} />}
                <span>{copiedToml ? t.btnCopied : t.btnCopyToml}</span>
              </button>
            </div>
            <pre className="code-preview">
              <code>{tomlPreview || (isGeneratingPreview ? '# ...' : '# No standard loaded')}</code>
            </pre>
          </div>
        </AccordionSection>
      </div>

      {/* Prominent Bottom CTA */}
      <div className="edit-footer-cta card">
        <div className="edit-cta-text">
          <CheckCircle2 size={22} color="var(--accent-emerald)" />
          <div>
            <h4 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>
              {t.ctaEditDoneTitle}
            </h4>
            <p style={{ margin: '0.2rem 0 0', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
              {t.ctaEditDoneDesc}
            </p>
          </div>
        </div>

        <button
          type="button"
          className="btn btn-emerald edit-cta-btn"
          onClick={onNavigateToSign}
        >
          <KeyRound size={18} />
          <span>{t.ctaProceedSignBtn}</span>
        </button>
      </div>
    </div>
  );
};
