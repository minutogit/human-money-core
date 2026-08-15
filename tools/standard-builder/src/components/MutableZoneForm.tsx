import React from 'react';
import { VoucherStandardDefinition } from '../types/standard';
import { Edit3, Globe, Settings, Languages } from 'lucide-react';
import { useLanguage } from '../i18n/LanguageContext';
import { FieldTooltip } from './FieldTooltip';

interface MutableZoneFormProps {
  standard: VoucherStandardDefinition;
  onChange: (updated: VoucherStandardDefinition) => void;
  onPrev?: () => void;
  onNext?: () => void;
}

export const MutableZoneForm: React.FC<MutableZoneFormProps> = ({
  standard,
  onChange,
  onPrev,
  onNext,
}) => {
  const { t } = useLanguage();
  const { metadata, app_config, i18n } = standard.mutable;

  const updateMetadata = (field: keyof typeof metadata, value: any) => {
    onChange({
      ...standard,
      mutable: {
        ...standard.mutable,
        metadata: {
          ...metadata,
          [field]: value,
        },
      },
    });
  };

  const updateAppConfig = (field: keyof typeof app_config, value: any) => {
    onChange({
      ...standard,
      mutable: {
        ...standard.mutable,
        app_config: {
          ...app_config,
          [field]: value,
        },
      },
    });
  };

  const updateI18nMap = (category: keyof typeof i18n, lang: string, text: string) => {
    const categoryMap = i18n[category] || {};
    const updatedMap = { ...categoryMap, [lang]: text };
    onChange({
      ...standard,
      mutable: {
        ...standard.mutable,
        i18n: {
          ...i18n,
          [category]: updatedMap,
        },
      },
    });
  };

  const handleKeywordsChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const list = e.target.value.split(',').map((s) => s.trim()).filter(Boolean);
    updateMetadata('keywords', list);
  };

  return (
    <div>
      <div className="panel-header">
        <h2 className="panel-title">
          <Edit3 color="var(--accent-cyan)" size={24} />
          {t.mutableHeaderTitle}
        </h2>
        <p className="panel-desc">
          {t.mutableHeaderDesc}
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        {/* Metadata Section */}
        <div>
          <h3 style={{ fontSize: '1.05rem', marginBottom: '1rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Globe size={18} />
            {t.metadataSectionTitle}
          </h3>
          <div className="form-grid">
            {/* Issuer Name */}
            <div className="form-group">
              <label>
                <span>{t.fieldIssuerName.label}</span>
                <FieldTooltip explanation={t.fieldIssuerName} zone="mutable" />
              </label>
              <input
                type="text"
                value={metadata.issuer_name}
                onChange={(e) => updateMetadata('issuer_name', e.target.value)}
                placeholder={t.fieldIssuerName.placeholder}
              />
              <span className="help-text">{t.fieldIssuerName.helpText}</span>
            </div>

            {/* Homepage URL */}
            <div className="form-group">
              <label>
                <span>{t.fieldHomepageUrl.label}</span>
                <FieldTooltip explanation={t.fieldHomepageUrl} zone="mutable" />
              </label>
              <input
                type="url"
                value={metadata.homepage_url || ''}
                onChange={(e) => updateMetadata('homepage_url', e.target.value || undefined)}
                placeholder={t.fieldHomepageUrl.placeholder}
              />
              <span className="help-text">{t.fieldHomepageUrl.helpText}</span>
            </div>

            {/* Documentation URL */}
            <div className="form-group">
              <label>
                <span>{t.fieldDocumentationUrl.label}</span>
                <FieldTooltip explanation={t.fieldDocumentationUrl} zone="mutable" />
              </label>
              <input
                type="url"
                value={metadata.documentation_url || ''}
                onChange={(e) => updateMetadata('documentation_url', e.target.value || undefined)}
                placeholder={t.fieldDocumentationUrl.placeholder}
              />
              <span className="help-text">{t.fieldDocumentationUrl.helpText}</span>
            </div>

            {/* Keywords */}
            <div className="form-group full-width">
              <label>
                <span>{t.fieldKeywords.label}</span>
                <FieldTooltip explanation={t.fieldKeywords} zone="mutable" />
              </label>
              <input
                type="text"
                value={(metadata.keywords || []).join(', ')}
                onChange={handleKeywordsChange}
                placeholder={t.fieldKeywords.placeholder}
              />
              <span className="help-text">{t.fieldKeywords.helpText}</span>
            </div>
          </div>
        </div>

        {/* App Config Section */}
        <div>
          <h3 style={{ fontSize: '1.05rem', marginBottom: '1rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Settings size={18} />
            {t.appConfigSectionTitle}
          </h3>
          <div className="form-grid">
            {/* Default Validity Duration */}
            <div className="form-group">
              <label>
                <span>{t.fieldDefaultValidityDuration.label}</span>
                <FieldTooltip explanation={t.fieldDefaultValidityDuration} zone="mutable" />
              </label>
              <input
                type="text"
                value={app_config.default_validity_duration || ''}
                onChange={(e) => updateAppConfig('default_validity_duration', e.target.value || undefined)}
                placeholder={t.fieldDefaultValidityDuration.placeholder}
              />
              <span className="help-text">{t.fieldDefaultValidityDuration.helpText}</span>
            </div>

            {/* Round Up Validity To */}
            <div className="form-group">
              <label>
                <span>{t.fieldRoundUpValidityTo.label}</span>
                <FieldTooltip explanation={t.fieldRoundUpValidityTo} zone="mutable" />
              </label>
              <input
                type="text"
                value={app_config.round_up_validity_to || ''}
                onChange={(e) => updateAppConfig('round_up_validity_to', e.target.value || undefined)}
                placeholder={t.fieldRoundUpValidityTo.placeholder}
              />
              <span className="help-text">{t.fieldRoundUpValidityTo.helpText}</span>
            </div>

            {/* Server History Retention */}
            <div className="form-group">
              <label>
                <span>{t.fieldServerHistoryRetention.label}</span>
                <FieldTooltip explanation={t.fieldServerHistoryRetention} zone="mutable" />
              </label>
              <input
                type="text"
                value={app_config.server_history_retention || ''}
                onChange={(e) => updateAppConfig('server_history_retention', e.target.value || undefined)}
                placeholder={t.fieldServerHistoryRetention.placeholder}
              />
              <span className="help-text">{t.fieldServerHistoryRetention.helpText}</span>
            </div>
          </div>
        </div>

        {/* i18n Section */}
        <div>
          <h3 style={{ fontSize: '1.05rem', marginBottom: '1rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Languages size={18} />
            {t.i18nSectionTitle}
          </h3>
          <div className="form-grid">
            {/* Description (de) */}
            <div className="form-group full-width">
              <label>
                <span>{t.fieldI18nDescDe.label}</span>
                <FieldTooltip explanation={t.fieldI18nDescDe} zone="mutable" />
              </label>
              <textarea
                value={i18n.descriptions?.de || ''}
                onChange={(e) => updateI18nMap('descriptions', 'de', e.target.value)}
                placeholder={t.fieldI18nDescDe.placeholder}
                rows={2}
              />
              <span className="help-text">{t.fieldI18nDescDe.helpText}</span>
            </div>

            {/* Description (en) */}
            <div className="form-group full-width">
              <label>
                <span>{t.fieldI18nDescEn.label}</span>
                <FieldTooltip explanation={t.fieldI18nDescEn} zone="mutable" />
              </label>
              <textarea
                value={i18n.descriptions?.en || ''}
                onChange={(e) => updateI18nMap('descriptions', 'en', e.target.value)}
                placeholder={t.fieldI18nDescEn.placeholder}
                rows={2}
              />
              <span className="help-text">{t.fieldI18nDescEn.helpText}</span>
            </div>

            {/* Footnote (de) */}
            <div className="form-group">
              <label>
                <span>{t.fieldI18nFootnoteDe.label}</span>
                <FieldTooltip explanation={t.fieldI18nFootnoteDe} zone="mutable" />
              </label>
              <input
                type="text"
                value={i18n.footnotes?.de || ''}
                onChange={(e) => updateI18nMap('footnotes', 'de', e.target.value)}
                placeholder={t.fieldI18nFootnoteDe.placeholder}
              />
              <span className="help-text">{t.fieldI18nFootnoteDe.helpText}</span>
            </div>

            {/* Footnote (en) */}
            <div className="form-group">
              <label>
                <span>{t.fieldI18nFootnoteEn.label}</span>
                <FieldTooltip explanation={t.fieldI18nFootnoteEn} zone="mutable" />
              </label>
              <input
                type="text"
                value={i18n.footnotes?.en || ''}
                onChange={(e) => updateI18nMap('footnotes', 'en', e.target.value)}
                placeholder={t.fieldI18nFootnoteEn.placeholder}
              />
              <span className="help-text">{t.fieldI18nFootnoteEn.helpText}</span>
            </div>

            {/* Collateral Description (de) */}
            <div className="form-group full-width">
              <label>
                <span>{t.fieldI18nCollateralDe.label}</span>
                <FieldTooltip explanation={t.fieldI18nCollateralDe} zone="mutable" />
              </label>
              <input
                type="text"
                value={i18n.collateral_descriptions?.de || ''}
                onChange={(e) => updateI18nMap('collateral_descriptions', 'de', e.target.value)}
                placeholder={t.fieldI18nCollateralDe.placeholder}
              />
              <span className="help-text">{t.fieldI18nCollateralDe.helpText}</span>
            </div>

            {/* Collateral Description (en) */}
            <div className="form-group full-width">
              <label>
                <span>{t.fieldI18nCollateralEn.label}</span>
                <FieldTooltip explanation={t.fieldI18nCollateralEn} zone="mutable" />
              </label>
              <input
                type="text"
                value={i18n.collateral_descriptions?.en || ''}
                onChange={(e) => updateI18nMap('collateral_descriptions', 'en', e.target.value)}
                placeholder={t.fieldI18nCollateralEn.placeholder}
              />
              <span className="help-text">{t.fieldI18nCollateralEn.helpText}</span>
            </div>
          </div>
        </div>
      </div>

      {(onPrev || onNext) && (
        <div className="wizard-actions">
          {onPrev ? (
            <button className="btn btn-secondary" onClick={onPrev}>
              &larr; {t.btnBack}
            </button>
          ) : <div />}
          {onNext && (
            <button className="btn btn-primary" onClick={onNext}>
              {t.btnNext}: {t.navSign} &rarr;
            </button>
          )}
        </div>
      )}
    </div>
  );
};
