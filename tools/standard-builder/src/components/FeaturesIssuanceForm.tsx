import React from 'react';
import { VoucherStandardDefinition, PrivacyMode } from '../types/standard';
import { Sliders, ShieldAlert } from 'lucide-react';
import { useLanguage } from '../i18n/LanguageContext';
import { FieldTooltip } from './FieldTooltip';

interface FeaturesIssuanceFormProps {
  standard: VoucherStandardDefinition;
  onChange: (updated: VoucherStandardDefinition) => void;
  onPrev?: () => void;
  onNext?: () => void;
}

export const FeaturesIssuanceForm: React.FC<FeaturesIssuanceFormProps> = ({
  standard,
  onChange,
  onPrev,
  onNext,
}) => {
  const { t } = useLanguage();
  const { features, issuance } = standard.immutable;

  const updateFeatures = (field: keyof typeof features, value: any) => {
    onChange({
      ...standard,
      immutable: {
        ...standard.immutable,
        features: {
          ...features,
          [field]: value,
        },
      },
    });
  };

  const updateIssuance = (field: keyof typeof issuance, value: any) => {
    onChange({
      ...standard,
      immutable: {
        ...standard.immutable,
        issuance: {
          ...issuance,
          [field]: value,
        },
      },
    });
  };

  const handleTTypesChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const arr = e.target.value.split(',').map((s) => s.trim()).filter(Boolean);
    updateFeatures('allowed_t_types', arr);
  };

  const handleRolesChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const arr = e.target.value.split(',').map((s) => s.trim()).filter(Boolean);
    updateIssuance('allowed_signature_roles', arr);
  };

  return (
    <div>
      <div className="panel-header">
        <h2 className="panel-title">
          <Sliders color="var(--accent-primary)" size={24} />
          {t.featuresHeaderTitle}
        </h2>
        <p className="panel-desc">
          {t.featuresHeaderDesc}
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        {/* Features Section */}
        <div>
          <h3 style={{ fontSize: '1.05rem', marginBottom: '1rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Sliders size={18} />
            {t.featuresSectionTitle}
          </h3>
          <div className="form-grid">
            {/* Allow Partial Transfers */}
            <div className="checkbox-group">
              <input
                type="checkbox"
                id="allow_partial"
                checked={features.allow_partial_transfers}
                onChange={(e) => updateFeatures('allow_partial_transfers', e.target.checked)}
              />
              <label htmlFor="allow_partial" style={{ cursor: 'pointer', margin: 0 }}>
                <span>{t.fieldAllowPartialTransfers.label}</span>
              </label>
              <FieldTooltip explanation={t.fieldAllowPartialTransfers} zone="immutable" />
            </div>

            {/* Balances are Summable */}
            <div className="checkbox-group">
              <input
                type="checkbox"
                id="balances_summable"
                checked={features.balances_are_summable}
                onChange={(e) => updateFeatures('balances_are_summable', e.target.checked)}
              />
              <label htmlFor="balances_summable" style={{ cursor: 'pointer', margin: 0 }}>
                <span>{t.fieldBalancesSummable.label}</span>
              </label>
              <FieldTooltip explanation={t.fieldBalancesSummable} zone="immutable" />
            </div>

            {/* Amount Decimal Places */}
            <div className="form-group">
              <label>
                <span>{t.fieldDecimalPlaces.label}</span>
                <FieldTooltip explanation={t.fieldDecimalPlaces} zone="immutable" />
              </label>
              <input
                type="number"
                min={0}
                max={6}
                value={features.amount_decimal_places}
                onChange={(e) => updateFeatures('amount_decimal_places', parseInt(e.target.value) || 0)}
              />
              <span className="help-text">{t.fieldDecimalPlaces.helpText}</span>
            </div>

            {/* Privacy Mode */}
            <div className="form-group">
              <label>
                <span>{t.fieldPrivacyMode.label}</span>
                <FieldTooltip explanation={t.fieldPrivacyMode} zone="immutable" />
              </label>
              <select
                value={features.privacy_mode}
                onChange={(e) => updateFeatures('privacy_mode', e.target.value as PrivacyMode)}
              >
                <option value="public">{t.fieldPrivacyMode.optPublic}</option>
                <option value="stealth">{t.fieldPrivacyMode.optStealth}</option>
                <option value="flexible">{t.fieldPrivacyMode.optFlexible}</option>
              </select>
              <span className="help-text">{t.fieldPrivacyMode.helpText}</span>
            </div>

            {/* Allowed Transaction Types */}
            <div className="form-group full-width">
              <label>
                <span>{t.fieldAllowedTTypes.label}</span>
                <FieldTooltip explanation={t.fieldAllowedTTypes} zone="immutable" />
              </label>
              <input
                type="text"
                value={features.allowed_t_types.join(', ')}
                onChange={handleTTypesChange}
                placeholder={t.fieldAllowedTTypes.placeholder}
              />
              <span className="help-text">{t.fieldAllowedTTypes.helpText}</span>
            </div>
          </div>
        </div>

        {/* Issuance Section */}
        <div>
          <h3 style={{ fontSize: '1.05rem', marginBottom: '1rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldAlert size={18} />
            {t.issuanceSectionTitle}
          </h3>
          <div className="form-grid">
            {/* Validity Duration Range */}
            <div className="form-group">
              <label>
                <span>{t.fieldValidityDurationRange.label}</span>
                <FieldTooltip explanation={t.fieldValidityDurationRange} zone="immutable" />
              </label>
              <div className="dual-input-row">
                <div className="dual-input-col">
                  <span className="input-mini-badge">Min</span>
                  <input
                    type="text"
                    value={issuance.validity_duration_range[0] || 'P1Y'}
                    onChange={(e) =>
                      updateIssuance('validity_duration_range', [e.target.value, issuance.validity_duration_range[1] || 'P5Y'])
                    }
                    placeholder={t.fieldValidityDurationRange.minPlaceholder}
                  />
                </div>
                <div className="dual-input-col">
                  <span className="input-mini-badge">Max</span>
                  <input
                    type="text"
                    value={issuance.validity_duration_range[1] || 'P5Y'}
                    onChange={(e) =>
                      updateIssuance('validity_duration_range', [issuance.validity_duration_range[0] || 'P1Y', e.target.value])
                    }
                    placeholder={t.fieldValidityDurationRange.maxPlaceholder}
                  />
                </div>
              </div>
              <span className="help-text">{t.fieldValidityDurationRange.helpText}</span>
            </div>

            {/* Creation Minimum Validity Duration */}
            <div className="form-group">
              <label>
                <span>{t.fieldIssuanceMinValidity.label}</span>
                <FieldTooltip explanation={t.fieldIssuanceMinValidity} zone="immutable" />
              </label>
              <input
                type="text"
                value={issuance.issuance_minimum_validity_duration}
                onChange={(e) => updateIssuance('issuance_minimum_validity_duration', e.target.value)}
                placeholder={t.fieldIssuanceMinValidity.placeholder}
              />
              <span className="help-text">{t.fieldIssuanceMinValidity.helpText}</span>
            </div>

            {/* Required Guarantors Count */}
            <div className="form-group">
              <label>
                <span>{t.fieldAdditionalSignaturesRange.label}</span>
                <FieldTooltip explanation={t.fieldAdditionalSignaturesRange} zone="immutable" />
              </label>
              <div className="dual-input-row">
                <div className="dual-input-col">
                  <span className="input-mini-badge">Min</span>
                  <input
                    type="number"
                    min={0}
                    value={issuance.additional_signatures_range[0] ?? 2}
                    onChange={(e) =>
                      updateIssuance('additional_signatures_range', [
                        parseInt(e.target.value) || 0,
                        issuance.additional_signatures_range[1] ?? 2,
                      ])
                    }
                  />
                </div>
                <div className="dual-input-col">
                  <span className="input-mini-badge">Max</span>
                  <input
                    type="number"
                    min={0}
                    value={issuance.additional_signatures_range[1] ?? 2}
                    onChange={(e) =>
                      updateIssuance('additional_signatures_range', [
                        issuance.additional_signatures_range[0] ?? 2,
                        parseInt(e.target.value) || 0,
                      ])
                    }
                  />
                </div>
              </div>
              <span className="help-text">{t.fieldAdditionalSignaturesRange.helpText}</span>
            </div>

            {/* Allowed Signature Roles */}
            <div className="form-group">
              <label>
                <span>{t.fieldAllowedSignatureRoles.label}</span>
                <FieldTooltip explanation={t.fieldAllowedSignatureRoles} zone="immutable" />
              </label>
              <input
                type="text"
                value={issuance.allowed_signature_roles.join(', ')}
                onChange={handleRolesChange}
                placeholder={t.fieldAllowedSignatureRoles.placeholder}
              />
              <span className="help-text">{t.fieldAllowedSignatureRoles.helpText}</span>
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
              {t.btnNext}: {t.sec3Title} &rarr;
            </button>
          )}
        </div>
      )}
    </div>
  );
};
