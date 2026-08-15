import React from 'react';
import { VoucherStandardDefinition, PrimaryRedemptionType, CollateralType } from '../types/standard';
import { Fingerprint, Landmark, Coins } from 'lucide-react';
import { useLanguage } from '../i18n/LanguageContext';
import { FieldTooltip } from './FieldTooltip';

interface ImmutableZoneFormProps {
  standard: VoucherStandardDefinition;
  onChange: (updated: VoucherStandardDefinition) => void;
  onNext?: () => void;
}

export const ImmutableZoneForm: React.FC<ImmutableZoneFormProps> = ({
  standard,
  onChange,
  onNext,
}) => {
  const { t } = useLanguage();
  const { identity, blueprint } = standard.immutable;

  const updateIdentity = (field: keyof typeof identity, value: string) => {
    onChange({
      ...standard,
      immutable: {
        ...standard.immutable,
        identity: {
          ...identity,
          [field]: value,
        },
      },
    });
  };

  const updateBlueprint = (field: keyof typeof blueprint, value: any) => {
    onChange({
      ...standard,
      immutable: {
        ...standard.immutable,
        blueprint: {
          ...blueprint,
          [field]: value,
        },
      },
    });
  };

  const generateUuid = () => {
    const randomUuid = `STD-${Date.now()}-${Math.random().toString(36).substring(2, 7).toUpperCase()}`;
    updateIdentity('uuid', randomUuid);
  };

  return (
    <div>
      <div className="panel-header">
        <h2 className="panel-title">
          <Fingerprint color="var(--accent-primary)" size={24} />
          {t.immutableHeaderTitle}
        </h2>
        <p className="panel-desc">
          {t.immutableHeaderDesc}
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        {/* Identity Section */}
        <div>
          <h3 style={{ fontSize: '1.05rem', marginBottom: '1rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Landmark size={18} />
            {t.identitySectionTitle}
          </h3>
          <div className="form-grid">
            {/* UUID */}
            <div className="form-group full-width">
              <label>
                <span>{t.fieldUuid.label}</span>
                <FieldTooltip explanation={t.fieldUuid} zone="immutable" />
              </label>
              <div className="dual-input-row">
                <input
                  type="text"
                  value={identity.uuid}
                  onChange={(e) => updateIdentity('uuid', e.target.value)}
                  placeholder={t.fieldUuid.placeholder}
                />
                <button className="btn btn-secondary" onClick={generateUuid} type="button" style={{ whiteSpace: 'nowrap', flexShrink: 0 }}>
                  {t.btnGenerateUuid}
                </button>
              </div>
              <span className="help-text">{t.fieldUuid.helpText}</span>
            </div>

            {/* Standard Name */}
            <div className="form-group">
              <label>
                <span>{t.fieldName.label}</span>
                <FieldTooltip explanation={t.fieldName} zone="immutable" />
              </label>
              <input
                type="text"
                value={identity.name}
                onChange={(e) => updateIdentity('name', e.target.value)}
                placeholder={t.fieldName.placeholder}
              />
              <span className="help-text">{t.fieldName.helpText}</span>
            </div>

            {/* Abbreviation */}
            <div className="form-group">
              <label>
                <span>{t.fieldAbbreviation.label}</span>
                <FieldTooltip explanation={t.fieldAbbreviation} zone="immutable" />
              </label>
              <input
                type="text"
                value={identity.abbreviation}
                onChange={(e) => updateIdentity('abbreviation', e.target.value.toUpperCase())}
                placeholder={t.fieldAbbreviation.placeholder}
                maxLength={8}
                style={{ textTransform: 'uppercase' }}
              />
              <span className="help-text">{t.fieldAbbreviation.helpText}</span>
            </div>
          </div>
        </div>

        {/* Blueprint Section */}
        <div>
          <h3 style={{ fontSize: '1.05rem', marginBottom: '1rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Coins size={18} />
            {t.blueprintSectionTitle}
          </h3>
          <div className="form-grid">
            {/* Unit */}
            <div className="form-group">
              <label>
                <span>{t.fieldUnit.label}</span>
                <FieldTooltip explanation={t.fieldUnit} zone="immutable" />
              </label>
              <input
                type="text"
                value={blueprint.unit}
                onChange={(e) => updateBlueprint('unit', e.target.value)}
                placeholder={t.fieldUnit.placeholder}
              />
              <span className="help-text">{t.fieldUnit.helpText}</span>
            </div>

            {/* Primary Redemption Type */}
            <div className="form-group">
              <label>
                <span>{t.fieldPrimaryRedemption.label}</span>
                <FieldTooltip explanation={t.fieldPrimaryRedemption} zone="immutable" />
              </label>
              <select
                value={blueprint.primary_redemption_type}
                onChange={(e) => updateBlueprint('primary_redemption_type', e.target.value as PrimaryRedemptionType)}
              >
                <option value="goods_or_services">{t.fieldPrimaryRedemption.optGoodsServices}</option>
                <option value="time">{t.fieldPrimaryRedemption.optTime}</option>
                <option value="physical_asset">{t.fieldPrimaryRedemption.optPhysicalAsset}</option>
              </select>
              <span className="help-text">{t.fieldPrimaryRedemption.helpText}</span>
            </div>

            {/* Collateral Type */}
            <div className="form-group">
              <label>
                <span>{t.fieldCollateralType.label}</span>
                <FieldTooltip explanation={t.fieldCollateralType} zone="immutable" />
              </label>
              <select
                value={blueprint.collateral_type}
                onChange={(e) => updateBlueprint('collateral_type', e.target.value as CollateralType)}
              >
                <option value="personal_guarantee">{t.fieldCollateralType.optPersonalGuarantee}</option>
                <option value="fiat_backed">{t.fieldCollateralType.optFiatBacked}</option>
                <option value="crypto_backed">{t.fieldCollateralType.optCryptoBacked}</option>
                <option value="physical_asset">{t.fieldCollateralType.optPhysicalAsset}</option>
              </select>
              <span className="help-text">{t.fieldCollateralType.helpText}</span>
            </div>
          </div>
        </div>
      </div>

      {onNext && (
        <div className="wizard-actions">
          <div></div>
          <button className="btn btn-primary" onClick={onNext}>
            {t.btnNext}: {t.sec2Title} &rarr;
          </button>
        </div>
      )}
    </div>
  );
};
