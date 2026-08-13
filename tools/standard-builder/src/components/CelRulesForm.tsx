import React, { useState } from 'react';
import { VoucherStandardDefinition, DynamicRule } from '../types/standard';
import { WasmBridge } from '../hooks/useWasmBridge';
import { Code, Plus, Trash2, CheckCircle2, AlertCircle } from 'lucide-react';
import { useLanguage } from '../i18n/LanguageContext';
import { FieldTooltip } from './FieldTooltip';

interface CelRulesFormProps {
  standard: VoucherStandardDefinition;
  wasm: WasmBridge;
  onChange: (updated: VoucherStandardDefinition) => void;
  onPrev?: () => void;
  onNext?: () => void;
}

export const CelRulesForm: React.FC<CelRulesFormProps> = ({
  standard,
  wasm,
  onChange,
  onPrev,
  onNext,
}) => {
  const { t } = useLanguage();
  const customRules = standard.immutable.custom_rules || {};
  const [newRuleKey, setNewRuleKey] = useState('');

  const updateRule = (key: string, field: keyof DynamicRule, value: string) => {
    const currentRule = customRules[key] || { expression: '', message: '' };
    const updatedRule = { ...currentRule, [field]: value };
    onChange({
      ...standard,
      immutable: {
        ...standard.immutable,
        custom_rules: {
          ...customRules,
          [key]: updatedRule,
        },
      },
    });
  };

  const removeRule = (key: string) => {
    const updated = { ...customRules };
    delete updated[key];
    onChange({
      ...standard,
      immutable: {
        ...standard.immutable,
        custom_rules: updated,
      },
    });
  };

  const addRule = () => {
    if (!newRuleKey.trim()) return;
    const cleanKey = newRuleKey.trim().replace(/\s+/g, '_').toLowerCase();
    if (customRules[cleanKey]) return;

    onChange({
      ...standard,
      immutable: {
        ...standard.immutable,
        custom_rules: {
          ...customRules,
          [cleanKey]: {
            expression: "Transaction.amount <= 5000",
            message: "Transaction amount exceeds limit",
          },
        },
      },
    });
    setNewRuleKey('');
  };

  return (
    <div>
      <div className="panel-header">
        <h2 className="panel-title">
          <Code color="var(--accent-primary)" size={24} />
          {t.celHeaderTitle}
        </h2>
        <p className="panel-desc">
          {t.celHeaderDesc}
        </p>
      </div>

      <div className="alert alert-info">
        <div>
          <strong>WASM CEL Engine:</strong> {t.celInfoBanner}
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', marginBottom: '2rem' }}>
        {Object.entries(customRules).length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem', border: '1px dashed var(--border-color)', borderRadius: 'var(--radius-md)', color: 'var(--text-muted)' }}>
            {t.celNoRulesYet}
          </div>
        ) : (
          Object.entries(customRules).map(([key, rule]) => {
            const celResult = wasm.validateCelExpression(rule.expression);
            return (
              <div key={key} className={`rule-card ${celResult.valid ? 'valid' : 'invalid'}`}>
                <div className="rule-header">
                  <span className="rule-title">{key}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <span className={`rule-status ${celResult.valid ? 'ok' : 'err'}`}>
                      {celResult.valid ? (
                        <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                          <CheckCircle2 size={12} /> {t.celSyntaxValid}
                        </span>
                      ) : (
                        <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                          <AlertCircle size={12} /> {t.celSyntaxError}
                        </span>
                      )}
                    </span>
                    <button
                      className="btn btn-danger"
                      onClick={() => removeRule(key)}
                      style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                    >
                      <Trash2 size={14} /> {t.celRemoveBtn}
                    </button>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  <div className="form-group">
                    <label>
                      <span>{t.fieldCelExpression.label}</span>
                      <FieldTooltip explanation={t.fieldCelExpression} zone="immutable" />
                    </label>
                    <textarea
                      className="cel-input"
                      value={rule.expression}
                      onChange={(e) => updateRule(key, 'expression', e.target.value)}
                      rows={2}
                    />
                    {!celResult.valid && (
                      <span style={{ fontSize: '0.78rem', color: 'var(--accent-rose)', marginTop: '0.2rem' }}>
                        {celResult.error}
                      </span>
                    )}
                  </div>

                  <div className="form-group">
                    <label>
                      <span>{t.fieldCelErrorMessage.label}</span>
                      <FieldTooltip explanation={t.fieldCelErrorMessage} zone="immutable" />
                    </label>
                    <input
                      type="text"
                      value={rule.message}
                      onChange={(e) => updateRule(key, 'message', e.target.value)}
                      placeholder={t.fieldCelErrorMessage.placeholder}
                    />
                  </div>
                </div>
              </div>
            );
          })
        )}

        {/* Add New Rule */}
        <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
          <input
            type="text"
            placeholder={t.fieldCelNewRuleKey.placeholder}
            value={newRuleKey}
            onChange={(e) => setNewRuleKey(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && addRule()}
            style={{ flex: 1 }}
          />
          <button className="btn btn-secondary" onClick={addRule} type="button">
            <Plus size={16} /> {t.btnAddCelRule}
          </button>
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
              {t.btnNext}: {t.sec4Title} &rarr;
            </button>
          )}
        </div>
      )}
    </div>
  );
};
