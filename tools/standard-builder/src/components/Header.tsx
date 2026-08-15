import React from 'react';
import { Cpu, ShieldCheck, RefreshCw, Sparkles, CheckSquare, KeyRound, Check, Globe } from 'lucide-react';
import { ViewMode } from '../types/standard';
import { useLanguage } from '../i18n/LanguageContext';

interface HeaderProps {
  isWasmReady: boolean;
  wasmError: string | null;
  viewMode: ViewMode;
  onViewModeChange: (mode: ViewMode) => void;
  onReset: () => void;
  isStandardValid?: boolean;
  isSigned?: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  isWasmReady,
  wasmError,
  viewMode,
  onViewModeChange,
  onReset,
  isStandardValid = false,
  isSigned = false,
}) => {
  const { language, setLanguage, t } = useLanguage();

  return (
    <header className="navbar">
      <div className="brand">
        <div className="brand-icon">
          <ShieldCheck size={22} />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span className="brand-title">{t.brandTitle}</span>
            <span className="brand-badge">{t.brandBadge}</span>
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            {t.brandSubtitle}
          </span>
        </div>
      </div>

      {/* 3-Phase Navigation Tabs */}
      <nav className="phase-tabs" aria-label="Workflow Phasen">
        <button
          type="button"
          className={`phase-tab ${viewMode === 'import' ? 'active' : ''}`}
          onClick={() => onViewModeChange('import')}
        >
          <Sparkles size={15} />
          <span>{t.navImport}</span>
          {isStandardValid && (
            <span className="tab-badge-indicator" title={t.statusValid}>
              <Check size={11} />
            </span>
          )}
        </button>

        <button
          type="button"
          className={`phase-tab ${viewMode === 'edit' ? 'active' : ''}`}
          onClick={() => onViewModeChange('edit')}
        >
          <CheckSquare size={15} />
          <span>{t.navEdit}</span>
        </button>

        <button
          type="button"
          className={`phase-tab ${viewMode === 'sign' ? 'active' : ''}`}
          onClick={() => onViewModeChange('sign')}
        >
          <KeyRound size={15} />
          <span>{t.navSign}</span>
          {isSigned && (
            <span className="tab-badge-indicator success" title={t.successTitle}>
              <Check size={11} />
            </span>
          )}
        </button>
      </nav>

      {/* Right Toolbar: Language Switcher, Reset, WASM Status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        {/* Language Switcher */}
        <div className="lang-switcher" aria-label="Sprachauswahl / Language Selector">
          <button
            type="button"
            className={`lang-btn ${language === 'de' ? 'active' : ''}`}
            onClick={() => setLanguage('de')}
            title="Deutsch"
          >
            <span>🇩🇪 DE</span>
          </button>
          <button
            type="button"
            className={`lang-btn ${language === 'en' ? 'active' : ''}`}
            onClick={() => setLanguage('en')}
            title="English"
          >
            <span>🇬🇧 EN</span>
          </button>
        </div>

        <button
          className="btn btn-secondary"
          onClick={onReset}
          title={t.btnReset}
          style={{ padding: '0.4rem 0.85rem', fontSize: '0.85rem' }}
        >
          <RefreshCw size={14} />
          <span>{t.btnReset}</span>
        </button>

        <div className="wasm-status">
          <Cpu size={14} color={isWasmReady ? 'var(--accent-emerald)' : 'var(--accent-amber)'} />
          <span className={`status-dot ${isWasmReady ? 'active' : 'loading'}`}></span>
          <span>
            {isWasmReady
              ? t.wasmActive
              : wasmError
              ? `${t.wasmError}: ${wasmError}`
              : t.wasmLoading}
          </span>
        </div>
      </div>
    </header>
  );
};
