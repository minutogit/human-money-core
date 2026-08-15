import React, { useState } from 'react';
import { useWasmBridge } from './hooks/useWasmBridge';
import {
  DEFAULT_STANDARD,
  VoucherStandardDefinition,
  StandardDiagnosticResult,
  SignResult,
  ViewMode,
} from './types/standard';
import { Header } from './components/Header';
import { ImportView } from './components/ImportView';
import { EditView } from './components/EditView';
import { SigningView } from './components/SigningView';
import { LanguageProvider, useLanguage } from './i18n/LanguageContext';

const AppContent: React.FC = () => {
  const wasm = useWasmBridge();
  const { t } = useLanguage();
  const [viewMode, setViewMode] = useState<ViewMode>('import');
  const [standard, setStandard] = useState<VoucherStandardDefinition>(DEFAULT_STANDARD);
  const [diagnostic, setDiagnostic] = useState<StandardDiagnosticResult | null>(null);
  const [signResult, setSignResult] = useState<SignResult | null>(null);

  const handleReset = () => {
    if (window.confirm(t.btnResetConfirm)) {
      setStandard(JSON.parse(JSON.stringify(DEFAULT_STANDARD)));
      setSignResult(null);
      setDiagnostic(null);
      setViewMode('import');
    }
  };

  const handleStandardChange = (updated: VoucherStandardDefinition) => {
    setStandard(updated);
    // Invalidate old signature if standard content changed
    if (signResult) {
      setSignResult(null);
    }
  };

  return (
    <div className="app-container">
      <Header
        isWasmReady={wasm.isReady}
        wasmError={wasm.error}
        viewMode={viewMode}
        onViewModeChange={(mode) => setViewMode(mode)}
        onReset={handleReset}
        isStandardValid={diagnostic?.valid === true}
        isSigned={signResult !== null}
      />

      <main className="main-content">
        {viewMode === 'import' && (
          <ImportView
            wasm={wasm}
            standard={standard}
            onStandardChange={handleStandardChange}
            diagnostic={diagnostic}
            onDiagnosticChange={setDiagnostic}
            onNavigateToEdit={() => setViewMode('edit')}
          />
        )}

        {viewMode === 'edit' && (
          <EditView
            wasm={wasm}
            standard={standard}
            onStandardChange={handleStandardChange}
            onNavigateToSign={() => setViewMode('sign')}
          />
        )}

        {viewMode === 'sign' && (
          <SigningView
            wasm={wasm}
            standard={standard}
            diagnostic={diagnostic}
            signResult={signResult}
            onSigned={(res) => setSignResult(res)}
            onNavigateToEdit={() => setViewMode('edit')}
          />
        )}
      </main>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <LanguageProvider>
      <AppContent />
    </LanguageProvider>
  );
};

export default App;
