export type Language = 'de' | 'en';

export interface FieldExplanation {
  label: string;
  tooltipTitle: string;
  tooltipWhat: string;
  tooltipWhy: string;
  tooltipImpact: string;
  helpText?: string;
  placeholder?: string;
}

export interface Translations {
  // Common & Navigation
  brandTitle: string;
  brandBadge: string;
  brandSubtitle: string;
  navImport: string;
  navEdit: string;
  navSign: string;
  btnReset: string;
  btnResetConfirm: string;
  btnNext: string;
  btnBack: string;
  btnCopy: string;
  btnCopied: string;
  btnDownload: string;
  btnDownloaded: string;
  btnPaste: string;
  btnPasted: string;
  btnClear: string;
  wasmActive: string;
  wasmLoading: string;
  wasmError: string;

  // Tooltip UI
  tooltipWhatLabel: string;
  tooltipWhyLabel: string;
  tooltipImpactLabel: string;
  tooltipImmutableBadge: string;
  tooltipMutableBadge: string;
  tooltipCryptoBadge: string;

  // Phase 1: Import & AI Fast-Lane
  phase1Title: string;
  phase1Subtitle: string;
  copyPromptBtn: string;
  copyPromptDone: string;
  downloadSkillBtn: string;
  downloadSkillDone: string;
  quickTemplates: string;
  smartImportTitle: string;
  smartImportDesc: string;
  pastePlaceholder: string;
  dropFileNotice: string;
  linesAndChars: (lines: number, chars: number) => string;
  validationRunning: string;
  liveInspectionTitle: string;
  statusValid: string;
  statusInvalid: (count: number) => string;
  validationFailed: string;
  copyAiErrorBtn: string;
  copyAiErrorDone: string;
  summaryTitleName: string;
  summaryTitleUnit: string;
  summaryTitleRedemption: string;
  summaryTitleCollateral: string;
  summaryTitlePrivacy: string;
  summaryTitleSignaturesLabel: string;
  summaryTitleSignatures: (min: number, max: number) => string;
  celRulesCount: (count: number) => string;
  celRulesEmpty: string;
  ctaStandardValid: string;
  ctaStandardValidDesc: string;
  ctaEditNow: string;

  // Phase 2: Edit & Review Workbench
  phase2Title: string;
  phase2Subtitle: string;
  btnProceedToSign: string;
  sec1Title: string;
  sec2Title: string;
  sec3Title: string;
  sec4Title: string;
  sec5Title: string;
  sec5Subtitle: string;
  sec5Desc: string;
  btnCopyToml: string;
  ctaEditDoneTitle: string;
  ctaEditDoneDesc: string;
  ctaProceedSignBtn: string;

  // Phase 2 - Section 1: Immutable Identity & Blueprint
  immutableHeaderTitle: string;
  immutableHeaderDesc: string;
  identitySectionTitle: string;
  blueprintSectionTitle: string;
  btnGenerateUuid: string;

  // Fields: Identity
  fieldUuid: FieldExplanation;
  fieldName: FieldExplanation;
  fieldAbbreviation: FieldExplanation;

  // Fields: Blueprint
  fieldUnit: FieldExplanation;
  fieldPrimaryRedemption: FieldExplanation & {
    optGoodsServices: string;
    optTime: string;
    optPhysicalAsset: string;
  };
  fieldCollateralType: FieldExplanation & {
    optPersonalGuarantee: string;
    optFiatBacked: string;
    optCryptoBacked: string;
    optPhysicalAsset: string;
  };

  // Phase 2 - Section 2: Features & Issuance Rules
  featuresHeaderTitle: string;
  featuresHeaderDesc: string;
  featuresSectionTitle: string;
  issuanceSectionTitle: string;

  // Fields: Features
  fieldAllowPartialTransfers: FieldExplanation;
  fieldBalancesSummable: FieldExplanation;
  fieldDecimalPlaces: FieldExplanation;
  fieldPrivacyMode: FieldExplanation & {
    optPublic: string;
    optStealth: string;
    optFlexible: string;
  };
  fieldAllowedTTypes: FieldExplanation;

  // Fields: Issuance
  fieldValidityDurationRange: FieldExplanation & {
    minPlaceholder: string;
    maxPlaceholder: string;
  };
  fieldIssuanceMinValidity: FieldExplanation;
  fieldAdditionalSignaturesRange: FieldExplanation;
  fieldAllowedSignatureRoles: FieldExplanation;

  // Phase 2 - Section 3: CEL Custom Rules
  celHeaderTitle: string;
  celHeaderDesc: string;
  celInfoBanner: string;
  celNoRulesYet: string;
  celSyntaxValid: string;
  celSyntaxError: string;
  celRemoveBtn: string;
  fieldCelExpression: FieldExplanation;
  fieldCelErrorMessage: FieldExplanation;
  fieldCelNewRuleKey: FieldExplanation;
  btnAddCelRule: string;

  // Phase 2 - Section 4: Mutable Zone (Metadata, AppConfig, i18n)
  mutableHeaderTitle: string;
  mutableHeaderDesc: string;
  metadataSectionTitle: string;
  appConfigSectionTitle: string;
  i18nSectionTitle: string;

  // Fields: Metadata
  fieldIssuerName: FieldExplanation;
  fieldHomepageUrl: FieldExplanation;
  fieldDocumentationUrl: FieldExplanation;
  fieldKeywords: FieldExplanation;

  // Fields: AppConfig
  fieldDefaultValidityDuration: FieldExplanation;
  fieldRoundUpValidityTo: FieldExplanation;
  fieldServerHistoryRetention: FieldExplanation;

  // Fields: i18n Texts
  fieldI18nDescDe: FieldExplanation;
  fieldI18nDescEn: FieldExplanation;
  fieldI18nFootnoteDe: FieldExplanation;
  fieldI18nFootnoteEn: FieldExplanation;
  fieldI18nCollateralDe: FieldExplanation;
  fieldI18nCollateralEn: FieldExplanation;

  // Phase 3: Signing & Export View
  phase3Title: string;
  phase3Subtitle: string;
  btnBackToEdit: string;
  securityNoticeText: string;
  fieldIssuerPrefix: FieldExplanation;
  identityCardTitle: string;
  labelIssuerDid: string;
  derivedDidPlaceholder: string;
  btnCopyDid: string;
  btnSignAndExport: string;
  signingInProgress: string;
  successTitle: string;
  successSubtitle: (filename: string) => string;
  sigLabelSignature: string;
  sigLabelIssuer: string;
  btnDownloadAgain: string;
  btnVerifySignature: string;
  verifyingInProgress: string;
  verifySuccess: (did: string) => string;
  verifyFailed: string;
  accordionSignedToml: (lineCount: number) => string;

  // Seed Vault
  vaultTitle: string;
  vaultWordCount: (count: number) => string;
  vaultModeChips: string;
  vaultModeFreetext: string;
  vaultPasteSeed: string;
  vaultHide: string;
  vaultShow: string;
  vaultClearTitle: string;
  vaultGen12: string;
  vaultGen24: string;
  vaultEditAsTextLink: string;
  vaultEmptyTitle: string;
  vaultFreetextPlaceholder: string;
  vaultFreetextTip: string;
  vaultStatusValid: (words: number, standard: boolean) => string;
  vaultStatusInvalid: (words: number) => string;
  vaultStatusChecking: string;
  vaultStatusIdle: string;
  fieldMnemonicSeed: FieldExplanation;
}
