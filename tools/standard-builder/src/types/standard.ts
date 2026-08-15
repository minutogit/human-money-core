// TypeScript definition matching Rust's VoucherStandardDefinition

export type PrimaryRedemptionType = 'goods_or_services' | 'time' | 'physical_asset';

export type CollateralType = 'personal_guarantee' | 'fiat_backed' | 'crypto_backed' | 'physical_asset';

export type PrivacyMode = 'public' | 'stealth' | 'flexible';

export type ViewMode = 'import' | 'edit' | 'sign';

export interface DynamicRule {
  expression: string;
  message: string;
}

export interface ImmutableIdentity {
  uuid: string;
  name: string;
  abbreviation: string;
}

export interface ImmutableBlueprint {
  unit: string;
  primary_redemption_type: PrimaryRedemptionType;
  collateral_type: CollateralType;
}

export interface ImmutableFeatures {
  allow_partial_transfers: boolean;
  balances_are_summable: boolean;
  amount_decimal_places: number;
  privacy_mode: PrivacyMode;
  allowed_t_types: string[];
}

export interface ImmutableIssuance {
  validity_duration_range: string[];
  issuance_minimum_validity_duration: string;
  additional_signatures_range: number[];
  allowed_signature_roles: string[];
}

export interface ImmutableZone {
  identity: ImmutableIdentity;
  blueprint: ImmutableBlueprint;
  features: ImmutableFeatures;
  issuance: ImmutableIssuance;
  custom_rules: Record<string, DynamicRule>;
}

export interface MutableMetadata {
  issuer_name: string;
  homepage_url?: string;
  documentation_url?: string;
  keywords: string[];
}

export interface MutableAppConfig {
  default_validity_duration?: string;
  round_up_validity_to?: string;
  server_history_retention?: string;
}

export interface MutableI18n {
  descriptions: Record<string, string>;
  footnotes: Record<string, string>;
  collateral_descriptions?: Record<string, string>;
}

export interface MutableZone {
  metadata: MutableMetadata;
  app_config: MutableAppConfig;
  i18n: MutableI18n;
}

export interface SignatureBlock {
  issuer_id: string;
  signature: string;
}

export interface VoucherStandardDefinition {
  immutable: ImmutableZone;
  mutable: MutableZone;
  signature?: SignatureBlock;
}

export interface SignResult {
  toml: string;
  signature: string;
  issuer_id: string;
  logic_hash: string;
}

export interface VerifyResult {
  valid: boolean;
  logic_hash: string;
  issuer_id: string;
  signature: string;
}

export interface CelDiagnostic {
  rule_id: string;
  expression: string;
  message: string;
  valid: boolean;
  error?: string | null;
}

export interface StandardSummary {
  uuid: string;
  name: string;
  abbreviation: string;
  unit: string;
  primary_redemption_type: string;
  collateral_type: string;
  allow_partial_transfers: boolean;
  balances_are_summable: boolean;
  amount_decimal_places: number;
  privacy_mode: string;
  allowed_t_types: string[];
  validity_duration_range: string[];
  issuance_minimum_validity_duration: string;
  additional_signatures_range: number[];
  allowed_signature_roles: string[];
  issuer_name: string;
  homepage_url?: string;
  documentation_url?: string;
  keywords: string[];
  default_validity_duration?: string;
  round_up_validity_to?: string;
  server_history_retention?: string;
  i18n_languages: string[];
}

export interface StandardDiagnosticResult {
  valid: boolean;
  clean_toml: string;
  logic_hash?: string | null;
  is_signed: boolean;
  signature_valid?: boolean | null;
  issuer_id?: string | null;
  summary?: StandardSummary | null;
  cel_diagnostics: CelDiagnostic[];
  errors: string[];
  warnings: string[];
  standard?: VoucherStandardDefinition | null;
}

// Default initial state template
export const DEFAULT_STANDARD: VoucherStandardDefinition = {
  immutable: {
    identity: {
      uuid: '123e4567-e89b-12d3-a456-426614174000',
      name: 'Minuto Regional',
      abbreviation: 'MIN',
    },
    blueprint: {
      unit: 'Minuten',
      primary_redemption_type: 'goods_or_services',
      collateral_type: 'personal_guarantee',
    },
    features: {
      allow_partial_transfers: true,
      balances_are_summable: true,
      amount_decimal_places: 0,
      privacy_mode: 'flexible',
      allowed_t_types: ['init', 'transfer', 'split'],
    },
    issuance: {
      validity_duration_range: ['P1Y', 'P10Y'],
      issuance_minimum_validity_duration: 'P3Y',
      additional_signatures_range: [2, 2],
      allowed_signature_roles: ['guarantor'],
    },
    custom_rules: {
      max_transfer_amount: {
        expression: 'Transaction.amount <= 5000',
        message: 'Ein einzelner Transfer darf 5000 Minuten nicht überschreiten.',
      },
    },
  },
  mutable: {
    metadata: {
      issuer_name: 'Minuto International',
      homepage_url: 'https://minutocash.org/',
      documentation_url: 'https://www.minuto.wiki/',
      keywords: ['community-currency', 'time-based', 'mutual-credit', 'minuto'],
    },
    app_config: {
      default_validity_duration: 'P5Y',
      round_up_validity_to: 'P1Y',
      server_history_retention: 'P6M',
    },
    i18n: {
      descriptions: {
        de: 'Dieser Gutschein verbrieft einen Anspruch auf {{amount}} Minuten Arbeits- oder Dienstleistung beim Aussteller.',
        en: 'This voucher entitles the holder to {{amount}} minutes of service or labor from the issuer.',
      },
      footnotes: {
        de: 'Einlösung nach Absprache. Keine Barauszahlung.',
        en: 'Redemption upon agreement. No cash payout.',
      },
      collateral_descriptions: {
        de: 'Gedeckt durch die persönliche Arbeitskraft des Ausstellers und 2 unabhängige Bürgen.',
        en: 'Backed by personal labor guarantee of the issuer and 2 independent guarantors.',
      },
    },
  },
};

export interface ArchetypeTemplate {
  id: string;
  name: string;
  badge: string;
  description: string;
  toml: string;
}

export const ARCHETYPES: ArchetypeTemplate[] = [
  {
    id: 'minuto',
    name: 'Minuto / Zeitbank',
    badge: 'Zeitwert & Bürgen',
    description: 'Arbeitszeit-Währung mit 2 Bürgen und persönlicher Leistungsgarantie.',
    toml: `[immutable.identity]
uuid = "123e4567-e89b-12d3-a456-426614174000"
name = "Minuto Regional"
abbreviation = "MIN"

[immutable.blueprint]
unit = "Minuten"
primary_redemption_type = "goods_or_services"
collateral_type = "personal_guarantee"

[immutable.features]
allow_partial_transfers = true
balances_are_summable = true
amount_decimal_places = 0
privacy_mode = "flexible"
allowed_t_types = ["init", "transfer", "split"]

[immutable.issuance]
validity_duration_range = ["P1Y", "P10Y"]
issuance_minimum_validity_duration = "P3Y"
additional_signatures_range = [2, 2]
allowed_signature_roles = ["guarantor"]

[immutable.custom_rules.max_single_transfer]
expression = "Transaction.amount <= 5000"
message = "Ein einzelner Transfer darf 5000 Minuten nicht überschreiten."

[mutable.metadata]
issuer_name = "Minuto International"
homepage_url = "https://minutocash.org"
documentation_url = "https://www.minuto.wiki"
keywords = ["zeitgutschein", "minuto", "nachbarschaftshilfe"]

[mutable.app_config]
default_validity_duration = "P5Y"
round_up_validity_to = "P1Y"
server_history_retention = "P6M"

[mutable.i18n.descriptions]
de = "Dieser Gutschein verbrieft einen Anspruch auf {{amount}} Minuten Arbeits- oder Dienstleistung beim Aussteller."
en = "This voucher entitles the holder to {{amount}} minutes of service or labor from the issuer."

[mutable.i18n.footnotes]
de = "Einlösung nach Absprache. Keine Barauszahlung."
en = "Redemption upon agreement. No cash payout."

[mutable.i18n.collateral_descriptions]
de = "Gedeckt durch die persönliche Arbeitskraft des Ausstellers und 2 unabhängige Bürgen."
en = "Backed by personal labor guarantee of the issuer and 2 independent guarantors."`,
  },
  {
    id: 'regiogeld',
    name: 'Regionalwährung (Regiogeld)',
    badge: 'Euro-Parität & Treuhand',
    description: '1:1 an Euro gebunden, fiat-besichert mit 2 Nachkommastellen.',
    toml: `[immutable.identity]
uuid = "234e5678-e89b-12d3-a456-426614174001"
name = "Chiemgau Regiogeld"
abbreviation = "REGIO"

[immutable.blueprint]
unit = "Regio"
primary_redemption_type = "goods_or_services"
collateral_type = "fiat_backed"

[immutable.features]
allow_partial_transfers = true
balances_are_summable = true
amount_decimal_places = 2
privacy_mode = "public"
allowed_t_types = ["init", "transfer", "split"]

[immutable.issuance]
validity_duration_range = ["P1Y", "P3Y"]
issuance_minimum_validity_duration = "P6M"
additional_signatures_range = [0, 0]
allowed_signature_roles = []

[mutable.metadata]
issuer_name = "Regiogeld Vereinigung e.V."
homepage_url = "https://regiogeld.de"
keywords = ["regionalwaehrung", "lokalwirtschaft", "nachhaltig"]

[mutable.app_config]
default_validity_duration = "P2Y"
round_up_validity_to = "P1Y"
server_history_retention = "P1Y"

[mutable.i18n.descriptions]
de = "Gutschein im Gegenwert von {{amount}} Regio (1:1 an Euro gebunden), einlösbar bei allen teilnehmenden Annahmestellen."
en = "Voucher worth {{amount}} Regio (1:1 pegged to Euro), redeemable at all participating local merchants."

[mutable.i18n.footnotes]
de = "Gültig im regionalen Wirtschaftsraum."
en = "Valid within the regional economic zone."

[mutable.i18n.collateral_descriptions]
de = "100% gedeckt durch Treuhandguthaben bei der regionalen Genossenschaftsbank."
en = "100% backed by escrow deposits at the local cooperative bank."`,
  },
  {
    id: 'b2b-credit',
    name: 'B2B Mutual Credit',
    badge: 'Clearing & Stealth',
    description: 'Zinsfreier Verrechnungsring mit Stealth-Transaktionen & Buchungslimits.',
    toml: `[immutable.identity]
uuid = "345e6789-e89b-12d3-a456-426614174002"
name = "B2B Business Credit"
abbreviation = "CRE"

[immutable.blueprint]
unit = "Credit"
primary_redemption_type = "goods_or_services"
collateral_type = "personal_guarantee"

[immutable.features]
allow_partial_transfers = true
balances_are_summable = true
amount_decimal_places = 2
privacy_mode = "stealth"
allowed_t_types = ["init", "transfer", "split"]

[immutable.issuance]
validity_duration_range = ["P1Y", "P5Y"]
issuance_minimum_validity_duration = "P1Y"
additional_signatures_range = [0, 1]
allowed_signature_roles = ["auditor"]

[immutable.custom_rules.transfer_limit]
expression = "Transaction.amount <= 50000.0"
message = "Maximales Transaktionsvolumen pro Einzelbuchung: 50.000 Credit."

[mutable.metadata]
issuer_name = "Mutual Credit Clearing Ring"
homepage_url = "https://clearing-ring.org"
keywords = ["b2b", "mutual-credit", "clearing", "wir-system"]

[mutable.app_config]
default_validity_duration = "P3Y"
round_up_validity_to = "P1Y"
server_history_retention = "P2Y"

[mutable.i18n.descriptions]
de = "Verrechnungseinheit über {{amount}} Credit für den zinsfreien B2B-Warenaustausch."
en = "Clearing unit worth {{amount}} Credit for zero-interest B2B goods settlement."

[mutable.i18n.footnotes]
de = "Ausschließlich für verifizierte Geschäftskunden."
en = "Exclusively for verified business participants."

[mutable.i18n.collateral_descriptions]
de = "Gegenseitige Kreditlinie abgesichert durch den Clearing-Pool des Verrechnungsrings."
en = "Mutual credit line secured by the clearing ring credit pool."`,
  },
  {
    id: 'silver-asset',
    name: 'Physisches Feinsilber',
    badge: 'Rohstoff & Tresor',
    description: '3 Nachkommastellen, auditiert durch Wirtschaftsprüfer.',
    toml: `[immutable.identity]
uuid = "456e7890-e89b-12d3-a456-426614174003"
name = "Physisches Feinsilber 999"
abbreviation = "AG999"

[immutable.blueprint]
unit = "Gramm Silber"
primary_redemption_type = "physical_asset"
collateral_type = "physical_asset"

[immutable.features]
allow_partial_transfers = true
balances_are_summable = true
amount_decimal_places = 3
privacy_mode = "flexible"
allowed_t_types = ["init", "transfer", "split"]

[immutable.issuance]
validity_duration_range = ["P1Y", "P10Y"]
issuance_minimum_validity_duration = "P2Y"
additional_signatures_range = [1, 2]
allowed_signature_roles = ["auditor", "guarantor"]

[mutable.metadata]
issuer_name = "Edelmetall Verwahrgenossenschaft"
homepage_url = "https://silber-tresor.org"
keywords = ["rohstoff", "silber", "sachwert", "tresor"]

[mutable.app_config]
default_validity_duration = "P5Y"
round_up_validity_to = "P1Y"
server_history_retention = "P5Y"

[mutable.i18n.descriptions]
de = "Dieser Gutschein verbrieft einen physischen Herausgabeanspruch auf {{amount}} Gramm Feinsilber (999/1000)."
en = "This voucher represents a physical redemption claim for {{amount}} grams of fine silver (999/1000)."

[mutable.i18n.footnotes]
de = "Auslieferung ab 100g oder Barausgleich zum aktuellen LBMA-Silberpreis."
en = "Physical delivery from 100g or cash settlement at current LBMA silver fixing."

[mutable.i18n.collateral_descriptions]
de = "Physisch eingelagert im Hochsicherheitslager Zürich, quartalsweise auditiert durch unabhängige Wirtschaftsprüfer."
en = "Physically stored in high-security vaults in Zurich, audited quarterly by independent auditors."`,
  },
];
