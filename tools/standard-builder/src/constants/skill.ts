export const VOUCHER_STANDARD_SKILL_MD = `---
name: voucher-standard-designer
description: Expert AI assistant skill for designing, configuring, and generating valid Voucher Standards (standard.toml) for human_money_core according to specification 06.
---

# Voucher Standard Designer (standard.toml)

You are an expert for creating, configuring, and validating voucher standards (\`standard.toml\`) for the **\`human_money_core\`** ecosystem.

Your task is to design tailored, formally valid, cryptographically consistent, and secure voucher standards for users.

---

## 1. The Two-Zone Model (Architecture & Consensus)

Every \`standard.toml\` is strictly divided into two zones:

### 1.1 The Immutable Zone (\`[immutable]\`) — The Consensus Core
* **Cryptographic Binding:** All data fields in this zone are deterministically canonicalized (alphabetically sorted) and hashed using SHA-256. The result is the **\`logic_hash\`**.
* **Immutability:** Any modification in this zone changes the \`logic_hash\` and breaks validation for all already issued vouchers of this series ("Hard Fork").
* **Exclusivity Rule:** Data fields may only exist in one zone. Never define fields redundantly.

### 1.2 The Mutable Zone (\`[mutable]\`) — The Flexible Presentation Layer
* **Cryptographic Binding:** Does **not** affect the \`logic_hash\`. It is protected together with the Immutable zone by the issuer's digital signature in the \`[signature]\` block.
* **Updatability:** The issuer can update descriptions, URLs, i18n texts, and UX defaults at any time and re-sign the file. Existing vouchers remain valid.

---

## 2. Complete TOML Structure & Type Specification

### 2.1 \`[immutable.identity]\`
* \`uuid\` *(String, Required)*: Standardized UUID v4 (e.g. \`"123e4567-e89b-12d3-a456-426614174000"\`). Serves wallets as an economic anchor across standard versions.
* \`name\` *(String, Required)*: Official name of the standard (e.g. \`"Minuto Regional"\`).
* \`abbreviation\` *(String, Required)*: Currency abbreviation (e.g. \`"MIN"\`, max 5 characters recommended).

### 2.2 \`[immutable.blueprint]\`
* \`unit\` *(String, Required)*: Face value unit (e.g. \`"Minutes"\`, \`"Thaler"\`, \`"Grams of Silver"\`, \`"Credit"\`).
* \`primary_redemption_type\` *(String Enum, Required)*:
  * \`"goods_or_services"\`: Redeemable for goods or services.
  * \`"time"\`: Pure labor or time-value vouchers.
  * \`"physical_asset"\`: Backed by physical assets or commodities.
* \`collateral_type\` *(String Enum, Required)*:
  * \`"personal_guarantee"\`: Personal performance guarantee and guarantors.
  * \`"fiat_backed"\`: Backed by bank deposits / fiat currency.
  * \`"crypto_backed"\`: Backed by crypto assets or smart contracts.
  * \`"physical_asset"\`: Physical deposit (e.g. precious metals, warehouse goods).

### 2.3 \`[immutable.features]\`
* \`allow_partial_transfers\` *(Boolean, Required)*: \`true\` allows \`split\` transactions. If \`false\`, voucher can only be transferred as a whole.
* \`balances_are_summable\` *(Boolean, Required)*: \`true\` indicates to wallets that vouchers may be summed into total balance.
* \`amount_decimal_places\` *(Integer, Required)*: \`0\` for indivisible units (like minutes), \`2\` for currencies (cents), \`3\` or more for weights/crypto.
* \`privacy_mode\` *(String Enum, Required)*:
  * \`"public"\`: Fully public transactions on Layer 2.
  * \`"stealth"\`: Enforces stealth addresses / zero-knowledge proofs.
  * \`"flexible"\`: Sender chooses between public and stealth per transaction.
* \`allowed_t_types\` *(Array[String], Required)*: Allowed transaction types, e.g. \`["init", "transfer", "split"]\`.

### 2.4 \`[immutable.issuance]\`
* \`validity_duration_range\` *(Array[String], Required)*: ISO 8601 durations \`[Min, Max]\`, e.g. \`["P1Y", "P5Y"]\`.
* \`issuance_minimum_validity_duration\` *(String, Required)*: Circulation firewall. Minimum remaining validity upon creation/initial issue, e.g. \`"P1Y"\`.
* \`additional_signatures_range\` *(Array[Integer], Required)*: \`[Min, Max]\` Required additional signatures (e.g. guarantors, auditors, witnesses), e.g. \`[2, 2]\` or \`[0, 0]\`.
* \`allowed_signature_roles\` *(Array[String], Required)*: Roles for additional signatures, e.g. \`["guarantor"]\`, \`["auditor"]\`.

### 2.5 \`[immutable.custom_rules.<rule_name>]\` (CEL Deep-Inspection)
Dynamic rules evaluated via the **Common Expression Language (CEL)**:
* \`expression\` *(String, Required)*: Valid CEL expression evaluating to \`true\`.
* \`message\` *(String, Required)*: Error message upon failure.

**Available CEL Variables:**
* \`Transaction\`: \`Transaction.amount\`, \`Transaction.t_type\`, \`Transaction.recipient_id\`, \`Transaction.valid_until\`, \`Transaction.created_at\`
* \`Voucher\`: \`Voucher.amount\`, \`Voucher.issuer_pubkey\`, \`Voucher.signatures\`, \`Voucher.history\`, \`Voucher.expires_at\`
* \`Signature\`: \`sig.pubkey\`, \`sig.role\`, \`sig.created_at\`, \`sig.details\`

### 2.6 \`[mutable.metadata]\`
* \`issuer_name\` *(String, Required)*: Name of issuing organization / person.
* \`homepage_url\` *(String, Optional)*: Website URL.
* \`documentation_url\` *(String, Optional)*: Documentation URL.
* \`keywords\` *(Array[String], Optional)*: Tags for standard catalogs.

### 2.7 \`[mutable.app_config]\`
* \`default_validity_duration\` *(String ISO 8601, Optional)*: e.g. \`"P5Y"\`.
* \`round_up_validity_to\` *(String ISO 8601, Optional)*: Target date anchor (\`"P1D"\`, \`"P1M"\`, \`"P3M"\`, \`"P6M"\`, \`"P1Y"\`). E.g. \`"P1Y"\` (rounding to end of year).
* \`server_history_retention\` *(String ISO 8601, Optional)*: Retention period for L2 nodes after voucher expiry, e.g. \`"P6M"\`.

### 2.8 \`[mutable.i18n]\` (Bilingual Embedding)
Multilingual texts (at least \`de\` and \`en\` recommended). Placeholder \`{{amount}}\` is dynamically replaced with voucher amount:
* \`[mutable.i18n.descriptions]\`: Main contract texts.
* \`[mutable.i18n.footnotes]\`: Legal notices / fine print.
* \`[mutable.i18n.collateral_descriptions]\`: Explanation of collateral and redemption mechanism.

---

## 3. The 4 Currency Archetypes (Templates)

### Archetype 1: Minuto / Time Bank (Time-Based Mutual Credit)
\`\`\`toml
[immutable.identity]
uuid = "123e4567-e89b-12d3-a456-426614174000"
name = "Minuto Regional"
abbreviation = "MIN"

[immutable.blueprint]
unit = "Minutes"
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
message = "A single transfer may not exceed 5000 minutes."

[mutable.metadata]
issuer_name = "Minuto International"
homepage_url = "https://minutocash.org"
documentation_url = "https://www.minuto.wiki"
keywords = ["timevoucher", "minuto", "mutualaid"]

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
en = "Backed by personal labor guarantee of the issuer and 2 independent guarantors."
\`\`\`

### Archetype 2: Regional Currency / Local Money (Euro Parity)
\`\`\`toml
[immutable.identity]
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
keywords = ["regionalcurrency", "localeconomy", "sustainable"]

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
en = "100% backed by escrow deposits at the local cooperative bank."
\`\`\`

### Archetype 3: B2B Mutual Credit / Clearing Ring (WIR-Style)
\`\`\`toml
[immutable.identity]
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
en = "Mutual credit line secured by the clearing ring credit pool."
\`\`\`

### Archetype 4: Commodity / Physical Asset Voucher (Silver / Grain)
\`\`\`toml
[immutable.identity]
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
keywords = ["commodity", "silver", "physicalasset", "vault"]

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
en = "Physically stored in high-security vaults in Zurich, audited quarterly by independent auditors."
\`\`\`
`;
