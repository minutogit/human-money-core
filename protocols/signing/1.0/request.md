# Signing Request Protocol v1.0

## Zweck
Dieses Protokoll beschreibt die Anfrage eines Gutschein-Erstellers an einen potenziellen Bürgen oder Notar. In einem Vertrauens-basierten System wie Human Money benötigt ein Gutschein zusätzliche Signaturen von vertrauenswürdigen Dritten, um in vollem Umfang akzeptiert zu werden.

## Schema Definition
Der Payload für eine Signaturanfrage ist die JSON-Repräsentation des `Voucher` Structs (definiert in `src/models/voucher.rs`).

Wichtige Bestandteile der Anfrage:
- **voucher_standard**: Informationen über den zugrunde liegenden Standard (z.B. Minuto).
- **creator**: Das detaillierte `PublicProfile` des Erstellers, inklusive Name und ggf. Adresse.
- **nominal_value**: Der Betrag und die Einheit des Gutscheins.
- **transactions**: Enthält initial mindestens die "init"-Transaktion, die den Gutschein an den Ersteller bindet.
- **signatures**: Zum Zeitpunkt der Anfrage ist dieses Array meist noch leer oder enthält bereits Signaturen anderer Bürgen.

Der Bürge validiert den Gutschein (insb. Identität und Besicherung) und sendet bei Erfolg eine Signatur über das `Signing Response Protocol` zurück.

## Beispiel (Schematisch)
```json
{
  "voucher_standard": {
    "name": "Minuto-Gutschein",
    "uuid": "550e8400-e29b...",
    "standard_definition_hash": "h72..."
  },
  "voucher_id": "v778...x9",
  "nominal_value": { "amount": "20", "unit": "Minuto" },
  "creator": {
    "first_name": "Max",
    "last_name": "Mustermann",
    "organization": "Bio-Hof",
    "id": "did:key:z6M..."
  },
  "transactions": [
    {
      "t_id": "init_778",
      "t_type": "init",
      "amount": "20",
      "recipient_id": "did:key:z6M..."
    }
  ],
  "signatures": []
}
```
