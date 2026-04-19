# Transfer Bundle Protocol v1.0

## Zweck
Dieses Protokoll beschreibt das Format für den sicheren Transfer von Gutscheinen zwischen zwei Parteien. Ein Transaction Bundle fasst eine oder mehrere Gutschein-Transaktionen zusammen und versieht sie mit einer verbindlichen Signatur des Senders. Es ist die atomare Einheit für den Austausch von Werten im Human Money System.

## Schema Definition
Der Payload dieses Protokolls entspricht dem JSON-Format des Rust-Structs `TransactionBundle` (abrufbar in `src/models/profile.rs`). 

Die wichtigsten Felder des Objekts sind:

- **bundle_id**: Eine eindeutige ID für dieses Bündel, generiert aus dem Hash seines Inhalts.
- **sender_id**: Die DID (Decentralized Identifier) des Senders.
- **recipient_id**: Die DID des Empfängers.
- **vouchers**: Ein Array von vollständigen `Voucher`-Objekten, inklusive ihrer gesamten Transaktionshistorie.
- **timestamp**: Der Zeitpunkt der Bündel-Erstellung im ISO 8601-Format.
- **notes**: Eine optionale, vom Sender hinzugefügte Nachricht für den Empfänger.
- **sender_signature**: Die digitale Signatur des Senders, die die `bundle_id` unterzeichnet.
- **forwarded_fingerprints**: Eine Liste von `TransactionFingerprint` Objekten. Diese dienen der Double-Spend-Erkennung, indem sie anonymisierte Transaktionsdaten im Netzwerk verbreiten (Gossip-Protokoll).

## Beispiel (Schematisch)
```json
{
  "bundle_id": "8f8e...2a1b",
  "sender_id": "did:key:z6MkpTHR...",
  "recipient_id": "did:key:z6MkgT6x...",
  "vouchers": [
    {
      "voucher_id": "v123...",
      "nominal_value": { "amount": "50", "unit": "Minuto" },
      "transactions": [ ... ]
    }
  ],
  "timestamp": "2024-05-20T12:00:00Z",
  "notes": "Zahlung für Gemüsekiste",
  "sender_signature": "6Gf...9A11",
  "forwarded_fingerprints": [
    {
      "ds_tag": "abc...123",
      "u": "def...456",
      "blinded_id": "ghi...789",
      "t_id": "t123",
      "layer2_signature": "sig..."
    }
  ]
}
```
