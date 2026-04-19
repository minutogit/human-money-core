# Trust Assertion Protocol v1.0

## Zweck
Dieses Protokoll beschreibt eine Vertrauensbekundung (Trust Assertion) innerhalb des dezentralen Web-of-Trust (WoT) des Human Money Systems. Eine Trust Assertion ermöglicht es einem Teilnehmer, einer anderen Partei öffentlich oder privat Vertrauen auszusprechen – z.B. als Bürge für die Identität und Zuverlässigkeit eines Gutschein-Erstellers.

> **Hinweis:** Dieses Protokoll ist für zukünftige Versionen reserviert. Die zugrundeliegende Struct-Definition befindet sich noch in der Entwicklung. Die nachfolgende Spezifikation beschreibt das geplante Format.

## Schema Definition
Der Payload ist ein JSON-Objekt, das eine Vertrauensbekundung eines Nutzers (`issuer_id`) gegenüber einem anderen Nutzer (`subject_id`) darstellt.

Geplante Felder des Objekts:

- **assertion_id**: Eindeutige, deterministische ID dieser Bekundung (`hash(issuer_id + subject_id + timestamp)`).
- **issuer_id**: Die DID der Person, die das Vertrauen ausspricht.
- **subject_id**: Die DID der Person, der Vertrauen ausgesprochen wird.
- **trust_level**: Ein Integer oder definierter String-Wert, der den Grad des Vertrauens angibt (z.B. `"direct"`, `"endorsement"`).
- **context**: Ein optionaler Freitext, der den Kontext der Bekundung beschreibt (z.B. "persönlich bekannt", "Geschäftspartner seit 2 Jahren").
- **timestamp**: Der Zeitpunkt der Erstellung im ISO 8601-Format.
- **issuer_signature**: Die kryptographische Signatur des `issuer_id`-Schlüssels über der `assertion_id`.

## Beispiel (Schematisch, geplant)
```json
{
  "assertion_id": "ta_8f2e...99ab",
  "issuer_id": "did:key:z6M_Issuer...",
  "subject_id": "did:key:z6M_Subject...",
  "trust_level": "direct",
  "context": "Lokaler Händler, persönlich bekannt.",
  "timestamp": "2024-05-20T14:00:00Z",
  "issuer_signature": "aB3f...DD9x"
}
```
