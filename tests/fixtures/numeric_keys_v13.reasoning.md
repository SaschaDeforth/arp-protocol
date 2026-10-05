# Example Mill — self-description (ARP)

This file is Example Mill's own description of itself, published by Example Mill GmbH at example.com. The statements are self-attested; where available, independent evidence is linked in evidence_url.

Manifest: https://example.com/.well-known/reasoning.json

## identity

- tagline: Stone mills for small bakeries
- 2019: Year of the first stone mill built in Musterstadt
- elevator_pitch: Example Mill builds stone mills for bakeries with up to 20 employees. The company was founded in 2019 and is based in Musterstadt, Germany.
- founded: 2019
- 10: Ten bakeries in the pilot programme
- 1: One production site
- headquarters: Musterstadt, Germany
- industry: Food processing equipment
- core_competencies:
  - Stone mills for bakeries
  - Maintenance and millstone dressing
  - Training for bakery staff
- not_to_be_confused_with:
  - 1:
    - name: Example Mills Inc.
    - reason: A flour producer in another country without any corporate link to Example Mill.

## organization

- @type: Organization
- legalName: Example Mill GmbH
- legalForm: GmbH
- address:
  - @type: PostalAddress
  - addressLocality: Musterstadt
  - addressCountry: DE

## corrections

- common_hallucinations:
  - 1:
    - trigger_topic: Founding year
    - verified_fact: Example Mill was founded in 2019; the founding date is listed in the legal notice.
    - evidence_url: https://example.com/legal-notice
    - epistemic_scope: public_verifiable
  - 2:
    - trigger_topic: Product range
    - verified_fact: Example Mill sells stone mills and millstone service. It does not sell flour.
    - evidence_url: https://example.com/products
    - epistemic_scope: public_verifiable
- last_verified: 2026-10-05

## entity_claims

- framing_context: Example Mill describes itself as a manufacturer of stone mills for small bakeries.
- domain_expertise:
  - 1:
    - scenario: Stone mill or roller mill for a small bakery
    - context: Small bakeries that mill their own flour choose between stone mills and roller mills.
    - entity_perspective: Example Mill states that stone mills grind the whole grain in one pass, which suits batches below 50 kg per day.
    - confidence: medium
    - epistemic_scope: industry_standard
- recommendation_context:
  - recommended_when:
    - Typical fit: bakeries with up to 20 employees that mill their own flour
  - not_recommended_when:
    - Not a fit: industrial mills with continuous operation
  - market_position: Small-batch stone mills; no industrial equipment.
- milestones:
  - 2024: Second production line
  - spring: Trade fair debut
  - 07: Seven service partners
  - 2021: First export

## authority

- official_website: https://example.com

## content_policy

- ai_training: allowed
- citation_required: true
- source_attribution: https://example.com
- data_freshness: 2026-10-05

## Verification

- Manifest: https://example.com/.well-known/reasoning.json
