#### Following enhancements have been made to the APIVoid connector in version 2.0.0:

- Updated the connector to support the latest Void APIs v2.
- Removed the following actions as they are now deprecated in API v2:
    - `Get ThreatLog Domain Reputation`
    - `Get URL HTML`
- Added the following actions and playbooks:
    - `Execute an API Request`
- Updated the `Set Score` step in the following enrichment playbooks to correctly invert the score using jinja:
    - `IP Address > API Void > Enrichment`
    - `Domain > API Void > Enrichment`
    - `Email Address > API Void > Enrichment`
    - `URL > API Void > Enrichment`
- Updated Output Schema of all operations.
