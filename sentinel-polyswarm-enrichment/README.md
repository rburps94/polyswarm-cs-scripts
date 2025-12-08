# Azure Sentinel, PolySwarm Enrichment

This package provides a Microsoft Sentinel playbook and optional custom connector
that enrich file hashes in incidents with PolySwarm intelligence including
PolyScore, detection counts, malicious engine names, malware family and threat labels.

When an incident is created, Sentinel sends any file hashes to PolySwarm, the
playbook retrieves enrichment data, and writes the results back into the
incident as a comment (and optionally into a custom log table).

## What this integration does

- Detects file hash entities in Sentinel incidents  
- Calls the PolySwarm REST API for each hash  
- Retrieves:  
  - PolyScore  
  - Detection counts (malicious, benign, total)  
  - Engine names that returned `verdict = true`  
  - Malware family and labels from PolyUnite metadata  
- Adds a detailed enrichment comment to the Sentinel incident  
- Optionally logs results in a custom table for hunting and analytics  

## Components

- `custom-connector/polyswarm-connector-swagger.json`  
  Custom Logic Apps connector that wraps the PolySwarm Hash Search API.

- `playbooks/polyswarm-enrich-hash-from-incident.json`  
  Logic App playbook that performs enrichment when an incident is created.

## Prerequisites

- Azure subscription with Microsoft Sentinel enabled  
- Permissions to deploy Logic Apps and custom connectors  
- PolySwarm API key with access to the `default` community  
- Optional, Azure Key Vault for storing the API key  

## PolySwarm API

The playbook uses the PolySwarm REST API.

Base URL  
`https://api.polyswarm.network/v3`

Hash search endpoint  
`GET /search/hash/sha256?hash=<sha256>&community=default`

Auth header  
`Authorization: YOUR_API_KEY`

The playbook expects a JSON response containing:

- `result[0].polyscore`  
- `result[0].detections` (malicious, benign, total)  
- `result[0].assertions[].engine.name` for engines with `verdict = true`  
- `result[0].metadata` entries where `tool = "polyunite"`  
  - `tool_metadata.malware_family`  
  - `tool_metadata.labels[]`  

## Deployment

### 1. Create the PolySwarm custom connector (optional but recommended)

1. In the Azure portal, go to Logic Apps → Custom connectors  
2. Create a new connector from OpenAPI file  
3. Upload `polyswarm-connector-swagger.json`  
4. Set the `Host` field to `api.polyswarm.network`  
5. Save and then create a connection using your API key  

### 2. Deploy the playbook

1. Go to **Deploy a custom template**  
2. Upload `polyswarm-enrich-hash-from-incident.json`  
3. Select resource group and region  
4. Bind the playbook to:  
   - Sentinel workspace  
   - PolySwarm connector connection  
5. Deploy  

### 3. Grant permissions

- Ensure the playbook has permission to read and comment on incidents  
- Grant Key Vault access if you store the API key there  

### 4. Attach the playbook to an analytic rule

1. Open the analytic rule that generates incidents  
2. Go to **Automated response**  
3. Add the PolySwarm playbook  
4. Map the Incident ARM ID parameter if prompted  

### 5. Test

1. Trigger or create a test incident with a file hash  
2. Verify the playbook runs  
3. Inspect the Sentinel incident for an enrichment comment containing:  
   - PolyScore  
   - Detection summary  
   - Malicious engine list  
   - Malware family  
   - Threat labels  

## Extending

Potential enhancements:

- URL and IP enrichment  
- Sandbox and IOC extraction into a custom table  
- A Sentinel Workbook visualising PolySwarm enrichment activity  
- Buttons for analyst on-demand enrichment  

## Support and contact

PolySwarm Customer Success  
customersuccess@polyswarm.io

For Sentinel configuration assistance, refer to Azure documentation or your SIEM team.
