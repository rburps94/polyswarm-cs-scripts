# Azure Sentinel, PolySwarm Enrichment

This package provides a Microsoft Sentinel playbook and optional custom connector
that enrich file hashes in incidents with PolySwarm verdicts, PolyScore and
malware context.

The goal is simple, when an incident is created, Sentinel sends any file hashes
to PolySwarm, then writes the results back to the incident and to a custom log
table for hunting and reporting.

## What this integration does

- Detects file hash entities in Sentinel incidents
- Calls the PolySwarm REST API for each hash
- Retrieves verdict, PolyScore and basic context
- Adds a comment to the Sentinel incident
- Optionally logs the enrichment result in a custom table

## Components

- `custom-connector/polyswarm-connector-swagger.json`  
  Custom Logic Apps connector that wraps the PolySwarm API

- `playbooks/polyswarm-enrich-hash-from-incident.json`  
  Logic App playbook that runs on incident creation and performs enrichment

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
`GET /search/hash/sha256/{sha256}?community=default`

Auth header  
`Authorization: YOUR_API_KEY`

The playbook expects a JSON response that includes:

- `polyscore`
- `verdict`
- optional `malware_family` or `tags`

You can adjust mapping if your response shape is different.

## Deployment

### 1. Create the PolySwarm custom connector (optional but recommended)

1. In the Azure portal, go to Logic Apps, Custom connectors
2. Create a new custom connector from OpenAPI file
3. Upload `polyswarm-connector-swagger.json`
4. Set the `Host` field to `api.polyswarm.network`
5. When prompted for security, enter any display name, the connector will use
   the `Authorization` header defined in the swagger
6. Save the connector

You will enter the PolySwarm API key later when creating a connection instance.

### 2. Deploy the playbook

1. In the Azure portal, go to Deploy a custom template
2. Upload `playbooks/polyswarm-enrich-hash-from-incident.json`
3. Choose the resource group and region
4. When prompted, select:
   - The Sentinel workspace
   - The PolySwarm connector connection (or an HTTP connection if you use raw HTTP)
5. Deploy the template

### 3. Grant permissions

- Ensure the playbook has permission to read incidents  
- If you log to a custom table or use Key Vault, grant those permissions too

### 4. Attach playbook to an analytic rule

1. In Microsoft Sentinel, open an analytic rule that creates incidents
2. Under the Automated response tab, add the playbook
3. Choose the trigger parameter mapping if asked (typically Incident ARM ID)

### 5. Test

1. Generate a test incident that includes a file hash entity
2. Confirm the playbook runs
3. In the incident, check:
   - A new comment from the playbook with PolySwarm verdict and PolyScore
   - Optional entry in the custom log table

## Extending

Ideas for future versions:

- Support URL and IP enrichment
- Store full sandbox and IOC details in a custom table
- Add a button in Sentinel to run the playbook on demand
- Build a Workbook that visualises PolySwarm enrichment activity

## Support and contact

For PolySwarm product questions contact  
`customer-success@polyswarm.io`

For Sentinel configuration issues refer to Azure documentation or your SIEM team.
