# Microsoft Sentinel — PolySwarm Enrichment

A Microsoft Sentinel playbook (Logic App) that enriches file hashes found on Sentinel
incidents with PolySwarm threat intelligence, and writes the results back onto the
incident as a comment.

An optional custom Logic Apps connector is also included for teams that prefer a
first-class connector action over a raw HTTP call.

---

## What this integration does

When an incident is created, an automation rule runs this playbook. The playbook:

1. Receives the incident (including its entities) from the **Microsoft Sentinel incident** trigger.
2. Extracts every `FileHash` entity via the Sentinel connector's `Entities - Get FileHashes` action.
3. Detects the hash type from its length — 32 = MD5, 40 = SHA1, 64 = SHA256 — and skips anything else.
4. Calls the matching PolySwarm hash-search endpoint for each hash.
5. Parses out:
   - An assessment (Malicious / Suspicious / Likely benign), derived from PolyScore
     against a configurable threshold
   - PolyScore and detection counts (malicious / benign / total)
   - Malware family and threat labels from PolyUnite
   - Classification tags, sandbox-reported family, and CAPE / Triage sandbox scores
   - MITRE ATT&CK technique IDs, merged from both sandboxes
   - File type, first seen and last seen
   - A link to the PolySwarm report
6. Posts a formatted comment back to the incident — including an explicit
   "no result" comment when PolySwarm has never seen the artifact, so the analyst
   knows the lookup ran and what it found.

Every field is optional in the output: lines are omitted rather than printed as `n/a`
when the underlying data is absent, so a sparse record still produces a clean comment.

Example comment for a known LockBit/BlackMatter sample:

> **PolySwarm enrichment**
> Hash (SHA256): 5da5a1e3983982a92341953929d4c7726da65fe5125d264dd8932a870f2f154a
> Assessment: **Malicious** (PolyScore 0.9999)
> Detections: 6 malicious / 2 benign of 8 engines
> Malware family: BlackMatter
> Labels: ransomware, trojan
> Tags: Ransomware, Trojan, PE32, Windows
> Sandbox-reported family: lockbit
> Sandbox scores: CAPE 8 / Triage 10
> MITRE ATT&CK: T1489, T1542.003, T1027, T1486, T1082, T1070.004, T1614.001
> File type: PE32 executable (GUI) Intel 80386, for MS Windows
> First seen: 2023-02-26T10:21:00Z | Last seen: 2026-07-09T14:09:03Z
> PolySwarm report: https://polyswarm.network/scan/results/file/5da5a1e...

The result is that an analyst opening a Sentinel incident sees third-party
multi-engine context on the file without leaving the portal or pivoting to another tool.

### What it deliberately does not do

- It does not submit or upload files to PolySwarm — it only looks up hashes that PolySwarm has already scanned.
- It does not write to a custom Log Analytics table (see [Extending](#extending) for why, and what to do instead).
- It does not enrich URL, IP or domain entities — only file hashes.

---

## Components

| Path | Purpose |
| --- | --- |
| `playbooks/polyswarm-enrich-hash-from-incident.json` | ARM template deploying the Logic App playbook plus its Sentinel API connection. This is the only file you need to deploy. |
| `custom-connector/polyswarm-connector-swagger.json` | Optional Swagger 2.0 definition for a PolySwarm custom Logic Apps connector. Not required by the playbook. |

The playbook calls PolySwarm with a built-in **HTTP** action rather than the custom
connector. That keeps it self-contained — it deploys and runs with no prerequisite
connector resource — and lets it switch between the MD5, SHA1 and SHA256 endpoints
at runtime, which a single connector operation cannot do.

---

## Prerequisites

- An Azure subscription with Microsoft Sentinel enabled on a Log Analytics workspace.
- Permission to deploy Logic Apps and API connections, and to assign RBAC roles
  (the playbook's managed identity needs the **Microsoft Sentinel Responder** role).
- A PolySwarm API key with access to the community you intend to query.
  Generate one at <https://polyswarm.network/account/api-keys>.

---

## PolySwarm API reference

Full documentation: <https://docs.polyswarm.io/customers/polyswarm-rest-api-v3>

**Base URL:** `https://api.polyswarm.network/v3`

**Auth header:** `Authorization: <YOUR_API_KEY>` — the raw key, with **no** `Bearer ` prefix.

**Endpoints used:**

```
GET /v3/search/hash/sha256?hash=<hash>&community=default
GET /v3/search/hash/sha1?hash=<hash>&community=default
GET /v3/search/hash/md5?hash=<hash>&community=default
```

### Response shape — read this before changing the playbook

All `/v3/search/*` endpoints return the same envelope:

```json
{ "status": "OK", "has_more": false, "limit": 50, "result": [ … ] }
```

`result[]` contains **artifact records**. This shape has been verified against a live
`/search/metadata/query` response. The fields the playbook reads:

| Path | Used for |
| --- | --- |
| `scan.latest_scan.polyscore` | PolyScore, and the derived assessment |
| `scan.detections.{malicious,benign,total}` | Detection summary |
| `polyunite.malware_family`, `polyunite.labels[]` | Family and threat labels |
| `families[]`, `tags[]` | Fallback family, classification tags |
| `triage_sandbox_v0.malware_family[]` | Sandbox-reported family |
| `cape_sandbox_v2.malscore`, `triage_sandbox_v0.analysis.score` | Sandbox scores |
| `cape_sandbox_v2.ttp[]`, `triage_sandbox_v0.ttp[]` | MITRE ATT&CK, merged with `union()` |
| `scan.mimetype.extended`, `artifact.size` | File type and size |
| `scan.first_seen`, `scan.last_seen` | Sighting window |
| `artifact.sha256` | Report link, constructed as `https://polyswarm.network/scan/results/file/{sha256}` |

**Two important notes.**

*Per-engine assertions are not enumerable.* On artifact records,
`scan.latest_scan.assertions` is an **object keyed by engine name**
(`{"ClamAV": {"assertion": "malicious"}, …}`), not an array. Logic Apps has no
expression to enumerate an object's dynamic keys, and the usual `xml()`/`xpath()`
workaround fails because engine names contain spaces (`Crowdstrike Falcon ML`),
which are invalid XML element names. The playbook therefore reports detection
*counts* rather than engine *names*. If you need the named list, either link the
Logic App to an Integration Account and use an inline JavaScript action, or move the
call into an Azure Function. See [Notes for the maintaining team](#notes-for-the-maintaining-team).

*The playbook reads both shapes.* Some PolySwarm endpoints return a flatter,
instance-shaped payload with `polyscore`, `detections`, `assertions[]` and
`permalink` at the record root. Every extraction in `Build_summary` is written as a
`coalesce()` across both layouts, and `Filter_malicious_assertions` reads only the
**root-level** `assertions` key — which is absent from artifact records — so it
safely yields an empty list rather than failing on the keyed object. If
`/search/hash/*` returns the flat shape on your account, the engine-name list
populates automatically and nothing else changes.

A hash PolySwarm has never seen returns HTTP `404`; the playbook handles this as a
normal outcome, not a failure.

### Confirm against your own account

The public docs page lists endpoints but does not publish example response bodies.
Run this once and confirm which shape `/search/hash/` returns for you:

```bash
curl -s -H "Authorization: $POLYSWARM_API_KEY" "https://api.polyswarm.network/v3/search/hash/sha256?hash=5da5a1e3983982a92341953929d4c7726da65fe5125d264dd8932a870f2f154a&community=default" | jq '.result[0] | {shape: (if .scan then "artifact-record" else "flat-instance" end), polyscore: (.scan.latest_scan.polyscore // .polyscore), detections: (.scan.detections // .detections), family: (.polyunite.malware_family // .families[0]), tags, ttps: ((.cape_sandbox_v2.ttp // []) + (.triage_sandbox_v0.ttp // []) | unique), assertions_type: (.scan.latest_scan.assertions // .assertions | type)}'
```

If `shape` is `artifact-record`, the playbook is already correct as shipped. If it is
`flat-instance`, it is also correct — the coalesce fallbacks cover it, and you get the
engine-name list as a bonus.

### Rate limits

- **PolySwarm:** community accounts are limited to 60 calls/hour; enterprise accounts to 1000 calls/second. A busy workspace on a community key will exhaust its quota quickly — the playbook retries 3 times with exponential backoff, but sustained `429`s will surface as "no result" comments.
- **Sentinel connector:** 600 calls per 60 seconds per connection.

---

## Deployment

### 1. Deploy the playbook

1. In the Azure portal, go to **Deploy a custom template** → **Build your own template in the editor**.
2. Load `playbooks/polyswarm-enrich-hash-from-incident.json`.
3. Fill in the parameters:

   | Parameter | Notes |
   | --- | --- |
   | `PlaybookName` | Defaults to `PolySwarm-Enrich-FileHash-IncidentTriggered`. |
   | `PolySwarmApiKey` | Your API key. Declared as a `securestring`. |
   | `PolySwarmCommunity` | `default` unless you have a private community. |
   | `PolySwarmApiBaseUrl` | Leave as-is unless directed otherwise. |
   | `PolySwarmMaliciousThreshold` | PolyScore at or above which the comment says "Malicious". Default `0.8`; at or above half that says "Suspicious". A string, because ARM templates have no float parameter type. |

4. Deploy into the resource group holding your Sentinel workspace.

The template creates the Logic App **and** its Microsoft Sentinel API connection,
wired to the playbook's system-assigned managed identity.

> **Storing the key in Key Vault.** `PolySwarmApiKey` is a `securestring`, so it is
> masked in the portal and in run history (the HTTP action is additionally marked
> with `secureData` on its inputs). To source it from Key Vault instead of typing it,
> deploy via a parameter file using a
> [Key Vault reference](https://learn.microsoft.com/azure/azure-resource-manager/templates/key-vault-parameter),
> or replace the header expression with a Key Vault connector lookup.

### 2. Grant the managed identity permissions

The playbook authenticates to Sentinel with its managed identity, which has no
permissions by default. **The playbook will fail until this is done.**

1. Open the resource group (or the Sentinel workspace) → **Access control (IAM)**.
2. **Add role assignment** → **Microsoft Sentinel Responder**.
3. Assign to **Managed identity** → select the playbook by name.

The deployment outputs `managedIdentityPrincipalId` if you prefer to script it.

### 3. Attach the playbook to an automation rule

Incident-triggered playbooks are attached via automation rules, not directly to an
analytics rule.

1. Sentinel → **Automation** → **Create** → **Automation rule**.
2. Trigger: **When incident is created**.
3. Optionally add a condition so it only runs on incidents that have a FileHash entity.
4. Action: **Run playbook** → select the PolySwarm playbook.
5. If prompted, grant Sentinel permission to run playbooks in that resource group.

### 4. Test

1. Create a test incident containing a file hash entity, or use **Run playbook** on an existing incident with one.

   > The **Run Trigger** button on the Logic App overview blade will **not** work —
   > Sentinel-triggered playbooks need an incident in the request body. Use Sentinel's
   > own "Run playbook", an automation rule, or **Resubmit** on a previous run.

2. Open the Logic App **Runs history** and confirm the run succeeded.
3. Open the incident and confirm the comment appears with PolyScore, detections,
   engine list, malware family and labels.

---

## Optional: the custom connector

`custom-connector/polyswarm-connector-swagger.json` defines a custom connector with
four operations — `EnrichSha256`, `EnrichSha1`, `EnrichMd5` and `SearchMetadata` —
and typed response schemas so the Logic App designer offers dynamic content for
PolySwarm fields. The schemas model the artifact-record shape verified above; the
flat-instance fields are included and marked `Legacy` in their descriptions.

To use it:

1. Azure portal → **Logic Apps Custom Connector** → **Create**.
2. Import the OpenAPI file. `host` (`api.polyswarm.network`) and `basePath` (`/v3`) are already set.
3. Create a connection, supplying your API key as the `Authorization` value.
4. In the playbook, replace the `Search_PolySwarm` HTTP action with the matching
   connector operation, and add the connector's connection to the `$connections`
   parameter block.

This is a designer convenience, not a functional upgrade. Because each hash type is
a separate operation, swapping to the connector means adding a `Switch` on
`Determine_hash_type` with one branch per operation.

---

## Extending

- **URL, IP and domain enrichment** — PolySwarm exposes `GET /v3/search/url` and
  `GET /v3/ioc/search?ip=…&domain=…`. The same playbook pattern applies against the
  `Url`, `Ip` and `DnsResolution` entity types.
- **Associated IOCs** — `GET /v3/ioc/sha256/{sha256}` returns IPs, domains, TTPs and
  imphashes tied to a sample, which is useful for expanding an investigation. Prefer
  this over scraping `cape_sandbox_v2.network.tcp[].dst` from the artifact record —
  those addresses include sandbox-internal ranges and unrelated Windows telemetry
  endpoints, and are not safe to treat as IOCs without filtering.
- **ATT&CK-driven automation** — the record already carries technique IDs. An
  automation rule could raise incident severity or add tactics as incident labels when
  the enrichment returns techniques your detections care about.
- **Sandbox detonation** — `POST /v3/sandbox/sandboxtask` for artifacts already known
  to PolySwarm, then poll `GET /v3/sandbox/sandboxtask`.
- **Logging enrichment to a custom table for hunting and workbooks** — do **not** use
  the Azure Log Analytics Data Collector connector for this. The legacy HTTP Data
  Collector API it depends on
  [is unsupported after 14 September 2026](https://learn.microsoft.com/azure/azure-monitor/logs/custom-logs-migrate).
  Use the [Logs Ingestion API](https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview)
  with a data collection rule and endpoint instead — the playbook's managed identity
  can post to the DCE directly with an HTTP action once granted **Monitoring Metrics Publisher**.
- **Bulk / streaming intelligence** — for ingesting PolySwarm data as a feed rather
  than per-incident enrichment, a playbook is the wrong tool. Use the
  [Codeless Connector Framework](https://learn.microsoft.com/azure/sentinel/create-codeless-connector)
  or an Azure Function against `GET /v3/search/metadata/query`.

---

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Playbook fails on `Entities - Get FileHashes` or on adding a comment, with 403 | The managed identity is missing the **Microsoft Sentinel Responder** role. See step 2. |
| Playbook never runs | No automation rule is attached, or the rule's conditions exclude the incident. |
| "Run trigger" on the Logic App blade errors | Expected. Sentinel triggers need an incident payload — see step 4. |
| Every hash returns "no result" with status 401 | Bad or missing API key. |
| Every hash returns "no result" with status 429 | PolySwarm rate limit reached. |
| Comment shows `Malware family: n/a` | The artifact has no PolyUnite classification and no `families[]`. Common for benign or rarely-seen files. |
| Comment has no "Malicious engines" line | Expected on artifact-record responses — per-engine names are not enumerable. See [Response shape](#response-shape--read-this-before-changing-the-playbook). |
| Comment has no Tags / ATT&CK / Sandbox lines | Those fields were absent from the record, so the lines were omitted by design. Sandbox fields only appear for detonated samples. |
| Hashes silently skipped | The hash was not 32, 40 or 64 characters. Check the entity in the incident. |

---

## Notes for the maintaining team

- Microsoft Sentinel in the **Azure portal is retiring after 31 March 2027**; it will
  be available only in the Defender portal. The playbook itself is unaffected — it is
  a Logic App — but the navigation paths in this README refer to the Azure portal and
  will need updating once you move to the
  [Defender portal](https://learn.microsoft.com/azure/sentinel/move-to-defender).
- The `For_each_file_hash` loop is deliberately set to `concurrency: { repetitions: 1 }`.
  Sentinel's connector documentation warns that parallel loop iterations updating the
  same incident are unsafe. Do not remove this.
- The playbook uses `Filter array` and `Select` actions rather than loop-scoped
  variables. This is intentional — variables mutated inside a parallel `For each`
  produce cross-contaminated results.
- All field extraction is centralised in the `Build_summary` Compose action. If a
  PolySwarm field path changes, that is the only action you need to edit; the comment
  body reads exclusively from its output.
- **If you want the named list of malicious engines**, link the Logic App to an
  Integration Account and insert an *Execute JavaScript Code* action after
  `Select_artifact_record`:

  ```javascript
  const a = workflowContext.actions.Select_artifact_record.outputs
             ?.scan?.latest_scan?.assertions ?? {};
  return Object.keys(a).filter(k => a[k].assertion === 'malicious');
  ```

  Then replace `"engines": "@body('Select_malicious_engine_names')"` in
  `Build_summary` with a reference to that action's body. Note that an Integration
  Account carries its own cost; an Azure Function doing the whole PolySwarm call is
  often the better trade if you need more than this one field.

---

## Support and contact

PolySwarm Customer Success — customersuccess@polyswarm.io

For Sentinel and Logic Apps configuration questions, refer to the
[Microsoft Sentinel connector reference](https://learn.microsoft.com/connectors/azuresentinel/)
or your internal SIEM team.
