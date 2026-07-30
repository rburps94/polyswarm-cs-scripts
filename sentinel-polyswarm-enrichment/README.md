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
4. Calls **two** PolySwarm endpoints per hash:
   - `GET /search/hash/{type}` — the primary lookup. Verdict, PolyScore, detection
     counts, the full per-engine assertion list, PolyUnite classification, PE
     metadata and a permalink.
   - `GET /search/metadata/query` — a best-effort secondary lookup that adds
     classification tags, normalised families and sandbox intelligence (CAPE and
     Triage scores, MITRE ATT&CK techniques).
5. Merges both records and posts a formatted comment to the incident — including an
   explicit "no result" comment when PolySwarm has never seen the artifact, so the
   analyst knows the lookup ran and what it found.

**Why two calls.** The two endpoints return genuinely different documents and neither
is a superset of the other:

| Field | `/search/hash/*` | `/search/metadata/query` |
| --- | --- | --- |
| Verdict (`result`), `permalink` | yes | no |
| PolyScore, detection counts | yes | yes |
| Per-engine assertions with engine names | yes — an **array**, enumerable | no — an **object keyed by engine name**, which Logic Apps cannot enumerate |
| PolyUnite family and labels | yes, under `metadata[]` | yes, at the record root |
| `imphash`, packer, PE detail | yes | yes |
| `tags[]`, `families[]` | no | yes |
| Sandbox scores, MITRE ATT&CK, ransom notes | no | yes |

Dropping the hash lookup would cost the named engine list — the multi-engine
corroboration that is the point of PolySwarm. Dropping the metadata lookup would cost
the sandbox and ATT&CK context. So the playbook does both, and the second call is
best-effort: if it fails, 429s or returns nothing, the comment is still posted using
the hash-lookup data alone.

The second call is contained in `Search_PolySwarm_artifact_metadata`. **Delete that
action and `Select_artifact_metadata_record` to halve the API calls per hash** — the
comment degrades cleanly, dropping only the tags, sandbox and ATT&CK lines.

Every field is optional in the output: lines are omitted rather than printed as `n/a`
when the underlying data is absent, so a sparse record still produces a clean comment.

### Example comment

Rendered from a live response for a LockBit/BlackMatter sample:

> **PolySwarm enrichment**
> Hash (SHA256): 5da5a1e3983982a92341953929d4c7726da65fe5125d264dd8932a870f2f154a
> Assessment: **Malicious** (PolyScore 0.9999)
> Detections: 6 malicious / 2 benign of 8 engines
> Malicious engines: Qihoo 360, SecondWrite, SecureAge, Lionic, DrWeb, Filseclab, Crowdstrike Falcon ML, NanoAV, ClamAV, SentinelOne Static ML, Ikarus
> Malware family: BlackMatter
> Labels: ransomware, trojan
> Tags: Ransomware, Trojan, PE32, Windows
> Sandbox-reported family: lockbit
> Sandbox scores: CAPE 8 / Triage 10
> MITRE ATT&CK: T1027, T1070.004, T1082, T1486, T1489, T1542.003, T1614.001
> File type: PE32 executable (GUI) Intel 80386, for MS Windows
> Imphash: 41fb8cb2943df6de998b35a9d28668e8
> Packer: AHTeam EP Protector 0.3 (fake PCGuard 4.03-4.15)
> First seen: 2023-02-26 | Last seen: 2026-07-09
> PolySwarm report: https://polyswarm.network/scan/results/file/5da5a1e…/75499664076494037

Note that the engine-reported families disagree (`Trojan-Ransom.LockBit`,
`Win.Ransomware.LockBitBlack`, `Trojan.Encoder.42541`, `Win32/Backdoor.ZAccess`) and the
sandbox says `lockbit` while PolyUnite normalises to `BlackMatter`. That divergence is
signal, not noise — it is why both the normalised family and the sandbox family are
shown rather than one being picked as authoritative.

### What it deliberately does not do

- It does not submit or upload files to PolySwarm — it only looks up artifacts PolySwarm has already seen.
- It does not write to a custom Log Analytics table (see [Extending](#extending) for why, and what to do instead).
- It does not enrich URL, IP or domain entities — only file hashes.

---

## Components

| Path | Purpose |
| --- | --- |
| `playbooks/polyswarm-enrich-hash-from-incident.json` | ARM template deploying the Logic App playbook plus its Sentinel API connection. This is the only file you need to deploy. |
| `custom-connector/polyswarm-connector-swagger.json` | Swagger 2.0 definition for the PolySwarm custom Logic Apps connector. Deployed independently of the playbook; see [The custom connector](#the-custom-connector). |

These are two separate deliverables that ship together. The **connector** turns the
PolySwarm v3 API into first-class Logic Apps actions so a security team can build
their own playbooks and automation rules against it. The **playbook** is a worked
reference showing one complete enrichment flow end to end.

The playbook deliberately calls PolySwarm with built-in **HTTP** actions rather than
through the connector. That keeps it self-contained — it deploys and runs with no
prerequisite connector resource — and lets it switch between the MD5, SHA1 and SHA256
endpoints at runtime, which a single connector operation cannot do. Teams that prefer
the connector's typed dynamic content can swap the HTTP action for the matching
operation; see the connector section for the trade-off.

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
GET /v3/search/metadata/query?query=artifact.sha256:<hash>&community=default&limit=1
```

### Response shapes

Both endpoints return the same envelope — `{ status, has_more, limit, result: [ … ] }` —
but `result[]` holds a **different document** in each. Both shapes below were verified
against live responses.

**`/search/hash/*` returns a scan instance**, with everything at the record root:

| Path | Used for |
| --- | --- |
| `result[0].polyscore` | PolyScore — **the assessment is derived from this**, against `PolySwarmMaliciousThreshold` |
| `result[0].detections.{malicious,benign,total}` | Detection summary |
| `result[0].assertions[]` → `.verdict`, `.engine.name` | Malicious engine list. `verdict` is `true`, `false` or **`null`** when an engine did not assert — the filter matches `true` only, so nulls are correctly excluded |
| `result[0].metadata[]` where `tool = "polyunite"` | `tool_metadata.malware_family`, `tool_metadata.labels[]` |
| `result[0].metadata[]` where `tool = "pefile"` | `tool_metadata.imphash`, `tool_metadata.peid` |
| `result[0].extended_type`, `.size`, `.first_seen`, `.last_seen`, `.permalink` | File and sighting detail |

**`/search/metadata/query` returns an artifact record**, nested differently:

| Path | Used for |
| --- | --- |
| `result[0].tags[]`, `result[0].families[]` | Classification tags, normalised families |
| `result[0].polyunite.{malware_family,labels}` | Family and labels (root-level here, not under `metadata[]`) |
| `result[0].triage_sandbox_v0.malware_family[]`, `.analysis.score` | Sandbox family and score |
| `result[0].cape_sandbox_v2.malscore`, `.ttp[]` | Sandbox score, MITRE ATT&CK |
| `result[0].scan.latest_scan.polyscore`, `result[0].scan.detections` | Fallbacks if the hash lookup is unavailable |
| `result[0].scan.latest_scan.assertions` | **Object keyed by engine name** — not enumerable, see below |

> **`result` is not a verdict — do not treat it as one.** Despite its name, and despite
> what earlier versions of this connector definition claimed, `result[0].result` tracks
> scan settlement, not maliciousness. A live scan of `https://polyswarm.io` returns
> `result: true` alongside `0` of `2` engines asserting malicious and a PolyScore of
> `0.33`. Reading it as a verdict marks known-good artifacts as Malicious. The playbook
> derives its assessment from PolyScore only, and carries the field as `scanSettled` in
> `Build_summary` so it cannot be mistaken for one.

All extraction is centralised in the `Build_summary` Compose action, where every value
`coalesce()`s across both records. If a field moves, that is the only action to edit —
the comment body reads exclusively from its output.

A hash PolySwarm has never seen returns HTTP `404` from the hash lookup, and `200`
with an empty `result[]` from the metadata query. The playbook's condition checks
`statusCode == 200 AND length(result) > 0`, so both are handled as a normal outcome
rather than a failure.

### Why engine names come from the hash lookup only

On artifact records, `scan.latest_scan.assertions` is an **object keyed by engine
name** (`{"ClamAV": {"assertion": "malicious"}, …}`), not an array. Logic Apps has no
expression to enumerate an object's dynamic keys, and the usual `xml()`/`xpath()`
workaround fails because engine names contain spaces (`Crowdstrike Falcon ML`,
`RedDrip APT Scanner - RAS`), which are invalid XML element names.

The hash lookup returns the same data as a proper array, so the playbook takes engine
names from there and never touches the keyed object. This is the main reason the hash
lookup is the primary call rather than the metadata query.

### Rate limits

- **PolySwarm:** community accounts are limited to 60 calls/hour; enterprise accounts to 1000 calls/second. **The playbook makes two calls per hash**, so a community key allows roughly 30 hashes per hour — not viable for a live workspace. Budget accordingly, or delete the secondary call.
- **Sentinel connector:** 600 calls per 60 seconds per connection.

The hash lookup retries 3 times with exponential backoff; the secondary metadata call
retries twice and is allowed to fail without blocking the comment.

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
   | `PolySwarmMaliciousThreshold` | Fallback PolyScore threshold, used only when the API returns no explicit verdict. Default `0.8`; at or above half that reports "Suspicious". A string, because ARM templates have no float parameter type. |

4. Deploy into the resource group holding your Sentinel workspace.

The template creates the Logic App **and** its Microsoft Sentinel API connection,
wired to the playbook's system-assigned managed identity.

> **Storing the key in Key Vault.** `PolySwarmApiKey` is a `securestring`, so it is
> masked in the portal and in run history (both HTTP actions are additionally marked
> with `secureData` on their inputs). To source it from Key Vault instead of typing it,
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
3. Open the incident and confirm the comment matches the example above.

To sanity-check the API independently of Sentinel:

```bash
curl -s -H "Authorization: $POLYSWARM_API_KEY" "https://api.polyswarm.network/v3/search/hash/sha256?hash=5da5a1e3983982a92341953929d4c7726da65fe5125d264dd8932a870f2f154a&community=default" | jq '.result[0] | {result, polyscore, detections, permalink, engines: [.assertions[] | select(.verdict == true) | .engine.name], polyunite: [.metadata[] | select(.tool == "polyunite") | .tool_metadata][0]}'
```

---

## The custom connector

`custom-connector/polyswarm-connector-swagger.json` wraps the PolySwarm v3 API as a
Logic Apps custom connector, so Sentinel playbooks, automation rules and Defender
XDR-triggered workflows can enrich an indicator inline as part of an automated
response — without anyone hand-writing HTTP actions and expressions.

| Operation | Endpoint | Purpose | Response typed |
| --- | --- | --- | --- |
| `EnrichSha256` | `/search/hash/sha256` | Verdict, PolyScore, per-engine assertions, PolyUnite family labelling | ✅ verified live |
| `EnrichSha1` / `EnrichMd5` | `/search/hash/{type}` | As above, for SHA1 and MD5 entities | ⚠️ inferred from SHA256 |
| `SearchUrl` | `/search/url` | URL enrichment | ❌ **not sampled** |
| `SearchIoc` | `/ioc/search` | SHA256 hashes associated with an IP, domain, TTP or imphash | ✅ verified live |
| `GetIocsForSha256` | `/ioc/sha256/{sha256}` | IPs, domains, TTPs and imphashes associated with a sample — corpus context for investigation expansion | ❌ **not sampled** |
| `SearchMetadata` | `/search/metadata/query` | Tags, families, sandbox scores, MITRE ATT&CK | ✅ verified live |

> **Two response schemas are unverified.** `SearchUrl` is provisionally typed as the
> scan-instance shape and `GetIocsForSha256` is left untyped. Both have correct request
> definitions and will work, but confirm each against a live response and type it
> before relying on designer dynamic content for those operations.

Note that the two IOC operations are **inverses of each other and do not share a
response shape**. `SearchIoc` returns a flat array of SHA256 strings (not objects);
`GetIocsForSha256` returns the indicators associated with one sample.

**`SearchIoc` results paginate, and volume is not a verdict.** A query for common
infrastructure — `8.8.8.8`, for instance — returns a full page with `has_more` set,
because a great deal of malware talks to public DNS. Treat the association as a pivot
lead, not as evidence the indicator is malicious, and page with the returned `offset`
token rather than assuming one call is the whole answer.

**File submission is intentionally not included.** PolySwarm's submission flow is
three steps, and the middle step uploads to a presigned S3 URL on a different host —
which a single Swagger document, pinned to one `host`, cannot express. It would also
need an explicit data-handling decision before being offered as a one-click action in
any regulated environment. If submission is required, it belongs in a playbook using
separate HTTP actions with an approval gate, not as a connector operation.

To use it:

1. Azure portal → **Logic Apps Custom Connector** → **Create**.
2. Import the OpenAPI file. `host` (`api.polyswarm.network`) and `basePath` (`/v3`) are already set.
3. Create a connection, supplying your API key as the `Authorization` value.
4. In the playbook, replace the `Search_PolySwarm_hash` HTTP action with the matching
   connector operation, and add the connector's connection to the `$connections`
   parameter block.

This is a designer convenience, not a functional upgrade. Because each hash type is a
separate operation, swapping to the connector means adding a `Switch` on
`Determine_hash_type` with one branch per operation.

---

## Extending

- **URL, IP and domain enrichment** — PolySwarm exposes `GET /v3/search/url` and
  `GET /v3/ioc/search?ip=…&domain=…`. The same playbook pattern applies against the
  `Url`, `Ip` and `DnsResolution` entity types.
- **Associated IOCs** — `GET /v3/ioc/sha256/{sha256}` returns IPs, domains, TTPs and
  imphashes tied to a sample. Prefer this over scraping
  `cape_sandbox_v2.network.tcp[].dst` from the artifact record — those addresses
  include sandbox-internal ranges and unrelated Windows telemetry endpoints, and are
  not safe to treat as IOCs without filtering.
- **Imphash pivoting** — the comment already surfaces `imphash`. Feeding it to
  `GET /v3/ioc/search?imphash=…` finds structurally related samples, which is a strong
  lead for campaign clustering.
- **ATT&CK-driven automation** — the record carries technique IDs. An automation rule
  could raise incident severity or add tactics as incident labels when the enrichment
  returns techniques your detections care about.
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
| Comment posted, but no Tags / Sandbox / ATT&CK lines | The secondary metadata call failed, was rate-limited, or returned nothing. Check `Search_PolySwarm_artifact_metadata` in the run history — it is allowed to fail by design. |
| "No PolySwarm result" with status 401 | Bad or missing API key. |
| "No PolySwarm result" with status 429 | PolySwarm rate limit reached. Remember it is two calls per hash. |
| "No PolySwarm result" with status 404 | The artifact has never been scanned in that community. A normal outcome, not an error. |
| Comment shows `Malware family: n/a` | No PolyUnite classification and no `families[]`. Common for benign or rarely-seen files. |
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
- `Filter_malicious_assertions` reads `assertions` from the **hash-lookup record
  only**. Do not repoint it at the metadata record: that field is a keyed object
  there, and `Filter array` fails on a non-array input.
- All field extraction lives in `Build_summary`. Add new fields there, then reference
  them from the comment body — not the other way round.

---

## Support and contact

PolySwarm Customer Success — customersuccess@polyswarm.io

For Sentinel and Logic Apps configuration questions, refer to the
[Microsoft Sentinel connector reference](https://learn.microsoft.com/connectors/azuresentinel/)
or your internal SIEM team.
