// Reusable prompt fragments for SIEM agent

template_string DatabaseSchema(
  database_name: string,
  siem_log_table_name: string,
  cdn_log_table_name: string
) #"
## Databases
**CRITICAL DATA MODEL CONSTRAINTS:**
- WAF table ({{ database_name }}.{{ siem_log_table_name }}) = **ATTACK EVENTS ONLY** (does not contain non-attack requests)
- CDN table ({{ database_name }}.{{ cdn_log_table_name }}) = **ALL REQUESTS** (both attack and non-attack)
- **JOIN capability**: These tables CAN be joined using `requestId = reqId` when you need to correlate specific request details
- **Prefer separate queries** for simple aggregations; use JOINs only when correlating specific request details across both tables is needed

### Available Tables

#### WAF (SIEM) logs table ({{ database_name }}.{{ siem_log_table_name }})
**CRITICAL: This table contains ONLY attack-triggered events. Normal/non-attack requests are NOT recorded here.**

##### Scalar Columns
|Column|Type|Description|Key Notes|
|--|--|--|--|
|timestamp|DateTime|Request timestamp||
|host|String|Request's `Host` header|MUST filter by this in all queries|
|clientIP|String|Client IP address||
|method|String|HTTP method||
|path|String|URL path (no query string)||
|query|String|Query string parameters|Rarely populated (0.2%)|
|status|UInt32|HTTP response status||
|attackTypes|Array(String)|High-level attack categories|Primary filter: `Bot`, `WAF`, `DoS`, `Reputation`, `Custom`, `Network Firewall` (only 6 broad categories, NOT specific rule identifiers—use `ruleTags` for those). **CAN contain multiple values** (e.g., `['Bot', 'WAF']` when a request triggers both bot and WAF rules).|
|appliedAction|String|WAF action taken|`monitor`, `deny`, `alert`, `allow`, `deny_custom_*`, `delay`, `slow`, `tarpit`, or `NULL`. **IMPORTANT**: `NULL` indicates historical data where the action was not recorded (this column was added later). `NULL` does NOT mean the request was allowed—it simply means no action was logged. When filtering for non-blocked events, use explicit action values like `alert` or `allow`, NOT `IS NULL`.|
|bot_type|String|Bot classification|`Unknown` (most common), `Customer`, `Akamai`|
|asn, city, country, regionCode, continent|String|Geo/network data|Use only explicit DB values, don't infer from IP/ASN|
|UA|String|User-Agent header|Easily spoofed, don't trust alone|
|bytes|UInt64|Response size||
|protocol, tls|String|HTTP/TLS versions||
|requestHeaders|Map(String, String)|All request headers|In WHERE: wrap with `assumeNotNull(requestHeaders['key'])`|
|requestId|String|Request ID|Useful for tracing individual requests|

##### Array Columns (Rule Information)
**IMPORTANT**: All `Array(String)` columns (including `attackTypes` above and the 5 rule arrays below) can contain **multiple elements**. Never assume any array column always has exactly 1 element. When using `ARRAY JOIN`, each element expands into a separate row—if an array has 3 elements, one original row becomes 3 rows, which inflates `count()` results.

**These 5 arrays have identical length with 1:1 index correspondence**

Each index represents one triggered rule: `ruleMessages[i] ↔ ruleSelectors[i] ↔ ruleData[i] ↔ ruleTags[i] ↔ rules[i]`

|Column|Type|Description|Empty When|Populated When|
|--|--|--|--|--|
|ruleMessages|Array(String)|Human-readable rule descriptions|Never empty|Always populated|
|ruleSelectors|Array(String)|WHERE payload was found|Bot behavioral rules, PENALTYBOX, REPUTATION, rate limiting|Attack payloads detected in specific locations (e.g., `REQUEST_FILENAME_RAW`, `ARGS:param`)|
|ruleData|Array(String)|Actual attack payload substrings or metadata|PENALTYBOX/REPUTATION (historical), some bot rules|Attack payloads, bot IDs, anomaly scores, rate data|
|ruleTags|Array(String)|Technical rule identifiers (hierarchical)|Never empty|Always populated (hierarchical names that evolve with updates). **DISTINCT from attackTypes**: `ruleTags` are specific rule IDs (e.g., `OWASP/SQL-INJECTION`, `BOT/IMPERSONATOR`), while `attackTypes` are only 6 broad categories.|
|rules|Array(String)|Numeric rule IDs or special identifiers|Never empty|Always populated|

#### CDN logs table ({{ database_name }}.{{ cdn_log_table_name }})
**CRITICAL: This table contains ALL requests (both attack and non-attack). Use this for total traffic analysis.**

##### Scalar Columns
|Column|Type|Description|Key Notes|
|--|--|--|--|
|cliIP|String|Client IP address|This field has the real client IP address|
|country|String|ISO 3166-1 alpha-2 country code for the client|Examples: `US`, `JP`|
|proto|String|Protocol and version used|Examples: `HTTP/3`, `HTTPS/1.1`|
|queryStr|String|Raw query string portion of the URL|May be empty|
|referer|String|HTTP `Referer` header|May be empty|
|reqHost|String|Host name|Use for host-level filtering if present|
|reqId|String|Request ID|Useful for tracing individual requests|
|reqMethod|String|HTTP method|e.g., `GET`, `POST`|
|reqPath|String|Request path without scheme/host|Combine with queryStr for full URL|
|reqTimeSec|DateTime64(3)|Request timestamp with milliseconds|2025-10-31 05:47:18.236000|
|statusCode|UInt32|HTTP response status|Standard HTTP codes|
|tlsVersion|String|TLS protocol version negotiated|e.g., `TLSv1.3`|
|xForwardedFor|String|Comma-separated proxies' IP chain||
"#

template_string WafDomainKnowledge() #"
## Key Concepts of Akamai WAF and CDN
- **WAF terminology in user questions**: The term "WAF" is often ambiguous in user questions. In this workflow, interpret "WAF" broadly to mean **all events in the WAF (SIEM) logs table**, NOT limited to `has(attackTypes, 'WAF')`. This includes Bot, Reputation, DoS, Custom, Network Firewall, and all other attack types. For example, "WAF security events" or "WAF logs" refers to the entire dataset of attack-triggered events, regardless of attackTypes value.
- **WAF logs record only rule-triggered events**, not total traffic
- **appliedAction** does NOT indicate severity (admins control this)
- **One row per request even with many triggered rules**: A single request that matches multiple WAF rules appears as a single log row; the 5 rule arrays hold each triggered rule. Row counts = request counts, not rule-trigger counts. Use ARRAY JOIN when you need per-rule statistics.
- **attackTypes vs ruleTags (DO NOT confuse these)**:
  - `attackTypes`: Only 6 broad categories (`Bot`, `WAF`, `DoS`, `Reputation`, `Custom`, `Network Firewall`) for initial filtering
  - `ruleTags`: Specific rule identifiers (dozens of values like `ASE/WEB_ATTACK/CMDI`, `AKAMAI/BOT/USER_BEHAVIOR`) for detailed analysis
  - **Analysis pattern**: Filter by `attackTypes` (broad) → Group by `ruleTags` (specific) → Examine `ruleMessages` (descriptions) / `ruleData` (payloads)
  - **All 5 rule arrays have identical length**: `ruleMessages[i] ↔ ruleSelectors[i] ↔ ruleData[i] ↔ ruleTags[i] ↔ rules[i]` (same index = same rule trigger)
- **appliedAction values**:
  - `alert`: Admin chose to log only (not block) for the time being due to false positive risk — NOT evidence of false positive
  - `deny`/`deny_custom_*`/`tarpit`: Blocked
  - `monitor`/`allow`: Bot Manager logging/allowing (often for good bots)
  - `delay`/`slow`: Bot Manager rate-limiting
- **Special ruleTags**:
  - `REPUTATION`: IP has attack history (may not have payload in current request)
  - `PENALTYBOX`: Previously detected client, flagged for 10 minutes (may not have current payload)
  - `BOT`: Bot Manager detection (may be good bots like Google crawler)
  - **CRITICAL**: When filtering by ruleTags, always use the complete hierarchical name from the available ruleTags list (e.g., `AKAMAI/WAF/PENALTYBOX`, NOT partial matches like `PENALTYBOX`)
- **Request ID**:
  - Both WAF (`requestId`) and CDN (`reqId`) tables contain request IDs that can be used to JOIN the tables
  - Use for correlating attack events with their CDN delivery metadata (protocol version, geographic location, TLS details, etc.)
  - Example JOIN: `FROM waf_table AS waf JOIN cdn_table AS cdn ON waf.requestId = cdn.reqId`

### Array Field Relationships
- **All 5 rule arrays have identical length**: Same index across arrays = same triggered rule
- **ruleTags first, details second**: Filter by specific `ruleTags`, then examine `ruleMessages`/`ruleData` for specifics
- **Empty ruleSelectors/ruleData semantics**:
  - `ruleSelectors = ''`: Behavioral detection (bot rules), historical flagging (PENALTYBOX), IP reputation
  - `ruleData = ''`: PENALTYBOX/REPUTATION (current request may be clean), some bot behavioral rules
  - Both populated: Actual attack payload with location (critical for forensic analysis)
- **Multi-rule events are common**: Single request can trigger 5-15 rules (bot behavioral checks, attack + anomaly score, PENALTYBOX + current attack)

### WAF Scoring Model and Risk Groups

Akamai WAF uses a **scoring model** where each rule (signature) has an associated score. When the aggregated score for a request exceeds the threshold for a **risk group** (e.g., Local File Inclusion, Bot Browser Impersonator), an action is triggered.

**CRITICAL: Array structure depends on `length(rules)`:**

**When `length(rules) > 1`** (multi-rule with risk group):
- **All elements EXCEPT the last** = individual triggered rules
- **The LAST element** = risk group aggregate information
- Example: `rules = ['3000508', 'LFI-ANOMALY']`
  - `rules[1]` = individual rule ID `3000508`
  - `rules[2]` = risk group `LFI-ANOMALY`
- The risk group's `ruleData` contains scoring metadata: `Vector Score: 1000, Group Threshold: 4, Triggered Rules: 3000508, ...`

**When `length(rules) = 1`** (single rule, no risk group):
- The single element IS the rule itself (no aggregate)
- Example: `rules = ['BOT-60242435']` - this is a direct rule, not a risk group
- These are typically: custom bot rules, unknown bot detection, reputation rules

**Examples from actual data:**
| requestId | length(rules) | rules | Interpretation |
|-----------|---------------|-------|----------------|
| 31093224 | 2 | `['3000508', 'LFI-ANOMALY']` | Rule 3000508 triggered LFI risk group |
| d7e5ecc | 12 | `['3904000', ..., 'BOT-BROWSER-IMPERSONATOR']` | 11 bot rules triggered Browser Impersonator risk group |
| 67e48168 | 1 | `['BOT-60242435']` | Single custom bot rule (no risk group) |
| 7059598 | 1 | `['REP_3119810']` | Single reputation rule (no risk group) |

**Analysis implications:**
- To count **individual rule triggers**: Use `arraySlice(rules, 1, length(rules) - 1)` when `length(rules) > 1`
- To identify **which risk groups were triggered**: Extract last element when `length(rules) > 1`

**Risk group `ruleData` interpretation by attackTypes (after ARRAY JOIN):**

**IMPORTANT**: `attackTypes` is an array that **can contain multiple values** (e.g., `['Bot', 'WAF']` when a request triggers both bot and WAF rules). When you `ARRAY JOIN attackTypes AS attackType`, a single request with `attackTypes = ['Bot', 'WAF']` expands into **2 rows**—one with `attackType = 'Bot'` and one with `attackType = 'WAF'`. Be aware of this expansion when using `count()` or other aggregations after ARRAY JOIN on `attackTypes`.

For each expanded `attackType` element:
- `'WAF'` → ruleData contains scoring metadata (Vector Score, Threshold, etc.) but is **NOT useful for analysis** - ignore it
- `'Bot'` → ruleData contains the **bot identifier** (e.g., `Bot_242D2FFE2B4BBF3E0E602CF38DA60674`) - useful for tracking specific bots
- `'Reputation'` → ruleData contains **IP reputation score** (e.g., `SCANTL=10`) - useful for severity assessment
- Other values → ruleData is **NOT useful for analysis** - ignore it
"#

template_string SqlRequirements(
  database_name: string,
  siem_log_table_name: string,
  cdn_log_table_name: string
) #"
## SQL Query Requirements

SQL MUST be in **ClickHouse dialect** and **single-line format** (no `\\n` escapes or line breaks).

---

### 1. Core Principles

#### 1.1 Immediate Executability
- **NO placeholders or template values**: Every query MUST be executable as-is without manual edits
- **NO runtime substitution**: All values must be concrete

#### 1.2 Query Simplicity
- **One query = one purpose**: For multiple requirements (e.g., "find top IP AND list its paths"), create SEPARATE queries

---

### 2. Required Filters (MUST include in every query)

#### 2.1 Host Filter
- **WAF table**: `WHERE host IN (...)` or `WHERE host = '...'`
- **CDN table**: `WHERE reqHost IN (...)` or `WHERE reqHost = '...'`
- To query all hosts intentionally: `WHERE host LIKE '%'` or `WHERE reqHost LIKE '%'`
- Prefer single-host queries; use `GROUP BY host` only for cross-host comparison

#### 2.2 Time Range Filter
**CRITICAL: Time filter is REQUIRED for every query.**

- **WAF table**: Filter `timestamp` → `WHERE timestamp BETWEEN start AND end`
- **CDN table**: Filter `reqTimeSec` → `WHERE reqTimeSec BETWEEN start AND end`
- **JOIN queries**: MUST filter BOTH tables
  ```sql
  WHERE waf.timestamp BETWEEN start AND end AND cdn.reqTimeSec BETWEEN start AND end
  ```
- Max 90 days range, upper boundary <= now()
- DateTime literals: `parseDateTimeBestEffort('YYYY-MM-DDTHH:MM:SSZ')`

---

### 3. ARRAY JOIN Syntax

#### 3.1 Basic Syntax (CRITICAL)
- ARRAY JOIN MUST come immediately after FROM, BEFORE WHERE
- Pass array column directly (NEVER wrap with `arrayJoin()` function)
- **Row expansion**: ARRAY JOIN expands each array element into a separate row. An array with N elements produces N rows from 1 original row. **Do NOT assume any `Array(String)` column always has exactly 1 element**—all array columns can contain multiple elements, which means `count()` after ARRAY JOIN counts expanded rows, not original requests.
- Example: `SELECT ruleTag, count() FROM {{ database_name }}.{{ siem_log_table_name }} ARRAY JOIN ruleTags AS ruleTag WHERE host = '...' GROUP BY ruleTag`

#### 3.2 Multiple ARRAY JOIN
- **Parallel expansion**: ONLY the 5 rule arrays (`ruleMessages`, `ruleSelectors`, `ruleData`, `ruleTags`, `rules`) have 1:1 index correspondence and can be expanded together
- **WARNING**: `attackTypes` has different length than rule arrays—do NOT use parallel ARRAY JOIN with it
- **Different-length arrays**: Run separate queries for each array

#### 3.3 Scoring Model Handling
When `length(rules) > 1`: last element = risk group, others = individual rules. When `length(rules) = 1`: no risk group.
- Extract individual rules: `arraySlice(rules, 1, if(length(rules) > 1, length(rules) - 1, length(rules)))`
- Extract risk group: `if(length(rules) > 1, rules[length(rules)], NULL)`

#### 3.4 Array Operations with GROUP BY (CRITICAL)
- `arrayDistinct()`, `arrayUnique()` are NOT aggregate functions—must be wrapped in a true aggregate
- **To count unique values**: Use `groupUniqArray()` to collect unique values across grouped rows
- Example: `SELECT clientIP, length(groupUniqArray(attackType)) AS unique_attack_count FROM {{ database_name }}.{{ siem_log_table_name }} ARRAY JOIN attackTypes AS attackType GROUP BY clientIP`

#### 3.5 NEVER Mix count() with arrayJoin() in SELECT Clause (CRITICAL)
- **PROHIBITED**: Using `arrayJoin()` in SELECT clause causes implicit row expansion, making `count()` inaccurate
- **Example problem**: `SELECT count(), arrayJoin(attackTypes) FROM ...` will count expanded rows, not original rows
- **Solution**: Use separate queries—one for row counts, another for unique array elements with `groupUniqArray()`

---

### 4. Query Pattern Guidelines

#### 4.1 Handling Complex Aggregations

**PRIMARY STRATEGY: Multi-round investigation** (RECOMMENDED)
- This architecture is designed for incremental analysis across multiple rounds
- Run simple queries first → examine results → generate follow-up queries with discovered values
- **Common pattern**: "Find top X" → "Analyze X in detail"
  - Round 1: `SELECT clientIP, count() AS cnt FROM ... GROUP BY clientIP ORDER BY cnt DESC LIMIT 10`
  - Round 2: `SELECT path, count() FROM ... WHERE clientIP IN ('1.2.3.4', '5.6.7.8', ...) GROUP BY path`
- **This is the PREFERRED approach** - it's clearer, more maintainable, and allows adaptive investigation

**ALTERNATIVE: ClickHouse aggregate functions** (for single-round calculations)
- Average of counts: `arrayAvg(groupArray(cnt))`
- Top-1 per group: `argMax(value, metric)`
- Use when the calculation is simple and doesn't require examining intermediate results

**PROHIBITED patterns**:
- Subqueries: `IN (SELECT ...)` — use multi-round investigation instead
- CTEs: `WITH ... AS (SELECT ...)` — use multi-round investigation instead
- Placeholders in SQL: `WHERE ip = 'REPLACE_WITH_VALUE'` — will be executed literally

#### 4.2 Array Transformations Without Lambdas

**Supported patterns for array operations:**
- **Filtering array elements**: Use `ARRAY JOIN` with `WHERE` clause
- **Aggregating across arrays**: Use `groupUniqArray()` or `groupArray()`
- **Conditional aggregation**: Use `GROUP BY` with standard aggregation functions

**Note**: Lambda expressions (`arrayMap(x -> ...)`, `arrayFilter(x -> ...)`) are PROHIBITED. Use the patterns above instead.

---

### 5. Table JOINs (WAF ↔ CDN)

- Join key: `{{ database_name }}.{{ siem_log_table_name }}.requestId = {{ database_name }}.{{ cdn_log_table_name }}.reqId`
- **Prefer separate queries** for simple aggregations; use JOINs only when correlating specific request details
- JOIN conditions: Only equality (`=`), no range operators. For time-based joins: use `WHERE` or `ASOF JOIN`
- **Time filters**: MUST include time filters for BOTH tables (see section 2.2)

### 6. Syntax Reference

| Category | Syntax |
|----------|--------|
| Aggregation | All SELECT/HAVING columns must be in GROUP BY or wrapped in aggregate. Alias pattern: `any(city) AS any_city` |
| Arrays | `length(array)`, `empty(array) = 1`, `has()`, `arrayElement()`, `indexOf()` |
| Maps | In WHERE: `assumeNotNull(map['key'])`. Check existence: `mapContains(map, 'key')` |
| arrayZip | Returns tuples. Access via `.1`, `.2`, etc. |
| Window functions | Use snake_case: `row_number()`, `dense_rank()`, `ntile()` |

---

### 7. Type Casting (CRITICAL for if() expressions)

**Problem**: `length()` returns `UInt64`, but `length() - 1` returns `Int64`. Mixing these in `if()` causes `NO_COMMON_TYPE` error.
**Solution**: Use explicit `toUInt64()` cast to ensure both branches have the same type.
**Examples:**
```sql
-- For counting individual rules (excluding risk group):
SELECT
  if(length(rules) > 1, toUInt64(length(rules) - 1), length(rules)) AS individual_rule_count,
  count() AS cnt
FROM table
WHERE individual_rule_count >= 5
GROUP BY individual_rule_count
```
"#

template_string CalcTagRequirements() #"
**CRITICAL - LLMs MUST NEVER perform arithmetic calculations directly**: You MUST delegate ALL calculations to either SQL or `<calc>` tags. Never attempt to compute percentages, ratios, sums, or any mathematical operations in your response text.

**When to use SQL-level calculations**: Use SQL for calculations ONLY when they are simple and contained within a single query:
- Basic aggregations: `count()`, `sum()`, `avg()`, `min()`, `max()`
- Percentage within same GROUP BY: `count() * 100.0 / sum(count()) OVER ()`
- Simple arithmetic on columns in the same row: `bytes / 1024`

**When to use `<calc>` tags**: Use `<calc>` tags for any calculation that would complicate the SQL:
- Calculations across different query results
- Ratios where numerator and denominator come from separate queries
- Any calculation that would require adding JOINs or subqueries to an otherwise simple query
- Derived metrics that span multiple data sources

**Default guidance**: When in doubt, keep SQL queries simple and use `<calc>` tags for post-processing. A working simple query + `<calc>` tag is better than a failing complex query.

`<calc>` Tag Format
```
<calc formula="human-readable description" expr="mathematical expression" precision="decimal places" />
```

**Attributes (ALL REQUIRED, in this order):**
- `formula`: Human-readable description of what is being calculated (for traceability and hallucination prevention). Use square brackets for variable names (e.g., `[attack count from 1.2.3.4] / [total traffic]`).
- `expr`: Mathematical expression using basic operators (`+`, `-`, `*`, `/`, `^`, `()`) and numeric values only
- `precision`: Number of decimal places in result (0 for integers)

**Examples:**
- Percentage: `<calc formula="[attack traffic from 1.2.3.4] / [total traffic]" expr="15234 / 892301 * 100" precision="2" />`
- Ratio: `<calc formula="[blocked requests] / [monitored requests]" expr="5000 / 200" precision="1" />`
- Sum across queries: `<calc formula="[WAF attacks] + [Bot attacks] + [DoS attacks]" expr="1500 + 2300 + 450" precision="0" />`

**When to use `<calc>` tags:**
- Cross-query calculations (values from different query results)
- Derived metrics not computable in a single SQL query
- Percentage/ratio calculations when the denominator comes from a different query

**When NOT to use `<calc>` tags:**
- Values already computed by SQL (use `<fact>` tags instead)
- Simple reporting of query results (use `<fact>` tags instead)
"#
