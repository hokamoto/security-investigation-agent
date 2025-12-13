# Security Investigation Agent for Akamai SIEM/CDN Logs

A multi-round investigation agent for Akamai WAF (SIEM) and CDN (DataStream 2) logs, stored in TrafficPeak (a managed data platform with a ClickHouse-compatible interface), that turns natural-language security questions into iterative security investigations, delivering evidence-backed answers.

## About This Program

**Disclaimer**: This project is not an official Akamai product and is not supported or endorsed by Akamai Technologies. It is provided as-is without warranty of any kind.

This agent serves as an experimental proof-of-concept exploring whether context engineering techniques can enable small LLMs running on consumer-grade hardware (16GB VRAM) to perform complex security log analysis tasks.

It is not intended for production deployment at this stage. As an experimental system, it deliberately delegates workflow recovery to the LLM even in scenarios where deterministic code (such as SQL error correction) would be more reliable, prioritizing demonstration of LLM reasoning capabilities over production robustness.

## Architecture Diagram

![Architecture diagram of this program](architecture-diagram.png)

## Key Technical Features

**Runs on Small LLMs (20B Parameters, 16GB VRAM)**
This agent achieves reliable SQL generation and investigation planning using `openai/gpt-oss-20b`, a 20-billion parameter model that requires only 16GB GPU memory. The key is an incremental planning architecture: the workflow breaks investigations into simple incremental rounds. Each round generates 1-5 straightforward SQL queries, synthesizes results, then decides if follow-up queries are needed. This iterative approach keeps individual LLM tasks simple enough for smaller models while enabling deep investigations through re-planning.

**Private Deployment for Sensitive Security Data**
All processing can be deployed to run within your own infrastructure via vLLM under your control. No security logs, attack data, or investigation results need to leave your network boundary, and WAF logs containing IP addresses, attack payloads, and blocked requests can remain on infrastructure you operate. This reduces the risk of sending sensitive data to third-party APIs.

**Domain-Specific Semantics Encoded in Prompts**
Akamai WAF logs appear simple, but without explicit security semantics, LLMs produce plausible-yet-wrong answers by treating them like ordinary web application databases. Two examples of systematic misinterpretation:

1. **Monitor mode as "attack success"**: Asked "how many attacks succeeded?", an LLM counts `appliedAction='monitor'` as successful attacks (not blocked = breach). Reality: monitor mode is a staged deployment strategy where new WAF rules observe traffic before blocking, validating false positive rates. The LLM conflates "risk management decision" with "attack outcome."

2. **Reputation blocks as false positives**: LLMs dismiss reputation-based blocking as false alarms because `ruleData` arrays are empty (no payload visible = no evidence). Reality: if IP `203.0.113.5` attacked at high frequency yesterday, Akamai may block it today regardless of current payload. Empty `ruleData` is expected for historical-behavior-based rules (`PENALTYBOX`, `REPUTATION`), not a quality issue.

Without explicit domain knowledge, even large LLMs fail at security log analysis, generating syntactically correct SQL that produces analytically wrong answers. This agent addresses this through structured prompts that encode domain rules: which fields mean what in security context, how detection mechanisms differ (payload-based vs. reputation-based), etc. No model fine-tuning is needed, but without rigorous prompt engineering, small LLMs cannot perform complex analysis, and even large LLMs produce confident nonsense.

**Calculator Tool for Arithmetic Prevents LLM Math Errors**
LLMs struggle with arithmetic (e.g., calculating percentage increases or rate comparisons) because they are token prediction models that learn numerical patterns from training data rather than executing symbolic computation rules. This agent externalizes all math to a `calculator` tool: when synthesis requires computing "211 / 712 * 100", the LLM invokes `calculator(expression="211 / 712 * 100", decimal_places=1)` and receives "29.6" as a verified result. The LLM never performs mental math; it only decides which calculations are needed.

**Adaptive Query Rewriting Prevents Context Overflow**
Security investigations often generate massive result sets (tens of thousands of rows), but naive approaches either truncate data (losing critical patterns) or exceed LLM context windows. This agent detects result overflow automatically before retrieving all data, then delegates statistical rewriting to the LLM itself. The LLM transforms the original query into 1-3 targeted summary queries, preserving equivalent analytical insight while fitting comfortably in context.

**Iterative Investigation Instead of One-Shot Generation**
Traditional text-to-SQL systems fail on complex security questions because they must predict all necessary queries upfront. This agent uses an incremental planning architecture: it starts with simple baseline queries (e.g., "get top attacking IPs"), synthesizes results to identify anomalies, then generates targeted follow-up queries using discovered values (e.g., "analyze all requests from 203.0.113.5"). 

**LLM-as-a-Judge for Regression Testing**
This agent validates analysis quality through LLM-as-a-Judge evaluation rather than traditional heuristics. When prompts or workflow logic change, automated tests execute the agent against pre-defined questions with known answers, then an LLM grader compares the agent's response to expected results and grading criteria.

**<num> Tags Prevent Numeric Hallucination**
LLMs may fabricate or misremember numbers from query results. This agent requires that all numeric claims use <num> tags that explicitly cite the data source and value, making hallucinated numbers detectable.

## Agent Workflow

1. **Plan**: LLM generates 1-5 simple SQL queries with answerability checks, validates against domain rules (time windows, host scope), and stores the investigation plan.
2. **Execute**: Runs queries sequentially with validation and one LLM-guided repair attempt on errors. Detects overflow and invokes statistical summary rewrite if the row limit is exceeded. Stores full results or summaries in execution history.
3. **Synthesize**: LLM analyzes all query results across all rounds, generates answer with <num> tags for numeric claims, assigns confidence level, and enumerates data gaps.
4. **Re-plan Decision**: LLM evaluates if additional investigation is needed by checking answer completeness, confidence, and remaining questions. Routes to re-planning if needed or ends the workflow.
5. **Re-plan**: Generates follow-up queries using specific values from previous results (e.g., discovered IP "203.0.113.5" → WHERE clientIP = '203.0.113.5'). Returns to execution step.

![Agent Workflow](workflow.png)

## Setup
- Copy `config.yaml.example` to `config.yaml` and fill in ClickHouse and vLLM endpoints plus credentials.
- Ensure Python with `uv` (or your preferred runner) is available; dependencies are managed via `pyproject.toml`.

## Usage
- CLI question: `uv run -m siem_agent "How many SQL injection attacks occurred yesterday?"`
- Interactive: `uv run -m siem_agent` and enter your question when prompted.

## Example Interaction

This example demonstrates the agent's incremental planning and re-planning capabilities. The user asks a complex question that requires multiple investigation rounds.

### User Question

> What types of attack techniques did the IP address that conducted the most application-layer attacks over the past week use? Also, what were the payloads used in those attacks? Did that IP address also send any non-attack requests?

---

### Initial Investigation

**Planning**

The agent generates an investigation plan to identify the most active attacker:

```
Answerable: True | Complexity: simple
Rationale: Query WAF logs to identify the client IP with the highest application-layer
attack count over the last 7 days.
```

**Execution**

Query 1: *Find the client IP that triggered the most application-layer attacks*

```sql
SELECT clientIP, count() AS attack_count
FROM akamai.siem
ARRAY JOIN ruleTags AS tag
WHERE host IN ('api.example.com', 'shop.example.com', 'cdn.example.com' /* ... */)
AND timestamp >= now() - INTERVAL 7 DAY
AND tag LIKE 'ASE/WEB_ATTACK/%'
GROUP BY clientIP
ORDER BY attack_count DESC
LIMIT 1
```

Results:
```
clientIP      | attack_count
--------------+-------------
203.0.113.42  | 106
```

**Synthesis**

The agent identifies the top attacker but recognizes that the answer is incomplete:

> IP address 203.0.113.42 conducted the most application-layer attacks (106 events) in the last 7 days. However, the specific attack techniques, payloads, and whether it sent non-attack requests require additional queries.

**Re-planning Decision**

```
Decision: Additional investigation needed

Rationale: The current answer identifies the top IP but does not provide the requested
attack techniques, payloads, or evidence of non-attack traffic. To fully answer the
user's question, we must query the WAF logs for ruleTags and ruleData for that IP and
query the CDN logs to determine total requests from the same IP.
```

---

### Follow-up Investigation

**Re-planning**

The agent generates a new investigation plan that uses the discovered IP address (`203.0.113.42`) in follow-up queries:

```
Answerable: True | Complexity: moderate
Rationale: The prior analysis identified IP 203.0.113.42 as the top attacker over the
past week but lacked details on attack techniques (ruleTags), payloads (ruleData), and
whether the IP also sent non-attack traffic. The new queries retrieve per-rule details
for that IP, count non-attack requests, and provide a total request count for context.
```

**Execution**

Query 2: *List distinct application-layer attack technique tags used by the top IP*

```sql
SELECT tag, count() AS cnt
FROM akamai.siem
ARRAY JOIN ruleTags AS tag
WHERE clientIP = '203.0.113.42'
AND timestamp >= now() - INTERVAL 7 DAY
AND host IN ('api.example.com', 'shop.example.com', 'cdn.example.com' /* ... */)
AND tag LIKE 'ASE/WEB_ATTACK/%'
GROUP BY tag
ORDER BY cnt DESC
```

Results:
```
tag                | cnt
-------------------+----
ASE/WEB_ATTACK/LFI | 106
```

Query 3: *Retrieve the payload substrings that triggered the WAF for the top IP*

```sql
SELECT payload, count() AS cnt
FROM akamai.siem
ARRAY JOIN ruleData AS payload
WHERE clientIP = '203.0.113.42'
AND timestamp >= now() - INTERVAL 7 DAY
AND host IN ('api.example.com', 'shop.example.com', 'cdn.example.com' /* ... */)
AND payload != ''
GROUP BY payload
ORDER BY cnt DESC
```

Results (top 15 rows shown):
```
payload                     | cnt
----------------------------+----
Vector Score: 1000 ...      | 34
DOSATCK=10                  | 17
Vector Score: 5 ...         | 16
/.env                       | 3
/.env.bak                   | 2
/.env.local                 | 1
/.env.prod                  | 1
/.env.staging               | 1
/api/.env                   | 1
/app/.env                   | 1
/admin/.env                 | 1
/backend/.env               | 1
/mailer/.env                | 1
/wp-config.php              | 1
/wp-config.php.old          | 1
... (49 more configuration file paths)
```

Query 4: *Count total requests from the top IP in the CDN logs*

```sql
SELECT count() AS total_requests
FROM akamai.logs
WHERE cliIP = '203.0.113.42'
AND reqTimeSec >= now() - INTERVAL 7 DAY
AND reqHost IN ('api.example.com', 'shop.example.com', 'cdn.example.com' /* ... */)
```

Results:
```
total_requests
--------------
423
```

Query 5: *Show the distribution of attackTypes for the top IP*

```sql
SELECT attackTypes, count() AS cnt
FROM akamai.siem
WHERE clientIP = '203.0.113.42'
AND timestamp >= now() - INTERVAL 7 DAY
AND host IN ('api.example.com', 'shop.example.com', 'cdn.example.com' /* ... */)
GROUP BY attackTypes
ORDER BY cnt DESC
```

Results:
```
attackTypes | cnt
------------+----
['WAF']     | 386
['DoS']     | 20
```

**Synthesis**

The agent now has complete data to answer all parts of the question:

> The top attacker in the last 7 days was IP **203.0.113.42**, which generated 106 application-layer attacks. All of those attacks were classified as **LFI (Local File Inclusion)** – the only ruleTag that appeared for this IP in the WAF logs was ASE/WEB_ATTACK/LFI.
>
> The payloads that triggered the WAF were primarily attempts to read sensitive configuration files. The most common payload strings included:
> * `/.env`, `/.env.bak`, `/.env.local`, `/.env.staging`, `/.env.prod`
> * `/api/.env`, `/app/.env`, `/admin/.env`, `/backend/.env`, `/mailer/.env`
> * `/wp-config.php`, `/wp-config.php.old`
> * And 49 other variations of configuration file paths
>
> In the CDN logs, the same IP made **423 requests** during the same period. Subtracting the 106 WAF-triggered attacks gives **317 non-attack requests**. Thus the IP did send a significant amount of legitimate traffic in addition to the LFI attempts.
>
> **Summary**: The top attacker used LFI techniques (ASE/WEB_ATTACK/LFI) with payloads attempting to read `.env`, `.htaccess`, and other configuration files. Non-attack traffic: yes – 317 requests out of 423 total (75% legitimate, 25% attacks).

**Re-planning Decision**

```
Decision: Investigation complete

Rationale: The answer fully addresses all parts of the user's question: it identifies
the top attacker, specifies that all application-layer attacks were LFI, lists the
payloads, and confirms that the IP also sent non-attack requests. No additional data or
clarification is required.
```

---

## Disclaimer and Legal Notices

This is an independent, unofficial, third-party tool.

- This project is **not an official Akamai product**.
- It is not supported, endorsed, or affiliated with Akamai Technologies, Inc.
- "Akamai", "TrafficPeak", and related product names are trademarks of Akamai Technologies, Inc.
- This tool is developed as a personal project by an individual and is provided as-is without warranty of any kind.
- Use of Akamai trademarks in this documentation is for descriptive purposes only, to indicate compatibility with Akamai products.
