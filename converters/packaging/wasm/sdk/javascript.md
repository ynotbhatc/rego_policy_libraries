# JavaScript / TypeScript

```bash
npm install @open-policy-agent/opa-wasm
tar -xzf opa-compliance.tar.gz policy.wasm data.json
```

```js
import { loadPolicy } from "@open-policy-agent/opa-wasm";
import { readFileSync } from "node:fs";

const policy = await loadPolicy(readFileSync("policy.wasm"));
policy.setData(JSON.parse(readFileSync("data.json", "utf8")));

const input = { mas_trm: { online_financial_services: true, controls: { "9.1.5": true /* ... */ } } };
const [{ result }] = policy.evaluate(input, "mas_trm/main/compliance_report");
console.log(result.compliant, result.violation_count, result.chapters["9"].gaps);
```
