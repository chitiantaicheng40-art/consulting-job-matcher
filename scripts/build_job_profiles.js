/**
 * Build AI job profiles from jobs_cache.json.
 * Output: job_profiles_cache.json
 *
 * Usage:
 *   node scripts/build_job_profiles.js
 *   node scripts/build_job_profiles.js --limit=50
 */

try {
  require("dotenv").config();
} catch (_) {}

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const OpenAI = require("openai");

const ROOT = path.join(__dirname, "..");
const JOBS_CACHE_PATH = path.join(ROOT, "jobs_cache.json");
const OUT_PATH = path.join(ROOT, "job_profiles_cache.json");

const MODEL = process.env.OPENAI_JOB_PROFILE_MODEL || process.env.OPENAI_PROFILE_MODEL || "gpt-4o-mini";
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

function safeText(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(safeText).join(" ");
  if (typeof value === "object") {
    try {
      return Object.entries(value)
        .filter(([k]) => !["html", "rawHtml"].includes(k))
        .map(([k, v]) => `${k}: ${safeText(v)}`)
        .join("\n");
    } catch (_) {
      return "";
    }
  }
  return String(value);
}

function loadJobs() {
  if (!fs.existsSync(JOBS_CACHE_PATH)) {
    throw new Error(`jobs_cache.json not found: ${JOBS_CACHE_PATH}`);
  }

  const raw = JSON.parse(fs.readFileSync(JOBS_CACHE_PATH, "utf8"));

  if (Array.isArray(raw)) return raw;
  if (Array.isArray(raw.jobs)) return raw.jobs;
  if (Array.isArray(raw.data)) return raw.data;
  if (raw.cache && Array.isArray(raw.cache.jobs)) return raw.cache.jobs;

  throw new Error("Could not find jobs array in jobs_cache.json");
}

function loadExistingProfiles() {
  if (!fs.existsSync(OUT_PATH)) return {};
  try {
    return JSON.parse(fs.readFileSync(OUT_PATH, "utf8"));
  } catch (_) {
    return {};
  }
}

function jobKey(job) {
  const company = job.company || job.companyName || "";
  const title = job.title || job.jobTitle || job.name || "";
  const url = job.url || job.link || job.detailUrl || "";
  const id = job.id || job.jobId || job.code || job.jobCode || "";

  const base = `${company}||${title}||${url}||${id}`;
  return crypto.createHash("sha1").update(base).digest("hex");
}

function jobDisplayName(job) {
  const company = job.company || job.companyName || "";
  const title = job.title || job.jobTitle || job.name || "";
  return `${company} / ${title}`.replace(/^\s*\/\s*/, "").trim() || "Unknown job";
}

function extractJson(text) {
  const s = String(text || "").trim();

  try {
    return JSON.parse(s);
  } catch (_) {}

  const fenced = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenced) {
    try {
      return JSON.parse(fenced[1]);
    } catch (_) {}
  }

  const first = s.indexOf("{");
  const last = s.lastIndexOf("}");
  if (first >= 0 && last > first) {
    try {
      return JSON.parse(s.slice(first, last + 1));
    } catch (_) {}
  }

  return null;
}

function normalizeProfile(profile, job) {
  const p = profile && typeof profile === "object" ? profile : {};

  const categories = p.role_categories || p.roleCategories || [];
  const roleCategories = Array.isArray(categories)
    ? categories.filter(Boolean)
    : Object.entries(categories)
        .filter(([_, v]) => v === true || (v && v.match === true))
        .map(([k]) => k);

  const coreMust = Array.isArray(p.core_must) ? p.core_must : Array.isArray(p.coreMust) ? p.coreMust : [];
  const subMust = Array.isArray(p.sub_must) ? p.sub_must : Array.isArray(p.subMust) ? p.subMust : [];
  const preferred = Array.isArray(p.preferred) ? p.preferred : [];
  const disqualifiers = Array.isArray(p.disqualifiers) ? p.disqualifiers : [];

  return {
    jobKey: jobKey(job),
    displayName: jobDisplayName(job),
    company: job.company || job.companyName || "",
    title: job.title || job.jobTitle || job.name || "",
    url: job.url || job.link || job.detailUrl || "",
    primaryRoleCategory: p.primary_role_category || p.primaryRoleCategory || roleCategories[0] || "GENERAL",
    roleCategories,
    summary: p.summary || "",
    coreMust,
    subMust,
    preferred,
    disqualifiers,
    productRequirements: p.product_requirements || p.productRequirements || {},
    educationRequirement: p.education_requirement || p.educationRequirement || null,
    locationRequirement: p.location_requirement || p.locationRequirement || null,
    evidenceNotes: Array.isArray(p.evidence_notes) ? p.evidence_notes : [],
    generatedAt: new Date().toISOString()
  };
}

async function buildJobProfile(job) {
  const text = safeText(job).slice(0, 14000);

  const systemPrompt = `
あなたは人材紹介会社のRA向けに、求人票を厳密に構造化するアナリストです。
目的は、候補者とのマッチング精度を上げるために、求人のCore must、Sub must、Preferred、Disqualifierを分けることです。

絶対ルール：
- 出力はJSONのみ。Markdown禁止。
- 求人票に根拠がない条件は作らない。
- 必須要件と歓迎要件を混ぜない。
- Core mustは、その求人で外すと提案困難な中核条件だけにする。
- Sub mustは、必須に近いがCore mustほどではない条件。
- Preferredは歓迎条件。
- Disqualifierは、欠けると大きく減点/対象外寄りになる条件。
- 「大卒以上」「英語力」などは原則Sub must。職種経験や製品導入経験の方をCore mustにする。
- SAP求人のCore mustは、SAP導入、SAP S/4HANA、ABAP、Basis、Fiori、BTP、SAPモジュール、要件定義、移行、カットオーバーなど。
- Salesforce/CRM求人のCore mustは、Salesforce/CRM/CX、導入、要件定義、設計、業務改革、顧客接点改革など。
- 営業/アライアンス求人のCore mustは、法人営業、ソリューション営業、プリセールス、アカウント営業、アライアンス営業、売上責任、販売実績など。
- Oracle求人のCore mustは、Oracle Fusion、Oracle Cloud ERP、Oracle EPM、Oracle HCM、Oracle SCM、OCIなどの導入経験。
- PMO求人とPM/PL求人は分けて考える。
`;

  const userPrompt = `
以下の求人票を構造化してください。

必ずこのJSONスキーマで返してください。

{
  "primary_role_category": "SALESFORCE_CRM | SAP_SPECIALIST | SAP_LIGHT | ORACLE_ERP | CLOUD_INFRA | IT_CONSULT_DELIVERY | PM_PL | PMO | SALES_ALLIANCE | BUSINESS_TRANSFORMATION | DATA_ANALYTICS | SECURITY | GENERAL",
  "role_categories": ["category"],
  "summary": "求人の短い要約",
  "core_must": [
    {
      "requirement": "中核必須条件",
      "category": "category",
      "evidence": "求人票内の根拠文"
    }
  ],
  "sub_must": [
    {
      "requirement": "補助必須条件",
      "category": "category | EDUCATION | LANGUAGE | LOCATION | EXPERIENCE_YEARS | OTHER",
      "evidence": "求人票内の根拠文"
    }
  ],
  "preferred": [
    {
      "requirement": "歓迎条件",
      "category": "category",
      "evidence": "求人票内の根拠文"
    }
  ],
  "disqualifiers": [
    {
      "condition": "欠けると大きく減点すべき条件",
      "category": "category",
      "reason": "理由"
    }
  ],
  "product_requirements": {
    "salesforce": "none | usage | implementation | lead",
    "sap": "none | adoption_or_support | implementation | lead",
    "oracle": "none | db_usage | implementation | lead",
    "sales": "none | confirmed",
    "cloud": "none | usage | implementation | lead"
  },
  "education_requirement": {
    "required": boolean,
    "level": "bachelor | graduate | unknown | none",
    "evidence": "根拠文"
  },
  "location_requirement": {
    "required": boolean,
    "locations": ["string"],
    "evidence": "根拠文"
  },
  "evidence_notes": ["判断メモ"]
}

求人票：
${text}
`;

  const res = await client.chat.completions.create({
    model: MODEL,
    temperature: 0,
    response_format: { type: "json_object" },
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userPrompt }
    ]
  });

  const content = res.choices?.[0]?.message?.content || "";
  const parsed = extractJson(content);

  if (!parsed) {
    throw new Error("Job profile JSON parse failed");
  }

  return normalizeProfile(parsed, job);
}

function getLimit() {
  const arg = process.argv.find(a => a.startsWith("--limit="));
  if (!arg) return 0;
  const n = Number(arg.split("=")[1]);
  return Number.isFinite(n) ? n : 0;
}

async function main() {
  if (!process.env.OPENAI_API_KEY) {
    throw new Error("OPENAI_API_KEY is missing");
  }

  const jobs = loadJobs();
  const existing = loadExistingProfiles();
  const limit = getLimit();

  console.log(`Loaded jobs: ${jobs.length}`);
  console.log(`Existing profiles: ${Object.keys(existing).length}`);
  console.log(`Model: ${MODEL}`);

  let processed = 0;
  let skipped = 0;
  let failed = 0;

  for (let i = 0; i < jobs.length; i++) {
    if (limit > 0 && processed >= limit) break;

    const job = jobs[i];
    const key = jobKey(job);

    if (existing[key]) {
      skipped++;
      continue;
    }

    const name = jobDisplayName(job);
    console.log(`[${i + 1}/${jobs.length}] Building profile: ${name}`);

    try {
      const profile = await buildJobProfile(job);
      existing[key] = profile;
      processed++;

      fs.writeFileSync(OUT_PATH, JSON.stringify(existing, null, 2), "utf8");
      console.log(`  -> saved: ${profile.primaryRoleCategory}`);
    } catch (e) {
      failed++;
      console.error(`  -> failed: ${e.message}`);
    }

    await new Promise(resolve => setTimeout(resolve, 250));
  }

  fs.writeFileSync(OUT_PATH, JSON.stringify(existing, null, 2), "utf8");

  console.log("Done.");
  console.log({ processed, skipped, failed, totalProfiles: Object.keys(existing).length, output: OUT_PATH });
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
