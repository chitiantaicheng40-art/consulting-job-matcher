const fs = require("fs");
const path = require("path");
const {
  normalizeCandidateProfileV2,
  classifyJobProfileV2
} = require("./profileV2");

function textOf(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(textOf).join(" ");
  if (typeof value === "object") {
    try {
      return Object.values(value).map(textOf).join(" ");
    } catch (_) {
      return "";
    }
  }
  return String(value);
}

function has(text, pattern) {
  return new RegExp(pattern, "i").test(text || "");
}

function arr(value) {
  return Array.isArray(value) ? value : [];
}

function uniq(values) {
  return [...new Set(values.filter(Boolean))];
}

function loadJobProfileCache() {
  try {
    const file = path.join(process.cwd(), "job_profiles_cache.json");
    if (!fs.existsSync(file)) return { byUrl: new Map(), all: [] };

    const raw = JSON.parse(fs.readFileSync(file, "utf8"));
    const all = Object.values(raw || {});
    const byUrl = new Map();

    for (const p of all) {
      if (p && p.url) byUrl.set(p.url, p);
    }

    return { byUrl, all };
  } catch (e) {
    console.warn("scoringV2: failed to load job profile cache:", e.message);
    return { byUrl: new Map(), all: [] };
  }
}

function getJobProfile(job, cacheByUrl) {
  const cached = job?.url ? cacheByUrl.get(job.url) : null;
  const base = cached || job?.aiJobProfile || job?.jobProfile || job || {};
  const v2 = classifyJobProfileV2(base);

  return {
    raw: base,
    v2
  };
}

function getTitle(job, profile) {
  return (
    job?.position ||
    job?.title ||
    profile?.displayName ||
    profile?.title ||
    "Unknown position"
  );
}

function getCompany(job, profile) {
  return job?.company || profile?.company || "Unknown";
}

function getUrl(job, profile) {
  return job?.url || profile?.url || "";
}

function getCoreMust(profile, job) {
  const p = profile || {};
  const source = arr(p.coreMust).length ? p.coreMust : arr(job?.requiredRequirements);
  return source
    .map(x => typeof x === "string" ? x : (x?.requirement || x?.text || x?.evidence || ""))
    .filter(Boolean);
}

function getPreferred(profile, job) {
  const p = profile || {};
  const source = arr(p.preferred).length ? p.preferred : arr(job?.preferredRequirements);
  return source
    .map(x => typeof x === "string" ? x : (x?.requirement || x?.text || x?.evidence || ""))
    .filter(Boolean);
}

function candidateText(candidate) {
  return [
    textOf(candidate?.rawResumeTextForValidation),
    textOf(candidate?.resumeText),
    textOf(candidate?.rawText),
    textOf(candidate?.skills),
    textOf(candidate?.projects),
    textOf(candidate?.career_summary),
    textOf(candidate?.summary),
    textOf(candidate?.candidateProfileV2?.evidence)
  ].join("\n");
}

function candidateYears(candidate) {
  const n = Number(candidate?.yearsExperience || candidate?.candidateProfileV2?.yearsExperience || candidate?.aiCandidateProfile?.yearsExperience || candidate?.candidateProfile?.yearsExperience || 0);
  return Number.isFinite(n) ? n : 0;
}

function matchRequirement(req, ctx) {
  const r = req || "";
  const cText = ctx.cText;
  const cp = ctx.cp || {};
  const cCats = new Set(arr(cp.roleCategories));
  const products = cp.productLevels || {};
  const years = ctx.years;

  if (!r.trim()) return false;

  // Experience years
  const yearMatch = r.match(/([0-9０-９]+)\s*年以上/);
  if (yearMatch) {
    const requiredYears = Number(String(yearMatch[1]).replace(/[０-９]/g, ch => String.fromCharCode(ch.charCodeAt(0) - 0xFEE0)));
    if (Number.isFinite(requiredYears) && years < requiredYears) return false;
  }

  // Language / tech
  if (has(r, "JavaもしくはC#|JavaまたはC#")) return has(cText, "Java") || has(cText, "C#|Cシャープ");
  if (has(r, "Java開発|Javaによる|Javaの")) return has(cText, "Java");
  if (has(r, "JavaScript|TypeScript|React|Angular|Vue")) return has(cText, "JavaScript|React|TypeScript|Angular|Vue");
  if (has(r, "Python")) return products.python === "implementation" || has(cText, "Python");
  if (has(r, "C#|Cシャープ")) return has(cText, "C#|Cシャープ");
  if (has(r, "C言語")) return has(cText, "C言語|\\bC\\b");

  // AI / data
  if (has(r, "AI|生成AI|LLM|機械学習|Machine Learning")) {
    return cCats.has("AI_ENGINEER") || products.genai === "implementation";
  }
  if (has(r, "データ分析|データサイエン|BI|DWH|ETL|データ基盤")) {
    return cCats.has("DATA_SCIENCE") || products.data === "implementation";
  }

  // Cloud / app
  if (has(r, "クラウド|AWS|Azure|GCP|Cloud")) {
    return products.cloud === "implementation" || cCats.has("CLOUD_APP_ENGINEER") || cCats.has("CLOUD_INFRA");
  }
  if (has(r, "API|WebAPI|REST")) {
    return products.api === "implementation" || has(cText, "REST API|WebAPI|API実装|API開発");
  }

  // Embedded / IoT
  if (has(r, "組み込み|組込み|車載|ECU|IoT|QNX|GPIO|I2C")) {
    return cCats.has("EMBEDDED_IOT") || products.embedded === "implementation";
  }

  // Salesforce / SAP / Oracle ERP
  if (has(r, "Salesforce|CRM|CX")) return cCats.has("SALESFORCE_CRM") || products.salesforce === "implementation";
  if (has(r, "S/4HANA|SAP|ABAP|Basis|Ariba|SuccessFactors")) return cCats.has("SAP_SPECIALIST") || products.sap === "implementation";
  if (has(r, "Oracle Fusion|Oracle ERP|Oracle Cloud ERP|EPM|SCM Cloud|HCM Cloud")) return cCats.has("ORACLE_ERP") || products.oracle === "implementation";

  // PM / management
  if (has(r, "PM|PMO|プロジェクト管理|チーム管理|マネジメント|スクラムマスタ|リード")) {
    return cCats.has("PM_PL") || cCats.has("PMO");
  }

  // Business/system delivery
  if (has(r, "要件定義|基本設計|詳細設計|開発|テスト|保守|運用|システム開発|導入")) {
    return cCats.has("SOFTWARE_ENGINEER") || cCats.has("IT_CONSULT_DELIVERY") || has(cText, "基本設計|詳細設計|開発|テスト|運用保守");
  }

  // Sales / PR / corporate are strict
  if (has(r, "法人営業|提案営業|プリセールス|アライアンス|リセール|製品販売|営業経験")) {
    return cCats.has("SALES_ALLIANCE") || products.sales === "confirmed";
  }
  if (has(r, "広報|PR|広告代理店|メディア|ソーシャルメディア|マーケティング")) return false;
  if (has(r, "法務|コンプライアンス|リスク|規制対応|ガバナンス")) return false;

  // Fallback: category level delivery
  return false;
}

function scoreJob(candidate, job, cachedProfile) {
  const cp = candidate?.candidateProfileV2 || normalizeCandidateProfileV2(candidate);
  const cCats = new Set(arr(cp.roleCategories));
  const products = cp.productLevels || {};
  const cText = candidateText(candidate);
  const years = candidateYears(candidate);

  const profile = cachedProfile?.raw || {};
  const jp = cachedProfile?.v2 || classifyJobProfileV2(profile || job);
  const jCats = new Set(arr(jp.roleCategories));
  const reqs = getCoreMust(profile, job);
  const preferred = getPreferred(profile, job);
  const jobText = [
    getTitle(job, profile),
    getCompany(job, profile),
    textOf(profile),
    textOf(reqs),
    textOf(preferred)
  ].join("\n");

  let score = 20;
  const notes = [];
  const matchedCategories = [];

  // Role category scoring
  const roleWeights = {
    SALESFORCE_CRM: 28,
    SAP_SPECIALIST: 30,
    ORACLE_ERP: 30,
    AI_ENGINEER: 26,
    DATA_SCIENCE: 24,
    SOFTWARE_ENGINEER: 26,
    EMBEDDED_IOT: 26,
    CLOUD_APP_ENGINEER: 22,
    CLOUD_INFRA: 18,
    IT_CONSULT_DELIVERY: 18,
    PM_PL: 12,
    PMO: 12,
    BUSINESS_TRANSFORMATION: 10,
    SECURITY: 22,
    SALES_ALLIANCE: 28
  };

  for (const cat of jCats) {
    if (cCats.has(cat)) {
      score += roleWeights[cat] || 8;
      matchedCategories.push(cat);
    }
  }

  if (matchedCategories.length) {
    notes.push(`カテゴリ一致：${matchedCategories.join(" / ")}`);
  } else {
    notes.push("カテゴリ一致なし");
  }

  // Product / tech requirements
  const jpReq = jp.productRequirements || {};
  const productKeys = ["salesforce", "sap", "oracle", "sales", "python", "genai", "embedded", "cloud", "data", "api", "security"];

  for (const key of productKeys) {
    const required = jpReq[key];
    if (!required || required === "none") continue;

    const level = products[key] || "none";

    if (["implementation", "lead", "specialist", "confirmed"].includes(level)) {
      score += 10;
      notes.push(`${key}要件：一致`);
    } else if (["user", "support", "adoption_or_support", "interest"].includes(level)) {
      score += 3;
      notes.push(`${key}要件：弱一致`);
    } else {
      score -= 18;
      notes.push(`${key}要件：不足`);
    }
  }

  // Required condition matching
  const ctx = { cp, cText, years };
  const requiredMatched = [];
  const requiredMissing = [];

  for (const r of reqs) {
    if (matchRequirement(r, ctx)) requiredMatched.push(r);
    else requiredMissing.push(r);
  }

  const requiredTotal = reqs.length;
  const requiredRate = requiredTotal ? Math.round((requiredMatched.length / requiredTotal) * 100) : 0;

  if (requiredTotal > 0) {
    if (requiredRate >= 80) score += 18;
    else if (requiredRate >= 60) score += 12;
    else if (requiredRate >= 40) score += 6;
    else if (requiredRate === 0) score -= 18;
    else score -= 6;
  }

  // Negative / hard mismatch caps
  let cap = 100;

  if (has(jobText, "AIアーキテクト|データサイエンティスト|生成AI|LLM|機械学習") && !cCats.has("AI_ENGINEER") && !cCats.has("DATA_SCIENCE")) {
    cap = Math.min(cap, 35);
    notes.push("AI/データ求人だが候補者にAI/データ実装経験が弱いため上限35");
  }

  if (has(jobText, "組み込み|組込み|車載|ECU|インダストリーX|IoT") && !cCats.has("EMBEDDED_IOT")) {
    cap = Math.min(cap, 40);
    notes.push("組み込み/IoT求人だが候補者に組み込み経験がないため上限40");
  }

  if (has(jobText, "Salesforce|CRM|CX") && !cCats.has("SALESFORCE_CRM")) {
    cap = Math.min(cap, 35);
    notes.push("Salesforce/CRM求人だが候補者経験なし");
  }

  if (has(jobText, "S/4HANA|SAP|ABAP|Basis|Ariba|SuccessFactors") && !cCats.has("SAP_SPECIALIST")) {
    cap = Math.min(cap, 30);
    notes.push("SAP専門求人だが候補者経験なし");
  }

  if (has(jobText, "Oracle Fusion|Oracle ERP|Oracle Cloud ERP|EPM|SCM Cloud|HCM Cloud") && !cCats.has("ORACLE_ERP")) {
    cap = Math.min(cap, 30);
    notes.push("Oracle ERP求人だが候補者経験なし");
  }

  if (has(jobText, "法人営業|プリセールス|アライアンス|リセール|製品販売|テクノロジーセールス") && !cCats.has("SALES_ALLIANCE")) {
    cap = Math.min(cap, 35);
    notes.push("営業/セールス求人だが候補者経験なし");
  }

  if (has(jobText, "広報|PR|広告代理店|メディア|ソーシャルメディア|マーケティング|コーポレート職")) {
    cap = Math.min(cap, 25);
    notes.push("PR/広報/コーポレート系のため上限25");
  }

  if (has(jobText, "法務|コンプライアンス|リスク|規制対応|ガバナンス|クライアントデータ保護")) {
    cap = Math.min(cap, 30);
    notes.push("法務/リスク系のため上限30");
  }

  if (has(jobText, "100名以上|PMP|PMBOK|大規模PM|プログラム・プロジェクト・サービスマネジメント")) {
    cap = Math.min(cap, 42);
    notes.push("大規模PM要件が強いため上限42");
  }

  if (requiredTotal > 0) {
    if (requiredRate === 0) cap = Math.min(cap, 25);
    else if (requiredRate < 30) cap = Math.min(cap, 45);
    else if (requiredRate < 50) cap = Math.min(cap, 58);
    else if (requiredRate < 70) cap = Math.min(cap, 72);
  }

  score = Math.max(0, Math.min(100, score, cap));
  score = Math.round(score);

  const preferredMatched = preferred.filter(p => matchRequirement(p, ctx)).slice(0, 5);

  return {
    company: getCompany(job, profile),
    position: getTitle(job, profile),
    title: getTitle(job, profile),
    url: getUrl(job, profile),
    score,
    rank: rankForScore(score),
    documentPassLikelihood: passForScore(score),
    documentPassPossibility: passForScore(score),
    passPossibility: passForScore(score),
    documentPassProbability: passForScore(score),
    recommendationLevel: recommendationForScore(score),
    isRecommended: score >= 35,
    source: "profile_v2_scoring",
    scoreBreakdown: {
      skill: Math.max(0, Math.min(45, score - 25)),
      industry: 0,
      role: matchedCategories.length ? 15 : 0,
      location: 0,
      career: years >= 3 ? 10 : 0
    },
    requiredMatched,
    requiredMissing,
    requiredTotal,
    requiredMatchedCount: requiredMatched.length,
    requiredMatchRate: requiredRate,
    preferredMatched,
    keywordMatched: matchedCategories,
    candidateProfileV2: cp,
    jobProfileV2: jp,
    aiJobProfile: profile,
    profileV2Scoring: {
      applied: true,
      matchedCategories,
      notes,
      requiredRate,
      cap
    },
    documentPassReason: `Profile v2共通スコアリングで${score}点と判定しました。`,
    reason: `Profile v2共通スコアリングで${score}点と判定しました。`,
    comment: [
      `Profile v2判定：${score}点。`,
      matchedCategories.length ? `一致カテゴリ：${matchedCategories.join(" / ")}` : "一致カテゴリは限定的です。",
      requiredTotal ? `必須一致率：${requiredRate}%（${requiredMatched.length}/${requiredTotal}）` : "必須条件の構造化情報が不足しています。",
      notes.join("。")
    ].filter(Boolean).join(" ")
  };
}

function rankForScore(score) {
  if (score >= 75) return "A";
  if (score >= 55) return "B";
  if (score >= 35) return "C";
  return "D";
}

function passForScore(score) {
  if (score >= 75) return "高";
  if (score >= 55) return "中";
  return "低";
}

function recommendationForScore(score) {
  if (score >= 75) return "優先提案";
  if (score >= 55) return "提案候補";
  if (score >= 35) return "要確認";
  return "参考・低一致";
}

function buildMatchesV2(candidate, jobs, options = {}) {
  const limit = options.limit || 100;
  const cache = loadJobProfileCache();
  const cp = candidate?.candidateProfileV2 || normalizeCandidateProfileV2(candidate);
  candidate.candidateProfileV2 = cp;

  const safeJobs = arr(jobs);
  const matches = [];

  for (const job of safeJobs) {
    try {
      const prof = getJobProfile(job, cache.byUrl);
      const match = scoreJob(candidate, job, prof);
      matches.push(match);
    } catch (e) {
      // Skip malformed job, but keep service alive.
    }
  }

  matches.sort((a, b) => b.score - a.score);

  return matches.slice(0, limit).map((m, i) => ({
    ...m,
    rankNo: i + 1,
    order: i + 1
  }));
}

module.exports = {
  buildMatchesV2,
  scoreJob
};
