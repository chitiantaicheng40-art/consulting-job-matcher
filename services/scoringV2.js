const fs = require("fs");
const path = require("path");
const {
  normalizeCandidateProfileV2,
  classifyJobProfileV2
} = require("./profileV2");
const { evaluateDomainFit } = require("./domainFit");

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

function isGenAiImplementationText(t) {
  return has(
    t || "",
    "RAG|LangChain|LangGraph|LLM.*(実装|開発|構築|アプリ)|生成AI.*(実装|開発|構築|アプリ|システム)|AIエージェント.*(実装|開発|構築)|機械学習モデル|モデル開発|MLOps|ファインチューニング|ベクトルDB|Vector DB|プロンプトエンジニアリング.*(実装|開発)"
  );
}

function isGenAiResearchOnlyText(t) {
  const text = t || "";
  return (
    has(text, "生成AI.*(調査|動向|キャッチアップ|資料|報告書|情報収集)|AI.*(調査|動向|キャッチアップ|資料|報告書|情報収集)|技術キャッチアップ|経営報告書") &&
    !isGenAiImplementationText(text)
  );
}

function normalizeCandidateProfileForScoring(cp, cText) {
  const next = {
    ...(cp || {}),
    roleCategories: Array.isArray(cp?.roleCategories) ? [...cp.roleCategories] : [],
    productLevels: { ...((cp && cp.productLevels) || {}) }
  };

  if (isGenAiResearchOnlyText(cText)) {
    next.productLevels.genai = "research";
    next.roleCategories = next.roleCategories.filter(c => c !== "AI_ENGINEER");
  }

  return next;
}

function candidateText(candidate) {
  // Robustly collect candidate-side text only.
  // In some routes, resume text is stored under different keys,
  // so relying on resumeText/rawText only makes career years and Java/React evidence disappear.
  const seen = new WeakSet();

  function walk(value, key = "", depth = 0) {
    if (value == null || depth > 8) return "";

    const k = String(key || "").toLowerCase();

    // Avoid job/match result pollution. Candidate object should not normally contain these,
    // but this keeps scoring clean if route payloads are merged.
    if ([
      "jobs",
      "job",
      "matches",
      "match",
      "recommendations",
      "aiJobProfile",
      "jobProfileV2",
      "profileV2Scoring"
    ].includes(k)) {
      return "";
    }

    if (typeof value === "string") return value;
    if (typeof value === "number" || typeof value === "boolean") return String(value);

    if (Array.isArray(value)) {
      return value.map(v => walk(v, key, depth + 1)).join("\n");
    }

    if (typeof value === "object") {
      if (seen.has(value)) return "";
      seen.add(value);

      return Object.entries(value)
        .map(([childKey, childValue]) => walk(childValue, childKey, depth + 1))
        .join("\n");
    }

    return "";
  }

  const direct = [
    textOf(candidate?.rawResumeTextForValidation),
    textOf(candidate?.resumeText),
    textOf(candidate?.rawText),
    textOf(candidate?.extractedText),
    textOf(candidate?.ocrText),
    textOf(candidate?.parsedText),
    textOf(candidate?.fullText),
    textOf(candidate?.profileText),
    textOf(candidate?.skills),
    textOf(candidate?.projects),
    textOf(candidate?.experiences),
    textOf(candidate?.workExperiences),
    textOf(candidate?.career_summary),
    textOf(candidate?.summary),
    textOf(candidate?.candidateProfileV2?.evidence)
  ].join("\n");

  // Prefer explicit candidate/resume fields.
  // Do not blindly walk the entire object when direct text exists,
  // because route payloads can contain previous match results or job text.
  if (direct.replace(/\s/g, "").length >= 80) {
    return direct;
  }

  function safeWalk(value, key = "", depth = 0) {
    if (value == null || depth > 6) return "";

    const k = String(key || "").toLowerCase();

    const blockedKeys = [
      "jobs",
      "job",
      "matches",
      "match",
      "recommendations",
      "aiJobProfile",
      "jobProfileV2",
      "profileV2Scoring",
      "domainFit",
      "requiredMatched",
      "requiredMissing",
      "preferredMatched",
      "preferredMissing",
      "comment",
      "reason",
      "documentPassReason",
      "recommendation_comment",
      "title",
      "position",
      "company",
      "url"
    ];

    if (blockedKeys.includes(k)) return "";

    const allowedKey =
      !k ||
      /resume|candidate|raw|extracted|ocr|parsed|fulltext|profiletext|skill|project|experience|career|summary|education|qualification|certification|text/.test(k);

    if (!allowedKey) return "";

    if (typeof value === "string") return value;
    if (typeof value === "number" || typeof value === "boolean") return String(value);

    if (Array.isArray(value)) {
      return value.map(v => safeWalk(v, key, depth + 1)).join("\n");
    }

    if (typeof value === "object") {
      if (seen.has(value)) return "";
      seen.add(value);

      return Object.entries(value)
        .map(([childKey, childValue]) => safeWalk(childValue, childKey, depth + 1))
        .join("\n");
    }

    return "";
  }

  const fallback = safeWalk(candidate);
  return [direct, fallback].filter(Boolean).join("\n");
}

function candidateYears(candidate) {
  const direct = Number(candidate?.yearsExperience || candidate?.candidateProfileV2?.yearsExperience || candidate?.aiCandidateProfile?.yearsExperience || candidate?.candidateProfile?.yearsExperience || 0);
  if (Number.isFinite(direct) && direct > 0) return direct;

  const t = candidateText(candidate);

  // Common resume phrasing: 2023年4月～現在 / 2021年10月～現在
  const m = t.match(/(20\d{2})年\s*(\d{1,2})月\s*[～〜\-－―]\s*現在/);
  if (m) {
    const startY = Number(m[1]);
    const startM = Number(m[2]);
    // Conservative current date assumption for scoring. Exact month is not critical.
    const nowY = new Date().getFullYear();
    const nowM = new Date().getMonth() + 1;
    const months = (nowY - startY) * 12 + (nowM - startM);
    return Math.max(0, Math.round((months / 12) * 10) / 10);
  }

  const y = t.match(/([0-9０-９]+)\s*年以上/);
  if (y) {
    const n = Number(String(y[1]).replace(/[０-９]/g, ch => String.fromCharCode(ch.charCodeAt(0) - 0xFEE0)));
    if (Number.isFinite(n)) return n;
  }

  return 0;
}

function matchRequirement(req, ctx) {

  const r = req || "";
  const cText = ctx.cText;
  const cp = ctx.cp || {};
  const cCats = new Set(arr(cp.roleCategories));
  const products = cp.productLevels || {};
  const years = ctx.years;

  if (!r.trim()) return false;

  if (
    has(r, "ITライフサイクル|企画、構築、運用保守|構築、運用保守|運用保守などのITライフサイクル|SDLC|Systems Development Life Cycle") &&
    has(cText, "要件定義|基本設計|詳細設計|設計|実装|製造|開発|単体テスト|結合テスト|テスト|保守|運用|運用保守|保守・運用|障害対応|改修|リリース|移行|次期システム|システム開発|基幹システム|勘定系|バッチ処理|オンライン処理")
  ) {
    return true;
  }

  // Specific product/domain requirements must be judged before generic "開発/設計/テスト".
  // Otherwise "Unreal Engineを活用したコンテンツ開発経験" is wrongly matched by generic development experience.
  if (has(r, "Unreal Engine|Unity|リアルタイムソフトウェア|3DCG|ゲーム|\\bXR\\b|\\bVR\\b|\\bAR\\b")) {
    return has(cText, "Unreal|Unity|リアルタイムソフトウェア|3DCG|ゲーム|\\bXR\\b|\\bVR\\b|\\bAR\\b");
  }

  if (has(r, "ServiceNow")) {
    return has(cText, "ServiceNow");
  }

  if (has(r, "Pega|PEGA")) {
    return has(cText, "Pega|PEGA");
  }

  if (has(r, "AIエンジニア|AIアーキテクト|LLM|機械学習|Machine Learning|AI開発|AIエンジニアリング")) {
    return products.genai === "implementation";
  }

  if (has(r, "生成AI|AI利活用|AI活用")) {
    if (has(r, "実装|開発|構築|エンジニアリング")) {
      return products.genai === "implementation";
    }
    return products.genai === "implementation" || products.genai === "usage";
  }

  if (has(r, "データサイエンティスト|データ分析")) {
    return cCats.has("DATA_SCIENCE") || products.data === "implementation";
  }

  if (has(r, "人事|HCM|Employee Workflows|SuccessFactors|Workday")) {
    return has(cText, "人事|HCM|人事システム|SuccessFactors|Workday");
  }

  if (has(r, "Supply Chain|SCM|サプライチェーン|物流|調達|購買|生産管理")) {
    return has(cText, "Supply Chain|SCM|サプライチェーン|物流|調達|購買|生産管理");
  }

  if (has(r, "法人営業|提案営業|プリセールス|アライアンス|リセール|製品販売|営業経験|テクノロジーセールス")) {
    return cCats.has("SALES_ALLIANCE") || products.sales === "confirmed";
  }

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
  if (has(r, "LLM|機械学習|Machine Learning|AIエンジニアリング|AI開発")) {
    return products.genai === "implementation";
  }

  if (has(r, "生成AI|AI利活用|AI活用")) {
    if (has(r, "実装|開発|構築|エンジニアリング")) {
      return products.genai === "implementation";
    }
    return products.genai === "implementation" || products.genai === "usage";
  }

  if (has(r, "AI")) {
    return products.genai === "implementation" || products.genai === "usage";
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

  // Product-specific CRM matching.
  // Dynamics 365 and Salesforce are adjacent CRM products, but should not satisfy each other's strict required criteria.
  if (has(r, "Dynamics 365|D365|Finance and Operations|Customer Service|Power Platform|Dataverse|Power Apps|Power Automate")) {
    return products.dynamics === "implementation";
  }

  if (has(r, "Salesforce|Service Cloud|Sales Cloud|Experience Cloud|Apex|SOQL|Lightning")) {
    return cCats.has("SALESFORCE_CRM") || products.salesforce === "implementation";
  }

  // Generic CRM/CX requirement can be matched by CRM experience broadly.
  if (has(r, "CRM|CX|MAツール|顧客接点|顧客体験")) {
    return cCats.has("SALESFORCE_CRM") || products.salesforce === "implementation" || products.dynamics === "implementation";
  }
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

  const domainFit = evaluateDomainFit({
    candidateProfileV2: cp,
    candidateText: cText,
    jobText,
    jobProfileV2: jp,
    years
  });

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

  // Positive fit for general Java/Web application engineers.
  const isJavaWebCandidate =
    has(cText, "Java") &&
    (has(cText, "JavaScript|React|Spring|Oracle|MySQL") || cCats.has("SOFTWARE_ENGINEER"));

  const isJavaWebJob =
    has(jobText, "Java|JavaScript|React|Spring|Webアプリ|WebやMobileアプリケーション|オープン系開発言語|システム設計・開発|システム開発");

  const isBankingOrFinancialJob =
    has(jobText, "銀行|バンキング|金融|決済|勘定系|インターネットバンキング");

  const isModernizationJob =
    has(jobText, "AMO|モダナイゼーション|レガシーシステム刷新|現行システム|アプリケーションモダナイゼーション");

  if (isJavaWebCandidate && isJavaWebJob) {
    score += 16;
    notes.push("Java/Webアプリ開発経験との親和性あり");
  }

  if (isJavaWebCandidate && isBankingOrFinancialJob) {
    score += 8;
    notes.push("金融/バンキングシステム経験との親和性あり");
  }

  if (isJavaWebCandidate && isModernizationJob) {
    score += 8;
    notes.push("既存システム更改/モダナイゼーションとの親和性あり");
  }

  // Negative / hard mismatch caps
  let cap = 100;

  cap = Math.min(cap, domainFit.cap);

  // DomainFit should not only cap mismatches; it should also rank closer jobs higher.
  if (domainFit.distance === "same") {
    score += 8;
    notes.push("DomainFit距離：sameのため加点");
  } else if (domainFit.distance === "near") {
    score += 3;
    notes.push("DomainFit距離：nearのため微加点");
  } else if (domainFit.distance === "far") {
    score -= 10;
    notes.push("DomainFit距離：farのため減点");
  }

  notes.push(domainFit.reason);

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

  // Senior manager / manager class caps.
  const isSeniorManagerJob = has(jobText, "シニアマネジャー|シニアマネージャー|マネジャー|マネージャー|Manager");
  const hasManagerExperience = cCats.has("PM_PL") || cCats.has("PMO") || has(cText, "プロジェクトマネージャー|プロジェクトリーダー|チームリード|プロジェクト管理|プロジェクトマネジメント");
  if (isSeniorManagerJob && (!hasManagerExperience || years < 5)) {
    cap = Math.min(cap, 30);
    notes.push("マネジャー/シニアマネジャー求人だが候補者の管理経験・年数が不足");
  }

  // Industry-specific senior consultant caps.
  if (has(jobText, "食品飲料|消費財|小売|流通|製造業|素材|エネルギー") && !has(cText, "食品飲料|消費財|小売|流通|製造業|素材|エネルギー")) {
    cap = Math.min(cap, 42);
    notes.push("特定業界知見求人だが候補者に該当業界経験なし");
  }

  // Domain / product-specific mismatch caps.
  // These are general rules, not candidate-specific patches.
  if (has(jobText, "ServiceNow") && !has(cText, "ServiceNow")) {
    cap = Math.min(cap, 30);
    notes.push("ServiceNow求人だが候補者にServiceNow経験なし");
  }

  if (has(jobText, "Pega|PEGA") && !has(cText, "Pega|PEGA")) {
    cap = Math.min(cap, 30);
    notes.push("Pega求人だが候補者にPega経験なし");
  }

  if (has(jobText, "人事|HCM|Employee Workflows|SuccessFactors|Workday") && !has(cText, "人事|HCM|人事システム|SuccessFactors|Workday")) {
    cap = Math.min(cap, 30);
    notes.push("人事/HRテクノロジー求人だが候補者に人事領域経験なし");
  }

  if (has(jobText, "Supply Chain|SCM|サプライチェーン|物流|調達|購買|生産管理") && !has(cText, "Supply Chain|SCM|サプライチェーン|物流|調達|購買|生産管理")) {
    cap = Math.min(cap, 30);
    notes.push("SCM/サプライチェーン求人だが候補者に該当領域経験なし");
  }

  if (has(jobText, "Unreal Engine|Unity|リアルタイムソフトウェア|ゲーム|3D|\\bXR\\b|\\bVR\\b|\\bAR\\b") && !has(cText, "Unreal|Unity|ゲーム|3D|\\bXR\\b|\\bVR\\b|\\bAR\\b")) {
    cap = Math.min(cap, 30);
    notes.push("Unreal/Unity/リアルタイム開発求人だが候補者に該当経験なし");
  }

  if (has(jobText, "RPA|UiPath|Automation Anywhere|Blue Prism") && !has(cText, "RPA|UiPath|Automation Anywhere|Blue Prism")) {
    cap = Math.min(cap, 40);
    notes.push("RPA求人だが候補者にRPA経験なし");
  }

  if (has(jobText, "リセール|製品販売|テクノロジーセールス|セールス") && !cCats.has("SALES_ALLIANCE")) {
    cap = Math.min(cap, 30);
    notes.push("セールス/リセール求人だが候補者に営業経験なし");
  }

  // Oracle DB is not Oracle ERP. Only cap Oracle ERP/Fusion/Cloud ERP jobs.
  if (has(jobText, "Oracle Fusion|Oracle ERP|Oracle Cloud ERP|EPM Cloud|SCM Cloud|HCM Cloud") && !cCats.has("ORACLE_ERP")) {
    cap = Math.min(cap, 30);
    notes.push("Oracle ERP求人だが候補者にOracle ERP経験なし");
  }

  if (requiredTotal > 0) {
    if (requiredRate === 0) cap = Math.min(cap, 25);
    else if (requiredRate < 30) cap = Math.min(cap, 45);
    else if (requiredRate < 50) cap = Math.min(cap, 58);
    else if (requiredRate < 70) cap = Math.min(cap, 72);
  }

  // Junior / low-experience caps.
  // General rule: candidates with under 3 years should not score as senior IT strategy / PM / architecture consultants.
  if (years > 0 && years < 3) {
    const seniorOrStrategyJob = has(jobText, "シニア|マネジャー|マネージャー|Manager|IT企画|構想策定|IT戦略|アーキテクチャ|アーキテクト|CPO|大規模プロジェクト|プログラム管理|PMO|プロジェクト管理|グローバルプロジェクト");
    if (seniorOrStrategyJob) {
      cap = Math.min(cap, 58);
      notes.push("実務3年未満の若手候補者のため、上流戦略/PM/アーキテクト求人は上限58");
    }
  }

  // Hard caps for specialist jobs when candidate-side evidence is missing.
  if (has(jobText, "Unreal Engine|Unity|リアルタイムソフトウェア|3DCG|ゲーム|\\bXR\\b|\\bVR\\b|\\bAR\\b") && !has(cText, "Unreal|Unity|3DCG|ゲーム|\\bXR\\b|\\bVR\\b|\\bAR\\b")) {
    cap = Math.min(cap, 25);
    notes.push("Unreal/Unity/3DCG求人だが候補者に該当経験なし");
  }

  if (has(jobText, "AIエンジニア|AIアーキテクト|生成AI|LLM|機械学習|データサイエンティスト") && !cCats.has("AI_ENGINEER") && !cCats.has("DATA_SCIENCE")) {
    cap = Math.min(cap, 35);
    notes.push("AI/データ専門求人だが候補者にAI/データ実装経験なし");
  }

  if (has(jobText, "CPOサポート|ビジネスアーキテクチャ|ITトランスフォーメーション|IT企画・構想策定") && years < 3) {
    cap = Math.min(cap, 58);
    notes.push("IT構想/ビジネスアーキテクチャ求人だが若手開発者のため上限58");
  }

  if (has(jobText, "プロジェクトマネジメント能力|プロジェクト管理|プログラム管理|大規模プロジェクト") && years < 3) {
    cap = Math.min(cap, 52);
    notes.push("PM/大規模PJ管理要件が強く、実務年数・管理経験が不足");
  }

  // Additional junior caps for architecture / transformation roles.
  if (years < 3 && has(jobText, "TAT|Tech Architecture Transformation|Architecture|Transformation|アーキテクチャ|IT戦略|IT企画|構想策定")) {
    cap = Math.min(cap, 58);
    notes.push("実務3年未満の若手候補者のため、Architecture/Transformation/IT戦略求人は上限58");
  }

  // Strong hard cap for creative/realtime engine jobs.
  if (has(jobText, "Unreal Engine|Unity|リアルタイムソフトウェア|3DCG|ゲーム|\\bXR\\b|\\bVR\\b|\\bAR\\b") && !has(cText, "Unreal|Unity|リアルタイムソフトウェア|3DCG|ゲーム|\\bXR\\b|\\bVR\\b|\\bAR\\b")) {
    cap = Math.min(cap, 25);
    notes.push("Unreal/Unity/3DCG/リアルタイム開発求人だが候補者に該当経験なし");
  }

  // AI/Data/Cloud engineering evidence alone should not make senior strategy / architect / management consulting roles A-rank.
  // These roles require consulting, architecture leadership, business transformation, or people/project management evidence.
  const isAiDataCloudCandidate =
    cCats.has("AI_ENGINEER") ||
    cCats.has("DATA_SCIENCE") ||
    cCats.has("CLOUD_APP_ENGINEER");

  const isSeniorAiConsultingJob =
    has(jobText, "AIアーキテクト|アーキテクト|データドリブン コンサルタント|価値創造経営|経営変革|業務変革|戦略|構想|リード|マネジメント|自社組織のマネジメント|データサイエンティスト人材|コンサルタント");

  const hasConsultingOrLeadEvidence =
    cCats.has("PM_PL") ||
    has(cText, "プロジェクトリード|プロジェクトリーダー|チームリード|\\bPL\\b|\\bPM\\b|プロジェクトマネジメント|プロジェクト管理|コンサルティング|戦略|構想策定|経営|業務改革|組織マネジメント");

  if (
    isAiDataCloudCandidate &&
    isSeniorAiConsultingJob &&
    !hasConsultingOrLeadEvidence &&
    requiredRate >= 80
  ) {
    cap = Math.min(cap, 72);
    notes.push("AI/Data/Cloud経験はあるが、戦略・アーキテクト・マネジメント色が強い求人のため上限72");
  }

  // Do not allow 80+ unless the candidate clearly matches the job's main specialty.
  const hasStrongSpecialtyMatch =
    requiredRate >= 80 &&
    (
      (isJavaWebCandidate && isJavaWebJob) ||
      (cCats.has("SALESFORCE_CRM") && has(jobText, "Salesforce|CRM")) ||
      (cCats.has("AI_ENGINEER") && has(jobText, "AI|生成AI|LLM")) ||
      (cCats.has("EMBEDDED_IOT") && has(jobText, "組み込み|車載|ECU|IoT")) ||
      (cCats.has("SAP_SPECIALIST") && has(jobText, "SAP|S/4HANA")) ||
      (cCats.has("ORACLE_ERP") && has(jobText, "Oracle ERP|Oracle Fusion"))
    );

  // Weak requirement cap: jobs whose must-have is only interest/willingness should not dominate the top.
  if (
    requiredTotal > 0 &&
    requiredMatched.length > 0 &&
    requiredMatched.join(" ").match(/興味がある|関心がある|意欲|学習意欲|キャッチアップ意欲|挑戦したい|志向/i)
  ) {
    cap = Math.min(cap, 78);
    notes.push("必須条件が興味・意欲中心のため、上限78");
  }

  // AI/Data specialist jobs require strong AI/Data primary evidence.
  if (
    has(jobText, "AIエンジニア|AIアーキテクト|Data＆AI|Data&AI|データサイエンティスト|データ活用コンサルタント|機械学習|LLM|生成AI") &&
    !cCats.has("AI_ENGINEER")
  ) {
    cap = Math.min(cap, 68);
    notes.push("AI/Data専門求人だが候補者にAI実装・専門職経験が弱いため上限68");
  }

  // HR / People / HCM strategy jobs require HR-domain experience.
  if (
    has(jobText, "人的資本|People|Culture|人事戦略|組織・人材|HRBP|人材開発|組織開発|HCM|Workday|SuccessFactors") &&
    !has(cText, "人事|人的資本|HRBP|人材開発|組織開発|HCM|Workday|SuccessFactors|タレントマネジメント|勤怠|給与")
  ) {
    cap = Math.min(cap, 58);
    notes.push("人事/人的資本領域求人だが候補者にHR領域経験なし");
  }

  const isDynamicsRequiredJob = has(jobText, "Dynamics 365|D365|Finance and Operations|Customer Service|Power Platform|Dataverse|Power Apps|Power Automate");
  const hasDynamicsCandidateExperience = products.dynamics === "implementation" || has(cText, "Dynamics 365|D365|Power Platform|Dataverse|Power Apps|Power Automate|Finance and Operations|Customer Service");

  if (
    isDynamicsRequiredJob &&
    !hasDynamicsCandidateExperience &&
    cCats.has("SALESFORCE_CRM")
  ) {
    cap = Math.min(cap, 65);
    notes.push("Dynamics 365必須求人だが候補者はSalesforce/CRM経験中心のため上限65");
  }

  // Salesforce/CRM primary candidates should not be highly ranked for unrelated specialist domains.
  if (
    cCats.has("SALESFORCE_CRM") &&
    !has(jobText, "Salesforce|CRM|Dynamics|MAツール|SaaSソリューション") &&
    has(jobText, "AIエンジニア|AIアーキテクト|Data＆AI|Data&AI|データサイエンティスト|データ活用|機械学習|LLM|生成AI")
  ) {
    cap = Math.min(cap, 62);
    notes.push("Salesforce/CRM主専門候補者に対してAI/Data専門求人のため上限62");
  }

  if (
    cCats.has("SALESFORCE_CRM") &&
    has(jobText, "人的資本|People|Culture|人事戦略|組織・人材|HRBP|人材開発|組織開発|HCM|Workday|SuccessFactors")
  ) {
    cap = Math.min(cap, 58);
    notes.push("Salesforce/CRM主専門候補者に対して人事/人的資本領域求人のため上限58");
  }

  if (
    cCats.has("SALESFORCE_CRM") &&
    has(jobText, "金融プラットフォーム|勘定系|金融機関|銀行|保険|証券|メインフレーム|COBOL|PL/I")
  ) {
    cap = Math.min(cap, 58);
    notes.push("Salesforce/CRM主専門候補者に対して金融基幹/金融PF求人のため上限58");
  }

  if (!hasStrongSpecialtyMatch && score > 78) {
    cap = Math.min(cap, 78);
    notes.push("主専門の強一致ではないため、80点以上は抑制");
  }


  // Relax accidental PM cap for cloud engineering / modernization roles.
  // Cloud engineering roles may mention large-scale projects, but should not be treated as pure PM roles
  // when the candidate has cloud application engineering evidence.
  if (
    has(jobText, "クラウド|Cloud|AWS|Azure|GCP|インテグレーション|アプリケーションモダナイゼーション|モダナイゼーション|Engineering") &&
    cCats.has("CLOUD_APP_ENGINEER") &&
    requiredRate >= 50 &&
    cap <= 42
  ) {
    cap = Math.max(cap, 58);
    notes.push("Cloud Engineering求人のため大規模PM上限を58まで緩和");
  }

  score = Math.max(0, Math.min(100, score, cap));

  // Final safety cap: if no structured required criteria were extracted,
  // keep the job as reference-only and prevent A-rank recommendations.
  if (!requiredTotal) {
    cap = Math.min(cap, 58);
    score = Math.min(score, 58);
    notes.push("必須条件の構造化情報が不足しているため、参考評価として上限58点に抑制");
  }

  score = Math.round(score);

  const preferredMatched = preferred.filter(p => matchRequirement(p, ctx) && !/PMBOK|PMP|100名以上|マネジャー|マネージャー/i.test(p)).slice(0, 5);

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
    domainFit,
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
      requiredTotal ? `必須一致率：${requiredRate}%（${requiredMatched.length}/${requiredTotal}）` : "必須条件の構造化情報が不足しているため、参考評価として上限58点に抑制。",
      notes.join("。")
    ].filter(Boolean).join(" ")
  };

  result.recommendation_comment = result.comment;
  result.recommendationComment = result.comment;
  result.matchComment = result.comment;
  result.aiComment = result.comment;
  result.documentPassReason = result.reason;
  result.passReason = result.reason;
  return result;
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

  const debugCandidateText = candidateText(candidate);
  console.log("===== scoringV2 candidate debug =====");
  console.log("primaryRole:", cp.primaryRole);
  console.log("roleCategories:", Array.isArray(cp.roleCategories) ? cp.roleCategories.join(", ") : "");
  console.log("productLevels:", JSON.stringify(cp.productLevels || {}));
  console.log("candidateYears:", candidateYears(candidate));
  console.log("candidateTextSample:", debugCandidateText.slice(0, 500).replace(/\n/g, " "));

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

  return matches
    .slice(0, limit)
    .map((m, i) => {
      const score = Math.round(Math.max(0, Math.min(100, Number(m.score || 0))));
      const baseReason = `Profile v2共通スコアリングで${score}点と判定しました。`;

      const notes = [
        m.comment,
        m.profileV2Scoring && Array.isArray(m.profileV2Scoring.notes) ? m.profileV2Scoring.notes.join("。") : "",
        m.domainFit && m.domainFit.reason ? m.domainFit.reason : ""
      ]
        .filter(Boolean)
        .join(" ")
        .split(/\s*Profile v2共通スコアリングで\d+点と判定しました。\s*/g)
        .join(" ")
        .split("。")
        .map(x => x.trim())
        .filter(Boolean);

      const finalComment = [...new Set(notes)].join("。") || baseReason;

      return {
        ...m,
        score,
        totalScore: score,
        matchScore: score,
        rank: rankForScore(score),
        documentPassLikelihood: passForScore(score),
        documentPassPossibility: passForScore(score),
        passPossibility: passForScore(score),
        documentPassProbability: passForScore(score),
        recommendationLevel: recommendationForScore(score),
        isRecommended: score >= 35,
        reason: baseReason,
        documentPassReason: baseReason,
        passReason: baseReason,
        comment: finalComment,
        recommendation_comment: finalComment,
        recommendationComment: finalComment,
        matchComment: finalComment,
        aiComment: finalComment,
        rankNo: i + 1,
        order: i + 1
      };
    })
    .sort((a, b) => {
      const scoreDiff = Number(b.score || 0) - Number(a.score || 0);
      if (scoreDiff !== 0) return scoreDiff;

      const distanceRank = {
        same: 4,
        near: 3,
        adjacent: 2,
        far: 1
      };

      const aDistance = distanceRank[a.domainFit?.distance] || 0;
      const bDistance = distanceRank[b.domainFit?.distance] || 0;
      if (bDistance !== aDistance) return bDistance - aDistance;

      const aRate = Number(a.profileV2Scoring?.requiredRate || a.requiredMatchRate || 0);
      const bRate = Number(b.profileV2Scoring?.requiredRate || b.requiredMatchRate || 0);
      if (bRate !== aRate) return bRate - aRate;

      const aMissing = Array.isArray(a.requiredMissing) ? a.requiredMissing.length : 999;
      const bMissing = Array.isArray(b.requiredMissing) ? b.requiredMissing.length : 999;
      if (aMissing !== bMissing) return aMissing - bMissing;

      const aCap = Number(a.domainFit?.cap || 0);
      const bCap = Number(b.domainFit?.cap || 0);
      if (bCap !== aCap) return bCap - aCap;

      return 0;
    })
    .map((m, i) => ({
      ...m,
      rankNo: i + 1,
      order: i + 1
    }));

}

module.exports = {
  buildMatchesV2,
  scoreJob
};
