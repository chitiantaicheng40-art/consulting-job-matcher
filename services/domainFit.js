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

function has(text, re) {
  return new RegExp(re, "i").test(text || "");
}

function arr(value) {
  return Array.isArray(value) ? value : [];
}

const DOMAIN = {
  JAVA_WEB_APP_ENGINEER: "JAVA_WEB_APP_ENGINEER",
  FINANCIAL_SYSTEM_ENGINEER: "FINANCIAL_SYSTEM_ENGINEER",
  MAINFRAME_LEGACY_ENGINEER: "MAINFRAME_LEGACY_ENGINEER",
  JUNIOR_IT_DELIVERY: "JUNIOR_IT_DELIVERY",
  IT_CONSULTING: "IT_CONSULTING",
  STRATEGY_ARCHITECTURE: "STRATEGY_ARCHITECTURE",
  PMO_PM: "PMO_PM",
  REALTIME_3D_ENGINEER: "REALTIME_3D_ENGINEER",
  AI_DATA_ENGINEER: "AI_DATA_ENGINEER",
  EMBEDDED_IOT_ENGINEER: "EMBEDDED_IOT_ENGINEER",
  CLOUD_INFRA_ENGINEER: "CLOUD_INFRA_ENGINEER",
  SALESFORCE_CRM: "SALESFORCE_CRM",
  SAP_ERP: "SAP_ERP",
  ORACLE_ERP: "ORACLE_ERP",
  HR_TECH: "HR_TECH",
  SCM: "SCM",
  SECURITY: "SECURITY",
  SALES: "SALES",
  PR_MARKETING: "PR_MARKETING",
  GENERAL_IT: "GENERAL_IT",
  UNKNOWN: "UNKNOWN"
};

function addScore(scores, domain, points, evidence) {
  if (!scores[domain]) scores[domain] = { score: 0, evidence: [] };
  scores[domain].score += points;
  if (evidence) scores[domain].evidence.push(evidence);
}

function topDomains(scores, max = 2) {
  return Object.entries(scores)
    .sort((a, b) => b[1].score - a[1].score)
    .filter(([, v]) => v.score > 0)
    .slice(0, max)
    .map(([k]) => k);
}

function classifyCandidateDomain(candidateProfileV2, candidateText) {
  const cats = new Set(arr(candidateProfileV2?.roleCategories));
  const products = candidateProfileV2?.productLevels || {};
  const t = candidateText || "";
  const scores = {};

  if (has(t, "Java|JavaScript|React|Spring|フロントエンド|バックエンド|Webアプリ|オープン系")) {
    addScore(scores, DOMAIN.JAVA_WEB_APP_ENGINEER, 50, "Java/Web app evidence");
  }

  if (has(t, "銀行|バンキング|金融|決済|勘定系|預金|為替|融資")) {
    addScore(scores, DOMAIN.FINANCIAL_SYSTEM_ENGINEER, 45, "financial system evidence");
  }

  if (has(t, "メインフレーム|PL/I|PLI|COBOL|JCL|バッチ処理|オンライン処理|勘定系|基幹システム|夜間バッチ|ジョブスケジューラ|保守・運用|障害対応|次期システム")) {
    addScore(scores, DOMAIN.MAINFRAME_LEGACY_ENGINEER, 70, "mainframe/legacy banking evidence");
  }

  // Do not convert generic SOFTWARE_ENGINEER into JAVA_WEB_APP_ENGINEER.
  // Java/Web needs explicit Java/JavaScript/React/Web evidence.
  if (cats.has("SOFTWARE_ENGINEER")) {
    addScore(scores, DOMAIN.JUNIOR_IT_DELIVERY, 20, "SOFTWARE_ENGINEER generic delivery category");
  }

  if (cats.has("IT_CONSULT_DELIVERY") || has(t, "基本設計|詳細設計|開発|テスト|保守|運用")) {
    addScore(scores, DOMAIN.JUNIOR_IT_DELIVERY, 25, "IT delivery evidence");
  }

  if (cats.has("AI_ENGINEER") || cats.has("DATA_SCIENCE") || products.genai === "implementation" || products.data === "implementation") {
    addScore(scores, DOMAIN.AI_DATA_ENGINEER, 60, "AI/data implementation");
  }

  if (cats.has("EMBEDDED_IOT") || products.embedded === "implementation") {
    addScore(scores, DOMAIN.EMBEDDED_IOT_ENGINEER, 60, "embedded implementation");
  }

  if (cats.has("SALESFORCE_CRM") || products.salesforce === "implementation") {
    addScore(scores, DOMAIN.SALESFORCE_CRM, 60, "Salesforce implementation");
  }

  if (cats.has("SAP_SPECIALIST") || products.sap === "implementation") {
    addScore(scores, DOMAIN.SAP_ERP, 60, "SAP implementation");
  }

  if (cats.has("ORACLE_ERP") || products.oracle === "implementation") {
    addScore(scores, DOMAIN.ORACLE_ERP, 60, "Oracle ERP implementation");
  }

  const domains = topDomains(scores, 3);
  return domains.length ? domains : [DOMAIN.UNKNOWN];
}

function classifyJobDomain(jobText, jobProfileV2) {
  const t = jobText || "";
  const titleAndReq = t;
  const scores = {};

  // Very specific product / specialty domains.
  if (has(titleAndReq, "リアルタイムソフトウェアデベロッパー|リアルタイムソフトウェア|Unreal\\s*Engine|Unity|3DCG|\\bXR\\b|\\bVR\\b|\\bAR\\b|ゲーム開発")) {
    addScore(scores, DOMAIN.REALTIME_3D_ENGINEER, 100, "realtime/3D engine requirement");
  }

  if (has(titleAndReq, "AIエンジニア|AIアーキテクト|生成AI|LLM|機械学習|データサイエンティスト|データ分析基盤")) {
    addScore(scores, DOMAIN.AI_DATA_ENGINEER, 95, "AI/data role evidence");
  }

  if (has(titleAndReq, "組み込み|組込み|車載|ECU|IoT|QNX|GPIO|I2C")) {
    addScore(scores, DOMAIN.EMBEDDED_IOT_ENGINEER, 95, "embedded/IoT evidence");
  }

  if (has(titleAndReq, "Salesforce|CRM|CX")) {
    addScore(scores, DOMAIN.SALESFORCE_CRM, 90, "Salesforce/CRM evidence");
  }

  if (has(titleAndReq, "SAP|S/4HANA|ABAP|Basis|Ariba|SuccessFactors")) {
    addScore(scores, DOMAIN.SAP_ERP, 90, "SAP evidence");
  }

  if (has(titleAndReq, "Oracle ERP|Oracle Fusion|Oracle Cloud ERP|EPM|Oracle SCM|Oracle HCM")) {
    addScore(scores, DOMAIN.ORACLE_ERP, 90, "Oracle ERP evidence");
  }

  if (has(titleAndReq, "Dynamics 365|Power Platform|Microsoft リーダークラス")) {
    addScore(scores, DOMAIN.ORACLE_ERP, 75, "enterprise package evidence");
  }

  if (has(titleAndReq, "ServiceNow|Workday|人事|HCM|Employee Workflows")) {
    addScore(scores, DOMAIN.HR_TECH, 85, "HR tech evidence");
  }

  if (has(titleAndReq, "SCM|Supply Chain|サプライチェーン|物流|調達|購買|生産管理")) {
    addScore(scores, DOMAIN.SCM, 85, "SCM evidence");
  }

  if (has(titleAndReq, "セキュリティ|Security|SOC|CSIRT|脆弱性|ゼロトラスト")) {
    addScore(scores, DOMAIN.SECURITY, 85, "security evidence");
  }

  if (has(titleAndReq, "法人営業|プリセールス|リセール|製品販売|テクノロジーセールス|アライアンス")) {
    addScore(scores, DOMAIN.SALES, 85, "sales evidence");
  }

  if (has(titleAndReq, "広報|PR|広告代理店|メディア|マーケティング|コーポレート職")) {
    addScore(scores, DOMAIN.PR_MARKETING, 85, "PR/marketing evidence");
  }

  // Consulting / delivery domains.
  if (has(titleAndReq, "メインフレーム|PL/I|PLI|COBOL|JCL|勘定系|基幹システム|レガシー|ホスト|バッチ処理|オンライン処理|モダナイゼーション|マイグレーション")) {
    addScore(scores, DOMAIN.MAINFRAME_LEGACY_ENGINEER, 90, "mainframe/legacy modernization evidence");
  }

  if (has(titleAndReq, "金融プラットフォーム|銀行|バンキング|金融|決済|勘定系")) {
    addScore(scores, DOMAIN.FINANCIAL_SYSTEM_ENGINEER, 80, "financial platform evidence");
  }

  if (has(titleAndReq, "Java|JavaScript|React|Spring|Web系開発|Webアプリ|フロントエンド|バックエンド|オープン系開発")) {
    addScore(scores, DOMAIN.JAVA_WEB_APP_ENGINEER, 75, "Java/Web development evidence");
  }

  if (has(titleAndReq, "PMO|プロジェクト管理|プロジェクトマネジメント|大規模プロジェクト|プログラム管理|マネジメント能力|リーダークラス")) {
    addScore(scores, DOMAIN.PMO_PM, 70, "PM/PMO evidence");
  }

  if (has(titleAndReq, "IT戦略|IT企画|構想策定|アーキテクチャ|Architecture|Transformation|ビジネスアーキテクチャ|CPO|TAT")) {
    addScore(scores, DOMAIN.STRATEGY_ARCHITECTURE, 70, "strategy/architecture evidence");
  }

  if (has(titleAndReq, "システム開発|要件定義|基本設計|詳細設計|テスト|保守|運用|モダナイゼーション|AMO|ITライフサイクル")) {
    addScore(scores, DOMAIN.IT_CONSULTING, 55, "IT consulting/delivery evidence");
  }

  const ranked = Object.entries(scores).sort((a, b) => b[1].score - a[1].score);
  if (!ranked.length) return [DOMAIN.GENERAL_IT];

  const primary = ranked[0][0];

  // Keep only closely supportive domains.
  // Do not keep every detected keyword. This is the key anti-itachi rule.
  const secondary = ranked
    .slice(1)
    .filter(([domain, value]) => {
      if (value.score < 70) return false;

      if (primary === DOMAIN.FINANCIAL_SYSTEM_ENGINEER && [DOMAIN.MAINFRAME_LEGACY_ENGINEER, DOMAIN.JAVA_WEB_APP_ENGINEER, DOMAIN.IT_CONSULTING].includes(domain)) return true;
      if (primary === DOMAIN.MAINFRAME_LEGACY_ENGINEER && [DOMAIN.FINANCIAL_SYSTEM_ENGINEER, DOMAIN.IT_CONSULTING].includes(domain)) return true;
      if (primary === DOMAIN.JAVA_WEB_APP_ENGINEER && [DOMAIN.FINANCIAL_SYSTEM_ENGINEER, DOMAIN.IT_CONSULTING].includes(domain)) return true;
      if (primary === DOMAIN.STRATEGY_ARCHITECTURE && [DOMAIN.IT_CONSULTING, DOMAIN.PMO_PM].includes(domain)) return true;
      if (primary === DOMAIN.PMO_PM && [DOMAIN.IT_CONSULTING, DOMAIN.STRATEGY_ARCHITECTURE].includes(domain)) return true;

      return false;
    })
    .slice(0, 1)
    .map(([domain]) => domain);

  return [primary, ...secondary];
}

function domainDistance(candidateDomains, jobDomains) {
  const c = new Set(candidateDomains);
  const primaryJob = jobDomains[0];

  if (c.has(primaryJob)) return "same";

  const nearMap = {
    [DOMAIN.FINANCIAL_SYSTEM_ENGINEER]: [DOMAIN.MAINFRAME_LEGACY_ENGINEER, DOMAIN.JAVA_WEB_APP_ENGINEER, DOMAIN.JUNIOR_IT_DELIVERY, DOMAIN.IT_CONSULTING],
    [DOMAIN.MAINFRAME_LEGACY_ENGINEER]: [DOMAIN.FINANCIAL_SYSTEM_ENGINEER, DOMAIN.JUNIOR_IT_DELIVERY, DOMAIN.IT_CONSULTING],
    [DOMAIN.JAVA_WEB_APP_ENGINEER]: [DOMAIN.FINANCIAL_SYSTEM_ENGINEER, DOMAIN.JUNIOR_IT_DELIVERY, DOMAIN.IT_CONSULTING],
    [DOMAIN.IT_CONSULTING]: [DOMAIN.JAVA_WEB_APP_ENGINEER, DOMAIN.FINANCIAL_SYSTEM_ENGINEER, DOMAIN.JUNIOR_IT_DELIVERY],
    [DOMAIN.STRATEGY_ARCHITECTURE]: [DOMAIN.IT_CONSULTING, DOMAIN.JUNIOR_IT_DELIVERY],
    [DOMAIN.PMO_PM]: [DOMAIN.IT_CONSULTING, DOMAIN.JUNIOR_IT_DELIVERY],
    [DOMAIN.CLOUD_INFRA_ENGINEER]: [DOMAIN.JAVA_WEB_APP_ENGINEER, DOMAIN.IT_CONSULTING],
    [DOMAIN.AI_DATA_ENGINEER]: [DOMAIN.CLOUD_INFRA_ENGINEER],
    [DOMAIN.EMBEDDED_IOT_ENGINEER]: [DOMAIN.AI_DATA_ENGINEER]
  };

  const nearCandidates = nearMap[primaryJob] || [];
  if (nearCandidates.some(d => c.has(d))) return "near";

  const specialistDomains = [
    DOMAIN.REALTIME_3D_ENGINEER,
    DOMAIN.MAINFRAME_LEGACY_ENGINEER,
    DOMAIN.AI_DATA_ENGINEER,
    DOMAIN.EMBEDDED_IOT_ENGINEER,
    DOMAIN.SALESFORCE_CRM,
    DOMAIN.SAP_ERP,
    DOMAIN.ORACLE_ERP,
    DOMAIN.HR_TECH,
    DOMAIN.SCM,
    DOMAIN.SECURITY,
    DOMAIN.SALES,
    DOMAIN.PR_MARKETING
  ];

  if (specialistDomains.includes(primaryJob) && !c.has(primaryJob)) return "far";

  if ([DOMAIN.PMO_PM, DOMAIN.STRATEGY_ARCHITECTURE].includes(primaryJob)) return "adjacent";

  return "adjacent";
}

function scoreCapForDistance(distance, candidateDomains, jobDomains, years) {
  if (distance === "same") return 82;
  if (distance === "near") return 68;
  if (distance === "adjacent") return years < 3 ? 58 : 65;
  if (distance === "far") return 30;
  return 45;
}

function evaluateDomainFit({ candidateProfileV2, candidateText, jobText, jobProfileV2, years }) {
  const candidateDomains = classifyCandidateDomain(candidateProfileV2, candidateText);
  const jobDomains = classifyJobDomain(jobText, jobProfileV2);
  const distance = domainDistance(candidateDomains, jobDomains);
  const cap = scoreCapForDistance(distance, candidateDomains, jobDomains, years || 0);

  return {
    candidateDomains,
    jobDomains,
    primaryCandidateDomain: candidateDomains[0],
    primaryJobDomain: jobDomains[0],
    distance,
    cap,
    reason: `DomainFit: candidate=${candidateDomains.join("/")}, primaryJob=${jobDomains[0]}, job=${jobDomains.join("/")}, distance=${distance}, cap=${cap}`
  };
}

module.exports = {
  DOMAIN,
  classifyCandidateDomain,
  classifyJobDomain,
  evaluateDomainFit
};
