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

function classifyCandidateDomain(candidateProfileV2, candidateText) {
  const cats = new Set(arr(candidateProfileV2?.roleCategories));
  const products = candidateProfileV2?.productLevels || {};
  const t = candidateText || "";

  const domains = [];

  if (
    has(t, "Java|JavaScript|React|Spring|Oracle|MySQL|フロントエンド|バックエンド|Web") ||
    cats.has("SOFTWARE_ENGINEER")
  ) {
    domains.push(DOMAIN.JAVA_WEB_APP_ENGINEER);
  }

  if (has(t, "銀行|バンキング|金融|決済|勘定系")) {
    domains.push(DOMAIN.FINANCIAL_SYSTEM_ENGINEER);
  }

  if (cats.has("IT_CONSULT_DELIVERY") || has(t, "基本設計|詳細設計|開発|テスト|保守|運用")) {
    domains.push(DOMAIN.JUNIOR_IT_DELIVERY);
  }

  if (cats.has("AI_ENGINEER") || cats.has("DATA_SCIENCE") || products.genai === "implementation" || products.data === "implementation") {
    domains.push(DOMAIN.AI_DATA_ENGINEER);
  }

  if (cats.has("EMBEDDED_IOT") || products.embedded === "implementation") {
    domains.push(DOMAIN.EMBEDDED_IOT_ENGINEER);
  }

  if (cats.has("CLOUD_INFRA")) {
    domains.push(DOMAIN.CLOUD_INFRA_ENGINEER);
  }

  if (cats.has("SALESFORCE_CRM") || products.salesforce === "implementation") {
    domains.push(DOMAIN.SALESFORCE_CRM);
  }

  if (cats.has("SAP_SPECIALIST") || products.sap === "implementation") {
    domains.push(DOMAIN.SAP_ERP);
  }

  if (cats.has("ORACLE_ERP") || products.oracle === "implementation") {
    domains.push(DOMAIN.ORACLE_ERP);
  }

  if (cats.has("SECURITY") || products.security === "implementation") {
    domains.push(DOMAIN.SECURITY);
  }

  if (cats.has("SALES_ALLIANCE") || products.sales === "confirmed") {
    domains.push(DOMAIN.SALES);
  }

  return [...new Set(domains.length ? domains : [DOMAIN.UNKNOWN])];
}

function classifyJobDomain(jobText, jobProfileV2) {
  const cats = new Set(arr(jobProfileV2?.roleCategories));
  const req = jobProfileV2?.productRequirements || {};
  const t = jobText || "";
  const domains = [];

  if (has(t, "Unreal|Unity|リアルタイムソフトウェア|3DCG|XR|VR|AR|ゲーム")) {
    domains.push(DOMAIN.REALTIME_3D_ENGINEER);
  }

  if (has(t, "AIエンジニア|AIアーキテクト|生成AI|LLM|機械学習|データサイエンティスト|データドリブン") || cats.has("AI_ENGINEER") || cats.has("DATA_SCIENCE")) {
    domains.push(DOMAIN.AI_DATA_ENGINEER);
  }

  if (has(t, "組み込み|組込み|車載|ECU|IoT|QNX|GPIO|I2C") || cats.has("EMBEDDED_IOT")) {
    domains.push(DOMAIN.EMBEDDED_IOT_ENGINEER);
  }

  if (has(t, "Salesforce|CRM|CX") || cats.has("SALESFORCE_CRM") || req.salesforce) {
    domains.push(DOMAIN.SALESFORCE_CRM);
  }

  if (has(t, "SAP|S/4HANA|ABAP|Basis|Ariba|SuccessFactors") || cats.has("SAP_SPECIALIST") || req.sap) {
    domains.push(DOMAIN.SAP_ERP);
  }

  if (has(t, "Oracle ERP|Oracle Fusion|Oracle Cloud ERP|EPM|SCM Cloud|HCM Cloud") || cats.has("ORACLE_ERP") || req.oracle) {
    domains.push(DOMAIN.ORACLE_ERP);
  }

  if (has(t, "ServiceNow|Workday|SuccessFactors|人事|HCM|Employee Workflows")) {
    domains.push(DOMAIN.HR_TECH);
  }

  if (has(t, "SCM|Supply Chain|サプライチェーン|物流|調達|購買|生産管理")) {
    domains.push(DOMAIN.SCM);
  }

  if (has(t, "セキュリティ|Security|SOC|CSIRT|脆弱性|ゼロトラスト")) {
    domains.push(DOMAIN.SECURITY);
  }

  if (has(t, "法人営業|プリセールス|リセール|製品販売|テクノロジーセールス|アライアンス")) {
    domains.push(DOMAIN.SALES);
  }

  if (has(t, "広報|PR|広告代理店|メディア|ソーシャルメディア|マーケティング|コーポレート職")) {
    domains.push(DOMAIN.PR_MARKETING);
  }

  if (has(t, "PMO|プロジェクト管理|プロジェクトマネジメント|大規模プロジェクト|プログラム管理|マネジメント能力")) {
    domains.push(DOMAIN.PMO_PM);
  }

  if (has(t, "IT戦略|IT企画|構想策定|アーキテクチャ|Architecture|Transformation|ビジネスアーキテクチャ|CPO")) {
    domains.push(DOMAIN.STRATEGY_ARCHITECTURE);
  }

  if (has(t, "Java|JavaScript|React|Spring|Webアプリ|フロントエンド|バックエンド|オープン系開発|システム設計・開発")) {
    domains.push(DOMAIN.JAVA_WEB_APP_ENGINEER);
  }

  if (has(t, "銀行|バンキング|金融|決済|金融プラットフォーム")) {
    domains.push(DOMAIN.FINANCIAL_SYSTEM_ENGINEER);
  }

  if (has(t, "システム開発|要件定義|基本設計|詳細設計|テスト|保守|運用|モダナイゼーション|AMO")) {
    domains.push(DOMAIN.IT_CONSULTING);
  }

  return [...new Set(domains.length ? domains : [DOMAIN.GENERAL_IT])];
}

function domainDistance(candidateDomains, jobDomains) {
  const c = new Set(candidateDomains);
  const j = new Set(jobDomains);

  for (const d of jobDomains) {
    if (c.has(d)) return "same";
  }

  const nearPairs = [
    [DOMAIN.JAVA_WEB_APP_ENGINEER, DOMAIN.FINANCIAL_SYSTEM_ENGINEER],
    [DOMAIN.JAVA_WEB_APP_ENGINEER, DOMAIN.IT_CONSULTING],
    [DOMAIN.JAVA_WEB_APP_ENGINEER, DOMAIN.JUNIOR_IT_DELIVERY],
    [DOMAIN.FINANCIAL_SYSTEM_ENGINEER, DOMAIN.IT_CONSULTING],
    [DOMAIN.JUNIOR_IT_DELIVERY, DOMAIN.IT_CONSULTING],
    [DOMAIN.AI_DATA_ENGINEER, DOMAIN.CLOUD_INFRA_ENGINEER],
    [DOMAIN.EMBEDDED_IOT_ENGINEER, DOMAIN.AI_DATA_ENGINEER]
  ];

  for (const [a, b] of nearPairs) {
    if ((c.has(a) && j.has(b)) || (c.has(b) && j.has(a))) return "near";
  }

  const farJobDomains = [
    DOMAIN.REALTIME_3D_ENGINEER,
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

  for (const d of farJobDomains) {
    if (j.has(d) && !c.has(d)) return "far";
  }

  if (j.has(DOMAIN.PMO_PM) || j.has(DOMAIN.STRATEGY_ARCHITECTURE)) return "adjacent";

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
    distance,
    cap,
    reason: `DomainFit: candidate=${candidateDomains.join("/")}, job=${jobDomains.join("/")}, distance=${distance}, cap=${cap}`
  };
}

module.exports = {
  DOMAIN,
  classifyCandidateDomain,
  classifyJobDomain,
  evaluateDomainFit
};
