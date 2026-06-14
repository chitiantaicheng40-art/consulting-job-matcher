const fs = require("fs");
const path = require("path");

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
  return re.test(text);
}

function candidateResumeTextOnly(candidate) {
  // IMPORTANT:
  // Do NOT read entire candidate object or existing AI profile JSON here.
  // Existing profile contains labels/reasons like "SAP experience is absent",
  // which causes false positives for SAP/Oracle/Sales/Security.
  const existing = candidate?.aiCandidateProfile || candidate?.candidateProfile || {};

  const parts = [
    candidate?.resumeText,
    candidate?.rawText,
    candidate?.extractedText,
    candidate?.text,
    candidate?.ocrText,
    candidate?.summary,
    existing?.summary,
    Array.isArray(candidate?.skills) ? candidate.skills.join(" ") : candidate?.skills,
    Array.isArray(candidate?.experiences) ? candidate.experiences.map(textOf).join("\n") : "",
    Array.isArray(candidate?.workExperiences) ? candidate.workExperiences.map(textOf).join("\n") : ""
  ].filter(Boolean);

  let text = parts.map(textOf).join("\n");

  // Remove diagnostic/category tokens if they leaked in.
  text = text
    .replace(/SALESFORCE_CRM|SAP_SPECIALIST|SAP_LIGHT|ORACLE_ERP|SALES_ALLIANCE|CLOUD_INFRA|IT_CONSULT_DELIVERY|DATA_ANALYTICS|DATA_SCIENCE|AI_ENGINEER|SOFTWARE_ENGINEER|EMBEDDED_IOT|CLOUD_APP_ENGINEER|SECURITY|BUSINESS_TRANSFORMATION|PM_PL|PMO/g, " ")
    .replace(/SAP関連の経験がないため|Oracle ERP関連の経験がないため|営業アライアンスの経験がないため|セキュリティ関連の経験がないため/g, " ");

  return text;
}

function normalizeCandidateProfileV2(candidate) {
  const existing = candidate?.aiCandidateProfile || candidate?.candidateProfile || {};
  const text = candidateResumeTextOnly(candidate);

  const roleCategories = new Set();
  const evidence = [];

  const productLevels = {
    salesforce: "none",
    sap: "none",
    oracle: "none",
    sales: "none",
    python: "none",
    genai: "none",
    embedded: "none",
    cloud: "none",
    data: "none",
    api: "none",
    security: "none"
  };

  // Salesforce / CRM
  if (has(text, /Salesforce|CRM刷新|CRM導入|顧客接点|CX/i)) {
    roleCategories.add("SALESFORCE_CRM");
    productLevels.salesforce = "implementation";
    evidence.push("Salesforce/CRM/CX関連経験を検出");
  }

  // SAP: strict distinction
  if (has(text, /SAP|SAC|SuccessFactors/i)) {
    if (has(text, /S\/4HANA|SAP\s*(FI|CO|MM|SD|PP|PM|PLM|EWM|Ariba)|ABAP|Basis|Fiori|BTP|SAP導入|SAP設計|SAP設定/i)) {
      roleCategories.add("SAP_SPECIALIST");
      productLevels.sap = "implementation";
      evidence.push("SAP専門導入・設計系の記載を検出");
    } else {
      roleCategories.add("SAP_LIGHT");
      productLevels.sap = "adoption_or_support";
      evidence.push("SAP/SAC利用・定着化・支援系の記載を検出");
    }
  }

  // Oracle ERP
  if (has(text, /Oracle\s*(Fusion|Cloud ERP|ERP|EPM|SCM|HCM|EBS)|OCI/i)) {
    roleCategories.add("ORACLE_ERP");
    productLevels.oracle = "implementation";
    evidence.push("Oracle ERP系経験を検出");
  }

  // Sales / alliance: strict, exclude Salesforce
  const textWithoutSalesforce = text.replace(/Salesforce/gi, "").replace(/Sales Cloud/gi, "");
  if (has(textWithoutSalesforce, /法人営業|提案営業|ソリューション営業|プリセールス|アライアンス|アカウント営業|売上責任|販売実績|新規開拓|既存深耕/i)) {
    roleCategories.add("SALES_ALLIANCE");
    productLevels.sales = "confirmed";
    evidence.push("本人の営業/アライアンス経験を検出");
  }

  // AI / GenAI
  if (has(text, /生成AI|LLM|LangChain|LangGraph|プロンプト|機械学習|Machine Learning|画像認識|G検定|AI/i)) {
    roleCategories.add("AI_ENGINEER");
    productLevels.genai = has(text, /生成AI|LLM|LangChain|LangGraph|プロンプト/i) ? "implementation" : "user";
    evidence.push("生成AI/AI/機械学習関連経験を検出");
  }

  // Data science
  if (has(text, /データ分析|クラスタリング|画像認識|データ基盤|DWH|ETL|BI|Python3 エンジニア認定データ分析/i)) {
    roleCategories.add("DATA_SCIENCE");
    productLevels.data = "implementation";
    evidence.push("データ分析/クラスタリング/画像認識経験を検出");
  }

  // Software engineer
  if (has(text, /ソフトウェアエンジニア|詳細設計|基本設計|実装|テスト|Python|C言語|Java|JavaScript|アプリケーション開発|システム開発/i)) {
    roleCategories.add("SOFTWARE_ENGINEER");
    if (has(text, /Python/i)) productLevels.python = "implementation";
    evidence.push("ソフトウェア開発経験を検出");
  }

  // Embedded / IoT / Automotive
  if (has(text, /組み込み|組込み|車載|ECU|カーナビ|QNX|GPIO|I2C|UFS|Linux\/QNX|IoT|制御系|C言語/i)) {
    roleCategories.add("EMBEDDED_IOT");
    productLevels.embedded = "implementation";
    evidence.push("車載/組み込み/IoT/制御系経験を検出");
  }

  // Cloud app / infra
  if (has(text, /AWS|Azure|GCP|EC2|DynamoDB|REST API|WebAPI|クラウド/i)) {
    if (has(text, /REST API|WebAPI|Azure 上の web システム|AWS.*EC2|DynamoDB|アプリ|システム開発/i)) {
      roleCategories.add("CLOUD_APP_ENGINEER");
      productLevels.cloud = "implementation";
      evidence.push("クラウド上でのアプリ/API開発経験を検出");
    } else {
      roleCategories.add("CLOUD_INFRA");
      productLevels.cloud = "user";
      evidence.push("クラウド利用経験を検出");
    }
  }

  // Security
  if (has(text, /セキュリティ|脆弱性|SOC|CSIRT|ゼロトラスト/i)) {
    roleCategories.add("SECURITY");
    productLevels.security = "implementation";
    evidence.push("セキュリティ関連経験を検出");
  }

  // IT delivery / PM
  if (has(text, /要件定義|基本設計|詳細設計|実装|テスト|運用保守|導入|保守開発|クライアント.*ヒアリング|改善提案/i)) {
    roleCategories.add("IT_CONSULT_DELIVERY");
    evidence.push("ITデリバリー/設計開発/顧客折衝経験を検出");
  }

  if (has(text, /PM|PL|リーダー|マネジメント|チームリード|プロジェクト管理/i)) {
    roleCategories.add("PM_PL");
    evidence.push("PM/PL系経験を検出");
  }

  if (has(text, /業務改革|DX推進|改善提案|課題抽出|全体最適|構想策定/i)) {
    roleCategories.add("BUSINESS_TRANSFORMATION");
    evidence.push("業務改善/DX/課題解決経験を検出");
  }

  // ===== Candidate Profile V2 cleanup guard =====
  // Remove false positives unless the resume text has strict positive evidence.
  const strictSap = /S\/4HANA|SAP\\s*(FI|CO|MM|SD|PP|PM|PLM|EWM|Ariba)|ABAP|Basis|Fiori|BTP|SAP導入|SAP設計|SAP設定|SAPモジュール/i.test(text);
  const lightSap = /SAP|SAC|SuccessFactors/i.test(text);
  if (!strictSap && !lightSap) {
    roleCategories.delete("SAP_SPECIALIST");
    roleCategories.delete("SAP_LIGHT");
    productLevels.sap = "none";
  } else if (!strictSap && lightSap) {
    roleCategories.delete("SAP_SPECIALIST");
    roleCategories.add("SAP_LIGHT");
    productLevels.sap = "adoption_or_support";
  }

  const strictOracle = /Oracle\\s*(Fusion|Cloud ERP|ERP|EPM|SCM|HCM|EBS)|OCI/i.test(text);
  if (!strictOracle) {
    roleCategories.delete("ORACLE_ERP");
    productLevels.oracle = "none";
  }

  const strictSales = /法人営業|提案営業|ソリューション営業|プリセールス|アライアンス|アカウント営業|売上責任|販売実績|新規開拓|既存深耕/i.test(textWithoutSalesforce);
  if (!strictSales) {
    roleCategories.delete("SALES_ALLIANCE");
    productLevels.sales = "none";
  }

  const strictSecurity = /サイバーセキュリティ|SOC|CSIRT|脆弱性診断|ゼロトラスト|インシデント対応|セキュリティ監査|情報セキュリティ/i.test(text);
  if (!strictSecurity) {
    roleCategories.delete("SECURITY");
    productLevels.security = "none";
  }

  const strictPm = /PM|プロジェクトマネージャー|PL|プロジェクトリーダー|チームリード|進捗管理|課題管理|メンバー管理|マネジメント経験/i.test(text);
  const onlyMember = /メンバー\s*\/\s*PJ要員|メンバー\/PJ要員/i.test(text);
  if (!strictPm || onlyMember) {
    roleCategories.delete("PM_PL");
  }

  if (/REST API|WebAPI|API実装|API開発/i.test(text)) {
    productLevels.api = "implementation";
  }

  const categories = Array.from(roleCategories);

  let primaryRole = existing.primaryRole || existing.primary_role || "General";
  if (categories.includes("AI_ENGINEER") && categories.includes("SOFTWARE_ENGINEER")) {
    primaryRole = "AI / Software Engineer";
  } else if (categories.includes("EMBEDDED_IOT")) {
    primaryRole = "Embedded / Software Engineer";
  } else if (categories.includes("SALESFORCE_CRM")) {
    primaryRole = "Salesforce/CRM/CX Consultant";
  } else if (categories.includes("CLOUD_APP_ENGINEER")) {
    primaryRole = "Cloud Application Engineer";
  } else if (categories.includes("SOFTWARE_ENGINEER")) {
    primaryRole = "Software Engineer";
  }

  return {
    version: "v2",
    primaryRole,
    roleCategories: categories.length ? categories : ["GENERAL"],
    productLevels,
    evidence,
    source: "profileV2.normalizeCandidateProfileV2"
  };
}

function classifyJobProfileV2(jobOrProfile) {
  const text = textOf(jobOrProfile);
  const categories = new Set();
  const productRequirements = {
    salesforce: "none",
    sap: "none",
    oracle: "none",
    sales: "none",
    python: "none",
    genai: "none",
    embedded: "none",
    cloud: "none",
    data: "none",
    api: "none",
    security: "none"
  };

  if (has(text, /Salesforce|CRM|CX\/CRM|顧客体験|顧客接点/i)) {
    categories.add("SALESFORCE_CRM");
    productRequirements.salesforce = "implementation";
  }

  if (has(text, /SAP|S\/4HANA|ABAP|Basis|FI|CO|MM|SD|PP|Ariba|SuccessFactors/i)) {
    categories.add("SAP_SPECIALIST");
    productRequirements.sap = "implementation";
  }

  if (has(text, /Oracle\s*(Fusion|Cloud ERP|ERP|EPM|SCM|HCM|EBS)|OCI/i)) {
    categories.add("ORACLE_ERP");
    productRequirements.oracle = "implementation";
  }

  const textWithoutSalesforce = text.replace(/Salesforce/gi, "").replace(/Sales Cloud/gi, "");
  if (has(textWithoutSalesforce, /法人営業|提案営業|プリセールス|アライアンス|アカウント営業|営業経験|売上責任/i)) {
    categories.add("SALES_ALLIANCE");
    productRequirements.sales = "confirmed";
  }

  if (has(text, /生成AI|LLM|LangChain|AI|機械学習|Machine Learning|データサイエンス/i)) {
    categories.add("AI_ENGINEER");
    productRequirements.genai = "implementation";
  }

  if (has(text, /Python|Java|JavaScript|C言語|アプリケーション|ソフトウェア|システム開発|Engineering|エンジニア/i)) {
    categories.add("SOFTWARE_ENGINEER");
    if (has(text, /Python/i)) productRequirements.python = "implementation";
  }

  if (has(text, /組み込み|組込み|車載|ECU|IoT|QNX|Linux|Automotive|インダストリーX/i)) {
    categories.add("EMBEDDED_IOT");
    productRequirements.embedded = "implementation";
  }

  if (has(text, /AWS|Azure|GCP|Cloud|クラウド|モダナイゼーション|アプリケーションモダナイゼーション/i)) {
    categories.add("CLOUD_APP_ENGINEER");
    productRequirements.cloud = "implementation";
  }

  if (has(text, /クラウド基盤|インフラ|IaC|Kubernetes|コンテナ|ネットワーク|運用基盤/i)) {
    categories.add("CLOUD_INFRA");
    productRequirements.cloud = "implementation";
  }

  if (has(text, /データ分析|データサイエンス|BI|DWH|ETL|データアーキテクト|データマネジメント|Data/i)) {
    categories.add("DATA_SCIENCE");
    productRequirements.data = "implementation";
  }

  if (has(text, /API|REST|WebAPI|MuleSoft|連携基盤/i)) {
    productRequirements.api = "implementation";
  }

  if (has(text, /要件定義|設計|導入|開発|保守|運用|テクノロジーコンサルタント|ITコンサル/i)) {
    categories.add("IT_CONSULT_DELIVERY");
  }

  if (has(text, /PM|PMO|PL|プロジェクト管理|マネジメント/i)) {
    categories.add("PM_PL");
  }

  if (has(text, /業務改革|DX|トランスフォーメーション|構想策定|戦略/i)) {
    categories.add("BUSINESS_TRANSFORMATION");
  }

  if (has(text, /セキュリティ|SOC|CSIRT|ゼロトラスト/i)) {
    categories.add("SECURITY");
    productRequirements.security = "implementation";
  }

  return {
    version: "v2",
    roleCategories: Array.from(categories).length ? Array.from(categories) : ["GENERAL"],
    productRequirements,
    source: "profileV2.classifyJobProfileV2"
  };
}

function scoreProfileV2(candidateProfileV2, jobProfileV2) {
  const c = new Set(candidateProfileV2.roleCategories || []);
  const j = new Set(jobProfileV2.roleCategories || []);
  const overlap = [...j].filter(x => c.has(x));

  let score = 0;
  const notes = [];

  if (overlap.length) {
    score += Math.min(45, overlap.length * 12 + 15);
    notes.push(`カテゴリ一致：${overlap.join(" / ")}`);
  } else {
    notes.push("カテゴリ一致なし");
  }

  const cp = candidateProfileV2.productLevels || {};
  const jp = jobProfileV2.productRequirements || {};

  for (const [key, required] of Object.entries(jp)) {
    if (!required || required === "none") continue;
    const level = cp[key] || "none";

    if (["implementation", "lead", "specialist"].includes(level)) {
      score += 10;
      notes.push(`${key}要件に対して候補者経験あり`);
    } else if (level === "user" || level === "support" || level === "adoption_or_support") {
      score += 3;
      notes.push(`${key}は軽経験のため弱一致`);
    } else {
      score -= 12;
      notes.push(`${key}要件に対して候補者経験不足`);
    }
  }

  score = Math.max(0, Math.min(100, score));

  return {
    score,
    overlap,
    notes
  };
}

module.exports = {
  normalizeCandidateProfileV2,
  classifyJobProfileV2,
  scoreProfileV2
};
