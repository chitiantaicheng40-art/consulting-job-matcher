require("dotenv").config();

const express = require("express");
const iconv = require("iconv-lite");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const axios = require("axios");
const cheerio = require("cheerio");
const { execSync } = require("child_process");
const OpenAI = require("openai");
const { chromium } = require("playwright");

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const upload = multer({ storage: multer.memoryStorage() });

const CACHE_PATH = path.join(__dirname, "jobs_cache.json");
const FETCH_LOG_PATH = path.join(__dirname, "fetch_logs.json");
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

const weakKeywords = [
  "IT",
  "DX",
  "AI",
  "PM",
  "MA",
  "ERP",
  "CRM",
  "SFA",
  "コンサル",
  "コンサルタント",
  "システム化",
  "業務改善",
  "プロジェクトマネジメント",
  "プロジェクト",
  "支援",
  "管理",
  "運用",
  "改善",
  "企画",
  "導入",
  "推進",
  "上流",
  "要件定義"
];

const strictRoleKeywords = [
  "SAP",
  "S/4HANA",
  "Salesforce",
  "ServiceNow",
  "Oracle",
  "Oracle ERP",
  "Dynamics",
  "SCM",
  "Supply Chain",
  "サプライチェーン",
  "需給",
  "在庫管理",
  "生産管理",
  "購買",
  "物流",
  "会計",
  "財務会計",
  "管理会計",
  "連結決算",
  "人事",
  "給与",
  "労務",
  "HR",
  "Workday",
  "SuccessFactors",
  "セキュリティ",
  "Cyber",
  "クラウド",
  "AWS",
  "Azure",
  "GCP",
  "データ分析",
  "Analytics",
  "BI",
  "Tableau",
  "Power BI",
  "RPA",
  "UiPath",
  "WinActor",
  "CRM",
  "SFA",
  "MA",
  "マーケティングオートメーション"
];

const criticalTechRules = [
  {
    name: "SAP",
    requiredPatterns: ["sap", "s/4hana"],
    candidatePatterns: ["sap", "s/4hana"]
  },
  {
    name: "Salesforce",
    requiredPatterns: ["salesforce", "sales cloud", "service cloud"],
    candidatePatterns: ["salesforce", "sales cloud", "service cloud"]
  },
  {
    name: "ServiceNow",
    requiredPatterns: ["servicenow"],
    candidatePatterns: ["servicenow"]
  },
  {
    name: "Oracle ERP",
    requiredPatterns: ["oracle erp", "oracle"],
    candidatePatterns: ["oracle erp", "oracle"]
  },
  {
    name: "Dynamics",
    requiredPatterns: ["dynamics"],
    candidatePatterns: ["dynamics"]
  }
];

const jobSources = [
  {
    company: "PwC",
    url: "https://jp-pwc.my.salesforce-sites.com/recruit/consulting/job/index"
  },
  {
    company: "Accenture",
    url: "https://www.accenture.com/jp-ja/careers/jobsearch"
  },
  {
    company: "Deloitte",
    url: "https://pgst02.jposting.net/u/job.phtml#job_category15"
  },
  {
    company: "Deloitte",
    url: "https://pgst02.jposting.net/u/job.phtml?job_code="
  },
  {
    company: "KPMG",
    url: "https://recruit.kpmg-consulting.jp/job-description"
  },
  {
    company: "Abeam Consulting",
    url: "https://www.abeam.com/jp/ja/recruit/career/jobs/"
  },
  {
    company: "Fortience",
    url: "https://js01.jposting.net/fortience/u/job.phtml"
  }
];

function safeJsonParse(text) {
  const cleaned = String(text)
    .replace(/```json/g, "")
    .replace(/```/g, "")
    .trim();

  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");

  if (start === -1 || end === -1) {
    throw new Error("JSON parse error");
  }

  return JSON.parse(cleaned.slice(start, end + 1));
}

function normalizeSkills(skills) {
  if (!Array.isArray(skills)) return [];
  return skills.map(s => String(s).trim()).filter(Boolean);
}

function normalizeText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/\s+/g, "")
    .trim();
}

function normalizeLooseText(value) {
  return String(value || "")
    .toLowerCase()
    .trim();
}

function isWeakKeyword(keyword) {
  return weakKeywords.some(w => normalizeText(w) === normalizeText(keyword));
}

function isStrictRoleKeyword(keyword) {
  const kw = normalizeText(keyword);

  return strictRoleKeywords.some(role => {
    const roleNorm = normalizeText(role);

    return (
      kw === roleNorm ||
      kw.includes(roleNorm) ||
      roleNorm.includes(kw)
    );
  });
}

function normalizeCandidate(candidate) {
  return {
    ...candidate,
    name: candidate.name || "候補者",
    skills: normalizeSkills(candidate.skills),
    yearsExperience: Number(candidate.yearsExperience || 0),
    industry: candidate.industry || "Other",
    location: candidate.location || "Tokyo",
    projects: Array.isArray(candidate.projects) ? candidate.projects : [],
    evidence: Array.isArray(candidate.evidence) ? candidate.evidence : []
  };
}

function toAbsoluteUrl(href, baseUrl) {
  try {
    return new URL(href, baseUrl).href;
  } catch {
    return baseUrl;
  }
}

function getCandidateSearchText(candidate) {
  return [
    candidate.skills,
    candidate.projects,
    candidate.career_summary,
    candidate.current_position,
    candidate.current_company,
    candidate.evidence
  ]
    .map(v => JSON.stringify(v || ""))
    .join(" ")
    .toLowerCase();
}

function getRank(score) {
  if (score >= 80) return "S：超おすすめ";
  if (score >= 60) return "A：おすすめ";
  if (score >= 40) return "B：検討";
  return "C：優先低";
}

function findEvidence(candidate, keyword) {
  const evidence = candidate.evidence || [];

  const found = evidence.find(e => {
    const text = JSON.stringify(e).toLowerCase();
    return text.includes(String(keyword).toLowerCase());
  });

  if (!found) return "職務経歴書内の関連記載";

  return found.evidence_text || found.value || "関連記載あり";
}

function buildEvidenceMap(candidate, matchedItems) {
  const map = {};

  matchedItems.forEach(item => {
    map[item] = findEvidence(candidate, item);
  });

  return map;
}

function hasAnyPattern(text, patterns) {
  const lower = normalizeLooseText(text);

  return patterns.some(pattern =>
    lower.includes(normalizeLooseText(pattern))
  );
}

function getRequiredCriticalRule(requiredSkill) {
  return criticalTechRules.find(rule =>
    hasAnyPattern(requiredSkill, rule.requiredPatterns)
  );
}

function hasCandidateCriticalTech(candidate, rule) {
  const candidateText = getCandidateSearchText(candidate);
  return hasAnyPattern(candidateText, rule.candidatePatterns);
}

function isImplementationRequirement(requiredSkill) {
  const text = String(requiredSkill || "");

  return (
    text.includes("導入") ||
    text.toLowerCase().includes("implementation") ||
    text.includes("構築") ||
    text.includes("要件定義") ||
    text.includes("Fit") ||
    text.includes("fit")
  );
}

function candidateHasImplementationExperience(candidate) {
  const text = getCandidateSearchText(candidate);

  return (
    text.includes("導入") ||
    text.includes("構築") ||
    text.includes("要件定義") ||
    text.includes("fit") ||
    text.includes("implementation")
  );
}

function strictSkillMatch(candidate, requiredSkill) {
  const req = String(requiredSkill || "").trim();
  if (!req) return false;

  const candidateSkills = normalizeSkills(candidate.skills);
  const candidateText = getCandidateSearchText(candidate);

  if (isWeakKeyword(req)) return false;

  const criticalRule = getRequiredCriticalRule(req);

  if (criticalRule) {
    if (!hasCandidateCriticalTech(candidate, criticalRule)) {
      return false;
    }

    if (isImplementationRequirement(req)) {
      return candidateHasImplementationExperience(candidate);
    }

    return true;
  }

  if (normalizeLooseText(req).includes("erp")) {
    const hasConcreteERP = hasAnyPattern(candidateText, [
      "sap",
      "s/4hana",
      "oracle erp",
      "dynamics",
      "基幹システム導入",
      "erp導入"
    ]);

    if (!hasConcreteERP) return false;
  }

  if (normalizeLooseText(req).includes("crm")) {
    const hasConcreteCRM = hasAnyPattern(candidateText, [
      "salesforce",
      "sales cloud",
      "service cloud",
      "crm導入"
    ]);

    if (!hasConcreteCRM) return false;
  }

  const reqNorm = normalizeText(req);

  const exactHit = candidateSkills.some(skill =>
    normalizeText(skill) === reqNorm
  );

  if (exactHit) return true;

  if (req.length >= 8) {
    return false;
  }

  const allowedShortKeywords = [
    "tableau",
    "rpa",
    "uipath",
    "winactor",
    "簿記",
    "会計",
    "英語",
    "toeic",
    "scm",
    "bi",
    "aws",
    "azure",
    "gcp"
  ];

  return allowedShortKeywords.some(keyword => {
    const k = normalizeText(keyword);
    return reqNorm === k && normalizeText(candidateText).includes(k);
  });
}

function strictRoleKeywordMatch(candidate, keyword) {
  const kw = String(keyword || "").trim();
  if (!kw) return false;

  if (isWeakKeyword(kw)) return false;
  if (!isStrictRoleKeyword(kw)) return false;

  const candidateText = getCandidateSearchText(candidate);
  const kwLower = kw.toLowerCase();

  const criticalRule = getRequiredCriticalRule(kw);
  if (criticalRule) {
    return hasCandidateCriticalTech(candidate, criticalRule);
  }

  if (normalizeLooseText(kw).includes("erp")) {
    return hasAnyPattern(candidateText, [
      "sap",
      "s/4hana",
      "oracle erp",
      "dynamics",
      "基幹システム導入",
      "erp導入"
    ]);
  }

  if (normalizeLooseText(kw).includes("crm")) {
    return hasAnyPattern(candidateText, [
      "salesforce",
      "sales cloud",
      "service cloud",
      "crm導入"
    ]);
  }

  return candidateText.includes(kwLower);
}

function calculateMatchScore(candidate, job) {
  let score = 0;

  const scoreBreakdown = {
    skill: 0,
    industry: 0,
    role: 0,
    location: 0,
    career: 0
  };

  const scoreLogs = [];

  const matchedRequired = [];
  const missingRequired = [];
  const matchedPreferred = [];
  const matchedKeywords = [];

  const requiredSkills = normalizeSkills(job.required_skills);
  const preferredSkills = normalizeSkills(job.preferred_skills);
  const roleKeywords = normalizeSkills(job.role_keywords);

  requiredSkills.forEach(skill => {
    if (strictSkillMatch(candidate, skill)) {
      score += 10;
      scoreBreakdown.skill += 10;
      matchedRequired.push(skill);

      scoreLogs.push({
        type: "必須一致",
        keyword: skill,
        point: 10
      });
    } else {
      missingRequired.push(skill);
    }
  });

  preferredSkills.forEach(skill => {
    if (strictSkillMatch(candidate, skill)) {
      score += 3;
      scoreBreakdown.skill += 3;
      matchedPreferred.push(skill);

      scoreLogs.push({
        type: "歓迎一致",
        keyword: skill,
        point: 3
      });
    }
  });

  roleKeywords.forEach(keyword => {
    if (strictRoleKeywordMatch(candidate, keyword)) {
      score += 5;
      scoreBreakdown.role += 5;
      matchedKeywords.push(keyword);

      scoreLogs.push({
        type: "ロール一致",
        keyword,
        point: 5
      });
    }
  });

  if (
    candidate.industry &&
    job.industry &&
    normalizeText(candidate.industry) === normalizeText(job.industry)
  ) {
    score += 20;
    scoreBreakdown.industry += 20;

    scoreLogs.push({
      type: "業界一致",
      keyword: candidate.industry,
      point: 20
    });
  }

  if (
    candidate.location &&
    candidate.location.toLowerCase().includes("tokyo")
  ) {
    score += 10;
    scoreBreakdown.location += 10;

    scoreLogs.push({
      type: "勤務地一致",
      keyword: "Tokyo",
      point: 10
    });
  }

  if (candidate.yearsExperience >= 3) {
    score += 10;
    scoreBreakdown.career += 10;

    scoreLogs.push({
      type: "経験年数一致",
      keyword: `${candidate.yearsExperience}年`,
      point: 10
    });
  }

  if (score > 100) score = 100;

  const requiredTotal = requiredSkills.length;
  const requiredMatchedCount = matchedRequired.length;
  const requiredMatchRate =
    requiredTotal > 0
      ? Math.round((requiredMatchedCount / requiredTotal) * 100)
      : 0;

  return {
    score,
    scoreBreakdown,
    scoreLogs,
    matchedRequired,
    missingRequired,
    matchedPreferred,
    matchedKeywords,
    requiredTotal,
    requiredMatchedCount,
    requiredMatchRate
  };
}

function getDocumentPassLikelihood(result) {
  const requiredTotal = result.requiredTotal || 0;
  const requiredMatchedCount = result.requiredMatchedCount || 0;
  const requiredMatchRate = result.requiredMatchRate || 0;
  const missingCount = result.missingRequired.length;

  if (requiredTotal === 0) {
    return {
      label: "低",
      reason: "求人側の必須要件が十分に取得できていないため、書類通過想定は保守的に低と判定しています。"
    };
  }

  if (
    requiredMatchRate >= 70 &&
    missingCount === 0 &&
    result.score >= 60
  ) {
    return {
      label: "高",
      reason: `必須一致率${requiredMatchRate}%（${requiredMatchedCount}/${requiredTotal}）で、不足必須がないため高めに判定しています。`
    };
  }

  if (
    requiredMatchRate >= 40 ||
    requiredMatchedCount >= 2
  ) {
    return {
      label: "中",
      reason: `必須一致率${requiredMatchRate}%（${requiredMatchedCount}/${requiredTotal}）です。一部要件の一致はありますが、不足要件の確認が必要です。`
    };
  }

  return {
    label: "低",
    reason: `必須一致率${requiredMatchRate}%（${requiredMatchedCount}/${requiredTotal}）のため、現時点では書類通過には追加確認・推薦補足が必要です。`
  };
}

function generateAIComment(candidate, job, result) {
  const strong = result.matchedRequired
    .concat(result.matchedPreferred)
    .concat(result.matchedKeywords)
    .slice(0, 3);

  const weak = result.missingRequired.slice(0, 2);

  return `
${candidate.name}様は、${strong.join("・") || "関連経験"}を有しており、${job.position}との親和性があります。
一方で、${weak.join("・") || "追加確認事項"}については確認・補足が必要です。
`.trim();
}

function isCacheValid() {
  if (!fs.existsSync(CACHE_PATH)) return false;

  try {
    const cache = JSON.parse(fs.readFileSync(CACHE_PATH, "utf8"));
    if (!cache.createdAt || !Array.isArray(cache.jobs)) return false;

    const age = Date.now() - new Date(cache.createdAt).getTime();

    return age < CACHE_TTL_MS && cache.jobs.length > 0;
  } catch {
    return false;
  }
}

function readJobsCache() {
  const cache = JSON.parse(fs.readFileSync(CACHE_PATH, "utf8"));
  console.log(`using jobs cache: ${cache.jobs.length} jobs`);
  return cache.jobs;
}


function writeFetchLog(logs) {
  fs.writeFileSync(
    FETCH_LOG_PATH,
    JSON.stringify(
      {
        createdAt: new Date().toISOString(),
        logs
      },
      null,
      2
    )
  );
}

function writeJobsCache(jobs) {
  let existingJobs = [];

  if (fs.existsSync(CACHE_PATH)) {
    try {
      const cache = JSON.parse(fs.readFileSync(CACHE_PATH, "utf8"));
      existingJobs = Array.isArray(cache.jobs) ? cache.jobs : [];
    } catch {
      existingJobs = [];
    }
  }

  const merged = [];
  const seen = new Set();

  for (const job of [...existingJobs, ...jobs]) {
    const key = [
      job.company || "",
      job.position || "",
      job.url || ""
    ].join("_").toLowerCase();

    if (seen.has(key)) continue;

    seen.add(key);
    merged.push(job);
  }

  fs.writeFileSync(
    CACHE_PATH,
    JSON.stringify(
      {
        createdAt: new Date().toISOString(),
        count: merged.length,
        jobs: merged
      },
      null,
      2
    )
  );

  console.log(`jobs cache merged: old ${existingJobs.length}, new ${jobs.length}, total ${merged.length}`);
}



function extractTitleFromPageText(text, url) {
  const lines = String(text || "")
    .split(/\n|。|｜|\|/)
    .map(v => v.trim())
    .filter(v => v.length >= 4 && v.length <= 120);

  const keywords = [
    "コンサル",
    "Consultant",
    "Manager",
    "SAP",
    "DX",
    "AI",
    "Data",
    "Technology",
    "Finance",
    "Transformation",
    "SCM",
    "PMO",
    "Strategy",
    "M&A",
    "Risk",
    "Deloitte"
  ];

  const found = lines.find(line =>
    keywords.some(k => line.toLowerCase().includes(k.toLowerCase()))
  );

  if (found) return found;

  const jobCodeMatch = String(url || "").match(/job_code=([^&]+)/);

  if (jobCodeMatch) {
    return `Deloitte Job ${jobCodeMatch[1]}`;
  }

  return "求人詳細";
}


function isNonJobPage(text, url = "") {
  const body = String(text || "").toLowerCase();
  const u = String(url || "").toLowerCase();

  const nonJobWords = [
    "セミナー",
    "説明会",
    "イベント",
    "選考会",
    "相談会",
    "キャリアセミナー",
    "採用イベント",
    "オンラインセミナー",
    "webinar",
    "seminar",
    "event",
    "session",
    "briefing",
    "会社説明会",
    "応募フォーム",
    "登録フォーム"
  ];

  const hasNonJobWord = nonJobWords.some(word =>
    body.includes(word.toLowerCase()) || u.includes(word.toLowerCase())
  );

  const jobWords = [
    "仕事内容",
    "職務内容",
    "応募資格",
    "必須条件",
    "必須要件",
    "求める経験",
    "歓迎条件",
    "募集要項",
    "雇用形態",
    "勤務地",
    "職種"
  ];

  const hasJobWords = jobWords.some(word => body.includes(word.toLowerCase()));

  // セミナー系ワードがあり、求人要素が弱い場合は除外
  if (hasNonJobWord && !hasJobWords) return true;

  // タイトル・本文内にセミナー/説明会が強く出ている場合も除外
  if (
    hasNonJobWord &&
    (
      body.includes("参加") ||
      body.includes("開催") ||
      body.includes("申込") ||
      body.includes("お申し込み") ||
      body.includes("視聴")
    )
  ) {
    return true;
  }

  return false;
}


function buildFallbackJobFromUrl(url, pageText) {
  const company = detectCompanyFromUrl(url);
  const position = extractTitleFromPageText(pageText, url);

  return {
    company,
    position,
    url,
    required_skills: [],
    required_evidence: {},
    preferred_skills: [],
    preferred_evidence: {},
    role_keywords: [position],
    industry: company === "Deloitte" ? "Consulting" : "Other",
    location: "Tokyo",
    minExp: 0
  };
}


function detectCompanyFromUrl(url) {
  const u = String(url || "").toLowerCase();

  if (u.includes("fortience")) return "Fortience";

  if (
    u.includes("pgst02.jposting.net") ||
    u.includes("deloittejapan.jposting.net") ||
    u.includes("deloitte")
  ) {
    return "Deloitte";
  }

  if (u.includes("kpmg")) return "KPMG";
  if (u.includes("abeam")) return "Abeam Consulting";
  if (u.includes("pwc")) return "PwC";
  if (u.includes("accenture")) return "Accenture";

  return "Unknown";
}


function normalizeJob(job, source) {
  return {
    company: job.company || source.company,
    position: job.position || "",
    url: job.url || source.url,
    required_skills: normalizeSkills(job.required_skills),
    preferred_skills: normalizeSkills(job.preferred_skills),
    role_keywords: normalizeSkills(job.role_keywords),
    required_evidence: job.required_evidence || {},
    preferred_evidence: job.preferred_evidence || {},
    industry: job.industry || "Other",
    location: job.location || "Unknown",
    minExp: Number(job.minExp || 0)
  };
}


function isLikelyJobLink(text, url) {
  const t = `${text} ${url}`.toLowerCase();

  // jposting系は求人詳細URLが phtml / job.phtml / job_id などになりやすい
  if (
    t.includes("jposting.net") &&
    (
      t.includes("job.phtml") ||
      t.includes("job_id") ||
      t.includes("id=") ||
      t.includes("job")
    )
  ) {
    return true;
  }

  const includeWords = [
    "job",
    "career",
    "recruit",
    "position",
    "consultant",
    "consulting",
    "コンサル",
    "募集",
    "求人",
    "職種",
    "応募",
    "採用",
    "phtml"
  ];

  const excludeWords = [
    "privacy",
    "terms",
    "login",
    "entry",
    "mypage",
    "contact",
    "faq",
    "news",
    "about",
    "javascript:",
    "mailto:"
  ];

  const hasInclude = includeWords.some(w => t.includes(w));
  const hasExclude = excludeWords.some(w => t.includes(w));

  return hasInclude && !hasExclude;
}

async function fetchPageText(url) {
  const response = await axios.get(url, {
    headers: { "User-Agent": "Mozilla/5.0" },
    timeout: 20000
  });

  const $ = cheerio.load(response.data);

  return {
    text: $("body").text().replace(/\s+/g, " ").slice(0, 20000),
    links: $("a")
      .map((_, el) => {
        const text = $(el).text().replace(/\s+/g, " ").trim();
        const href = $(el).attr("href");
        if (!href) return null;
        return { text, url: toAbsoluteUrl(href, url) };
      })
      .get()
      .filter(Boolean)
  };
}

async function extractJobsFromDetailPage(source, pageUrl, pageText) {
  const gptResponse = await client.responses.create({
    model: "gpt-4.1-mini",
    input:
`あなたは人材紹介会社のRAです。

以下は ${source.company} の求人詳細ページ、または求人一覧ページの本文です。

このページ内に実在するコンサル・IT・DX・業務改善系求人があれば抽出してください。
求人がなければ jobs は空配列にしてください。

重要:
- 推測は禁止です。
- required_skillsには「必須条件/MUST/応募資格として明記されている具体スキル・経験」のみ入れてください。
- 根拠文が本文にない要件はrequired_skillsに入れないでください。
- IT、DX、AI、PM、ERP、CRM、MA、コンサル、システム化、業務改善、プロジェクトマネジメント、支援、管理、推進のような抽象語だけをrequired_skillsに入れないでください。
- SAP経験が必須の場合は「SAP導入経験」「SAP会計導入経験」のように具体化してください。
- ERP単体ではなく「SAP導入経験」「Oracle ERP導入経験」「基幹システム導入経験」のように具体化してください。
- CRM単体ではなく「Salesforce導入経験」「CRM戦略経験」など具体化してください。
- required_evidenceには、required_skillsの各要件について求人本文から抜粋した根拠文を入れてください。
- role_keywordsには仕事内容・領域を入れてください。ただし抽象語だけは避け、SCM、SAP、会計、Salesforce、RPAなど具体領域中心にしてください。
- urlには必ずこのURLを入れてください: ${pageUrl}

JSONのみ返してください。

{
  "jobs":[
    {
      "company":"${source.company}",
      "position":"",
      "url":"${pageUrl}",
      "required_skills":[],
      "required_evidence":{},
      "preferred_skills":[],
      "preferred_evidence":{},
      "role_keywords":[],
      "industry":"",
      "location":"",
      "minExp":0
    }
  ]
}

本文:
${pageText}
`
  });

  const parsed = safeJsonParse(gptResponse.output_text);
  return Array.isArray(parsed.jobs) ? parsed.jobs : [];
}


async function scrapeAccentureJobs() {
  try {
    const url = "https://www.accenture.com/jp-ja/careers/jobsearch";

    const pageData = await fetchPageText(url);

    const jobs = [];

    for (const link of pageData.links || []) {
      const text = (link.text || "").trim();
      const href = link.url || "";

      const combined = `${text} ${href}`.toLowerCase();

      const isJob =
        combined.includes("jobdetails") ||
        combined.includes("jobdetail") ||
        combined.includes("careers/jobdetails") ||
        combined.includes("consultant") ||
        combined.includes("コンサル") ||
        combined.includes("engineer") ||
        combined.includes("technology");

      if (!isJob) continue;
      if (!text || text.length < 5) continue;
      if (text.length > 120) continue;

      jobs.push({
        company: "Accenture",
        position: text,
        url: href,
        required_skills: [],
        required_evidence: {},
        preferred_skills: [],
        preferred_evidence: {},
        role_keywords: [text],
        industry: "Consulting",
        location: "Tokyo",
        minExp: 0
      });
    }

    const unique = [];
    const seen = new Set();

    for (const job of jobs) {
      const key = `${job.position}_${job.url}`;

      if (seen.has(key)) continue;
      seen.add(key);
      unique.push(job);
    }

    console.log(`Accenture special scraper: ${unique.length} jobs`);
    return unique.slice(0, 50);

  } catch (err) {
    console.error("Accenture scrape error:", err.message);
    return [];
  }
}



async function scrapeDeloitteJobs() {
  const source = {
    company: "Deloitte",
    url: "https://pgst02.jposting.net/u/job.phtml#job_category15"
  };

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    ignoreHTTPSErrors: true
  });
  const page = await context.newPage();

  try {
    console.log("Deloitte special scraper start");

    await page.goto(source.url, {
      waitUntil: "networkidle",
      timeout: 60000
    });

    await page.waitForTimeout(4000);

    // ページ内のアコーディオン/カテゴリがあれば可能な範囲で開く
    const clickableTexts = [
      "コンサルティング",
      "Consulting",
      "職種",
      "募集職種",
      "中途採用",
      "キャリア採用"
    ];

    for (const text of clickableTexts) {
      try {
        const target = page.getByText(text, { exact: false }).first();
        if (await target.count()) {
          await target.click({ timeout: 3000 }).catch(() => {});
          await page.waitForTimeout(1000);
        }
      } catch {}
    }

    const bodyText = await page.locator("body").innerText();

    const links = await page.locator("a").evaluateAll((els) =>
      els.map(a => ({
        text: (a.innerText || "").trim(),
        url: a.href
      })).filter(x => x.url)
    );

    const jobs = [];

    // まず、表示後ページ本文そのものからGPTで抽出
    try {
      const pageJobs = await extractJobsFromDetailPage(
        source,
        source.url,
        bodyText.replace(/\s+/g, " ").slice(0, 25000)
      );

      jobs.push(
        ...pageJobs.map(job => ({
          ...job,
          company: "Deloitte",
          url: job.url || source.url
        }))
      );
    } catch (e) {
      console.error("Deloitte page extraction error:", e.message);
    }

    // 次に、求人っぽいリンクを拾って詳細ページも読む
    const jobLinks = links
      .filter(link => {
        const text = `${link.text} ${link.url}`.toLowerCase();

        const include =
          text.includes("consult") ||
          text.includes("コンサル") ||
          text.includes("strategy") ||
          text.includes("technology") ||
          text.includes("risk") ||
          text.includes("sap") ||
          text.includes("data") ||
          text.includes("digital") ||
          text.includes("job") ||
          text.includes("phtml");

        const exclude =
          text.includes("privacy") ||
          text.includes("login") ||
          text.includes("mypage") ||
          text.includes("entry") ||
          text.includes("faq") ||
          text.includes("contact");

        return include && !exclude && link.text && link.text.length >= 4;
      })
      .slice(0, 40);

    for (const link of jobLinks) {
      try {
        const detail = await fetchPageText(link.url);

        const detailJobs = await extractJobsFromDetailPage(
          source,
          link.url,
          detail.text
        );

        if (detailJobs.length) {
          jobs.push(
            ...detailJobs.map(job => ({
              ...job,
              company: "Deloitte",
              url: job.url || link.url
            }))
          );
        } else {
          jobs.push({
            company: "Deloitte",
            position: link.text,
            url: link.url,
            required_skills: [],
            required_evidence: {},
            preferred_skills: [],
            preferred_evidence: {},
            role_keywords: [link.text],
            industry: "Consulting",
            location: "Tokyo",
            minExp: 0
          });
        }
      } catch (e) {
        console.error("Deloitte detail error:", link.url, e.message);
      }
    }

    // 最後に、本文の行から求人タイトルらしいものをfallback抽出
    const titleKeywords = [
      "コンサルタント",
      "Consultant",
      "Manager",
      "PMO",
      "SAP",
      "DX",
      "AI",
      "Data",
      "データ",
      "Risk",
      "リスク",
      "Strategy",
      "戦略",
      "Finance",
      "会計",
      "Technology",
      "Human Capital",
      "M&A"
    ];

    const lines = bodyText
      .split(/\n/)
      .map(v => v.trim())
      .filter(v => v.length >= 8 && v.length <= 120)
      .filter(v => titleKeywords.some(k => v.toLowerCase().includes(k.toLowerCase())))
      .filter(v => !v.includes("ログイン"))
      .filter(v => !v.includes("応募"))
      .filter(v => !v.includes("プライバシー"));

    for (const line of lines) {
      jobs.push({
        company: "Deloitte",
        position: line,
        url: source.url,
        required_skills: [],
        required_evidence: {},
        preferred_skills: [],
        preferred_evidence: {},
        role_keywords: [line],
        industry: "Consulting",
        location: "Tokyo",
        minExp: 0
      });
    }

    const unique = [];
    const seen = new Set();

    for (const job of jobs) {
      const position = String(job.position || "").trim();
      if (!position) continue;

      const key = `${position}_${job.url || ""}`.toLowerCase();
      if (seen.has(key)) continue;

      seen.add(key);
      unique.push(job);
    }

    console.log(`Deloitte special scraper: ${unique.length} jobs`);

    return unique.slice(0, 60);

  } catch (err) {
    console.error("Deloitte scrape error:", err.message);
    return [];
  } finally {
    await browser.close();
  }
}


async function fetchJobsFromWebFresh() {
  const allJobs = [];
  const fetchLogs = [];

  const deloitteJobs = await scrapeDeloitteJobs();
  allJobs.push(...deloitteJobs);

  fetchLogs.push({
    company: "Deloitte",
    status: "success",
    fetchedCount: deloitteJobs.length,
    message: "Deloitte専用crawler取得"
  });

  const accentureJobs = await scrapeAccentureJobs();
  allJobs.push(...accentureJobs);

  fetchLogs.push({
    company: "Accenture",
    status: "success",
    fetchedCount: accentureJobs.length,
    message: "Accenture専用crawler取得"
  });

  for (const source of jobSources) {
    try {
      console.log("fetching list:", source.company);
      const beforeCount = allJobs.length;


      const listPage = await fetchPageText(source.url);

      let detailLinks = listPage.links
        .filter(link => isLikelyJobLink(link.text, link.url))
        .map(link => link.url);

      detailLinks = [...new Set([source.url, ...detailLinks])].slice(0, 30);

      console.log(`${source.company}: detail links ${detailLinks.length}`);

      for (const detailUrl of detailLinks) {
        try {
          console.log("  detail:", detailUrl);

          const detailPage = await fetchPageText(detailUrl);
          const jobs = await extractJobsFromDetailPage(
            source,
            detailUrl,
            detailPage.text
          );

          allJobs.push(
            ...jobs
              .map(job => normalizeJob(job, source))
              .filter(job => job.position)
          );
        } catch (error) {
          console.error("detail fetch error:", source.company, detailUrl, error.message);
        }
      }
      const afterCount = allJobs.length;

      fetchLogs.push({
        company: source.company,
        status: "success",
        fetchedCount: afterCount - beforeCount,
        message: "取得完了"
      });

    } catch (error) {
      console.error("job fetch error:", source.company, error.message);

      fetchLogs.push({
        company: source.company,
        status: "error",
        fetchedCount: 0,
        message: error.message
      });
    }
  }

  writeFetchLog(fetchLogs);

  const uniqueJobs = [];
  const seen = new Set();

  for (const job of allJobs) {
    const key = `${job.company}_${job.position}_${job.url}`.toLowerCase();

    if (!seen.has(key)) {
      seen.add(key);
      uniqueJobs.push(job);
    }
  }

  return uniqueJobs;
}

async function getJobs(options = {}) {
  if (!options.forceRefresh && isCacheValid()) {
    return readJobsCache();
  }

  const jobs = await fetchJobsFromWebFresh();
  writeJobsCache(jobs);

  return jobs;
}

function pdfToImages(pdfBuffer) {
  const workDir = path.join(__dirname, "tmp_ocr");

  if (fs.existsSync(workDir)) {
    fs.rmSync(workDir, {
      recursive: true,
      force: true
    });
  }

  fs.mkdirSync(workDir);

  const pdfPath = path.join(workDir, "resume.pdf");
  const outputPrefix = path.join(workDir, "page");

  fs.writeFileSync(pdfPath, pdfBuffer);

  execSync(`pdftoppm -png -r 300 "${pdfPath}" "${outputPrefix}"`);

  const files = fs
    .readdirSync(workDir)
    .filter(file => file.endsWith(".png"))
    .map(file => path.join(workDir, file))
    .sort();

  return {
    workDir,
    imageFiles: files
  };
}

async function analyzeResumeWithVision(pdfBuffer) {
  const { workDir, imageFiles } = pdfToImages(pdfBuffer);

  const imageContents = imageFiles.slice(0, 5).map(imagePath => {
    const base64 = fs.readFileSync(imagePath).toString("base64");

    return {
      type: "input_image",
      image_url: `data:image/png;base64,${base64}`
    };
  });

  const response = await client.responses.create({
    model: "gpt-4.1-mini",
    input: [
      {
        role: "user",
        content: [
          ...imageContents,
          {
            type: "input_text",
            text:
`職務経歴書を解析してください。

推測禁止。
書いてあることのみ。

重要:
- skillsには本文に明記されている具体スキル・経験だけを入れてください。
- SAPと明記されていない場合、SAP経験をskillsに入れないでください。
- ERP導入と明記されていない場合、ERP経験をskillsに入れないでください。
- CRM/SFA/Salesforceと明記されていない場合、CRM/SFA/Salesforce経験をskillsに入れないでください。
- IT、DX、PM、ERP、CRM、MAなどの抽象語を、本文根拠なしにskillsへ入れないでください。
- 「業務改善」だけでDXと判断しないでください。
- 「在庫管理」だけでSAP経験と判断しないでください。
- 「システム利用」だけでERP経験と判断しないでください。

JSONのみ返してください。

{
  "name":"",
  "current_company":"",
  "current_position":"",
  "skills":[],
  "industry":"",
  "yearsExperience":0,
  "location":"",
  "projects":[],
  "career_summary":"",
  "evidence":[
    {
      "field":"",
      "value":"",
      "evidence_text":""
    }
  ]
}
`
          }
        ]
      }
    ]
  });

  fs.rmSync(workDir, {
    recursive: true,
    force: true
  });

  return normalizeCandidate(safeJsonParse(response.output_text));
}


function isUsableJobForMatching(job) {
  const position = job.position || "";
  const url = job.url || "";
  const required = Array.isArray(job.required_skills) ? job.required_skills : [];

  if (!position || position === "職種名なし") return false;
  if (!url) return false;
  if (!required.length) return false;

  const lowerUrl = url.toLowerCase();

  const looksLikeListPage =
    lowerUrl.includes("jobsearch") ||
    lowerUrl.endsWith("/jobs/") ||
    lowerUrl.includes("#job_category") ||
    lowerUrl.includes("job.phtml#");

  if (looksLikeListPage) return false;

  return true;
}

function buildMatches(candidate, jobs) {
  const usableJobs = jobs.filter(isUsableJobForMatching);
  const matches = [];

  console.log(`matching target jobs: ${usableJobs.length}/${jobs.length}`);

  for (const job of usableJobs) {
    const result = calculateMatchScore(candidate, job);
    const pass = getDocumentPassLikelihood(result);

    const evidenceMap = buildEvidenceMap(candidate, [
      ...result.matchedRequired,
      ...result.matchedPreferred,
      ...result.matchedKeywords
    ]);

    matches.push({
      company: job.company,
      position: job.position,
      url: job.url,
      score: result.score,
      rank: getRank(result.score),

      scoreBreakdown: result.scoreBreakdown,
      scoreLogs: result.scoreLogs,

      requiredMatched: result.matchedRequired,
      requiredMissing: result.missingRequired,
      jobRequiredEvidence: job.required_evidence || {},
      jobPreferredEvidence: job.preferred_evidence || {},
      requiredTotal: result.requiredTotal,
      requiredMatchedCount: result.requiredMatchedCount,
      requiredMatchRate: result.requiredMatchRate,

      preferredMatched: result.matchedPreferred,
      keywordMatched: result.matchedKeywords,

      evidenceMap,

      recommendation_comment: generateAIComment(candidate, job, result),

      documentPassLikelihood: pass.label,
      documentPassReason: pass.reason
    });
  }

  matches.sort((a, b) => b.score - a.score);

  return matches;
}





app.post("/add-job-urls", async (req, res) => {
  try {
    const urlsText = req.body.urls || "";

    const urls = urlsText
      .split(/\n/)
      .map(v => v.trim())
      .filter(Boolean);

    if (!urls.length) {
      return res.status(400).json({
        message: "URLが入力されていません"
      });
    }

    const addedJobs = [];
    const errors = [];

    for (const url of urls) {
      try {
        console.log("manual job url:", url);

        let pageData = await fetchPageText(url);

        if (
          url.includes("js01.jposting.net/fortience") ||
          url.includes("fortience")
        ) {
          pageData = await fetchFortienceJobCodePageText(url);
        } else if (
          url.includes("pgst02.jposting.net") ||
          url.includes("deloittejapan.jposting.net")
        ) {
          pageData = await fetchDeloitteJobCodePageText(url);
        }

        // 手動URL追加では、非求人判定だけでスキップしない
        // job_code=3 のように求人本文があるのに誤判定されるケースがあるため
        // if (isNonJobPage(pageData.text, url)) {
        //   console.log("manual url skipped as non-job page:", url);
        //   errors.push({
        //     url,
        //     message: "求人ではなく、セミナー・イベント・説明会系ページと判定したため追加しませんでした"
        //   });
        //   continue;
        // }

        const source = {
          company: detectCompanyFromUrl(url),
          url
        };

        let normalizedJobs = [];

        const isFortienceManualUrl =
          detectCompanyFromUrl(url) === "Fortience" ||
          url.includes("fortience");

        const isDeloitteManualUrl =
          detectCompanyFromUrl(url) === "Deloitte" ||
          url.includes("pgst02.jposting.net") ||
          url.includes("deloittejapan.jposting.net");

        if (isFortienceManualUrl) {
          try {
            console.log("===== Fortience fetched text length =====");
            console.log(pageData.text ? pageData.text.length : 0);
            console.log("===== Fortience fetched text sample =====");
            console.log(String(pageData.text || "").slice(0, 4000));

            let fortienceJob = extractFortienceManualJobFromText(
              url,
              pageData.text
            );

            fortienceJob = augmentFortienceMustRequirements(fortienceJob, pageData.text);

            // Fortienceの必須要件が画面側で「なし」にならないよう、返却・保存用キーを強制統一
            const fortienceMust = Array.isArray(fortienceJob.mustRequirements)
              ? fortienceJob.mustRequirements
              : String(
                  fortienceJob.mustRequirements ||
                  fortienceJob.requiredRequirements ||
                  fortienceJob.requirements ||
                  fortienceJob.must ||
                  ""
                )
                  .split(/[、,\n]/)
                  .map(v => v.trim())
                  .filter(Boolean)
                  .filter(v => v !== "なし");

            if (fortienceMust.length) {
              fortienceJob.mustRequirements = fortienceMust;
              fortienceJob.requiredRequirements = fortienceMust;
              fortienceJob.requirements = fortienceMust;
              fortienceJob.must = fortienceMust.join("、");
              fortienceJob.required = fortienceMust.join("、");
            }

            normalizedJobs = [fortienceJob];
          } catch (e) {
            console.error("Fortience manual extract error:", url, e.message);
            errors.push({
              url,
              message: `Fortience求人抽出に失敗しました: ${e.message}`
            });
            continue;
          }
        } else if (isDeloitteManualUrl) {
          try {
            let deloitteJob = await extractDeloitteManualJobFromUrl(
              url,
              pageData.text
            );

            // Deloitte求人は、登録資格・共通要件・出身母体・受け入れランクを必須要件へ補強
            deloitteJob = augmentDeloitteMustRequirements(deloitteJob, pageData.text);

            normalizedJobs = [deloitteJob];
          } catch (e) {
            console.error("Deloitte manual extract error:", url, e.message);

            const fallbackJob = buildFallbackJobFromUrl(url, pageData.text);
            normalizedJobs = [normalizeJob(fallbackJob, source)];
          }
        } else {
          let jobs = [];

          try {
            jobs = await extractJobsFromDetailPage(
              source,
              url,
              pageData.text
            );
          } catch (e) {
            console.error("manual AI extract error:", url, e.message);
            jobs = [];
          }

          normalizedJobs = jobs
            .map(job => normalizeJob({
              ...job,
              url: job.url || url,
              company: job.company || detectCompanyFromUrl(url)
            }, source))
            .filter(job => job.position);

          if (!normalizedJobs.length) {
            const fallbackJob = buildFallbackJobFromUrl(url, pageData.text);
            normalizedJobs = [normalizeJob(fallbackJob, source)];
          }
        }

        addedJobs.push(...normalizedJobs);

      } catch (error) {
        console.error("manual url fetch error:", url, error.message);
        errors.push({
          url,
          message: error.message
        });
      }
    }

    if (!addedJobs.length) {
      return res.status(500).json({
        message: "求人を抽出できませんでした",
        addedCount: 0,
        errors
      });
    }

    writeJobsCache(addedJobs);

    res.json({
      message: "求人URLから求人を追加しました",
      addedCount: addedJobs.length,
      jobs: addedJobs,
      errors
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "求人URL追加失敗",
      error: error.message
    });
  }
});


app.post("/upload-resume", upload.single("resume"), async (req, res) => {
  try {
    const forceRefresh = req.query.refresh === "1";

    const candidate = await analyzeResumeWithVision(req.file.buffer);
    const jobs = await getJobs({ forceRefresh });
    const matches = buildMatches(candidate, jobs);

    const usableJobsCount = jobs.filter(isUsableJobForMatching).length;

    res.json({
      candidate,
      jobsCount: jobs.length,
      usableJobsCount,
      cacheUsed: !forceRefresh && isCacheValid(),
      matches
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "解析失敗",
      error: error.message
    });
  }
});

app.post("/manual-match", async (req, res) => {
  try {
    const forceRefresh = req.query.refresh === "1";

    const candidate = normalizeCandidate({
      name: req.body.name || "候補者",
      skills: Array.isArray(req.body.skills) ? req.body.skills : [],
      industry: req.body.industry || "Other",
      yearsExperience: req.body.yearsExperience || 0,
      location: req.body.location || "Tokyo",
      projects: [],
      career_summary: "",
      evidence: []
    });

    const jobs = await getJobs({ forceRefresh });
    const matches = buildMatches(candidate, jobs);

    const usableJobsCount = jobs.filter(isUsableJobForMatching).length;

    res.json({
      candidate,
      jobsCount: jobs.length,
      usableJobsCount,
      cacheUsed: !forceRefresh && isCacheValid(),
      matches
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "manual match error",
      error: error.message
    });
  }
});

app.post("/refresh-jobs", async (req, res) => {
  try {
    const jobs = await getJobs({ forceRefresh: true });

    res.json({
      message: "求人キャッシュを更新しました",
      jobsCount: jobs.length
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "求人キャッシュ更新失敗",
      error: error.message
    });
  }
});


app.get("/fetch-logs", (req, res) => {
  try {
    if (!fs.existsSync(FETCH_LOG_PATH)) {
      return res.json({
        exists: false,
        logs: []
      });
    }

    const data = JSON.parse(fs.readFileSync(FETCH_LOG_PATH, "utf8"));

    res.json({
      exists: true,
      createdAt: data.createdAt,
      logs: data.logs || []
    });
  } catch (error) {
    res.status(500).json({
      message: "fetch log read error",
      error: error.message
    });
  }
});

app.get("/jobs-cache", (req, res) => {
  try {
    if (!fs.existsSync(CACHE_PATH)) {
      return res.json({
        exists: false,
        jobsCount: 0,
        jobs: []
      });
    }

    const cache = JSON.parse(fs.readFileSync(CACHE_PATH, "utf8"));

    const companyCounts = {};

    for (const job of cache.jobs || []) {
      const company = job.company || "Unknown";
      companyCounts[company] = (companyCounts[company] || 0) + 1;
    }

    res.json({
      exists: true,
      createdAt: cache.createdAt,
      jobsCount: cache.count || cache.jobs.length,
      companyCounts,
      jobs: cache.jobs
    });
  } catch (error) {
    res.status(500).json({
      message: "cache read error",
      error: error.message
    });
  }
});

const PORT = 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


async function fetchDeloitteJobCodePageText(url) {
  const browser = await chromium.launch({
    headless: true
  });

  const context = await browser.newContext({
    ignoreHTTPSErrors: true
  });

  const page = await context.newPage();

  try {
    console.log("===== Deloitte job_code page fetch =====");
    console.log("URL:", url);

    await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout: 60000
    });

    await page.waitForTimeout(5000);

    // 念のため networkidle も待つ
    try {
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    } catch {}

    const title = await page.title().catch(() => "");

    const bodyText = await page.evaluate(() => {
      const body = document.body ? document.body.innerText : "";
      const tables = Array.from(document.querySelectorAll("table"))
        .map(t => t.innerText)
        .join("\n");

      const main = Array.from(document.querySelectorAll("main, article, section, div"))
        .map(el => el.innerText)
        .filter(Boolean)
        .sort((a, b) => b.length - a.length)[0] || "";

      return [body, tables, main].join("\n");
    });

    const text = [
      `PAGE_TITLE: ${title}`,
      bodyText
    ].join("\n");

    console.log("Deloitte fetched text length:", text.length);
    console.log("Deloitte fetched text sample:", text.slice(0, 1200));

    return {
      text,
      links: []
    };

  } finally {
    await browser.close();
  }
}

function extractRequiredSkillsBySection(text) {
  const body = String(text || "");

  const sectionLabels = [
    "必須条件",
    "必須要件",
    "応募資格",
    "応募要件",
    "登録資格",
    "応募条件",
    "求める経験",
    "求めるスキル",
    "必要な経験",
    "必要なスキル",
    "必要経験",
    "必要スキル",
    "経験・スキル",
    "スキル・経験",
    "資格・経験",
    "求める人材",
    "求める人物像",
    "Must",
    "MUST",
    "Requirements",
    "Required",
    "Required Skills",
    "Basic Qualifications"
  ];

  const stopLabels = [
    "歓迎条件",
    "歓迎要件",
    "WANT",
    "Want",
    "望ましい経験",
    "待遇",
    "勤務地",
    "勤務時間",
    "雇用形態",
    "休日",
    "福利厚生",
    "選考",
    "応募方法"
  ];

  for (const label of sectionLabels) {
    const idx = body.indexOf(label);
    if (idx === -1) continue;

    let end = body.length;

    for (const stop of stopLabels) {
      const stopIdx = body.indexOf(stop, idx + label.length);
      if (stopIdx !== -1 && stopIdx < end) {
        end = stopIdx;
      }
    }

    const section = body.slice(idx, end);

    const candidates = section
      .split(/\n|・|●|■|◇|◆|-/)
      .map(v => v.trim())
      .filter(v => v.length >= 4 && v.length <= 120)
      .filter(v => !sectionLabels.includes(v))
      .filter(v => !v.includes("歓迎"))
      .filter(v => !v.includes("勤務地"))
      .slice(0, 8);

    if (candidates.length) {
      return candidates;
    }
  }

  return [];
}


// Deloitte manual extractor alias fix
async function extractDeloitteManualJobFromUrl(url, pageText) {
  console.log("===== Deloitte manual extractor FINAL CALLED =====");
  console.log("URL:", url);
  console.log("TEXT SAMPLE:", String(pageText || "").slice(0, 1500));

  const source = {
    company: "Deloitte",
    url
  };

  try {
    const response = await client.responses.create({
      model: "gpt-4.1-mini",
      input:
`あなたは人材紹介会社のRAです。

以下はDeloitteの求人詳細ページ本文です。
必ず1件の求人としてJSON化してください。

重要:
- positionには求人タイトルを入れてください。
- required_skillsには、応募資格・必須条件・必須要件・求める経験・経験/スキル欄に書かれている具体要件だけを入れてください。
- preferred_skillsには、歓迎条件・望ましい要件・尚可条件を書いてください。
- role_keywordsには、仕事内容・領域・テーマを入れてください。
- required_evidenceには、required_skillsごとの根拠文を入れてください。
- 本文に「必須」という見出しがなくても、「応募資格」「登録資格」「求める経験」「経験/スキル」欄があれば required_skills として抽出してください。
- 推測は禁止です。
- JSONのみ返してください。

{
  "job": {
    "company": "Deloitte",
    "position": "",
    "url": "${url}",
    "required_skills": [],
    "required_evidence": {},
    "preferred_skills": [],
    "preferred_evidence": {},
    "role_keywords": [],
    "industry": "Consulting",
    "location": "Tokyo",
    "minExp": 0
  }
}

求人URL:
${url}

求人本文:
${String(pageText || "").slice(0, 30000)}
`
    });

    const parsed = safeJsonParse(response.output_text);

    if (parsed.job && parsed.job.position) {
      return normalizeJob({
        ...parsed.job,
        company: "Deloitte",
        url
      }, source);
    }
  } catch (e) {
    console.error("Deloitte FINAL AI extract error:", e.message);
  }

  const fallbackJob = buildFallbackJobFromUrl(url, pageText);
  const requiredBySection =
    typeof extractRequiredSkillsBySection === "function"
      ? extractRequiredSkillsBySection(pageText)
      : [];

  return normalizeJob({
    ...fallbackJob,
    company: "Deloitte",
    url,
    required_skills: requiredBySection,
    required_evidence: requiredBySection.reduce((acc, skill) => {
      acc[skill] = "Deloitte求人本文から抽出";
      return acc;
    }, {})
  }, source);
}


// ===== Deloitte求人: 登録資格・共通要件・出身母体・受け入れランクを必須要件へ補強 =====
function extractDeloitteExtraMustRequirements(rawText) {
  const text = String(rawText || "")
    .replace(/\r/g, "\n")
    .replace(/\n{3,}/g, "\n\n");

  const results = [];

  function add(v) {
    const x = String(v || "")
      .replace(/[ \t]+/g, " ")
      .replace(/^[・\-\s]+/, "")
      .trim();

    if (!x) return;
    if (x.length < 2) return;
    if (!results.includes(x)) results.push(x);
  }

  // 1. 登録資格 / 共通要件 / 個別要件 周辺を拾う
  const sectionHeadings = [
    "登録資格",
    "共通要件",
    "個別要件",
    "応募資格",
    "必須条件",
    "必須要件",
    "求める経験",
    "必要な経験",
    "MUST",
    "Required",
    "Requirements"
  ];

  const stopHeadings = [
    "歓迎要件",
    "歓迎条件",
    "望ましい経験",
    "勤務地",
    "待遇",
    "給与",
    "勤務時間",
    "休日",
    "福利厚生",
    "選考",
    "求人詳細を見る"
  ];

  const lines = text.split("\n").map(l => l.trim()).filter(Boolean);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const isStart = sectionHeadings.some(h => line.includes(h));

    if (!isStart) continue;

    for (let j = i + 1; j < Math.min(lines.length, i + 45); j++) {
      const l = lines[j];

      const isStop = stopHeadings.some(h => l.includes(h));
      if (isStop) break;

      // 長すぎる説明文は分割
      if (l.includes("、")) {
        l.split("、").forEach(add);
      } else {
        add(l);
      }
    }
  }

  // 2. 出身母体キーワードを拾う
  const backgroundKeywords = [
    "コンサルファーム出身",
    "戦略コンサルファーム出身",
    "総合コンサルファーム出身",
    "ITコンサルファーム出身",
    "事業会社出身",
    "金融機関出身",
    "金融機関IT部門出身",
    "SIer出身",
    "Sler出身",
    "ベンダー出身",
    "監査法人出身",
    "FAS出身",
    "PEファンド出身",
    "スタートアップ出身",
    "テクノロジ系スタートアップ出身"
  ];

  for (const kw of backgroundKeywords) {
    if (text.includes(kw)) add(kw);
  }

  // 3. 受け入れランク・クラスを拾う
  const rankKeywords = [
    "マネージャークラス",
    "スタッフクラス",
    "シニアスタッフ",
    "コンサルタントクラス",
    "シニアコンサルタント",
    "マネージャー以上",
    "シニアマネージャー",
    "ディレクター",
    "パートナー",
    "オペレーション・ITコンサルタント",
    "戦略コンサルタント",
    "事業会社出身スタッフクラス",
    "コンサルファーム出身者スタッフクラス",
    "コンサルファーム出身者マネージャークラス"
  ];

  for (const kw of rankKeywords) {
    if (text.includes(kw)) add(kw);
  }

  // 4. 語学・資格も拾う
  const skillKeywords = [
    "TOEIC700点以上",
    "TOEIC800点以上",
    "TOEIC850点以上",
    "英語力",
    "海外オフィスと電話会議が出来るレベル",
    "PMP資格",
    "CPA",
    "USCPA"
  ];

  for (const kw of skillKeywords) {
    if (text.includes(kw)) add(kw);
  }

  return results.slice(0, 80);
}

function augmentDeloitteMustRequirements(job, rawText) {
  if (!job || typeof job !== "object") return job;

  const extra = extractDeloitteExtraMustRequirements(rawText);
  if (!extra.length) return job;

  const candidateKeys = [
    "mustRequirements",
    "requiredRequirements",
    "requirements",
    "must",
    "required",
    "necessaryRequirements",
    "requiredSkills",
    "mustSkills"
  ];

  let touched = false;

  for (const key of candidateKeys) {
    if (Object.prototype.hasOwnProperty.call(job, key)) {
      const current = Array.isArray(job[key])
        ? job[key]
        : String(job[key] || "")
            .split(/[、,\n]/)
            .map(v => v.trim())
            .filter(Boolean);

      const merged = Array.from(new Set([...current, ...extra]));
      job[key] = Array.isArray(job[key]) ? merged : merged.join("、");
      touched = true;
    }
  }

  // どのキーも無い場合は、標準キーとして追加
  if (!touched) {
    job.mustRequirements = extra;
  }

  // 後でUI改善・DB改善するとき用に別項目にも保持
  job.backgroundFit = Array.from(new Set([
    ...(job.backgroundFit || []),
    ...extra.filter(x =>
      x.includes("出身") ||
      x.includes("SIer") ||
      x.includes("Sler") ||
      x.includes("ベンダー") ||
      x.includes("監査法人") ||
      x.includes("FAS") ||
      x.includes("PEファンド")
    )
  ]));

  job.acceptableRanks = Array.from(new Set([
    ...(job.acceptableRanks || []),
    ...extra.filter(x =>
      x.includes("クラス") ||
      x.includes("マネージャー") ||
      x.includes("スタッフ") ||
      x.includes("コンサルタント") ||
      x.includes("ディレクター") ||
      x.includes("パートナー")
    )
  ]));

  return job;
}


// ===== Fortience求人: 手動URL用抽出 =====
function extractFortienceManualJobFromText(url, rawText) {
  const text = String(rawText || "")
    .replace(/\r/g, "\n")
    .replace(/\n{3,}/g, "\n\n");

  const lines = text
    .split("\n")
    .map(l => l.trim())
    .filter(Boolean);

  function clean(v) {
    return String(v || "")
      .replace(/[ \t]+/g, " ")
      .replace(/^[:：・\-\s]+/, "")
      .trim();
  }

  function uniq(arr) {
    return Array.from(new Set(arr.map(clean).filter(Boolean)));
  }

  function extractTitle() {
    const badTitles = [
      "CAREER RECRUITING",
      "JOB DETAILS",
      "募集要項",
      "求人詳細",
      "職務内容",
      "仕事内容",
      "応募資格"
    ];

    const titleCandidates = [];

    for (const line of lines.slice(0, 40)) {
      if (badTitles.some(b => line.includes(b))) continue;
      if (line.includes("Fortience")) continue;
      if (line.length < 4) continue;
      if (line.length > 90) continue;
      if (/^https?:\/\//.test(line)) continue;

      if (
        line.includes("コンサル") ||
        line.includes("Consultant") ||
        line.includes("エンジニア") ||
        line.includes("マネージャ") ||
        line.includes("IT") ||
        line.includes("AI") ||
        line.includes("DX") ||
        line.includes("戦略")
      ) {
        titleCandidates.push(line);
      }
    }

    return titleCandidates[0] || `Fortience Job ${String(url).match(/job_code=(\d+)/)?.[1] || ""}`.trim();
  }

  function extractSection(startWords, stopWords, maxLines = 80) {
    const results = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const isStart = startWords.some(w => line.includes(w));

      if (!isStart) continue;

      // 見出し行自体に中身がある場合
      const afterHeading = startWords.reduce((acc, w) => {
        if (acc.includes(w)) return acc.split(w).slice(1).join(w);
        return acc;
      }, line);
      if (afterHeading && afterHeading !== line) results.push(afterHeading);

      for (let j = i + 1; j < Math.min(lines.length, i + maxLines); j++) {
        const l = lines[j];

        const isStop = stopWords.some(w => l.includes(w));
        if (isStop) break;

        if (!l) continue;
        if (l.length > 500) continue;

        results.push(l);
      }
    }

    return uniq(
      results
        .flatMap(v => String(v).split(/[・\n]/))
        .flatMap(v => String(v).split(/(?=【)/))
    );
  }

  const mustStart = [
    "必須条件",
    "必須要件",
    "応募資格",
    "求める経験",
    "必要な経験",
    "必要経験",
    "登録資格",
    "対象となる方",
    "MUST",
    "Required",
    "Requirements"
  ];

  const welcomeStart = [
    "歓迎条件",
    "歓迎要件",
    "歓迎経験",
    "尚可",
    "WANT",
    "Preferred",
    "歓迎する経験"
  ];

  const domainStart = [
    "領域",
    "サービス",
    "業務内容",
    "仕事内容",
    "職務内容",
    "プロジェクト"
  ];

  const stopForMust = [
    "歓迎条件",
    "歓迎要件",
    "歓迎経験",
    "尚可",
    "勤務地",
    "給与",
    "待遇",
    "勤務時間",
    "休日",
    "福利厚生",
    "選考",
    "会社概要",
    "職務内容",
    "仕事内容"
  ];

  const stopForWelcome = [
    "勤務地",
    "給与",
    "待遇",
    "勤務時間",
    "休日",
    "福利厚生",
    "選考",
    "会社概要",
    "職務内容",
    "仕事内容"
  ];

  const mustRequirements = extractSection(mustStart, stopForMust, 80);
  const preferredRequirements = extractSection(welcomeStart, stopForWelcome, 60);

  let domains = extractSection(domainStart, [
    "応募資格",
    "必須条件",
    "必須要件",
    "歓迎条件",
    "歓迎要件",
    "勤務地",
    "給与",
    "待遇"
  ], 30);

  domains = domains
    .filter(v => v.length <= 120)
    .slice(0, 20);

  return {
    company: "Fortience",
    position: extractTitle(),
    title: extractTitle(),
    url,
    mustRequirements: mustRequirements.length ? mustRequirements.slice(0, 40) : [],
    preferredRequirements: preferredRequirements.length ? preferredRequirements.slice(0, 40) : [],
    domains: domains.length ? domains : ["Fortience", "コンサルティング"],
    source: "manual-url",
    extractionSource: "fortience-manual"
  };
}


// ===== Fortience求人ページ: 文字化け回避fetch =====

function augmentFortienceMustRequirements(job, rawText) {
  if (!job || typeof job !== "object") return job;

  const text = String(rawText || "")
    .replace(/\r/g, "\n")
    .replace(/\n{3,}/g, "\n\n");

  const compact = text.replace(/\s+/g, " ");

  function uniq(arr) {
    return Array.from(new Set(
      arr
        .map(v => String(v || "").replace(/[ \t]+/g, " ").replace(/^[:：・\-●■□◆◇\s]+/, "").trim())
        .filter(Boolean)
        .filter(v => v !== "なし")
    ));
  }

  const picked = [];

  // 1. Qualifications / 応募条件 周辺をざっくり抜く
  const startPatterns = [
    "Qualifications",
    "Requirement",
    "Requirements",
    "応募資格",
    "応募条件",
    "必須条件",
    "必須要件",
    "求める経験",
    "求めるスキル",
    "必要な経験",
    "人材要件"
  ];

  const stopPatterns = [
    "Preferred",
    "歓迎条件",
    "歓迎要件",
    "Salary",
    "Benefits",
    "Location",
    "勤務地",
    "給与",
    "待遇",
    "福利厚生",
    "Open positions",
    "PAGE TOP",
    "会社概要"
  ];

  for (const start of startPatterns) {
    const si = compact.indexOf(start);
    if (si === -1) continue;

    let end = compact.length;
    for (const stop of stopPatterns) {
      const ei = compact.indexOf(stop, si + start.length);
      if (ei !== -1 && ei < end) end = ei;
    }

    const block = compact.slice(si + start.length, end).trim();

    block
      .split(/[、,。・\n]/)
      .map(v => v.trim())
      .filter(v => v.length >= 2 && v.length <= 120)
      .forEach(v => picked.push(v));
  }

  // 2. それでも弱い場合、本文から重要キーワードを直接拾う
  const keywordRules = [
    ["IT戦略", ["IT戦略経験", "IT戦略に関する知見"]],
    ["AI", ["AI開発経験", "AI活用・AI導入に関する知見"]],
    ["プロジェクトマネジメント", ["プロジェクトマネジメント経験"]],
    ["プロジェクトマネージメント", ["プロジェクトマネジメント経験"]],
    ["M&A", ["M&Aプロジェクト経験"]],
    ["MBSE", ["MBSEの知識・経験"]],
    ["CAD", ["CAD/PLM/BOMの知識"]],
    ["PLM", ["CAD/PLM/BOMの知識"]],
    ["BOM", ["CAD/PLM/BOMの知識"]],
    ["製造", ["製造業向けプロジェクト経験"]],
    ["インダストリーコンサルタント", ["インダストリー領域のコンサルティング経験"]]
  ];

  for (const [kw, items] of keywordRules) {
    if (compact.includes(kw)) {
      items.forEach(v => picked.push(v));
    }
  }

  let items = uniq(picked);

  // ノイズ除去
  items = items
    .filter(v => !v.includes("Salary"))
    .filter(v => !v.includes("Benefits"))
    .filter(v => !v.includes("Location"))
    .filter(v => !v.includes("PAGE TOP"))
    .filter(v => !v.includes("Open positions"))
    .filter(v => !v.includes("職種詳細"))
    .filter(v => !v.includes("フォーティエンスコンサルティング株式会社"))
    .filter(v => !v.includes("Qualifications"))
    .filter(v => !v.includes("Requirement"))
    .filter(v => !v.includes("【学歴】"))
    .filter(v => !v.includes("大学以上"))
    .filter(v => !v.includes("【必要な経験"))
    .filter(v => !v.includes("スキル等】"))
    .filter(v => v.length >= 3)
    .slice(0, 30);

  if (!items.length) {
    console.log("WARN: Fortience must requirements could not be extracted");
    return job;
  }

  const current = Array.isArray(job.mustRequirements)
    ? job.mustRequirements
    : String(job.mustRequirements || "")
        .split(/[、,\n]/)
        .map(v => v.trim())
        .filter(Boolean)
        .filter(v => v !== "なし");

  const merged = uniq([...current, ...items]);

  // 表示側・マッチング側どちらのキーでも拾えるように複数キーへ入れる
  job.mustRequirements = merged;
  job.requiredRequirements = merged;
  job.requirements = merged;
  job.must = merged.join("、");

  console.log("===== Fortience extracted must requirements =====");
  console.log(merged);

  return job;
}


async function fetchFortienceJobCodePageText(url) {
  console.log("===== Fortience job_code page fetch =====");
  console.log("URL:", url);

  const res = await fetch(url, {
    headers: {
      "User-Agent": "Mozilla/5.0",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
  });

  if (!res.ok) {
    throw new Error(`Fortience page fetch failed: ${res.status}`);
  }

  const buffer = Buffer.from(await res.arrayBuffer());

  const candidates = [
    iconv.decode(buffer, "EUC-JP"),
    iconv.decode(buffer, "Shift_JIS"),
    iconv.decode(buffer, "UTF-8")
  ];

  function badness(text) {
    const t = String(text || "");
    const mojibake = (t.match(/�/g) || []).length;
    const japanese = (t.match(/[ぁ-んァ-ヶ一-龠]/g) || []).length;
    return mojibake * 10 - japanese;
  }

  let html = candidates.sort((a, b) => badness(a) - badness(b))[0];

  let text = html
    .replace(/<script[\s\S]*?<\/script>/gi, "\n")
    .replace(/<style[\s\S]*?<\/style>/gi, "\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n")
    .replace(/<\/div>/gi, "\n")
    .replace(/<\/li>/gi, "\n")
    .replace(/<\/tr>/gi, "\n")
    .replace(/<[^>]+>/g, "\n")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\r/g, "\n")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{2,}/g, "\n")
    .trim();

  console.log("Fortience decoded text length:", text.length);
  console.log("Fortience decoded text sample:", text.slice(0, 2500));

  return { html, text };
}


// ===== Fortience求人: 必須要件の後処理補強 =====

