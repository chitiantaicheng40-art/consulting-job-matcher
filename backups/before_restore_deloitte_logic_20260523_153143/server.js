const express = require("express");
const path = require("path");
const fs = require("fs");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const jobs = JSON.parse(fs.readFileSync("./references/jobs_database.json", "utf-8"));

function hasOverlap(a = [], b = []) {
  return a.some((x) => b.includes(x));
}

function calculateMatches(candidate) {
  const candidateSkills = candidate.skills || [];
  const candidateIndustry = candidate.industry || [];
  const candidateLocation = candidate.location || "";
  const years = candidate.years_experience || 0;

  return jobs.map((job) => {
    let score = 0;
    const matchedSkills = [];
    const matchReasons = [];

    job.required_skills.forEach((skill) => {
      if (candidateSkills.includes(skill)) {
        score += 30;
        matchedSkills.push(skill);
        matchReasons.push(`${skill} が必須スキルに一致`);
      }
    });

    if (hasOverlap(candidateIndustry, job.industry || []) || (job.industry || []).includes("All")) {
      score += 20;
      matchReasons.push("業界経験が求人対象と一致");
    }

    if (candidateLocation && candidateLocation === job.location) {
      score += 10;
      matchReasons.push("希望勤務地が一致");
    }

    if (years >= (job.min_years || 0) && years <= (job.max_years || 99)) {
      score += 15;
      matchReasons.push("経験年数が想定レンジ内");
    }

    if (job.new) {
      score += 5;
      matchReasons.push("新着求人のため優先度高め");
    }

    if (matchReasons.length === 0) {
      matchReasons.push("現時点では一致項目が少ない");
    }

    return {
      company: job.company,
      position: job.position_name,
      job_code: job.job_code,
      location: job.location,
      level: job.level,
      score,
      matched_skills: matchedSkills,
      match_reasons: matchReasons
    };
  }).sort((a, b) => b.score - a.score);
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/match", (req, res) => {
  const candidate = req.body;
  res.json({
    candidate_name: candidate.name || "名前未設定",
    matches: calculateMatches(candidate)
  });
});


// ===== jobs_cache.json を返すAPI =====
app.get("/jobs-cache", (req, res) => {
  try {
    const cachePath = path.join(__dirname, "jobs_cache.json");

    if (!fs.existsSync(cachePath)) {
      return res.json({
        exists: false,
        jobs: [],
        jobsCount: 0,
        companyCounts: {},
        createdAt: null
      });
    }

    const raw = fs.readFileSync(cachePath, "utf8");
    const parsed = JSON.parse(raw);

    const jobs = Array.isArray(parsed)
      ? parsed
      : Array.isArray(parsed.jobs)
        ? parsed.jobs
        : [];

    const companyCounts = {};
    for (const job of jobs) {
      const company = job.company || "Unknown";
      companyCounts[company] = (companyCounts[company] || 0) + 1;
    }

    res.json({
      exists: true,
      jobs,
      jobsCount: jobs.length,
      companyCounts,
      createdAt: parsed.createdAt || parsed.updatedAt || null
    });
  } catch (e) {
    console.error("jobs-cache error:", e);
    res.status(500).json({
      exists: false,
      jobs: [],
      jobsCount: 0,
      companyCounts: {},
      message: e.message
    });
  }
});


// ===== 手動求人URL追加API =====
app.post("/add-job-urls", async (req, res) => {
  try {
    const input = String(req.body?.urls || "");
    const urls = input
      .split(/\n/)
      .map(v => v.trim())
      .filter(Boolean);

    if (!urls.length) {
      return res.status(400).json({
        message: "URLが入力されていません",
        jobs: []
      });
    }

    const cachePath = path.join(__dirname, "jobs_cache.json");

    let cache = {
      jobs: [],
      createdAt: new Date().toISOString()
    };

    if (fs.existsSync(cachePath)) {
      const raw = fs.readFileSync(cachePath, "utf8");
      const parsed = JSON.parse(raw);
      cache = Array.isArray(parsed)
        ? { jobs: parsed, createdAt: new Date().toISOString() }
        : parsed;
      if (!Array.isArray(cache.jobs)) cache.jobs = [];
    }

    function stripHtml(html) {
      return String(html || "")
        .replace(/<script[\s\S]*?<\/script>/gi, " ")
        .replace(/<style[\s\S]*?<\/style>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/g, " ")
        .replace(/&amp;/g, "&")
        .replace(/\s+/g, " ")
        .trim();
    }

    function pickTitle(html, url) {
      const patterns = [
        /<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']/i,
        /<title[^>]*>([\s\S]*?)<\/title>/i,
        /<h1[^>]*>([\s\S]*?)<\/h1>/i
      ];

      for (const pat of patterns) {
        const m = String(html || "").match(pat);
        if (m && m[1]) {
          return stripHtml(m[1])
            .replace(/\s*\|.*$/g, "")
            .replace(/\s*[-｜].*$/g, "")
            .trim();
        }
      }

      return url.includes("hrmos.co/pages/abeamconsulting")
        ? "Abeam Consulting 手動追加求人"
        : "手動追加求人";
    }

    function detectCompany(url) {
      if (url.includes("abeamconsulting")) return "Abeam Consulting";
      if (url.includes("deloitte") || url.includes("pgst02.jposting.net")) return "Deloitte";
      if (url.includes("kpmg")) return "KPMG";
      if (url.includes("pwc")) return "PwC";
      if (url.includes("accenture")) return "Accenture";
      if (url.includes("fortience")) return "Fortience";
      return "Unknown";
    }

    function extractSection(text, labels) {
      const t = String(text || "");
      for (const label of labels) {
        const idx = t.indexOf(label);
        if (idx === -1) continue;

        const rest = t.slice(idx + label.length);
        const nextLabels = [
          "歓迎", "歓迎要件", "歓迎条件", "求める人物像",
          "勤務地", "勤務時間", "給与", "待遇", "福利厚生",
          "仕事内容", "業務内容", "応募資格", "必須要件", "必須条件"
        ];

        let end = rest.length;
        for (const nl of nextLabels) {
          const ni = rest.indexOf(nl);
          if (ni > 20 && ni < end) end = ni;
        }

        const section = rest.slice(0, end)
          .replace(/[■◆●・]/g, "、")
          .replace(/\s+/g, " ")
          .trim();

        if (section) return section;
      }

      return "";
    }

    const addedJobs = [];
    const errors = [];

    for (const url of urls) {
      try {
        const response = await fetch(url, {
          headers: {
            "User-Agent": "Mozilla/5.0"
          }
        });

        if (!response.ok) {
          errors.push({ url, message: `HTTP ${response.status}` });
          continue;
        }

        const html = await response.text();
        const text = stripHtml(html);

        const company = detectCompany(url);
        const title = pickTitle(html, url);

        const must =
          extractSection(text, ["必須要件", "必須条件", "応募資格", "必要な経験", "求める経験"]) ||
          "";

        const welcome =
          extractSection(text, ["歓迎要件", "歓迎条件", "歓迎する経験", "歓迎スキル"]) ||
          "";

        const job = {
          company,
          position: title,
          title,
          url,
          mustRequirements: must ? [must] : [],
          requiredRequirements: must ? [must] : [],
          required_skills: must ? [must] : [],
          preferredRequirements: welcome ? [welcome] : [],
          preferred_skills: welcome ? [welcome] : [],
          role_keywords: [],
          source: "manual-url",
          addedAt: new Date().toISOString()
        };

        const exists = cache.jobs.some(j => String(j.url || "") === url);
        if (!exists) {
          cache.jobs.push(job);
        }

        addedJobs.push(job);
      } catch (e) {
        errors.push({ url, message: e.message });
      }
    }

    cache.jobsCount = cache.jobs.length;
    cache.createdAt = cache.createdAt || new Date().toISOString();
    cache.updatedAt = new Date().toISOString();

    fs.writeFileSync(cachePath, JSON.stringify(cache, null, 2));

    res.json({
      message: `${addedJobs.length}件の求人を追加しました`,
      jobs: addedJobs,
      errors
    });
  } catch (e) {
    console.error("add-job-urls error:", e);
    res.status(500).json({
      message: e.message,
      jobs: []
    });
  }
});

app.listen(3000, () => {
  console.log("Server running");
});
