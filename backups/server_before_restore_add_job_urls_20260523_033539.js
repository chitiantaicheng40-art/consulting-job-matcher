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

app.listen(3000, () => {
  console.log("Server running");
});
