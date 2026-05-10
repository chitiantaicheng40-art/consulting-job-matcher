const express = require("express");
const fs = require("fs");

const app = express();
app.use(express.json());

const jobs = JSON.parse(
  fs.readFileSync("./references/jobs_database.json", "utf-8")
);

function calculateMatches(candidate) {
  const candidateSkills = candidate.skills || [];

  const results = jobs.map((job) => {
    let score = 0;
    const matchedSkills = [];

    job.required_skills.forEach((skill) => {
      if (candidateSkills.includes(skill)) {
        score += 50;
        matchedSkills.push(skill);
      }
    });

    return {
      company: job.company,
      position: job.position_name,
      job_code: job.job_code,
      location: job.location,
      level: job.level,
      score: score,
      matched_skills: matchedSkills
    };
  });

  return results.sort((a, b) => b.score - a.score);
}

app.get("/", (req, res) => {
  res.send("Consulting Job Matcher API");
});

app.get("/test-match", (req, res) => {
  const candidate = {
    name: "テスト候補者",
    skills: ["Salesforce", "CRM"]
  };

  res.json(calculateMatches(candidate));
});

app.post("/match", (req, res) => {
  const candidate = req.body;
  const matches = calculateMatches(candidate);

  res.json({
    candidate_name: candidate.name || "名前未設定",
    matches: matches
  });
});

app.listen(3000, () => {
  console.log("Server running");
});
