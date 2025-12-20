/*SMART LOADER CONTROLS */

function showSmartLoader(title, subtitle, progress = 10) {
  document.getElementById("loaderMain").textContent = title;
  document.getElementById("loaderSub").textContent = subtitle;
  document.getElementById("smartProgress").style.width = progress + "%";
  document.getElementById("smartLoader").classList.remove("hidden");
}

function updateSmartLoader(progress, subtitle) {
  document.getElementById("smartProgress").style.width = progress + "%";
  if (subtitle) document.getElementById("loaderSub").textContent = subtitle;
}

function hideSmartLoader() {
  document.getElementById("smartLoader").classList.add("hidden");
}
/*BASIC UTILITIES*/

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function extractURLs(text) {
  return text.match(/https?:\/\/[^\s<>"')]+/gi) || [];
}

function shannonEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  return Object.values(freq)
    .reduce((e, f) => e - (f / str.length) * Math.log2(f / str.length), 0);
}

/*AI MODEL LOADING */
let aiModel = null;
let phishingModel = null;

async function loadAIModels() {
  showSmartLoader("Loading AI", "Initializing models…", 20);

  try {
    phishingModel = await tf.loadLayersModel("model/nlm/model.json");
    updateSmartLoader(50, "Custom phishing model loaded");
  } catch {
    phishingModel = null;
  }

  aiModel = await use.load();
  updateSmartLoader(90, "Semantic language model ready");

  setTimeout(hideSmartLoader, 500);
}

loadAIModels();

/* AI SEMANTIC + ML ANALYSIS*/

async function aiModelScore(text) {
  if (!aiModel) return { used: false, confidence: 0 };

  const embedding = await aiModel.embed([text]);
  const vector = embedding.arraySync()[0];
  embedding.dispose();

  let confidence = 0.3;

  if (phishingModel) {
    const input = tf.tensor([vector.slice(0, 256)]);
    const prediction = phishingModel.predict(input);
    confidence = prediction.dataSync()[0];
    input.dispose();
    prediction.dispose();
  }

  return {
    used: true,
    confidence: Math.min(1, Math.max(0, confidence))
  };
}

/* HEURISTIC ANALYSIS*/
const TRIGGERS = [
  "urgent","verify","password","otp","transfer",
  "account locked","reset","security alert","unauthorized"
];

function heuristicAnalyze(text) {
  let score = 0;
  const findings = [];
  const lower = text.toLowerCase();

  extractURLs(text).forEach(u => {
    score += 8;
    findings.push("URL detected: " + u);
  });

  TRIGGERS.forEach(w => {
    if (lower.includes(w)) {
      score += 3;
      findings.push("Trigger word: " + w);
    }
  });

  if (shannonEntropy(text) > 4.2) {
    score += 10;
    findings.push("High entropy detected");
  }

  return { score, findings };
}

/* FULL HYBRID ANALYSIS */

async function advancedAnalyze(text) {
  let score = 0;
  const findings = [];

  const heur = heuristicAnalyze(text);
  score += heur.score;
  findings.push(...heur.findings);

  const ai = await aiModelScore(text);
  if (ai.used) {
    const aiBoost = Math.round(ai.confidence * 40);
    score += aiBoost;
    findings.push(` AI Model Confidence: ${Math.round(ai.confidence * 100)}%`);
  }

  return {
    score: Math.min(100, score),
    findings
  };
}

/* MAIN SCAN HANDLER */
async function runScan() {
  const text = document.getElementById("input").value.trim();
  const statusEl = document.getElementById("status");
  const out = document.getElementById("output");

  if (!text) {
    statusEl.className = "unknown";
    statusEl.textContent = "Enter text to scan.";
    return;
  }

  showSmartLoader("Scanning", "AI analyzing content…", 30);

  const result = await advancedAnalyze(text);

  updateSmartLoader(90, "Finalizing results…");
  setTimeout(hideSmartLoader, 400);

  let level = "safe", msg = "Low Risk";
  if (result.score >= 75) { level = "danger"; msg = " HIGH RISK — Likely phishing"; }
  else if (result.score >= 45) { level = "warn"; msg = "⚠ Suspicious — Be cautious"; }

  statusEl.className = level;
  statusEl.textContent = `${msg} (Score: ${result.score})`;

  out.textContent =
    "--- Findings ---\n" +
    (result.findings.join("\n") || "None") +
    "\n\n--- Text ---\n" +
    text;
}

/* EVENTS*/
document.getElementById("scanBtn").onclick = runScan;

document.getElementById("input").oninput = () => {
  document.getElementById("status").className = "unknown";
  document.getElementById("status").textContent = "Ready to scan.";
  document.getElementById("output").textContent = "";
};
