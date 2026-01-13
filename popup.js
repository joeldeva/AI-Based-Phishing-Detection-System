const currentUrlEl = document.getElementById("currentUrl");
const checkBtn = document.getElementById("checkBtn");
const resultBox = document.getElementById("resultBox");
const verdictEl = document.getElementById("verdict");
const scoreEl = document.getElementById("score");
const reasonsEl = document.getElementById("reasons");

function setBoxStyle(type) {
  resultBox.classList.remove("good", "warn", "bad");
  resultBox.classList.add(type);
}

async function getCurrentTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab.url;
}

async function callAPI(url) {
  const res = await fetch("http://127.0.0.1:8000/predict", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });

  if (!res.ok) throw new Error("API error: " + res.status);
  return await res.json();
}

function renderResult(data) {
  resultBox.style.display = "block";

  const risk = Number(data.risk_score || 0);

  // Map verdict to UI
  if (data.verdict === "TRUSTED_DOMAIN") {
    verdictEl.textContent = "✅ Trusted Domain";
    setBoxStyle("good");
  } else if (data.verdict === "HIGH_RISK_PHISHING") {
    verdictEl.textContent = "🚨 High Risk Phishing";
    setBoxStyle("bad");
  } else if (data.verdict === "SUSPICIOUS") {
    verdictEl.textContent = "⚠️ Suspicious (Review)";
    setBoxStyle("warn");
  } else {
    verdictEl.textContent = "✅ Likely Legit";
    setBoxStyle("good");
  }

  scoreEl.textContent = risk.toFixed(4);

  if (data.reasons && data.reasons.length) {
    reasonsEl.innerHTML = "<b>Reasons:</b><br>" + data.reasons.map(r => "• " + r).join("<br>");
  } else {
    reasonsEl.innerHTML = "";
  }
}

async function init() {
  try {
    const url = await getCurrentTabUrl();
    currentUrlEl.textContent = url;
  } catch (e) {
    currentUrlEl.textContent = "Could not read current tab URL.";
  }
}

checkBtn.addEventListener("click", async () => {
  checkBtn.textContent = "Checking...";
  checkBtn.disabled = true;

  try {
    const url = await getCurrentTabUrl();
    const data = await callAPI(url);
    renderResult(data);
  } catch (e) {
    resultBox.style.display = "block";
    verdictEl.textContent = "❌ Error";
    scoreEl.textContent = "-";
    reasonsEl.textContent = "Make sure FastAPI is running at http://127.0.0.1:8000";
    setBoxStyle("warn");
  } finally {
    checkBtn.textContent = "Check Current Site";
    checkBtn.disabled = false;
  }
});

init();
