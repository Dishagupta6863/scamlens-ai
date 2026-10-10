(() => {
  const tabs = [...document.querySelectorAll(".mode-tab")];
  const textarea = document.querySelector("#scan-content");
  const label = document.querySelector("#input-label");
  const hint = document.querySelector("#input-hint");
  const count = document.querySelector("#char-count");
  const button = document.querySelector("#analyze-button");
  const sampleButton = document.querySelector("#sample-button");
  const error = document.querySelector("#error-message");
  const result = document.querySelector("#result-card");
  const modelBox = document.querySelector("#model-score");
  const signalList = document.querySelector("#signal-list");
  const signalsBlock = document.querySelector("#signals-block");
  const scoreRing = document.querySelector("#score-ring");
  let mode = "message";

  const samples = {
    message: "Your account will be suspended immediately. Reply with your OTP to restore access.",
    url: "https://account-verify.example/login",
  };

  function updateMode(nextMode) {
    mode = nextMode;
    for (const tab of tabs) {
      const active = tab.dataset.mode === mode;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
    }
    document.querySelector("#scan-panel").setAttribute("aria-labelledby", `${mode}-tab`);
    label.textContent = mode === "message" ? "Paste the message you received" : "Paste the link you want to inspect";
    hint.textContent = mode === "message" ? "Include the full message for more context." : "ScamLens checks the URL text only; it will not open the link.";
    textarea.placeholder = mode === "message"
      ? "Example: Your account will be suspended immediately. Verify your details at…"
      : "Example: https://example.com/account/verify";
    textarea.value = "";
    updateCount();
    result.hidden = true;
    error.hidden = true;
  }

  function updateCount() {
    count.textContent = `${textarea.value.length.toLocaleString()} / 5,000`;
  }

  function addText(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = text;
    return node;
  }

  function showResult(data) {
    const score = Math.max(0, Math.min(100, Number(data.score) || 0));
    document.querySelector("#risk-score").textContent = String(score);
    document.querySelector("#risk-summary").textContent = data.summary;
    document.querySelector("#risk-advice").textContent = data.advice;

    const labelNode = document.querySelector("#risk-label");
    labelNode.textContent = data.label;
    labelNode.className = "result-label";
    scoreRing.style.setProperty("--score", `${score * 3.6}deg`);
    let tint = "var(--teal)";
    if (score >= 60) {
      labelNode.classList.add("high");
      tint = "var(--red)";
    } else if (score >= 30) {
      labelNode.classList.add("medium");
      tint = "var(--amber)";
    }
    scoreRing.style.setProperty("--score-color", tint);

    signalList.replaceChildren();
    if (data.signals.length) {
      for (const signal of data.signals) {
        const item = document.createElement("li");
        item.append(addText("strong", "", signal.title));
        item.append(document.createTextNode(signal.detail));
        signalList.append(item);
      }
    } else {
      const item = document.createElement("li");
      item.className = "no-signals";
      item.textContent = "No configured warning signs were found. That does not prove the content is safe.";
      signalList.append(item);
    }

    const modelScore = mode === "message" ? data.spam_model_score : data.url_model_score;
    const clues = mode === "message" ? data.spam_model_clues : data.url_model_clues;
    if (modelScore === null || modelScore === undefined) {
      modelBox.hidden = true;
      modelBox.replaceChildren();
    } else {
      modelBox.hidden = false;
      modelBox.replaceChildren();
      const modelName = mode === "message" ? "SMS spam model score" : "Phishing URL model score";
      modelBox.append(addText("strong", "", `${modelName} (uncalibrated): ${Math.round(modelScore * 100)}%`));
      modelBox.append(addText("small", "", "This raw class score is not the probability that the content is fraudulent."));
      if (clues && clues.length) {
        const list = document.createElement("ul");
        list.className = "model-clues";
        for (const clue of clues) list.append(addText("li", "", clue));
        modelBox.append(list);
      }
    }

    result.hidden = false;
    result.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  async function analyzeInput() {
    const content = textarea.value.trim();
    error.hidden = true;
    if (!content) {
      error.textContent = "Paste a message or URL first.";
      error.hidden = false;
      textarea.focus();
      return;
    }
    button.disabled = true;
    button.querySelector("span").textContent = "Checking signals…";
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content, scan_type: mode }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The analysis could not be completed.");
      showResult(data);
    } catch (requestError) {
      error.textContent = requestError.message || "Could not reach ScamLens. Please try again.";
      error.hidden = false;
    } finally {
      button.disabled = false;
      button.querySelector("span").textContent = "Analyze signals";
    }
  }

  tabs.forEach((tab) => tab.addEventListener("click", () => updateMode(tab.dataset.mode)));
  textarea.addEventListener("input", updateCount);
  button.addEventListener("click", analyzeInput);
  textarea.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") analyzeInput();
  });
  sampleButton.addEventListener("click", () => {
    textarea.value = samples[mode];
    updateCount();
    textarea.focus();
  });
  document.querySelector("#reset-button").addEventListener("click", () => {
    result.hidden = true;
    textarea.value = "";
    updateCount();
    textarea.focus();
  });
})();
