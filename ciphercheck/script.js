"use strict";

const COMMON_WORDS = [
  "password",
  "admin",
  "welcome",
  "letmein",
  "qwerty",
  "iloveyou",
  "monkey",
  "dragon",
  "football",
  "secret",
  "login",
  "princess",
  "sunshine",
  "master",
  "trustno1",
  "abc123",
  "changeme",
  "default",
  "root",
];

const KEYBOARD_SEQUENCES = ["qwerty", "asdfgh", "zxcvbn"];

const STRENGTH_BANDS = [
  { min: 0, max: 19, name: "Very Weak", key: "very-weak" },
  { min: 20, max: 39, name: "Weak", key: "weak" },
  { min: 40, max: 64, name: "Fair", key: "fair" },
  { min: 65, max: 84, name: "Strong", key: "strong" },
  { min: 85, max: 100, name: "Very Strong", key: "very-strong" },
];

const PATTERN_PENALTIES = {
  sequence: 25,
  common: 25,
  repetition: 22,
  repeatedSequence: 18,
  construction: 15,
};

const CHARACTER_POOLS = {
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{}:,.?",
};

function getStrengthBand(score) {
  return STRENGTH_BANDS.find((band) => score >= band.min && score <= band.max);
}

function lengthPoints(length) {
  if (length < 6) return 0;
  if (length < 8) return 6;
  if (length < 12) return 12;
  if (length < 16) return 27;
  if (length < 20) return 35;
  return 40;
}

function hasCharacter(password, expression) {
  return expression.test(password);
}

function hasSequentialRun(password) {
  let ascending = 1;
  let descending = 1;
  const normalized = password.toLowerCase();

  for (let index = 1; index < normalized.length; index += 1) {
    const previous = normalized.charCodeAt(index - 1);
    const current = normalized.charCodeAt(index);
    const isAsciiAlphaNumeric =
      (current >= 48 && current <= 57) ||
      (current >= 97 && current <= 122);
    const previousIsAsciiAlphaNumeric =
      (previous >= 48 && previous <= 57) ||
      (previous >= 97 && previous <= 122);

    if (!isAsciiAlphaNumeric || !previousIsAsciiAlphaNumeric) {
      ascending = 1;
      descending = 1;
      continue;
    }

    ascending = current === previous + 1 ? ascending + 1 : 1;
    descending = current === previous - 1 ? descending + 1 : 1;

    if (ascending >= 3 || descending >= 3) return true;
  }

  return false;
}

function hasRepeatedCharacterRun(password) {
  return /(.)\1{3,}/su.test(password);
}

function hasRepeatedSequence(password) {
  const normalized = password.toLowerCase();

  for (
    let sequenceLength = 2;
    sequenceLength <= Math.min(8, Math.floor(normalized.length / 2));
    sequenceLength += 1
  ) {
    for (
      let start = 0;
      start <= normalized.length - sequenceLength * 2;
      start += 1
    ) {
      const sequence = normalized.slice(start, start + sequenceLength);
      const repeated = normalized.slice(
        start + sequenceLength,
        start + sequenceLength * 2,
      );

      if (sequence === repeated && new Set(sequence).size > 1) return true;
    }
  }

  return false;
}

function normalizeForWordChecks(password) {
  return password.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function hasCommonWord(normalized) {
  return COMMON_WORDS.some((word) => normalized.includes(word));
}

function hasKeyboardPattern(normalized) {
  return KEYBOARD_SEQUENCES.some(
    (sequence) =>
      normalized.includes(sequence) ||
      normalized.includes([...sequence].reverse().join("")),
  );
}

function hasSimpleConstruction(normalized) {
  return /^[a-z]{3,}\d{1,6}$/.test(normalized);
}

function analyzePassword(password) {
  const value = String(password);
  const length = [...value].length;
  const categories = {
    uppercase: hasCharacter(value, /[A-Z]/),
    lowercase: hasCharacter(value, /[a-z]/),
    numbers: hasCharacter(value, /\d/),
    symbols: hasCharacter(value, /[^A-Za-z0-9]/),
  };
  const categoryCount = Object.values(categories).filter(Boolean).length;
  const uniqueCount = new Set([...value]).size;
  const uniquePoints =
    length === 0 ? 0 : Math.round((uniqueCount / length) * 15);
  const normalized = normalizeForWordChecks(value);
  const findings = [];

  if (hasSequentialRun(value)) {
    findings.push({
      id: "sequence",
      title: "Predictable sequence",
      explanation:
        "Three or more consecutive letters or digits appear in ascending or descending order.",
      recommendation:
        "Replace the run with unrelated characters rather than shifting or extending the sequence.",
    });
  }

  if (hasCommonWord(normalized) || hasKeyboardPattern(normalized)) {
    findings.push({
      id: "common",
      title: "Common password pattern",
      explanation:
        "The password contains a word from CipherCheck’s documented common-pattern list or a familiar keyboard row.",
      recommendation:
        "Avoid familiar words and keyboard patterns, including when they are combined with symbols or digits.",
    });
  }

  if (hasRepeatedCharacterRun(value)) {
    findings.push({
      id: "repetition",
      title: "Excessive character repetition",
      explanation:
        "The same character appears four or more times consecutively.",
      recommendation:
        "Replace repeated runs with different, unrelated characters.",
    });
  }

  if (hasRepeatedSequence(value)) {
    findings.push({
      id: "repeatedSequence",
      title: "Repeated sequence",
      explanation:
        "A sequence of two or more different characters is repeated immediately, such as “abcabc”.",
      recommendation:
        "Use a unique sequence instead of repeating part of the password.",
    });
  }

  if (hasSimpleConstruction(normalized)) {
    findings.push({
      id: "construction",
      title: "Predictable construction",
      explanation:
        "The password follows a letters-then-digits pattern, a common way to modify a word.",
      recommendation:
        "Avoid appending a number string to a word; use a longer, less structured combination.",
    });
  }

  const patternPoints = Math.max(
    0,
    25 -
      findings.reduce(
        (penalty, finding) => penalty + PATTERN_PENALTIES[finding.id],
        0,
      ),
  );
  const points = {
    length: lengthPoints(length),
    categories: categoryCount * 5,
    uniqueness: uniquePoints,
    patternResistance: patternPoints,
  };
  const score =
    length === 0
      ? 0
      : Math.min(
          100,
          points.length +
            points.categories +
            points.uniqueness +
            points.patternResistance,
        );
  const band = getStrengthBand(score);

  return {
    score,
    band,
    length,
    categories,
    uniqueCount,
    points,
    findings,
  };
}

function secureRandomIndex(maxExclusive, cryptoProvider = globalThis.crypto) {
  if (!Number.isInteger(maxExclusive) || maxExclusive < 1) {
    throw new RangeError("The random selection range must be a positive integer.");
  }
  if (!cryptoProvider || typeof cryptoProvider.getRandomValues !== "function") {
    throw new Error("Secure random generation is not available in this browser.");
  }

  const range = 0x100000000;
  const acceptanceLimit = Math.floor(range / maxExclusive) * maxExclusive;
  const randomValue = new Uint32Array(1);

  do {
    cryptoProvider.getRandomValues(randomValue);
  } while (randomValue[0] >= acceptanceLimit);

  return randomValue[0] % maxExclusive;
}

function generateSecurePassword(length, selectedCategories, cryptoProvider) {
  if (!Number.isInteger(length) || length < 1 || length > 64) {
    throw new RangeError("Choose a whole-number length from 1 to 64.");
  }
  if (!Array.isArray(selectedCategories) || selectedCategories.length === 0) {
    throw new Error("Select at least one character type.");
  }
  if (selectedCategories.length > length) {
    throw new RangeError(
      "The password is too short to include every selected character type.",
    );
  }

  const pools = selectedCategories.map((category) => {
    const characters = CHARACTER_POOLS[category];
    if (!characters) throw new Error("A selected character type is invalid.");
    return characters;
  });
  const allCharacters = pools.join("");
  const result = pools.map(
    (pool) => pool[secureRandomIndex(pool.length, cryptoProvider)],
  );

  while (result.length < length) {
    result.push(allCharacters[secureRandomIndex(allCharacters.length, cryptoProvider)]);
  }

  for (let index = result.length - 1; index > 0; index -= 1) {
    const swapIndex = secureRandomIndex(index + 1, cryptoProvider);
    [result[index], result[swapIndex]] = [result[swapIndex], result[index]];
  }

  return result.join("");
}

function renderAnalysis(password) {
  const results = document.getElementById("analysisResults");
  const result = analyzePassword(password);
  const band = result.band;
  const meter = document.getElementById("strengthMeter");
  const fill = document.getElementById("strengthFill");
  const label = document.getElementById("strengthLabel");
  const scoreValue = document.getElementById("scoreValue");
  const lengthPointsValue = document.getElementById("lengthPoints");
  const lengthDetail = document.getElementById("lengthDetail");
  const categoryPointsValue = document.getElementById("categoryPoints");
  const categoryDetail = document.getElementById("categoryDetail");
  const uniquenessPointsValue = document.getElementById("uniquenessPoints");
  const uniquenessDetail = document.getElementById("uniquenessDetail");
  const patternPointsValue = document.getElementById("patternPoints");
  const patternDetail = document.getElementById("patternDetail");
  const summary = document.getElementById("assessmentSummary");
  const findingsList = document.getElementById("findingsList");
  const findingCount = document.getElementById("findingCount");
  const categoryNames = {
    uppercase: "Uppercase",
    lowercase: "Lowercase",
    numbers: "Numbers",
    symbols: "Symbols",
  };
  const categoriesPresent = Object.entries(result.categories)
    .filter(([, present]) => present)
    .map(([category]) => categoryNames[category]);

  results.hidden = false;
  label.textContent = band.name;
  label.dataset.level = band.key;
  scoreValue.textContent = String(result.score);
  lengthPointsValue.textContent = `${result.points.length} / 40`;
  lengthDetail.textContent = `${result.length} characters`;
  categoryPointsValue.textContent = `${result.points.categories} / 20`;
  categoryDetail.textContent =
    categoriesPresent.length > 0 ? categoriesPresent.join(", ") : "None";
  uniquenessPointsValue.textContent = `${result.points.uniqueness} / 15`;
  uniquenessDetail.textContent = `${result.uniqueCount} unique`;
  patternPointsValue.textContent = `${result.points.patternResistance} / 25`;
  patternDetail.textContent =
    result.findings.length === 0
      ? "No listed patterns"
      : `${result.findings.length} detected`;
  meter.setAttribute("aria-valuenow", String(result.score));
  meter.setAttribute(
    "aria-valuetext",
    `${band.name}, ${result.score} out of 100 rule-based points`,
  );
  fill.style.width = `${result.score}%`;
  fill.dataset.level = band.key;
  summary.textContent = `Length: ${result.length} characters · ${Object.values(result.categories).filter(Boolean).length} of 4 character types · ${result.findings.length} detected ${result.findings.length === 1 ? "weakness" : "weaknesses"}.`;
  findingCount.textContent = `${result.findings.length} ${result.findings.length === 1 ? "finding" : "findings"}`;
  findingsList.replaceChildren();

  if (result.findings.length === 0) {
    const item = document.createElement("li");
    item.className = "no-findings";
    item.textContent =
      "No listed patterns were detected by these rules. This is not a breach check and does not guarantee that the password is safe.";
    findingsList.append(item);
    return;
  }

  for (const finding of result.findings) {
    const item = document.createElement("li");
    item.className = "finding";

    const title = document.createElement("p");
    title.className = "finding-title";
    const marker = document.createElement("span");
    marker.className = "finding-marker";
    marker.setAttribute("aria-hidden", "true");
    title.append(marker, document.createTextNode(finding.title));

    const explanation = document.createElement("p");
    explanation.className = "finding-copy";
    explanation.textContent = finding.explanation;

    const recommendation = document.createElement("p");
    recommendation.className = "finding-recommendation";
    const prefix = document.createElement("strong");
    prefix.textContent = "Recommendation: ";
    recommendation.append(prefix, document.createTextNode(finding.recommendation));

    item.append(title, explanation, recommendation);
    findingsList.append(item);
  }
}

function initAnalyzer() {
  const input = document.getElementById("passwordInput");
  const analyzeButton = document.getElementById("analyzeButton");
  const results = document.getElementById("analysisResults");

  const analyze = () => {
    if (!input.value) {
      input.focus();
      return;
    }
    renderAnalysis(input.value);
  };

  analyzeButton.addEventListener("click", analyze);

  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      analyze();
    }
  });

  input.addEventListener("input", () => {
    if (input.value.length === 0) {
      results.hidden = true;
      return;
    }
    renderAnalysis(input.value);
  });
}

function initGenerator() {
  const lengthInput = document.getElementById("lengthInput");
  const lengthHint = document.getElementById("lengthHint");
  const categoryInputs = [
    ...document.querySelectorAll('input[name="characterType"]'),
  ];
  const output = document.getElementById("generatedPassword");
  const generateButton = document.getElementById("generateButton");
  const copyButton = document.getElementById("copyButton");
  const status = document.getElementById("generatorStatus");

  const clearOutput = () => {
    output.value = "";
    copyButton.disabled = true;
    status.textContent = "";
    status.removeAttribute("data-state");
  };

  const selectedCategories = () =>
    categoryInputs
      .filter((input) => input.checked)
      .map((input) => input.value);

  const validateConfiguration = () => {
    const rawLength = lengthInput.value.trim();
    const length = Number(rawLength);
    const categories = selectedCategories();
    let message = "";

    if (!/^\d+$/.test(rawLength) || !Number.isInteger(length)) {
      message = "Enter a whole-number length.";
    } else if (length < 1 || length > 64) {
      message = "Choose a length from 1 to 64.";
    } else if (categories.length === 0) {
      message = "Select at least one character type.";
    } else if (categories.length > length) {
      message = `Length ${length} is too short for ${categories.length} selected character types.`;
    }

    lengthInput.setAttribute("aria-invalid", message ? "true" : "false");
    lengthHint.textContent = message || "Choose a length from 1 to 64.";
    if (message) {
      lengthHint.dataset.state = "error";
    } else {
      lengthHint.removeAttribute("data-state");
    }

    return message ? null : { length, categories };
  };

  const onConfigurationChange = () => {
    clearOutput();
    validateConfiguration();
  };

  lengthInput.addEventListener("input", onConfigurationChange);
  for (const input of categoryInputs) {
    input.addEventListener("change", onConfigurationChange);
  }

  generateButton.addEventListener("click", () => {
    clearOutput();
    const configuration = validateConfiguration();
    if (!configuration) {
      status.textContent = "Update the settings before generating a password.";
      status.dataset.state = "error";
      return;
    }

    try {
      output.value = generateSecurePassword(
        configuration.length,
        configuration.categories,
      );
      copyButton.disabled = false;
      status.textContent = "Generated locally with Web Crypto.";
      status.removeAttribute("data-state");
    } catch (error) {
      status.textContent =
        error instanceof Error
          ? error.message
          : "The password could not be generated.";
      status.dataset.state = "error";
    }
  });

  copyButton.addEventListener("click", async () => {
    if (!output.value) return;

    try {
      if (!navigator.clipboard || !navigator.clipboard.writeText) {
        throw new Error("Clipboard access is unavailable.");
      }
      await navigator.clipboard.writeText(output.value);
      status.textContent = "Password copied to clipboard.";
      status.removeAttribute("data-state");
    } catch {
      status.textContent =
        "Could not copy automatically. Select the generated password and copy it manually.";
      status.dataset.state = "error";
    }
  });

  validateConfiguration();
}

const THEME_STORAGE_KEY = "ciphercheck-theme";

function applyTheme(theme, isUserAction = false) {
  const effectiveTheme = theme === "dark" ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", effectiveTheme);

  const metaTheme = document.querySelector('meta[name="theme-color"]');
  if (metaTheme) {
    metaTheme.setAttribute(
      "content",
      effectiveTheme === "dark" ? "#0f1411" : "#f4f6f3",
    );
  }

  const toggle = document.getElementById("themeToggle");
  const label = document.getElementById("themeLabel");
  if (toggle) {
    const nextThemeLabel = effectiveTheme === "dark" ? "Light" : "Dark";
    toggle.setAttribute(
      "aria-label",
      `Switch to ${nextThemeLabel.toLowerCase()} theme`,
    );
    toggle.setAttribute(
      "title",
      `Switch to ${nextThemeLabel.toLowerCase()} theme`,
    );
    if (label) {
      label.textContent = nextThemeLabel;
    }
  }

  if (isUserAction) {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, effectiveTheme);
    } catch (_) {}
  }
}

function getStoredTheme() {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY);
  } catch (_) {
    return null;
  }
}

function getSystemTheme() {
  return window.matchMedia &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function initThemeToggle() {
  const toggle = document.getElementById("themeToggle");
  const stored = getStoredTheme();
  const currentTheme = stored || getSystemTheme();

  applyTheme(currentTheme, false);

  if (toggle) {
    toggle.addEventListener("click", () => {
      const activeTheme =
        document.documentElement.getAttribute("data-theme") || "light";
      const newTheme = activeTheme === "dark" ? "light" : "dark";
      applyTheme(newTheme, true);
    });
  }

  if (window.matchMedia) {
    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = (e) => {
      if (!getStoredTheme()) {
        applyTheme(e.matches ? "dark" : "light", false);
      }
    };
    if (typeof mediaQuery.addEventListener === "function") {
      mediaQuery.addEventListener("change", handler);
    } else if (typeof mediaQuery.addListener === "function") {
      mediaQuery.addListener(handler);
    }
  }
}

function initAuth() {
  const dialog = document.getElementById("authDialog");
  const openBtn = document.getElementById("authOpenButton");
  const closeBtn = document.getElementById("authModalClose");
  const buttonLabel = document.getElementById("authButtonLabel");
  const guestView = document.getElementById("authGuestView");
  const userView = document.getElementById("authUserView");
  const tabLogin = document.getElementById("tabLogin");
  const tabRegister = document.getElementById("tabRegister");
  const panelLogin = document.getElementById("panelLogin");
  const panelRegister = document.getElementById("panelRegister");
  const loginForm = document.getElementById("loginForm");
  const registerForm = document.getElementById("registerForm");
  const loginStatus = document.getElementById("loginStatus");
  const registerStatus = document.getElementById("registerStatus");
  const profileEmail = document.getElementById("profileEmail");
  const profileUserId = document.getElementById("profileUserId");
  const profileCreated = document.getElementById("profileCreated");
  const profileVerified = document.getElementById("profileVerified");
  const logoutBtn = document.getElementById("logoutButton");
  const forgotBtn = document.getElementById("forgotPasswordBtn");

  const updateAuthUI = (user) => {
    if (user) {
      if (buttonLabel) {
        buttonLabel.textContent = user.email.split("@")[0];
      }
      if (guestView) guestView.hidden = true;
      if (userView) userView.hidden = false;
      if (profileEmail) profileEmail.textContent = user.email;
      if (profileUserId) profileUserId.textContent = `#${user.id}`;
      if (profileCreated) {
        profileCreated.textContent = new Date(user.createdAt).toLocaleDateString();
      }
      if (profileVerified) {
        profileVerified.textContent = user.isVerified
          ? "Verified"
          : "Unverified (SMTP offline)";
      }
    } else {
      if (buttonLabel) buttonLabel.textContent = "Sign in";
      if (guestView) guestView.hidden = false;
      if (userView) userView.hidden = true;
    }
  };

  const switchTab = (tab) => {
    if (tab === "login") {
      tabLogin.classList.add("active");
      tabLogin.setAttribute("aria-selected", "true");
      tabRegister.classList.remove("active");
      tabRegister.setAttribute("aria-selected", "false");
      panelLogin.hidden = false;
      panelRegister.hidden = true;
    } else {
      tabRegister.classList.add("active");
      tabRegister.setAttribute("aria-selected", "true");
      tabLogin.classList.remove("active");
      tabLogin.setAttribute("aria-selected", "false");
      panelRegister.hidden = false;
      panelLogin.hidden = true;
    }
    if (loginStatus) {
      loginStatus.textContent = "";
      loginStatus.removeAttribute("data-state");
    }
    if (registerStatus) {
      registerStatus.textContent = "";
      registerStatus.removeAttribute("data-state");
    }
  };

  if (tabLogin) tabLogin.addEventListener("click", () => switchTab("login"));
  if (tabRegister) tabRegister.addEventListener("click", () => switchTab("register"));

  if (openBtn && dialog) {
    openBtn.addEventListener("click", () => {
      if (typeof dialog.showModal === "function") {
        dialog.showModal();
      } else {
        dialog.setAttribute("open", "");
      }
      openBtn.setAttribute("aria-expanded", "true");
    });
  }

  const closeDialog = () => {
    if (dialog) {
      if (typeof dialog.close === "function") {
        dialog.close();
      } else {
        dialog.removeAttribute("open");
      }
    }
    if (openBtn) openBtn.setAttribute("aria-expanded", "false");
  };

  if (closeBtn) closeBtn.addEventListener("click", closeDialog);
  if (dialog) {
    dialog.addEventListener("click", (e) => {
      const rect = dialog.getBoundingClientRect();
      const isInDialog =
        rect.top <= e.clientY &&
        e.clientY <= rect.top + rect.height &&
        rect.left <= e.clientX &&
        e.clientX <= rect.left + rect.width;
      if (!isInDialog) {
        closeDialog();
      }
    });
  }

  async function checkSession() {
    try {
      const res = await fetch("/api/auth/me");
      if (res.ok) {
        const data = await res.json();
        updateAuthUI(data.user);
      } else {
        updateAuthUI(null);
      }
    } catch (_) {
      updateAuthUI(null);
    }
  }

  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      loginStatus.textContent = "";
      loginStatus.removeAttribute("data-state");

      const email = document.getElementById("loginEmail").value.trim();
      const password = document.getElementById("loginPassword").value;

      if (!email || !password) {
        loginStatus.textContent = "Please fill in all fields.";
        loginStatus.dataset.state = "error";
        return;
      }

      try {
        const res = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password }),
        });
        const data = await res.json();
        if (res.ok && data.user) {
          loginStatus.textContent = "Signed in successfully.";
          updateAuthUI(data.user);
          loginForm.reset();
        } else {
          loginStatus.textContent = data.error || "Failed to sign in.";
          loginStatus.dataset.state = "error";
        }
      } catch (err) {
        loginStatus.textContent = "Connection error. Please try again.";
        loginStatus.dataset.state = "error";
      }
    });
  }

  if (registerForm) {
    registerForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      registerStatus.textContent = "";
      registerStatus.removeAttribute("data-state");

      const email = document.getElementById("registerEmail").value.trim();
      const password = document.getElementById("registerPassword").value;

      if (!email || !password) {
        registerStatus.textContent = "Please fill in all fields.";
        registerStatus.dataset.state = "error";
        return;
      }

      if (password.length < 8) {
        registerStatus.textContent = "Password must be at least 8 characters.";
        registerStatus.dataset.state = "error";
        return;
      }

      try {
        const res = await fetch("/api/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password }),
        });
        const data = await res.json();
        if (res.ok && data.user) {
          registerStatus.textContent = "Account created successfully.";
          updateAuthUI(data.user);
          registerForm.reset();
        } else {
          registerStatus.textContent = data.error || "Registration failed.";
          registerStatus.dataset.state = "error";
        }
      } catch (err) {
        registerStatus.textContent = "Connection error. Please try again.";
        registerStatus.dataset.state = "error";
      }
    });
  }

  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      try {
        await fetch("/api/auth/logout", { method: "POST" });
        updateAuthUI(null);
        switchTab("login");
      } catch (_) {
        updateAuthUI(null);
      }
    });
  }

  if (forgotBtn) {
    forgotBtn.addEventListener("click", async () => {
      loginStatus.textContent =
        "Notice: SMTP email delivery service is currently not configured. Password recovery is unavailable in this environment.";
      loginStatus.dataset.state = "error";
    });
  }

  checkSession();
}

document.addEventListener("DOMContentLoaded", () => {
  initThemeToggle();
  initAnalyzer();
  initGenerator();
  initAuth();
});

