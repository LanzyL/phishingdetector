const GLOSSARY = {
  ip: "IP address — the raw numeric address of a server (e.g. 192.168.1.1). Legitimate businesses almost always use a readable domain name instead.",
  https: "HTTPS encrypts the data sent between your browser and the site. Its absence alone doesn't prove a scam, but it's a red flag combined with other signs.",
  "at-trick": "The \"@\" symbol trick: browsers ignore everything before an @ in a link, so scammers use it to make a fake URL look like it points to a trusted site.",
  subdomain: "A subdomain is the part of a domain before the main name (e.g. \"login.example.com\"). Scammers stack fake subdomains to bury the real destination.",
  urgency: "Urgency / trust-bait language is wording designed to make you act fast without thinking — a core tactic in phishing and voice-phishing scams.",
  typosquatting: "Typosquatting is registering a domain that looks almost identical to a real brand (e.g. \"paypa1.com\") to trick people who don't look closely.",
  shortener: "A URL shortener hides the real destination behind a short link, making it harder to see where you're actually being sent before you click.",
  tld: "A TLD (top-level domain) is the ending of a domain (.com, .xyz, .top). Some cheap or free TLDs are disproportionately used for scam sites.",
  homograph: "A homograph attack uses lookalike characters from other alphabets (e.g. a Cyrillic \"а\") to create a domain that looks identical to a real one.",
  "credential-harvesting": "Credential harvesting is when a message directly asks for passwords, PINs, or one-time codes — something no legitimate company asks for this way.",
  "mass-phishing": "Generic greetings like \"Dear Customer\" instead of your real name suggest a bulk message sent to thousands of people, not a real personal notice.",
  "money-mule": "Requests for gift cards, wire transfers, or crypto payments are a major red flag, since these are hard to trace or reverse once sent.",
  impersonation: "Impersonation and threats — pretending to be police, a bank, or a government agency and threatening arrest or account loss to trigger panic — is exactly the tactic used by the scam call centers in \"On the Line.\""
};

const KNOWN_BRANDS = [
  { name: "paypal",   realDomain: "paypal.com" },
  { name: "google",   realDomain: "google.com" },
  { name: "facebook", realDomain: "facebook.com" },
  { name: "apple",    realDomain: "apple.com" },
  { name: "amazon",   realDomain: "amazon.com" },
  { name: "microsoft",realDomain: "microsoft.com" },
  { name: "netflix",  realDomain: "netflix.com" },
];

const URGENCY_WORDS = [
  "verify-now", "act-now", "confirm-now", "claim-reward", "claim-prize",
  "suspended", "unusual-activity", "security-alert", "locked-out",
  "click-here", "limited-time", "you-won", "winner-selected"
];

const SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"
];

const SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".work", ".loan", ".gq", ".tk", ".ml", ".cf"];

function ruleUsesIP(url, link) {
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(link.hostname);
  return { flagged: isIP, why: isIP
    ? "The link uses a raw IP address instead of a normal domain name."
    : "The link uses a normal domain name, not a raw IP address." };
}

function ruleNoHTTPS(url, link) {
  const insecure = link.protocol !== "https:";
  return { flagged: insecure, why: insecure
    ? "The link does not use HTTPS (no padlock), so data sent isn't encrypted."
    : "The link uses HTTPS, which encrypts the connection." };
}

function ruleHasAtSymbol(url) {
  const hasAt = url.includes("@");
  return { flagged: hasAt, why: hasAt
    ? 'Contains an "@" symbol, a classic trick to disguise the real destination.'
    : 'No "@" symbol trick found.' };
}

function ruleTooManySubdomains(url, link) {
  const dotCount = (link.hostname.match(/\./g) || []).length;
  const tooMany = dotCount >= 4;
  return { flagged: tooMany, why: tooMany
    ? `The domain has an unusually large number of sub-parts (${dotCount} dots).`
    : "The domain structure looks like a normal number of parts." };
}

function ruleHyphens(url, link) {
  const hyphens = (link.hostname.match(/-/g) || []).length;
  const many = hyphens >= 2;
  return { flagged: many, why: many
    ? `The domain name has several hyphens (${hyphens}), often used to fake official-sounding names.`
    : "The domain doesn't have an unusual number of hyphens." };
}

function ruleUrgencyWords(url) {
  const lower = url.toLowerCase();
  const found = URGENCY_WORDS.filter(word => lower.includes(word));
  return { flagged: found.length > 0, why: found.length > 0
    ? `Contains urgency/trust-bait phrasing: ${found.join(", ")}.`
    : "No common urgency or trust-bait phrasing found." };
}

function ruleFakeBrand(url, link) {
  const lower = url.toLowerCase();
  for (const brand of KNOWN_BRANDS) {
    if (lower.includes(brand.name)) {
      const isRealDomain = link.hostname === brand.realDomain ||
                            link.hostname.endsWith("." + brand.realDomain);
      if (!isRealDomain) {
        return { flagged: true, why: `Mentions "${brand.name}" but the domain isn't ${brand.realDomain}.` };
      }
    }
  }
  return { flagged: false, why: "No mismatched brand name detected." };
}

function ruleLongURL(url) {
  const long = url.length > 75;
  return { flagged: long, why: long
    ? `The link is quite long (${url.length} characters), which can hide suspicious parts.`
    : "The link length looks normal." };
}

function ruleShortener(url, link) {
  const flagged = SHORTENERS.includes(link.hostname);
  return { flagged, why: flagged
    ? "Uses a URL-shortening service, which hides the real destination until you click."
    : "Not a known URL-shortening service." };
}

function ruleSuspiciousTLD(url, link) {
  const flagged = SUSPICIOUS_TLDS.some(tld => link.hostname.endsWith(tld));
  return { flagged, why: flagged
    ? `Ends in a domain extension (${link.hostname.slice(link.hostname.lastIndexOf("."))}) frequently abused for scam sites.`
    : "Domain ending looks normal." };
}

function ruleHomograph(url, link) {
  const flagged = link.hostname.split(".").some(part => part.startsWith("xn--"));
  return { flagged, why: flagged
    ? "Domain uses encoded international characters — a common trick for lookalike domains."
    : "No hidden lookalike-character encoding detected." };
}

const RULES = [
  { label: "Uses a raw IP address",           weight: 3, fn: ruleUsesIP,            glossaryKey: "ip" },
  { label: "Brand name doesn't match domain", weight: 3, fn: ruleFakeBrand,          glossaryKey: "typosquatting" },
  { label: "Hidden lookalike characters",     weight: 3, fn: ruleHomograph,          glossaryKey: "homograph" },
  { label: "Missing HTTPS encryption",        weight: 2, fn: ruleNoHTTPS,            glossaryKey: "https" },
  { label: '"@" symbol disguise trick',       weight: 2, fn: ruleHasAtSymbol,        glossaryKey: "at-trick" },
  { label: "URL shortener hides destination", weight: 2, fn: ruleShortener,          glossaryKey: "shortener" },
  { label: "Suspicious domain extension",     weight: 1, fn: ruleSuspiciousTLD,      glossaryKey: "tld" },
  { label: "Excessive sub-domains",           weight: 1, fn: ruleTooManySubdomains,  glossaryKey: "subdomain" },
  { label: "Excessive hyphens in domain",     weight: 1, fn: ruleHyphens,            glossaryKey: null },
  { label: "Urgency / trust-bait wording",    weight: 1, fn: ruleUrgencyWords,       glossaryKey: "urgency" },
  { label: "Unusually long link",             weight: 1, fn: ruleLongURL,            glossaryKey: null },
];
const TOTAL_WEIGHT = RULES.reduce((sum, r) => sum + r.weight, 0);

const MSG_URGENCY_PHRASES = [
  "act now", "act immediately", "urgent", "verify your account", "confirm your identity",
  "suspended", "unusual activity", "unauthorized access", "your account will be closed",
  "final notice", "immediate action required", "limited time"
];

const MSG_SENSITIVE_REQUESTS = [
  "password", "one-time code", "one time code", "otp", "pin number", "cvv",
  "social security", "ssn", "verification code", "login credentials"
];

const MSG_MONEY_REQUESTS = [
  "gift card", "wire transfer", "western union", "bitcoin", "crypto wallet",
  "send money", "processing fee", "deposit fee", "claim your prize"
];

const MSG_THREAT_PHRASES = [
  "arrest", "police", "warrant", "legal action", "lawsuit", "court", "investigation",
  "your account will be frozen", "suspended permanently", "criminal charges"
];

function ruleMsgUrgency(text) {
  const lower = text.toLowerCase();
  const found = MSG_URGENCY_PHRASES.filter(p => lower.includes(p));
  return { flagged: found.length > 0, why: found.length > 0
    ? `Contains urgency language: "${found[0]}"${found.length > 1 ? ` (+${found.length - 1} more)` : ""}.`
    : "No strong urgency phrasing detected." };
}

function ruleMsgSensitiveInfo(text) {
  const lower = text.toLowerCase();
  const found = MSG_SENSITIVE_REQUESTS.filter(p => lower.includes(p));
  return { flagged: found.length > 0, why: found.length > 0
    ? `Directly asks for sensitive info: "${found[0]}". Real companies never ask for this by message.`
    : "No direct request for passwords/codes/PINs found." };
}

function ruleMsgMoneyRequest(text) {
  const lower = text.toLowerCase();
  const found = MSG_MONEY_REQUESTS.filter(p => lower.includes(p));
  return { flagged: found.length > 0, why: found.length > 0
    ? `Mentions a payment method common in scams: "${found[0]}".`
    : "No suspicious payment requests found." };
}

function ruleMsgThreats(text) {
  const lower = text.toLowerCase();
  const found = MSG_THREAT_PHRASES.filter(p => lower.includes(p));
  return { flagged: found.length > 0, why: found.length > 0
    ? `Uses threatening/authority language: "${found[0]}" to pressure a fast reaction.`
    : "No threatening or authority-impersonation language found." };
}

function ruleMsgGenericGreeting(text) {
  const flagged = /\b(dear (customer|user|member|sir\/madam|valued customer)|hello customer)\b/i.test(text);
  return { flagged, why: flagged
    ? "Uses a generic greeting instead of your real name, typical of mass-sent scam messages."
    : "No generic mass-message greeting detected." };
}

function ruleMsgAllCaps(text) {
  const shoutWords = text.match(/\b[A-Z]{4,}\b/g) || [];
  const flagged = shoutWords.length >= 2;
  return { flagged, why: flagged
    ? `Uses excessive ALL CAPS (e.g. "${shoutWords[0]}") to create alarm.`
    : "Normal capitalization." };
}

const MESSAGE_RULES = [
  { label: "Asks for passwords/codes directly", weight: 3, fn: ruleMsgSensitiveInfo, glossaryKey: "credential-harvesting" },
  { label: "Threats / impersonates authority",  weight: 3, fn: ruleMsgThreats,        glossaryKey: "impersonation" },
  { label: "Requests risky payment method",     weight: 2, fn: ruleMsgMoneyRequest,   glossaryKey: "money-mule" },
  { label: "Urgency / pressure language",       weight: 2, fn: ruleMsgUrgency,        glossaryKey: "urgency" },
  { label: "Generic mass-message greeting",     weight: 1, fn: ruleMsgGenericGreeting,glossaryKey: "mass-phishing" },
  { label: "Excessive ALL-CAPS alarm words",    weight: 1, fn: ruleMsgAllCaps,        glossaryKey: null },
];
const MSG_TOTAL_WEIGHT = MESSAGE_RULES.reduce((sum, r) => sum + r.weight, 0);

function extractFirstLink(text) {
  const match = text.match(/(https?:\/\/[^\s]+)|(\bwww\.[^\s]+)/i);
  if (!match) return null;
  const raw = match[0];
  try {
    const withProtocol = /^https?:\/\//i.test(raw) ? raw : "https://" + raw;
    return { raw, link: new URL(withProtocol) };
  } catch (e) {
    return null;
  }
}

function switchTab(mode) {
  const isLink = mode === "link";
  document.getElementById("linkPanel").style.display = isLink ? "block" : "none";
  document.getElementById("messagePanel").style.display = isLink ? "none" : "block";
  document.getElementById("tabLinkBtn").classList.toggle("active", isLink);
  document.getElementById("tabMessageBtn").classList.toggle("active", !isLink);
  document.getElementById("result").classList.remove("show");
  document.getElementById("result").style.display = "none";
  hideInputError();
}

function checkURL() {
  const raw = document.getElementById("urlInput").value.trim();
  hideInputError();
  if (!raw) return;

  let link;
  try {
    const withProtocol = /^https?:\/\//i.test(raw) ? raw : "https://" + raw;
    link = new URL(withProtocol);
    if (!link.hostname.includes(".")) throw new Error("no dot in hostname");
  } catch (e) {
    showInputError("That doesn't look like a valid link. Check the spelling and try again.");
    return;
  }

  const results = RULES.map(rule => ({ label: rule.label, glossaryKey: rule.glossaryKey, weight: rule.weight, ...rule.fn(raw, link) }));
  const flaggedWeight = results.filter(r => r.flagged).reduce((sum, r) => sum + r.weight, 0);
  const flaggedCount = results.filter(r => r.flagged).length;
  const score = Math.round((flaggedWeight / TOTAL_WEIGHT) * 100);

  renderResult(score, flaggedCount, results.length, results);
}

function checkMessage() {
  const text = document.getElementById("msgInput").value.trim();
  hideInputError();
  if (!text) return;

  const results = MESSAGE_RULES.map(rule => ({ label: rule.label, glossaryKey: rule.glossaryKey, weight: rule.weight, ...rule.fn(text) }));
  let totalWeight = MSG_TOTAL_WEIGHT;

  const found = extractFirstLink(text);
  if (found) {
    const linkResults = RULES.map(rule => {
      const r = rule.fn(found.raw, found.link);
      const halfWeight = Math.max(1, Math.round(rule.weight / 2));
      return { label: `${rule.label} (link in message)`, glossaryKey: rule.glossaryKey, weight: halfWeight, flagged: r.flagged, why: r.why };
    });
    results.push(...linkResults);
    totalWeight += linkResults.reduce((sum, r) => sum + r.weight, 0);
  } else {
    results.push({ label: "Contains a link", glossaryKey: null, weight: 0, flagged: false, why: "No link found in this message." });
  }

  const flaggedWeight = results.filter(r => r.flagged).reduce((sum, r) => sum + r.weight, 0);
  const flaggedCount = results.filter(r => r.flagged).length;
  const score = Math.round((flaggedWeight / totalWeight) * 100);

  renderResult(score, flaggedCount, results.length, results);
}

function showInputError(message) {
  let el = document.getElementById("inputError");
  if (!el) {
    el = document.createElement("div");
    el.id = "inputError";
    el.className = "input-error";
    document.querySelector(".input-row").insertAdjacentElement("afterend", el);
  }
  el.textContent = message;
  el.style.display = "block";
}

function hideInputError() {
  const el = document.getElementById("inputError");
  if (el) el.style.display = "none";
}

function renderResult(score, flaggedCount, totalChecks, results) {
  const resultEl = document.getElementById("result");
  resultEl.style.display = "block";
  requestAnimationFrame(() => resultEl.classList.add("show"));

  let level, icon, title, sub;
  if (score <= 20) {
    level = "safe";   icon = "✅"; title = "Looks okay";
    sub = "Few or no common phishing red flags were found.";
  } else if (score <= 45) {
    level = "warn";    icon = "⚠️"; title = "Be cautious";
    sub = "A couple of warning signs showed up. Double-check before acting.";
  } else {
    level = "danger";  icon = "🚨"; title = "High phishing risk";
    sub = "Several red flags found. Avoid clicking links or sharing info.";
  }

  const box = document.getElementById("verdictBox");
  box.className = "verdict " + level;
  document.getElementById("verdictIcon").textContent = icon;
  document.getElementById("verdictTitle").textContent = title;
  document.getElementById("verdictSub").textContent = `${sub} (${flaggedCount} of ${totalChecks} warning signs found)`;

  const fill = document.getElementById("scoreFill");
  fill.style.width = score + "%";
  fill.style.background = level === "safe" ? "var(--safe)" : level === "warn" ? "var(--warn)" : "var(--danger)";

  const list = document.getElementById("checksList");
  list.innerHTML = "";
  results.forEach(r => {
    const li = document.createElement("li");
    li.className = r.flagged ? "flagged" : "ok";
    const infoBtn = r.glossaryKey
      ? `<button class="info-btn" data-term="${r.glossaryKey}" aria-label="What does this mean?" onclick="toggleGlossary(event, '${r.glossaryKey}')">ⓘ</button>`
      : "";
    li.innerHTML = `
      <span class="mark">${r.flagged ? "✕" : "✓"}</span>
      <div>
        <div class="label">${r.label} ${infoBtn}</div>
        <div class="why">${r.why}</div>
      </div>`;
    list.appendChild(li);
  });
}

function toggleGlossary(evt, term) {
  evt.stopPropagation();
  const tip = document.getElementById("glossaryTooltip");
  const isSameOpen = tip.dataset.term === term && tip.classList.contains("open");
  closeGlossary();
  if (isSameOpen) return;

  tip.textContent = GLOSSARY[term] || "No definition available.";
  tip.dataset.term = term;

  const btnRect = evt.currentTarget.getBoundingClientRect();
  const top = window.scrollY + btnRect.bottom + 6;
  let left = window.scrollX + btnRect.left;
  const maxLeft = window.scrollX + document.documentElement.clientWidth - 300;
  left = Math.min(left, Math.max(10, maxLeft));

  tip.style.top = top + "px";
  tip.style.left = left + "px";
  tip.classList.add("open");
}

function closeGlossary() {
  const tip = document.getElementById("glossaryTooltip");
  tip.classList.remove("open");
  delete tip.dataset.term;
}

document.addEventListener("click", closeGlossary);
document.addEventListener("keydown", e => { if (e.key === "Escape") closeGlossary(); });

function loadExample(url) {
  document.getElementById("urlInput").value = url;
  checkURL();
}

const MESSAGE_EXAMPLES = {
  safe: "Hi Lance, just confirming our meeting tomorrow at 10am in the usual conference room. Let me know if that still works for you. Thanks, Angelo",
  phish: "Dear Customer, URGENT: Unusual activity was detected on your account. Your account will be suspended within 24 hours unless you verify your identity immediately. Please confirm your password and one-time code here: http://secure-account-verify.top/login. Failure to respond may result in legal action."
};

function loadMessageExample(kind) {
  document.getElementById("msgInput").value = MESSAGE_EXAMPLES[kind] || "";
  checkMessage();
}

document.getElementById("urlInput").addEventListener("keydown", e => {
  if (e.key === "Enter") checkURL();
});
