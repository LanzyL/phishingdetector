/* ================================================================
   PHISHING LINK CHECKER — the logic, explained step by step
   ================================================================
   The idea: real anti-phishing tools use big databases and machine
   learning. We can't do that in a school project, so instead we do
   what a careful human would do: look for a handful of WARNING SIGNS
   that phishing links commonly have, and add up how many are found.

   Each "rule" below is its own small function that:
     1) looks at the URL for one specific red flag
     2) returns true/false (flag found or not)
     3) comes with a short human-readable explanation

   More flags found  =  higher risk score  =  more likely phishing.
================================================================= */

// A short list of well-known brand names phishing links love to fake.
// If one of these words appears in the URL BUT the site is not the
// real domain for that brand, that's suspicious (this is a very
// simplified version of what's called "typosquatting" detection).
const KNOWN_BRANDS = [
  { name: "paypal",  realDomain: "paypal.com" },
  { name: "google",  realDomain: "google.com" },
  { name: "facebook",realDomain: "facebook.com" },
  { name: "apple",   realDomain: "apple.com" },
  { name: "amazon",  realDomain: "amazon.com" },
  { name: "microsoft",realDomain: "microsoft.com" },
  { name: "netflix", realDomain: "netflix.com" },
  { name: "bank",    realDomain: null } // generic word, no single "real" domain
];

// Words that often show up in urgent, scary, or too-good-to-be-true
// phishing messages / URLs.
const URGENCY_WORDS = [
  "verify", "suspend", "urgent", "confirm", "update", "secure",
  "account", "login", "signin", "unlock", "limited", "reward", "winner"
];

/* ---------- RULE FUNCTIONS ---------- */
/* Each function takes the URL (and a parsed "link" object from the
   built-in URL() tool) and returns { flagged: bool, why: string } */

function ruleUsesIP(url, link) {
  // Real companies almost never send you to a raw IP address
  // (like http://192.168.1.5). Phishing sites do this often to
  // hide who they really are.
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(link.hostname);
  return {
    flagged: isIP,
    why: isIP
      ? "The link uses a raw IP address instead of a normal domain name."
      : "The link uses a normal domain name, not a raw IP address."
  };
}

function ruleNoHTTPS(url, link) {
  // HTTPS encrypts the connection. Its absence doesn't PROVE a site
  // is fake, but legit login pages almost always use it today.
  const insecure = link.protocol !== "https:";
  return {
    flagged: insecure,
    why: insecure
      ? "The link does not use HTTPS (no padlock), so data sent isn't encrypted."
      : "The link uses HTTPS, which encrypts the connection."
  };
}

function ruleHasAtSymbol(url) {
  // Browsers ignore everything before an "@" in a URL, so scammers
  // write things like https://google.com@evil.com to LOOK like
  // Google while actually sending you to evil.com.
  const hasAt = url.includes("@");
  return {
    flagged: hasAt,
    why: hasAt
      ? 'Contains an "@" symbol, a classic trick to disguise the real destination.'
      : 'No "@" symbol trick found.'
  };
}

function ruleTooManySubdomains(url, link) {
  // login.account.secure.example.com.phisher.net — lots of dots
  // before the real domain is a common disguise technique.
  const dotCount = (link.hostname.match(/\./g) || []).length;
  const tooMany = dotCount >= 4;
  return {
    flagged: tooMany,
    why: tooMany
      ? `The domain has an unusually large number of sub-parts (${dotCount} dots).`
      : "The domain structure looks like a normal number of parts."
  };
}

function ruleHyphens(url, link) {
  // paypal-secure-login-verify.com — scammers stack hyphenated
  // keywords to look "official" while using a totally different
  // real domain.
  const hyphens = (link.hostname.match(/-/g) || []).length;
  const many = hyphens >= 2;
  return {
    flagged: many,
    why: many
      ? `The domain name has several hyphens (${hyphens}), often used to fake official-sounding names.`
      : "The domain doesn't have an unusual number of hyphens."
  };
}

function ruleUrgencyWords(url) {
  const lower = url.toLowerCase();
  const found = URGENCY_WORDS.filter(word => lower.includes(word));
  return {
    flagged: found.length > 0,
    why: found.length > 0
      ? `Contains urgency/trust-bait words: ${found.join(", ")}.`
      : "No common urgency or trust-bait keywords found."
  };
}

function ruleFakeBrand(url, link) {
  // If a brand name appears in the URL but the actual domain is NOT
  // that brand's real domain, flag it (simplified typosquatting check).
  const lower = url.toLowerCase();
  for (const brand of KNOWN_BRANDS) {
    if (brand.realDomain && lower.includes(brand.name)) {
      const isRealDomain = link.hostname === brand.realDomain ||
                            link.hostname.endsWith("." + brand.realDomain);
      if (!isRealDomain) {
        return {
          flagged: true,
          why: `Mentions "${brand.name}" but the domain isn't ${brand.realDomain}.`
        };
      }
    }
  }
  return { flagged: false, why: "No mismatched brand name detected." };
}

function ruleLongURL(url) {
  // Phishing links are often stuffed with extra text/tracking junk
  // to bury the suspicious part and look more "legitimate".
  const long = url.length > 75;
  return {
    flagged: long,
    why: long
      ? `The link is quite long (${url.length} characters), which can hide suspicious parts.`
      : "The link length looks normal."
  };
}

// All rules in one place — add/remove rules here and the app updates.
const RULES = [
  { label: "Uses a raw IP address",        fn: ruleUsesIP },
  { label: "Missing HTTPS encryption",      fn: ruleNoHTTPS },
  { label: '"@" symbol disguise trick',     fn: ruleHasAtSymbol },
  { label: "Excessive sub-domains",         fn: ruleTooManySubdomains },
  { label: "Excessive hyphens in domain",   fn: ruleHyphens },
  { label: "Urgency / trust-bait wording",  fn: ruleUrgencyWords },
  { label: "Brand name doesn't match domain", fn: ruleFakeBrand },
  { label: "Unusually long link",           fn: ruleLongURL },
];

/* ---------- MAIN FUNCTION: runs when "Check" is clicked ---------- */
function checkURL() {
  const raw = document.getElementById("urlInput").value.trim();
  if (!raw) return;

  // The browser's built-in URL() tool splits a link into pieces
  // (protocol, hostname, path, etc). We add "https://" if the user
  // forgot to type it, so URL() doesn't crash.
  let link;
  try {
    const withProtocol = /^https?:\/\//i.test(raw) ? raw : "https://" + raw;
    link = new URL(withProtocol);
  } catch (e) {
    alert("That doesn't look like a valid link. Please check and try again.");
    return;
  }

  // Run every rule and collect the results.
  const results = RULES.map(rule => ({
    label: rule.label,
    ...rule.fn(raw, link)
  }));

  const flaggedCount = results.filter(r => r.flagged).length;
  const score = Math.round((flaggedCount / RULES.length) * 100); // 0–100%

  renderResult(score, flaggedCount, results);
}

/* ---------- Puts the results on the page ---------- */
function renderResult(score, flaggedCount, results) {
  document.getElementById("result").style.display = "block";

  // Decide the overall verdict from the score.
  let level, icon, title, sub;
  if (score <= 20) {
    level = "safe";   icon = "✅";
    title = "Looks okay";
    sub = "Few or no common phishing red flags were found.";
  } else if (score <= 45) {
    level = "warn";    icon = "⚠️";
    title = "Be cautious";
    sub = "A couple of warning signs showed up. Double-check before entering info.";
  } else {
    level = "danger";  icon = "🚨";
    title = "High phishing risk";
    sub = "Several red flags found. Avoid entering any personal information.";
  }

  const box = document.getElementById("verdictBox");
  box.className = "verdict " + level;
  document.getElementById("verdictIcon").textContent = icon;
  document.getElementById("verdictTitle").textContent = title;
  document.getElementById("verdictSub").textContent =
    `${sub} (${flaggedCount} of ${RULES.length} warning signs found)`;

  const fill = document.getElementById("scoreFill");
  fill.style.width = score + "%";
  fill.style.background =
    level === "safe" ? "var(--safe)" : level === "warn" ? "var(--warn)" : "var(--danger)";

  // Build the checklist showing every rule and whether it triggered.
  const list = document.getElementById("checksList");
  list.innerHTML = "";
  results.forEach(r => {
    const li = document.createElement("li");
    li.className = r.flagged ? "flagged" : "ok";
    li.innerHTML = `
      <span class="mark">${r.flagged ? "✕" : "✓"}</span>
      <div>
        <div class="label">${r.label}</div>
        <div class="why">${r.why}</div>
      </div>`;
    list.appendChild(li);
  });
}

function loadExample(url) {
  document.getElementById("urlInput").value = url;
  checkURL();
}

// Let pressing Enter trigger a check too.
document.getElementById("urlInput").addEventListener("keydown", e => {
  if (e.key === "Enter") checkURL();
});
