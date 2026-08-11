const KNOWN_BRANDS = [
  { name: "paypal",  realDomain: "paypal.com" },
  { name: "google",  realDomain: "google.com" },
  { name: "facebook",realDomain: "facebook.com" },
  { name: "apple",   realDomain: "apple.com" },
  { name: "amazon",  realDomain: "amazon.com" },
  { name: "microsoft",realDomain: "microsoft.com" },
  { name: "netflix", realDomain: "netflix.com" },
  { name: "bank",    realDomain: null } 
];

const URGENCY_WORDS = [
  "verify", "suspend", "urgent", "confirm", "update", "secure",
  "account", "login", "signin", "unlock", "limited", "reward", "winner"
];

function ruleUsesIP(url, link) {
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(link.hostname);
  return {
    flagged: isIP,
    why: isIP
      ? "The link uses a raw IP address instead of a normal domain name."
      : "The link uses a normal domain name, not a raw IP address."
  };
}

function ruleNoHTTPS(url, link) {
  const insecure = link.protocol !== "https:";
  return {
    flagged: insecure,
    why: insecure
      ? "The link does not use HTTPS (no padlock), so data sent isn't encrypted."
      : "The link uses HTTPS, which encrypts the connection."
  };
}

function ruleHasAtSymbol(url) {
  const hasAt = url.includes("@");
  return {
    flagged: hasAt,
    why: hasAt
      ? 'Contains an "@" symbol, a classic trick to disguise the real destination.'
      : 'No "@" symbol trick found.'
  };
}

function ruleTooManySubdomains(url, link) {
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
  const long = url.length > 75;
  return {
    flagged: long,
    why: long
      ? `The link is quite long (${url.length} characters), which can hide suspicious parts.`
      : "The link length looks normal."
  };
}

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

function checkURL() {
  const raw = document.getElementById("urlInput").value.trim();
  if (!raw) return;

  let link;
  try {
    const withProtocol = /^https?:\/\//i.test(raw) ? raw : "https://" + raw;
    link = new URL(withProtocol);
  } catch (e) {
    alert("That doesn't look like a valid link. Please check and try again.");
    return;
  }

  const results = RULES.map(rule => ({
    label: rule.label,
    ...rule.fn(raw, link)
  }));

  const flaggedCount = results.filter(r => r.flagged).length;
  const score = Math.round((flaggedCount / RULES.length) * 100); 

  renderResult(score, flaggedCount, results);
}

function renderResult(score, flaggedCount, results) {
  document.getElementById("result").style.display = "block";

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

document.getElementById("urlInput").addEventListener("keydown", e => {
  if (e.key === "Enter") checkURL();
});
