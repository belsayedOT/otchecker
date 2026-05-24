import { chromium } from "playwright";

/* ========= Utilities ========= */

function normaliseUrl(url) {
  const trimmed = (url || "").trim();
  if (!trimmed) return "";
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function computeSeverity(findings) {
  if (findings.some(f => f.severity === "HIGH")) return "HIGH";
  if (findings.some(f => f.severity === "MEDIUM")) return "MEDIUM";
  if (findings.length > 0) return "LOW";
  return "NONE";
}

function toList(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(v => String(v).trim());
  return String(value)
    .split(/[\s,;]+/)
    .map(v => v.trim())
    .filter(Boolean);
}

function lowerList(value) {
  return toList(value).map(v => v.toLowerCase());
}

/* ========= Rule Matching ========= */

function resolveTemplate(ruleSet, country, state) {
  country = (country || "").toLowerCase();
  state = (state || "").toLowerCase();

  let best = null;

  for (let i = 0; i < ruleSet.length; i++) {
    const r = ruleSet[i];

    const countries = lowerList(r.Countries);
    const states = lowerList(r.States);

    if (!countries.includes(country)) continue;

    const hasStates = states.length > 0;
    const exactState = hasStates && states.includes(state);

    if (hasStates && state && !exactState) continue;
    if (hasStates && !state) continue;

    const score = exactState ? 2 : 1;

    const candidate = {
      templateName: r.TemplateName || "",
      matchedIndex: i,
      matchType: exactState ? "country_state" : "country_only",
      score
    };

    if (!best || candidate.score > best.score) best = candidate;
  }

  return best || {
    templateName: "",
    matchedIndex: -1,
    matchType: "no_match"
  };
}

/* ========= MAIN ========= */

export async function runCheck(inputUrl) {
  const url = normaliseUrl(inputUrl);
  if (!url) throw new Error("url is required");

  let browser;

  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();

    let config = null;

    // capture JSON
    page.on("response", async res => {
      try {
        const text = await res.text();
        const parsed = JSON.parse(text);

        if (parsed?.RuleSet) {
          config = parsed;
        }
      } catch {}
    });

    await page.goto(url, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(4000);

    const ruleSet = config?.RuleSet || [];
    const skip = config?.SkipGeolocation === true;

    let country = "";
    let state = "";
    let resolved = "";

    if (skip) {
      resolved = ruleSet?.[0]?.TemplateName || "";
    } else {
      try {
        const geo = await page.evaluate(() => {
          try {
            return window.OneTrust.getGeolocationData();
          } catch {
            return null;
          }
        });

        country = geo?.country || "";
        state = geo?.state || "";
      } catch {}

      const match = resolveTemplate(ruleSet, country, state);
      resolved = match.templateName;
    }

    return {
      checkedUrl: url,
      geo: { country, state },
      SkipGeolocation: skip,
      ruleSetCount: ruleSet.length,
      resolvedTemplateName: resolved
    };

  } finally {
    if (browser) await browser.close();
  }
}