import { chromium } from "playwright";import { chromium } from "function normaliseUrl(url) {
  const trimmed = (url || "").trim();
  if (!trimmed) return "";
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function cleanUdid(udid = "") {
  return udid.toLowerCase().endsWith("-test") ? udid.slice(0, -5) : udid;
}

function isTestScript(udid = "") {
  return udid.toLowerCase().endsWith("-test");
}

function mkFinding(severity, message) {
  return { severity, message };
}

function computeSeverity(findings) {
  if (findings.some(f => f.severity === "HIGH")) return "HIGH";
  if (findings.some(f => f.severity === "MEDIUM")) return "MEDIUM";
  if (findings.length > 0) return "LOW";
  return "NONE";
}

function isDomainMatching(host, domain) {
  if (!host || !domain) return false;
  const h = host.toLowerCase();
  const d = domain.toLowerCase();
  return h === d || h.endsWith(`.${d}`);
}

function looksLikeUdidJson(obj) {
  if (!obj || typeof obj !== "object") return false;
  return Array.isArray(obj.RuleSet);
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

/* -------------------------
   Template Resolution Logic
-------------------------- */

function resolveTemplateFromRuleSet(ruleSet, geoCountry, geoState) {
  const country = (geoCountry || "").toLowerCase();
  const state = (geoState || "").toLowerCase();

  if (!ruleSet?.length) {
    return { templateName: "", matchType: "no_rules" };
  }

  let bestMatch = null;

  for (let i = 0; i < ruleSet.length; i++) {
    const rule = ruleSet[i];

    const countries = lowerList(rule.Countries ?? rule.countries);
    const states = lowerList(rule.States ?? rule.states);

    if (!countries.includes(country)) continue;

    const hasStates = states.length > 0;
    const stateMatch = hasStates && states.includes(state);

    // Prefer state match
    if (stateMatch) {
      return {
        templateName: rule.TemplateName ?? "",
        matchType: "country_and_state",
        matchedIndex: i
      };
    }

    // fallback: country only
    if (!hasStates) {
      bestMatch = {
        templateName: rule.TemplateName ?? "",
        matchType: "country_only",
        matchedIndex: i
      };
    }
  }

  return bestMatch || { templateName: "", matchType: "no_match" };
}

/* -------------------------
   Main Export
-------------------------- */

export async function runCheck(inputUrl) {
  const targetUrl = normaliseUrl(inputUrl);
  if (!targetUrl) throw new Error("url is required");

  let browser = null;
  let capturedConfig = null;
  let capturedConfigUrl = "";

  let geoCountry = "";
  let geoState = "";

  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();

    /* -------------------------
       Capture udid.json
    -------------------------- */

    page.on("response", async response => {
      try {
        const url = response.url().toLowerCase();

        if (!url.includes(".json")) return;

        const text = await response.text();
        const parsed = JSON.parse(text);

        if (looksLikeUdidJson(parsed)) {
          capturedConfig = parsed;
          capturedConfigUrl = url;
        }
      } catch {}
    });

    await page.goto(targetUrl, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(5000);

    /* -------------------------
       Extract config
    -------------------------- */

    const ruleSet = capturedConfig?.RuleSet || [];
    const skipGeolocation = capturedConfig?.SkipGeolocation === true;

    let resolvedTemplateName = "";
    let resolvedRuleInfo = {};

    /* -------------------------
       Apply your logic
    -------------------------- */

    if (skipGeolocation) {
      resolvedTemplateName = ruleSet?.[0]?.TemplateName || "";
      resolvedRuleInfo = {
        matchType: "skip_geolocation_rule0",
        matchedIndex: 0
      };
    } else {
      try {
        await page.waitForFunction(
          () => window.OneTrust?.getGeolocationData,
          { timeout: 5000 }
        );

        const geo = await page.evaluate(() => {
          try {
            return window.OneTrust.getGeolocationData();
          } catch {
            return null;
          }
        });

        geoCountry = geo?.country || "";
        geoState = geo?.state || "";
      } catch {}

      const match = resolveTemplateFromRuleSet(ruleSet, geoCountry, geoState);

      resolvedTemplateName = match.templateName;
      resolvedRuleInfo = match;
    }

    return {
      checkedUrl: targetUrl,

      udidJsonUrl: capturedConfigUrl,

      SkipGeolocation: skipGeolocation,
      ruleSetCount: ruleSet.length,

      geoLocation: {
        country: geoCountry,
        state: geoState
      },

      resolvedTemplateName,
      resolvedRuleInfo
    };

  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}

/* -------------------------
   Helpers
-------------------------- */

