import { chromium } from "playwright";

/* ---------------- /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;/* -------------------------
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
  const keys = [
    "TenantGuid",
    "EnvId",
    "Domain",
    "Version",
    "ScriptType",
    "RuleSet",
    "SkipGeolocation",
    "LanguageDetectionEnabled",
    "LanguageDetectionByHtml",
    "GeoRuleGroupName"
  ];
  return keys.some(k => Object.prototype.hasOwnProperty.call(obj, k));
}

function toList(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(v => String(v).trim()).filter(Boolean);
  if (typeof value === "string") {
    return value
      .split(/[\s,;]+/g)
      .map(v => v.trim())
      .filter(Boolean);
  }
  return [String(value).trim()].filter(Boolean);
}

function lowerList(value) {
  return toList(value).map(v => v.toLowerCase());
}

/**
 * Your RuleSet → Template resolution rules:
 * - match RuleSet[x].Countries to geolocation country
 * - if RuleSet[x].States is empty => wildcard (country-only match)
 * - if RuleSet[x].States has values => must match state
 * - prefer exact state match over wildcard state match
 */
function resolveTemplateFromRuleSet(ruleSet, geoCountry, geoState) {
  const country = (geoCountry || "").toLowerCase().trim();
  const state = (geoState || "").toLowerCase().trim();

  if (!Array.isArray(ruleSet) || ruleSet.length === 0) {
    return { templateName: "", matchType: "no_rules", matchedIndex: -1, matchedRule: null };
  }
  if (!country) {
    return { templateName: "", matchType: "no_geo_country", matchedIndex: -1, matchedRule: null };
  }

  let best = null;

  for (let i = 0; i < ruleSet.length; i++) {
    const r = ruleSet[i] || {};

    const countries = lowerList(r.Countries ?? r.countries);
    const states = lowerList(r.States ?? r.states);

    if (!countries.includes(country)) continue;

    const hasStateList = states.length > 0;
    const exactStateMatch = hasStateList && state && states.includes(state);
    const wildcardState = !hasStateList;

    // If rule expects states but geo state is empty -> cannot match
    if (hasStateList && !state) continue;

    // If state present but does not match -> cannot match
    if (hasStateList && state && !exactStateMatch) continue;

    const score = exactStateMatch ? 3 : 2;

    const candidate = {
      matchedIndex: i,
      matchedRule: r,
      templateName: r.TemplateName ?? "",
      matchType: exactStateMatch
        ? "country_and_state"
        : (wildcardState ? "country_and_wildcard_state" : "country_only"),
      score
    };

    if (!best || candidate.score > best.score) best = candidate;
  }

  if (!best) {
    return { templateName: "", matchType: "no_match", matchedIndex: -1, matchedRule: null };
  }

  return best;
}

/* -------------------------
   Main (ESM export)
-------------------------- */

export async function runCheck(inputUrl) {
  const targetUrl = normaliseUrl(inputUrl);
  if (!targetUrl) throw new Error("url is required");

  let browser = null;

  const notes = [];
  let capturedConfig = null;
  let capturedConfigUrl = "";

  let accessDenied = false;
  let navigationError = null;
  let isCspBlocked = false; // reserved

  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();

    // Access denied detection via HTTP status
    page.on("response", async response => {
      try {
        const status = response.status();
        if (response.request().resourceType() === "document" && (status === 401 || status === 403)) {
          accessDenied = true;
        }
      } catch {}
    });

    // Capture udid.json-like response
    page.on("response", async response => {
      try {
        const url = response.url();
        const lowerUrl = url.toLowerCase();
        const contentType = (response.headers()?.["content-type"] || "").toLowerCase();

        const isLikelyJson =
          lowerUrl.includes(".json") ||
          contentType.includes("application/json") ||
          contentType.includes("text/json");

        if (!isLikelyJson) return;

        const text = await response.text().catch(() => "");
        if (!text) return;

        let parsed;
        try {
          parsed = JSON.parse(text);
        } catch {
          return;
        }

        if (looksLikeUdidJson(parsed)) {
          capturedConfig = parsed;
          capturedConfigUrl = url;
        }
      } catch {}
    });

    // Navigate safely
    let navigationResponse = null;
    try {
      navigationResponse = await page.goto(targetUrl, { waitUntil: "domcontentloaded" });
    } catch (err) {
      navigationError = err?.message || String(err);
    }

    if (!navigationResponse && navigationError) {
      return {
        checkedUrl: targetUrl,
        navigationError,
        accessDenied: false,
        severity: "HIGH",
        issues: [mkFinding("HIGH", `Navigation failed: ${navigationError}`)],
        recommendations: [
          "Verify URL spelling (e.g., www vs wwww)",
          "Check DNS/network access from runner"
        ],
        notes
      };
    }

    // extra accessDenied detection from page body text
    try {
      await page.waitForTimeout(3000);
      const bodyText = await page.evaluate(() => document.body?.innerText || "");
      const lowered = (bodyText || "").toLowerCase();
      if (
        lowered.includes("access denied") ||
        lowered.includes("403 forbidden") ||
        lowered.includes("request blocked") ||
        lowered.includes("you don't have permission") ||
        lowered.includes("forbidden") ||
        lowered.includes("not authorised") ||
        lowered.includes("not authorized")
      ) {
        accessDenied = true;
      }
    } catch {}

    await page.waitForTimeout(2000);

    // Script scan
    const scripts = await page.locator("script").evaluateAll(nodes =>
      nodes.map((s, idx) => ({
        index: idx,
        inHead: !!(document.head && document.head.contains(s)),
        src: s.src || "",
        dataDomainScript: s.getAttribute("data-domain-script") || ""
      }))
    );

    const stubScripts = scripts.filter(s => (s.src || "").toLowerCase().includes("otsdkstub.js"));
    const autoBlockScripts = scripts.filter(s => (s.src || "").toLowerCase().includes("otautoblock.js"));

    const hasDuplicateOtSdkStub = stubScripts.length > 1;
    const hasDuplicateAutoBlock = autoBlockScripts.length > 1;

    const otSDKStubFound = stubScripts.length > 0;
    const autoBlockEnabled = autoBlockScripts.length > 0;

    const primaryUdid = stubScripts.find(s => s.dataDomainScript)?.dataDomainScript || "";
    const productionUdid = cleanUdid(primaryUdid);
    const usingTestScript = isTestScript(primaryUdid);

    // Domain match
    const checkedHost = new URL(targetUrl).hostname || "";
    const configDomain = capturedConfig?.Domain ?? "";

    let domainScopeValid = false;
    let domainOutOfScope = false;

    if (usingTestScript) {
      domainScopeValid = true;
      domainOutOfScope = false;
    } else if (configDomain && checkedHost) {
      const match = isDomainMatching(checkedHost, configDomain);
      domainScopeValid = Boolean(match);
      domainOutOfScope = Boolean(!match);
    }

    // RuleSet/template selection (your newest requirement)
    const ruleSet = Array.isArray(capturedConfig?.RuleSet) ? capturedConfig.RuleSet : [];
    const ruleSetCount = ruleSet.length;
    const skipGeolocation = Boolean(capturedConfig?.SkipGeolocation);

    let geoCountry = "";
    let geoState = "";
    let resolvedTemplateName = "";
    let resolvedRuleInfo = { matchedIndex: -1, matchType: "not_evaluated" };

    if (skipGeolocation) {
      resolvedTemplateName = ruleSet?.[0]?.TemplateName ?? "";
      resolvedRuleInfo = {
        matchedIndex: ruleSetCount > 0 ? 0 : -1,
        matchType: "skip_geolocation_true_rule0",
        templateName: resolvedTemplateName
      };
    } else {
      // capture geolocation from OneTrust
      try {
        await page.waitForFunction(
          () => window.OneTrust && typeof window.OneTrust.getGeolocationData === "function",
          { timeout: 8000 }
        );

        const geo = await page.evaluate(async () => {
          try {
            const fn = window.OneTrust?.getGeolocationData;
            if (typeof fn !== "function") return null;
            const res = fn.call(window.OneTrust);
            if (res && typeof res.then === "function") return await res;
            return res ?? null;
          } catch {
            return null;
          }
        });

        geoCountry = geo?.country ?? "";
        geoState = geo?.state ?? "";
      } catch {}

      const match = resolveTemplateFromRuleSet(ruleSet, geoCountry, geoState);
      resolvedTemplateName = match.templateName || "";
      resolvedRuleInfo = {
        matchedIndex: match.matchedIndex,
        matchType: match.matchType,
        templateName: match.templateName || "",
        geoCountry,
        geoState
      };
    }

    // Consent modes (best-effort)
    let googleConsentModeEnabled = null;
    let microsoftConsentModeEnabled = null;
    let amazonConsentModeEnabled = null;

    try {
      await page.waitForFunction(
        () => window.OneTrust && typeof window.OneTrust.GetDomainData === "function",
        { timeout: 5000 }
      );

      const domainData = await page.evaluate(() => {
        try {
          return window.OneTrust.GetDomainData();
        } catch {
          return null;
        }
      });

      googleConsentModeEnabled = domainData?.GoogleConsent?.GCEnable ?? null;
      microsoftConsentModeEnabled = domainData?.MCMData?.Enabled ?? null;
      amazonConsentModeEnabled = domainData?.ACMData?.Enabled ?? null;
    } catch {}

    // Findings
    const issues = [];
    const recommendations = [];

    if (accessDenied) issues.push(mkFinding("HIGH", "Access denied or blocked"));
    if (domainOutOfScope) issues.push(mkFinding("HIGH", `Domain mismatch (${configDomain} vs ${checkedHost})`));
    if (!otSDKStubFound) issues.push(mkFinding("HIGH", "otSDKStub.js not detected"));
    if (hasDuplicateOtSdkStub) issues.push(mkFinding("HIGH", "Duplicate otSDKStub.js detected"));
    if (hasDuplicateAutoBlock) issues.push(mkFinding("MEDIUM", "Duplicate otAutoBlock.js detected"));

    const severity = computeSeverity(issues);

    return {
      checkedUrl: targetUrl,

      udidJsonUrl: capturedConfigUrl,

      TenantGuid: capturedConfig?.TenantGuid ?? "",
      EnvId: capturedConfig?.EnvId ?? "",
      Domain: configDomain,

      udidJson: {
        Version: capturedConfig?.Version ?? "",
        ScriptType: capturedConfig?.ScriptType ?? "",
        LanguageDetectionByHtml: capturedConfig?.LanguageDetectionByHtml ?? "",
        LanguageDetectionEnabled: capturedConfig?.LanguageDetectionEnabled ?? "",
        GeoRuleGroupName: capturedConfig?.GeoRuleGroupName ?? "",
        SkipGeolocation: skipGeolocation,
        RuleSetCount: ruleSetCount
      },

      resolvedTemplateName,
      resolvedRuleInfo,

      geoLocation: {
        country: geoCountry,
        state: geoState
      },

      primaryUdid,
      productionUdid,
      usingTestScript,

      otSDKStubFound,
      autoBlockEnabled,
      hasDuplicateOtSdkStub,
      hasDuplicateAutoBlock,

      isCspBlocked,
      accessDenied,

      checkedHost,
      configDomain,
      domainScopeValid,
      domainOutOfScope,

      consentModes: {
        google: { enabled: googleConsentModeEnabled },
        microsoft: { enabled: microsoftConsentModeEnabled },
        amazon: { enabled: amazonConsentModeEnabled }
      },

      severity,
      issues,
      recommendations,
      notes
    };
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}
   Helpers
-------------------------- */

function normaliseUrl(url) {
  const trimmed = (url || "").trim();
  if (!trimmed) return "";
