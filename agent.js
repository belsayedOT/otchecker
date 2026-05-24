import { chromium } from "playwright";

/* =========================
   Utilities
================ const trimmed = (url || "").trim();========================= */
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
  // keep flexible but safe: most udid/config JSON include RuleSet + identity fields
  const hasRuleSet = Array.isArray(obj.RuleSet);
  const hasIdentity = Boolean(obj.Domain || obj.TenantGuid || obj.EnvId || obj.Version || obj.ScriptType);
  return hasRuleSet && hasIdentity;
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

function isJsSrc(src = "") {
  const s = (src || "").toLowerCase().trim();
  if (!s) return false;
  return s.includes(".js") || s.includes("/scripttemplates/");
}

/* =========================
   RuleSet -> Template matching (NEW)
   - If SkipGeolocation true => RuleSet[0].TemplateName
   - Else:
        geo = OneTrust.getGeolocationData()
        match RuleSet[x] where:
           countries includes geo.country
           AND (States empty OR contains geo.state)
        prefer exact state match over wildcard
========================= */
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

    // if rule requires states but we have none
    if (hasStateList && !state) continue;

    // if rule requires a specific state but doesn't match
    if (hasStateList && state && !exactStateMatch) continue;

    // scoring
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

/* =========================
   Main
========================= */

export async function runCheck(inputUrl) {
  const targetUrl = normaliseUrl(inputUrl);
  if (!targetUrl) throw new Error("url is required");

  let browser = null;

  const notes = [];
  let capturedConfig = null;
  let capturedConfigUrl = "";

  let accessDenied = false;
  const isCspBlocked = false; // reserved (not implemented)

  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();

    // Access denied detection via HTTP status
    page.on("response", response => {
      try {
        const status = response.status();
        if (response.request().resourceType() === "document" && (status === 401 || status === 403)) {
          accessDenied = true;
        }
      } catch {}
    });

    // Capture udid/config JSON (best-effort)
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

    // Navigate (graceful)
    let navigationResponse = null;
    let navigationError = null;
    try {
      navigationResponse = await page.goto(targetUrl, { waitUntil: "domcontentloaded" });
    } catch (err) {
      navigationError = err?.message || String(err);
    }

    // If navigation failed, return a full shaped response (so API always returns JSON)
    if (!navigationResponse && navigationError) {
      const issues = [mkFinding("HIGH", `Navigation failed: ${navigationError}`)];
      return {
        checkedUrl: targetUrl,
        TenantGuid: "",
        EnvId: "",
        Domain: "",
        primaryUdid: "",
        productionUdid: "",
        usingTestScript: false,
        otSDKStubFound: false,
        autoBlockEnabled: false,
        hasDuplicateOtSdkStub: false,
        hasDuplicateAutoBlock: false,
        isCspBlocked,
        accessDenied: false,
        checkedHost: (() => { try { return new URL(targetUrl).hostname || ""; } catch { return ""; } })(),
        configDomain: "",
        domainScopeValid: false,
        domainOutOfScope: false,
        severity: computeSeverity(issues),
        issues,
        recommendations: [
          "Verify URL spelling (e.g., www vs wwww)",
          "Check DNS/network reachability from the runner"
        ],
        notes
      };
    }

    // allow scripts/config to load
    await page.waitForTimeout(5000);

    // Script scan (order + inHead)
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

    const otSDKStubFound = stubScripts.length > 0;
    const autoBlockEnabled = autoBlockScripts.length > 0;

    const hasDuplicateOtSdkStub = stubScripts.length > 1;
    const hasDuplicateAutoBlock = autoBlockScripts.length > 1;

    const primaryUdid = stubScripts.find(s => s.dataDomainScript)?.dataDomainScript || "";
    const productionUdid = cleanUdid(primaryUdid);
    const usingTestScript = isTestScript(primaryUdid);

    const checkedHost = (() => {
      try { return new URL(targetUrl).hostname || ""; } catch { return ""; }
    })();

    const configDomain = capturedConfig?.Domain ?? "";

    // Domain validation
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

    // Script ordering check: any .js before first OT script
    const firstOtIndexCandidates = [...stubScripts, ...autoBlockScripts].map(s => s.index);
    const firstOtIndex = firstOtIndexCandidates.length ? Math.min(...firstOtIndexCandidates) : -1;

    const jsScriptsBeforeOt =
      firstOtIndex > 0
        ? scripts.filter(s => s.index < firstOtIndex && isJsSrc(s.src)).map(s => s.src).filter(Boolean)
        : [];

    const hasJsBeforeOt = jsScriptsBeforeOt.length > 0;

    // head placement checks (your earlier requirement)
    const otSdkStubInHead = stubScripts.some(s => s.inHead);
    const otAutoBlockInHead = autoBlockScripts.some(s => s.inHead);

    // OneTrust object presence (best-effort "running" indicator)
    let oneTrustObjectPresent = false;
    try {
      oneTrustObjectPresent = await page.evaluate(() => !!window.OneTrust);
    } catch {}

    // ===== udid.json fields you wanted =====
    const ruleSet = Array.isArray(capturedConfig?.RuleSet) ? capturedConfig.RuleSet : [];
    const ruleSetCount = ruleSet.length;
    const skipGeolocation = Boolean(capturedConfig?.SkipGeolocation);

    // ===== NEW TemplateName resolution =====
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
      // capture OneTrust.getGeolocationData().country/state
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
        try { return window.OneTrust.GetDomainData(); } catch { return null; }
      });

      googleConsentModeEnabled = domainData?.GoogleConsent?.GCEnable ?? null;
      microsoftConsentModeEnabled = domainData?.MCMData?.Enabled ?? null;
      amazonConsentModeEnabled = domainData?.ACMData?.Enabled ?? null;
    } catch {}

    // Findings (restore old behaviour: if stub missing => HIGH)
    const issues = [];
    const recommendations = [];

    if (!otSDKStubFound) issues.push(mkFinding("HIGH", "otSDKStub.js not detected"));
    if (hasDuplicateOtSdkStub) issues.push(mkFinding("HIGH", "Duplicate otSDKStub.js detected"));
    if (hasDuplicateAutoBlock) issues.push(mkFinding("MEDIUM", "Duplicate otAutoBlock.js detected"));
    if (domainOutOfScope) issues.push(mkFinding("HIGH", `Domain mismatch (${configDomain} vs ${checkedHost})`));
    if (accessDenied) issues.push(mkFinding("HIGH", "Access denied or blocked"));

    const severity = computeSeverity(issues);

    return {
      checkedUrl: targetUrl,

      // keep the old top-level keys you expect
      TenantGuid: capturedConfig?.TenantGuid ?? "",
      EnvId: capturedConfig?.EnvId ?? "",
      Domain: configDomain,

      primaryUdid,
      productionUdid,
      usingTestScript,

      otSDKStubFound,
      autoBlockEnabled,
      hasDuplicateOtSdkStub,
      hasDuplicateAutoBlock,

      // original flags
      isCspBlocked,
      accessDenied,

      checkedHost,
      configDomain,
      domainScopeValid,
      domainOutOfScope,

      // new + restored detail blocks
      udidJsonUrl: capturedConfigUrl,
      udidJson: {
        Version: capturedConfig?.Version ?? "",
        ScriptType: capturedConfig?.ScriptType ?? "",
        LanguageDetectionByHtml: capturedConfig?.LanguageDetectionByHtml ?? "",
        LanguageDetectionEnabled: capturedConfig?.LanguageDetectionEnabled ?? "",
        GeoRuleGroupName: capturedConfig?.GeoRuleGroupName ?? "",
        SkipGeolocation: skipGeolocation,
        RuleSetCount: ruleSetCount
      },

      // head/order checks
      otSdkStubInHead,
      otAutoBlockInHead,
      hasJsBeforeOt,
      previousScripts: jsScriptsBeforeOt,

      oneTrustObjectPresent,

      // template result
      geoLocation: { country: geoCountry, state: geoState },
      resolvedTemplateName,
      resolvedRuleInfo,

      // consent modes
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

function normaliseUrl(url) {
