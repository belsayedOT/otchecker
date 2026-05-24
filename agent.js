import { chromium } from "playwright";

function normaliseUrlSeverity(findings) {function normaliseUrl(url) {
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

  // some payloads store lists as space-separated strings
  // e.g. "us ca gb" or "us,ca,gb"
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

function resolveTemplateFromRuleSet(ruleSet, geoCountry, geoState) {
  const country = (geoCountry || "").toLowerCase().trim();
  const state = (geoState || "").toLowerCase().trim();

  if (!Array.isArray(ruleSet) || ruleSet.length === 0) {
    return { templateName: "", matchType: "no_rules", matchedIndex: -1, matchedRule: null };
  }

  if (!country) {
    return { templateName: "", matchType: "no_geo_country", matchedIndex: -1, matchedRule: null };
  }

  // Find best match:
  // - must match country
  // - if States empty => wildcard match
  // - if States has values => must match state to be "state-specific"
  let best = null;

  for (let i = 0; i < ruleSet.length; i++) {
    const r = ruleSet[i] || {};
    const countries = lowerList(r.Countries ?? r.countries);
    const states = lowerList(r.States ?? r.states);

    const countryMatch = countries.includes(country);
    if (!countryMatch) continue;

    const hasStateList = states.length > 0;
    const wildcardState = !hasStateList; // empty means applies to any state
    const exactStateMatch = hasStateList && state && states.includes(state);

    // If state is present but doesn't match state list, skip
    if (hasStateList && state && !exactStateMatch) continue;

    // If state is empty (geolocation didn’t provide it), prefer wildcardState rules
    if (hasStateList && !state) continue;

    // scoring: prefer exact state match over wildcard
    const score = exactStateMatch ? 3 : 2; // both already match country

    const candidate = {
      matchedIndex: i,
      matchedRule: r,
      templateName: r.TemplateName ?? "",
      matchType: exactStateMatch ? "country_and_state" : "country_only_or_wildcard_state",
      score
    };

    if (!best || candidate.score > best.score) best = candidate;
  }

  if (!best) {
    return { templateName: "", matchType: "no_match", matchedIndex: -1, matchedRule: null };
  }

  return best;
}

export async function runCheck(inputUrl) {
  const targetUrl = normaliseUrl(inputUrl);
  if (!targetUrl) throw new Error("url is required");

  let browser = null;

  const notes = [];
  let capturedConfig = null;
  let capturedConfigUrl = "";

  let isCspBlocked = false; // reserved
  let accessDenied = false;
  let navigationError = null;

  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();

    page.on("response", async response => {
      try {
        const status = response.status();
        const req = response.request();
        const resourceType = req.resourceType();
        const url = response.url();

        if (resourceType === "document" && (status === 401 || status === 403)) {
          accessDenied = true;
        }

        const lowerUrl = url.toLowerCase();
        const contentType = (response.headers()?.["content-type"] || "").toLowerCase();

        const isLikelyJson =
          lowerUrl.includes(".json") ||
          contentType.includes("application/json") ||
          contentType.includes("text/json");

        if (!isLikelyJson) return;

        const text = await response.text().catch(() => "");
        if (!text) return;

        let parsed = null;
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

    let navigationResponse = null;
    try {
      navigationResponse = await page.goto(targetUrl, { waitUntil: "domcontentloaded" });
    } catch (err) {
      navigationError = err?.message || String(err);
    }

    if (!navigationResponse && navigationError) {
      return {
        checkedUrl: targetUrl,
        accessDenied: false,
        isCspBlocked: false,
        navigationError,
        severity: "HIGH",
        issues: [mkFinding("HIGH", `Navigation failed: ${navigationError}`)],
        recommendations: [
          "Verify the URL is correct (e.g., www vs wwww)",
          "Check DNS resolution / network access from runner"
        ],
        notes
      };
    }

    if (navigationResponse) {
      const status = navigationResponse.status();
      if (status === 401 || status === 403) {
        accessDenied = true;
      }
    }

    await page.waitForTimeout(5000);

    // script scan
    const scripts = await page.locator("script").evaluateAll(nodes =>
      nodes.map((s, idx) => ({
        index: idx,
        inHead: !!(document.head && document.head.contains(s)),
        src: s.src || "",
        dataDomainScript: s.getAttribute("data-domain-script") || ""
      }))
    );

    const stubScripts = scripts.filter(s =>
      (s.src || "").toLowerCase().includes("otsdkstub.js")
    );

    const autoBlockScripts = scripts.filter(s =>
      (s.src || "").toLowerCase().includes("otautoblock.js")
    );

    const primaryUdid =
      stubScripts.find(s => s.dataDomainScript)?.dataDomainScript || "";

    const productionUdid = cleanUdid(primaryUdid);
    const usingTestScript = isTestScript(primaryUdid);

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

    const otSDKStubFound = stubScripts.length > 0;
    const autoBlockEnabled = autoBlockScripts.length > 0;

    const hasDuplicateOtSdkStub = stubScripts.length > 1;
    const hasDuplicateAutoBlock = autoBlockScripts.length > 1;

    // udid.json fields
    const ruleSet = Array.isArray(capturedConfig?.RuleSet) ? capturedConfig.RuleSet : [];
    const ruleSetCount = ruleSet.length;
    const skipGeolocation = Boolean(capturedConfig?.SkipGeolocation);

    // ---- NEW TEMPLATE RESOLUTION LOGIC ----
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

    // findings
    const issues = [];
    const recommendations = [];

    if (accessDenied) {
      issues.push(mkFinding("HIGH", "Access denied or blocked (401/403 or page content detected)"));
    }

    if (domainOutOfScope) {
      issues.push(
        mkFinding("HIGH", `Domain mismatch between script and site (${configDomain} vs ${checkedHost})`)
      );
    }

    if (!otSDKStubFound) {
      issues.push(mkFinding("HIGH", "otSDKStub.js not detected"));
    }

    if (hasDuplicateOtSdkStub) {
      issues.push(mkFinding("HIGH", "Duplicate otSDKStub.js detected"));
    }

    if (hasDuplicateAutoBlock) {
      issues.push(mkFinding("MEDIUM", "Duplicate otAutoBlock.js detected"));
    }

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

      severity,
      issues,
      recommendations,
      notes
    };
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}
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

