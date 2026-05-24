import { chromium } from "playwright";

function normaliseUrl(url) {
  const trimmed = (    try {  const trimmed = (url || "").trim();
      navigationResponse = await page.goto(targetUrl, { waitUntil: "domcontentloaded" });
    } catch (err) {
      navigationError = err?.message || String(err);
    }

    // if navigation failed hard, return a structured response (no crash)
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
          "Check DNS resolution / network access from runner",
          "If site requires auth, try a public URL or add auth support"
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

    // ---- detect access denied from page content ----
    try {
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

    // ---- script extraction with order + head placement ----
    const scripts = await page.locator("script").evaluateAll(nodes =>
      nodes.map((s, idx) => ({
        index: idx,
        inHead: !!(document.head && document.head.contains(s)),
        src: s.src || "",
        type: s.getAttribute("type") || "",
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

    // ---- checks: scripts in head yes/no (your request) ----
    const otSdkStubInHead = stubScripts.length > 0 ? stubScripts.some(s => s.inHead) : false;
    const otAutoBlockInHead = autoBlockScripts.length > 0 ? autoBlockScripts.some(s => s.inHead) : false;

    // ---- check: any script tags calling JS before stub/autoblock (your request) ----
    const firstOtIndexCandidates = [
      ...stubScripts.map(s => s.index),
      ...autoBlockScripts.map(s => s.index)
    ];
    const firstOtIndex =
      firstOtIndexCandidates.length > 0 ? Math.min(...firstOtIndexCandidates) : -1;

    const jsScriptsBeforeOt = firstOtIndex > 0
      ? scripts
          .filter(s => s.index < firstOtIndex && isJsFileSrc(s.src))
          .map(s => s.src)
          .filter(Boolean)
      : [];

    const hasJsBeforeOt = jsScriptsBeforeOt.length > 0;

    // ---- "running in head yes/no" (best-effort) ----
    // We cannot truly prove "running" from HTML alone, so we return:
    // - inHead booleans (placement)
    // - oneTrustObjectPresent (indicates stub executed/loaded enough to create window.OneTrust)
    let oneTrustObjectPresent = false;
    try {
      oneTrustObjectPresent = await page.evaluate(() => !!window.OneTrust);
    } catch {
      oneTrustObjectPresent = false;
    }

    // ---- domain scope check ----
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

    // ---- script checks ----
    const otSDKStubFound = stubScripts.length > 0;
    const autoBlockEnabled = autoBlockScripts.length > 0;

    const hasDuplicateOtSdkStub = stubScripts.length > 1;
    const hasDuplicateAutoBlock = autoBlockScripts.length > 1;

    // ---- udid.json fields you asked for ----
    const udidJsonFields = {
      Version: capturedConfig?.Version ?? "",
      ScriptType: capturedConfig?.ScriptType ?? "",
      LanguageDetectionByHtml: capturedConfig?.LanguageDetectionByHtml ?? "",
      LanguageDetectionEnabled: capturedConfig?.LanguageDetectionEnabled ?? "",
      GeoRuleGroupName: capturedConfig?.GeoRuleGroupName ?? ""
    };

    // ---- ruleset count ----
    const ruleSetCount = Array.isArray(capturedConfig?.RuleSet)
      ? capturedConfig.RuleSet.length
      : 0;

    const skipGeolocation = Boolean(capturedConfig?.SkipGeolocation);

    // ---- geolocation logic you requested ----
    // if RuleSet only has one value AND SkipGeolocation true => do not return location info
    const shouldReturnGeolocation = !(ruleSetCount === 1 && skipGeolocation === true);

    let geolocationData = null;

    // ---- consent mode checks you requested via OneTrust.GetDomainData() ----
    let googleConsentModeEnabled = null;
    let microsoftConsentModeEnabled = null;
    let amazonConsentModeEnabled = null;

    // Attempt to wait for OneTrust.GetDomainData
    try {
      await page.waitForFunction(
        () => window.OneTrust && typeof window.OneTrust.GetDomainData === "function",
        { timeout: 8000 }
      );

      const domainData = await page.evaluate(() => {
        try {
          return window.OneTrust.GetDomainData();
        } catch {
          return null;
        }
      });

      googleConsentModeEnabled =
        domainData?.GoogleConsent?.GCEnable ?? null;

      microsoftConsentModeEnabled =
        domainData?.MCMData?.Enabled ?? null;

      amazonConsentModeEnabled =
        domainData?.ACMData?.Enabled ?? null;

      if (shouldReturnGeolocation) {
        geolocationData = await page.evaluate(async () => {
          try {
            const fn = window.OneTrust?.getGeolocationData;
            if (typeof fn !== "function") return null;

            const res = fn.call(window.OneTrust);
            if (res && typeof res.then === "function") {
              return await res;
            }
            return res ?? null;
          } catch {
            return null;
          }
        });
      }
    } catch {
      // keep as null if OneTrust is not available
    }

    // ---- findings ----
    const issues = [];
    const recommendations = [];

    if (accessDenied) {
      issues.push(
        mkFinding("HIGH", "Access denied or blocked (401/403 or page content detected)")
      );
    }

    if (domainOutOfScope) {
      issues.push(
        mkFinding(
          "HIGH",
          `Domain mismatch between script and site (${configDomain} vs ${checkedHost})`
        )
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

    // helpful warnings (optional)
    if (otSDKStubFound && !otSdkStubInHead) {
      issues.push(mkFinding("LOW", "otSDKStub.js detected but not placed in <head>"));
    }

    if (autoBlockEnabled && !otAutoBlockInHead) {
      issues.push(mkFinding("LOW", "otAutoBlock.js detected but not placed in <head>"));
    }

    if (hasJsBeforeOt) {
      issues.push(mkFinding("LOW", "Other JS files appear before otSDKStub.js/otAutoBlock.js"));
    }

    const severity = computeSeverity(issues);

    // ---- response ----
    return {
      checkedUrl: targetUrl,

      // captured udid.json info
      udidJsonUrl: capturedConfigUrl,

      TenantGuid: capturedConfig?.TenantGuid ?? "",
      EnvId: capturedConfig?.EnvId ?? "",
      Domain: configDomain,

      // udid.json fields requested + ruleset count
      udidJson: {
        ...udidJsonFields,
        SkipGeolocation: skipGeolocation,
        RuleSetCount: ruleSetCount
      },

      // script-tag udid
      primaryUdid,
      productionUdid,
      usingTestScript,

      // script checks
      otSDKStubFound,
      autoBlockEnabled,
      hasDuplicateOtSdkStub,
      hasDuplicateAutoBlock,

      // requested head/order checks
      otSdkStubInHead,
      otAutoBlockInHead,
      hasJsBeforeOt,
      jsScriptsBeforeOt, // returning the actual list helps debugging

      // best-effort "running" indicator
      oneTrustObjectPresent,

      // csp/access flags
      isCspBlocked,
      accessDenied,

      // domain validation
      checkedHost,
      configDomain,
      domainScopeValid,
      domainOutOfScope,

      // geolocation gating + result
      geolocationReturned: Boolean(shouldReturnGeolocation),
      geolocationData: shouldReturnGeolocation ? geolocationData : null,

      // consent mode flags requested
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

// ---- Domain helper ----
function isDomainMatching(host, domain) {
  if (!host || !domain) return false;
  const h = host.toLowerCase();
  const d = domain.toLowerCase();
  return h === d || h.endsWith(`.${d}`);
}

// ---- Detect udid.json / domaindata-like payloads ----
function looksLikeUdidJson(obj) {
  if (!obj || typeof obj !== "object") return false;

  // keys commonly present in udid.json / domain data responses
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

// best-effort to detect "JS file" scripts
function isJsFileSrc(src = "") {
  const s = (src || "").toLowerCase().trim();
  if (!s) return false;
  // allow .js plus common script urls without extension (some CDNs)
  return s.includes(".js") || s.includes("/scripttemplates/") || s.includes("javascript");
}

export async function runCheck(inputUrl) {
  const targetUrl = normaliseUrl(inputUrl);
  if (!targetUrl) throw new Error("url is required");

  let browser = null;

  const notes = [];

  // captured udid.json payload
  let capturedConfig = null;
  let capturedConfigUrl = "";

  let isCspBlocked = false; // reserved (not implemented here)
  let accessDenied = false;

  // additional navigation/lookup errors (DNS, TLS, etc.)
  let navigationError = null;

  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();

    // ---- capture access denied + udid.json in ONE response handler ----
    page.on("response", async response => {
      try {
        const status = response.status();
        const req = response.request();
        const resourceType = req.resourceType();
        const url = response.url();

        // access denied detection (document)
        if (resourceType === "document" && (status === 401 || status === 403)) {
          accessDenied = true;
        }

        // attempt to capture udid.json / domain data payload
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

        // only save if it resembles udid.json/domain-data
        if (looksLikeUdidJson(parsed)) {
          capturedConfig = parsed;
          capturedConfigUrl = url;
        }
      } catch {}
    });

    // ---- navigate (graceful) ----
    let navigationResponse = null;
