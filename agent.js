import { chromium } from "playwright";

function normaliseUrl(url) {
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

function isJsFileSrc(src = "") {
  const s = (src || "").toLowerCase();
  return s.includes(".js") || s.includes("scripttemplates");
}

export async function runCheck(inputUrl) {
  const targetUrl = normaliseUrl(inputUrl);
  if (!targetUrl) throw new Error("url is required");

  let browser = null;
  let capturedConfig = null;
  let capturedConfigUrl = "";

  let accessDenied = false;
  let navigationError = null;

  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();

    // capture JSON + access issues
    page.on("response", async response => {
      try {
        const status = response.status();
        const url = response.url();

        if (response.request().resourceType() === "document" && (status === 401 || status === 403)) {
          accessDenied = true;
        }

        const isJson =
          url.toLowerCase().includes(".json") ||
          (response.headers()["content-type"] || "").includes("json");

        if (!isJson) return;

        const text = await response.text();
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

    let response;
    try {
      response = await page.goto(targetUrl, { waitUntil: "domcontentloaded" });
    } catch (err) {
      navigationError = err.message;
    }

    if (!response && navigationError) {
      return {
        checkedUrl: targetUrl,
        severity: "HIGH",
        issues: [mkFinding("HIGH", navigationError)],
        recommendations: ["Check URL spelling or DNS"],
      };
    }

    await page.waitForTimeout(5000);

    // script scan
    const scripts = await page.locator("script").evaluateAll(nodes =>
      nodes.map((s, i) => ({
        index: i,
        src: s.src || "",
        inHead: document.head.contains(s),
        dataDomainScript: s.getAttribute("data-domain-script") || ""
      }))
    );

    const stubScripts = scripts.filter(s => s.src.toLowerCase().includes("otsdkstub"));
    const autoBlockScripts = scripts.filter(s => s.src.toLowerCase().includes("otautoblock"));

    const firstOtIndex = Math.min(
      ...[...stubScripts, ...autoBlockScripts].map(s => s.index)
    );

    const jsBefore = scripts.filter(s => s.index < firstOtIndex && isJsFileSrc(s.src));

    const primaryUdid = stubScripts.find(s => s.dataDomainScript)?.dataDomainScript || "";

    // udid.json fields
    const version = capturedConfig?.Version ?? "";
    const scriptType = capturedConfig?.ScriptType ?? "";
    const langHtml = capturedConfig?.LanguageDetectionByHtml ?? "";
    const langEnabled = capturedConfig?.LanguageDetectionEnabled ?? "";
    const geoRule = capturedConfig?.GeoRuleGroupName ?? "";

    const ruleSet = Array.isArray(capturedConfig?.RuleSet) ? capturedConfig.RuleSet : [];
    const ruleCount = ruleSet.length;
    const skipGeo = capturedConfig?.SkipGeolocation === true;

    // geolocation logic
    let geoData = null;
    if (!(ruleCount === 1 && skipGeo)) {
      try {
        await page.waitForFunction(() => window.OneTrust, { timeout: 5000 });
        geoData = await page.evaluate(() => {
          try {
            return window.OneTrust?.getGeolocationData?.() ?? null;
          } catch {
            return null;
          }
        });
      } catch {}
    }

    // consent modes
    let consentData = {};
    try {
      consentData = await page.evaluate(() => {
        try {
          return window.OneTrust.GetDomainData();
        } catch {
          return {};
        }
      });
    } catch {}

    const issues = [];

    if (!stubScripts.length) {
      issues.push(mkFinding("HIGH", "otSDKStub missing"));
    }

    return {
      checkedUrl: targetUrl,

      TenantGuid: capturedConfig?.TenantGuid ?? "",
      EnvId: capturedConfig?.EnvId ?? "",
      Domain: capturedConfig?.Domain ?? "",

      udidJson: {
        Version: version,
        ScriptType: scriptType,
        LanguageDetectionByHtml: langHtml,
        LanguageDetectionEnabled: langEnabled,
        GeoRuleGroupName: geoRule,
        RuleSetCount: ruleCount,
        SkipGeolocation: skipGeo
      },

      primaryUdid,
      productionUdid: cleanUdid(primaryUdid),
      usingTestScript: isTestScript(primaryUdid),

      otSDKStubFound: !!stubScripts.length,
      autoBlockEnabled: !!autoBlockScripts.length,
      otSdkStubInHead: stubScripts.some(s => s.inHead),
      otAutoBlockInHead: autoBlockScripts.some(s => s.inHead),

      hasJsBeforeOt: jsBefore.length > 0,
      previousScripts: jsBefore.map(s => s.src),

      geolocation: geoData,

      consentModes: {
        google: consentData?.GoogleConsent?.GCEnable ?? null,
        microsoft: consentData?.MCMData?.Enabled ?? null,
        amazon: consentData?.ACMData?.Enabled ?? null
      },

      accessDenied,

      severity: computeSeverity(issues),
      issues
    };
}