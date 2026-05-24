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
  if (findings.length > 0) return "LOW";
  return "NONE";
}

function looksLikeUdidJson(obj) {
  if (!obj) return false;
  return obj.Domain && obj.Version && obj.ScriptType;
}

export async function runCheck(inputUrl) {
  const targetUrl = normaliseUrl(inputUrl);

  let capturedConfig = null;
  let accessDenied = false;

  let browser;

  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();

    // capture responses
    page.on("response", async (response) => {
      try {
        const status = response.status();

        if (response.request().resourceType() === "document" && (status === 401 || status === 403)) {
          accessDenied = true;
        }

        const url = response.url().toLowerCase();

        if (!url.includes("json")) return;

        const text = await response.text();
        const parsed = JSON.parse(text);

        if (looksLikeUdidJson(parsed)) {
          capturedConfig = parsed;
        }

      } catch {}
    });

    let navError = null;

    try {
      await page.goto(targetUrl, { waitUntil: "domcontentloaded" });
    } catch (err) {
      navError = err.message;
    }

    if (navError) {
      return {
        checkedUrl: targetUrl,
        severity: "HIGH",
        issues: [mkFinding("HIGH", navError)]
      };
    }

    await page.waitForTimeout(5000);

    // scan scripts
    const scripts = await page.locator("script").evaluateAll(nodes =>
      nodes.map((s, i) => ({
        index: i,
        src: s.src || "",
        inHead: document.head.contains(s),
        udid: s.getAttribute("data-domain-script") || ""
      }))
    );

    const stub = scripts.filter(s => s.src.toLowerCase().includes("otsdkstub"));
    const autoblock = scripts.filter(s => s.src.toLowerCase().includes("otautoblock"));

    const firstOt = Math.min(...[...stub, ...autoblock].map(s => s.index));

    const jsBefore = scripts.filter(s => s.index < firstOt && s.src.includes(".js"));

    const primaryUdid = stub.find(s => s.udid)?.udid || "";

    // udid json fields
    const ruleSet = capturedConfig?.RuleSet || [];
    const skipGeo = capturedConfig?.SkipGeolocation === true;

    let geoData = null;

    if (!(ruleSet.length === 1 && skipGeo)) {
      try {
        await page.waitForFunction(() => window.OneTrust, { timeout: 5000 });

        geoData = await page.evaluate(() => {
          try {
            return window.OneTrust?.getGeolocationData?.();
          } catch {
            return null;
          }
        });
      } catch {}
    }

    // consent modes
    let consent = {};

    try {
      consent = await page.evaluate(() => {
        try {
          return window.OneTrust?.GetDomainData?.();
        } catch {
          return {};
        }
      });
    } catch {}

    return {
      checkedUrl: targetUrl,

      TenantGuid: capturedConfig?.TenantGuid ?? "",
      EnvId: capturedConfig?.EnvId ?? "",
      Domain: capturedConfig?.Domain ?? "",

      udidJson: {
        Version: capturedConfig?.Version ?? "",
        ScriptType: capturedConfig?.ScriptType ?? "",
        LanguageDetectionByHtml: capturedConfig?.LanguageDetectionByHtml ?? "",
        LanguageDetectionEnabled: capturedConfig?.LanguageDetectionEnabled ?? "",
        GeoRuleGroupName: capturedConfig?.GeoRuleGroupName ?? "",
        RuleSetCount: ruleSet.length,
        SkipGeolocation: skipGeo
      },

      primaryUdid,
      productionUdid: cleanUdid(primaryUdid),
      usingTestScript: isTestScript(primaryUdid),

      otSDKStubFound: stub.length > 0,
      autoBlockEnabled: autoblock.length > 0,

      otSdkStubInHead: stub.some(s => s.inHead),
      otAutoBlockInHead: autoblock.some(s => s.inHead),

      hasJsBeforeOt: jsBefore.length > 0,
      previousScripts: jsBefore.map(s => s.src),

      geolocation: geoData,

      consentModes: {
        google: consent?.GoogleConsent?.GCEnable ?? null,
        microsoft: consent?.MCMData?.Enabled ?? null,
        amazon: consent?.ACMData?.Enabled ?? null
      },

      accessDenied,

      severity: "NONE",
      issues: []
    };

  } finally {
    if (browser) await browser.close();
  }
}