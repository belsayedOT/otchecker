import { chromium } from "playwright";

function normaliseUrl(url) {
  const trimmed(trimmed) ? trimmed : `https://${trimmed}`;  const trimmed = (url || "").trim();
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

export async function runCheck(inputUrl) {
  const targetUrl = normaliseUrl(inputUrl);
  if (!targetUrl) throw new Error("url is required");

  let browser = null;

  const notes = [];
  let capturedConfig = null;

  let isCspBlocked = false;
  let accessDenied = false;

  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();

    // ---- detect HTTP access issues ----
    page.on("response", response => {
      try {
        const status = response.status();

        if (response.request().resourceType() === "document") {
          if (status === 401 || status === 403) {
            accessDenied = true;
          }
        }
      } catch {}
    });

    // ---- capture config JSON ----
    page.on("response", async response => {
      try {
        const url = response.url().toLowerCase();
        if (url.endsWith(".json")) {
          const text = await response.text();
          const parsed = JSON.parse(text);
          if (parsed?.Domain) {
            capturedConfig = parsed;
          }
        }
      } catch {}
    });

    // ---- navigate ----
    const navigationResponse = await page.goto(targetUrl, { waitUntil: "domcontentloaded" });

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
      const lowered = bodyText.toLowerCase();

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

    // ---- script extraction ----
    const scripts = await page.locator("script").evaluateAll(nodes =>
      nodes.map(s => ({
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
    } else {
      domainScopeValid = false;
      domainOutOfScope = false;
    }

    domainScopeValid = Boolean(domainScopeValid);
    domainOutOfScope = Boolean(domainOutOfScope);

    const otSDKStubFound = stubScripts.length > 0;
    const autoBlockEnabled = autoBlockScripts.length > 0;

    const hasDuplicateOtSdkStub = stubScripts.length > 1;
    const hasDuplicateAutoBlock = autoBlockScripts.length > 1;

    const issues = [];
    const recommendations = [];

    if (accessDenied) {
      issues.push(mkFinding("HIGH", "Access denied or blocked (401/403 or page content detected)"));
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

    const severity = computeSeverity(issues);

    return {
      checkedUrl: targetUrl,

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
  if (!trimmed) return "";
