import { chromium } from "playwright";

function normal();function normaliseUrl(url) {
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

export async function runCheck(inputUrl) {
  const targetUrl = normaliseUrl(inputUrl);
  if (!targetUrl) throw new Error("url is required");

  let browser = null;

  const notes = [];
  let capturedConfig = null;

  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();

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

    await page.goto(targetUrl, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(5000);

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

    // ✅ FIXED: ALWAYS BOOLEAN (no nulls, no undefined)
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

    // ✅ EXTRA GUARANTEE (critical for Copilot)
    domainScopeValid = Boolean(domainScopeValid);
    domainOutOfScope = Boolean(domainOutOfScope);

    const otSDKStubFound = stubScripts.length > 0;
    const autoBlockEnabled = autoBlockScripts.length > 0;

    const hasDuplicateOtSdkStub = stubScripts.length > 1;
    const hasDuplicateAutoBlock = autoBlockScripts.length > 1;

    const isCspBlocked = false;
    const accessDenied = false;

    const issues = [];
    const recommendations = [];

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