import { chromium } from "playwright";
import fs from "fs";

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

async function safeEvaluate(page, expression) {
  try {
    return { success: true, value: await page.evaluate(expression) };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

function extractBodyPreview(text = "", max = 3000) {
  return text.length > max ? `${text.slice(0, max)}... [truncated]` : text;
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

// ---- CSP helpers ----
function looksLikeCspViolation(text = "") {
  const t = (text || "").toLowerCase();
  return (
    t.includes("content security policy") ||
    t.includes("violates the following content security policy directive") ||
    t.includes("refused to load the script") ||
    t.includes("refused to execute inline script") ||
    t.includes("unsafe-eval") ||
    t.includes("unsafe-inline")
  );
}

function looksLikeCspNetworkBlock(errText = "") {
  const t = (errText || "").toLowerCase();
  return (
    t.includes("blocked by content security policy") ||
    t.includes("content security policy") ||
    t.includes("csp") ||
    t.includes("unsafe-eval") ||
    t.includes("unsafe-inline") ||
    t.includes("err_blocked_by_client") ||
    t.includes("blocked")
  );
}

// ---- Domain scope helper ----
function isDomainMatching(host, domain) {
  if (!host || !domain) return false;
  const h = host.toLowerCase();
  const d = domain.toLowerCase();
  return h === d || h.endsWith(`.${d}`);
}

/**
 * Exported for server.js:
 * import { runCheck } from "./agent.js";
 */
export async function runCheck(inputUrl) {
  const targetUrl = normaliseUrl(inputUrl);
  if (!targetUrl) throw new Error("url is required");

  const DEBUG = process.env.DEBUG_ARTIFACTS === "true";

  // Per-run state (no globals)
  const notes = [];
  const apiCalls = [];
  const otStubNetworkCalls = [];
  const otAutoBlockNetworkCalls = [];
  const possibleJsonResponses = [];

  // CSP tracking
  const cspConsoleViolations = [];
  const cspNetworkFailures = [];
  let hasCspHeaderSeen = false;

  let accessDenied = false;
  let autoBlockResponseDetails = null;
  let geoLocationResponseDetails = null;

  let browser = null;

  try {
    browser = await chromium.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-dev-shm-usage"]
    });

    const page = await browser.newPage({
      viewport: { width: 1366, height: 768 },
      userAgent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    });

    // ---- CSP: capture console violations ----
    page.on("console", msg => {
      try {
        const text = msg.text?.() || "";
        if (looksLikeCspViolation(text)) {
          cspConsoleViolations.push({
            type: msg.type?.() || "log",
            text
          });
        }
      } catch {
        // ignore
      }
    });

    // ---- CSP: capture request failures ----
    page.on("requestfailed", request => {
      try {
        const url = request.url();
        const lowerUrl = url.toLowerCase();
        const failure = request.failure();
        const errText = failure?.errorText || "";

        const isOtRelevant =
          lowerUrl.includes("otsdkstub.js") ||
          lowerUrl.includes("otautoblock.js") ||
          lowerUrl.includes("cookielaw.org") ||
          lowerUrl.includes("onetrust");

        if (isOtRelevant && looksLikeCspNetworkBlock(errText)) {
          cspNetworkFailures.push({ url, errorText: errText });
        }
      } catch {
        // ignore
      }
    });

    // Track key requests
    page.on("request", request => {
      const url = request.url();
      const lowerUrl = url.toLowerCase();

      if (lowerUrl.includes("otsdkstub.js")) {
        otStubNetworkCalls.push({
          url,
          method: request.method(),
          resourceType: request.resourceType()
        });
      }

      if (lowerUrl.includes("otautoblock.js")) {
        otAutoBlockNetworkCalls.push({
          url,
          method: request.method(),
          resourceType: request.resourceType()
        });
      }
    });

    // Track responses + capture JSON bodies
    page.on("response", async response => {
      const url = response.url();
      const request = response.request();
      const lowerUrl = url.toLowerCase();

      const headers = response.headers?.() || {};
      if (headers["content-security-policy"] || headers["content-security-policy-report-only"]) {
        hasCspHeaderSeen = true;
      }

      const responseSummary = {
        url,
        method: request.method(),
        resourceType: request.resourceType(),
        status: response.status()
      };

      apiCalls.push(responseSummary);

      // Capture AutoBlock body
      if (lowerUrl.includes("otautoblock.js")) {
        try {
          const bodyText = await response.text();
          autoBlockResponseDetails = {
            ...responseSummary,
            headers: DEBUG ? headers : undefined,
            bodyPreview: extractBodyPreview(bodyText),
            bodyLength: bodyText.length
          };
        } catch (error) {
          autoBlockResponseDetails = { ...responseSummary, error: error.message };
        }
      }

      // Capture geolocation response
      if (lowerUrl.includes("/v1/geo/location")) {
        try {
          const bodyText = await response.text();
          let parsedBody = null;
          try {
            parsedBody = JSON.parse(bodyText);
          } catch {
            parsedBody = null;
          }

          geoLocationResponseDetails = {
            ...responseSummary,
            headers: DEBUG ? headers : undefined,
            body: parsedBody ?? bodyText,
            bodyLength: bodyText.length
          };
        } catch (error) {
          geoLocationResponseDetails = { ...responseSummary, error: error.message };
        }
      }

      // Collect *.json responses
      try {
        const urlObj = new URL(url);
        const pathname = urlObj.pathname.toLowerCase();

        if (pathname.endsWith(".json")) {
          const bodyText = await response.text();
          possibleJsonResponses.push({
            url,
            status: response.status(),
            resourceType: request.resourceType(),
            bodyText
          });
        }
      } catch {
        // ignore URL parse errors
      }
    });

    // -------- NAVIGATION --------
    try {
      await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 60000 });

      await page.waitForLoadState("networkidle", { timeout: 30000 }).catch(() => {
        notes.push("Network did not become idle within 30 seconds.");
      });

      // Give async OneTrust calls time
      await page.waitForTimeout(8000);
    } catch (error) {
      notes.push(`Page navigation issue: ${error.message}`);
    }

    // WAF/CDN detection
    const pageBodyText = await page.locator("body").innerText().catch(() => "");
    if (
      pageBodyText.includes("Access Denied") ||
      pageBodyText.includes("You don't have permission to access") ||
      page.url().includes("errors.edgesuite.net")
    ) {
      accessDenied = true;
      notes.push("Access denied by CDN/WAF. Playwright could not access the real page.");
    }

    // -------- SCRIPT INSPECTION --------
    const allFrameScripts = [];

    for (const frame of page.frames()) {
      try {
        const scripts = await frame.locator("script").evaluateAll(nodes =>
          nodes.map((script, index) => ({
            index,
            frameUrl: window.location.href,
            src: script.src || "",
            id: script.id || "",
            dataDomainScript: script.getAttribute("data-domain-script") || "",
            outerHTML: script.outerHTML || "",
            parentTagName: script.parentElement?.tagName?.toLowerCase() || "",
            inHead: script.closest("head") !== null,
            inBody: script.closest("body") !== null
          }))
        );
        allFrameScripts.push(...scripts);
      } catch {
        notes.push(`Could not inspect scripts in frame: ${frame.url()}`);
      }
    }

    const stubScripts = allFrameScripts.filter(s => {
      const src = (s.src || "").toLowerCase();
      const html = (s.outerHTML || "").toLowerCase();
      return src.includes("otsdkstub.js") || html.includes("otsdkstub.js");
    });

    const autoBlockScripts = allFrameScripts.filter(s => {
      const src = (s.src || "").toLowerCase();
      const html = (s.outerHTML || "").toLowerCase();
      return src.includes("otautoblock.js") || html.includes("otautoblock.js");
    });

    const firstStubScript = stubScripts[0] || null;
    const firstAutoBlockScript = autoBlockScripts[0] || null;

    function getScriptsBefore(targetScript, scriptList) {
      if (!targetScript) return [];
      return scriptList
        .filter(s => s.frameUrl === targetScript.frameUrl)
        .filter(s => s.index < targetScript.index)
        .map(s => ({
          index: s.index,
          src: s.src,
          id: s.id,
          parentTagName: s.parentTagName,
          inHead: s.inHead,
          inBody: s.inBody
        }));
    }

    const scriptsBeforeOtSDKStub = getScriptsBefore(firstStubScript, allFrameScripts);
    const scriptsBeforeAutoBlock = getScriptsBefore(firstAutoBlockScript, allFrameScripts);

    // -------- Extract data-domain-script --------
    const dataDomainScriptValues = stubScripts
      .map(s => s.dataDomainScript)
      .filter(Boolean);

    const primaryUdid = dataDomainScriptValues[0] || "";
    const productionUdid = cleanUdid(primaryUdid);
    const usingTestScript = isTestScript(primaryUdid);

    // -------- Capture UDID JSON --------
    let capturedConfig = null;
    let capturedConfigUrl = "";

    for (const item of possibleJsonResponses) {
      try {
        const pathname = new URL(item.url).pathname.toLowerCase();

        const isTargetUdidJson =
          productionUdid &&
          pathname.endsWith(`/${productionUdid.toLowerCase()}.json`);

        if (!isTargetUdidJson) continue;

        capturedConfig = JSON.parse(item.bodyText);
        capturedConfigUrl = item.url;
        break;
      } catch {
        notes.push(`Found possible UDID JSON but could not parse it: ${item.url}`);
      }
    }

    const cookies = await page.context().cookies();

    // -------- REQUIRED FLAGS --------
    const otSDKStubFound = stubScripts.length > 0 || otStubNetworkCalls.length > 0;
    const autoBlockEnabled = autoBlockScripts.length > 0 || otAutoBlockNetworkCalls.length > 0;

    const hasDuplicateOtSdkStub = stubScripts.length > 1 || otStubNetworkCalls.length > 1;
    const hasDuplicateAutoBlock = autoBlockScripts.length > 1 || otAutoBlockNetworkCalls.length > 1;

    const scriptsBeforeOtSdkStub = scriptsBeforeOtSDKStub.length > 0;
    const scriptsBeforeAutoBlockFlag = scriptsBeforeAutoBlock.length > 0;

    const otSdkStubInHead = firstStubScript?.inHead ?? false;
    const autoBlockInHead = firstAutoBlockScript?.inHead ?? false;

    // -------- CSP BLOCK FLAG --------
    const isCspBlocked = cspConsoleViolations.length > 0 || cspNetworkFailures.length > 0;
    if (isCspBlocked) {
      notes.push("CSP violation detected (console and/or request failure).");
      if (hasCspHeaderSeen) notes.push("CSP header observed in responses.");
    }

    // -------- NEW: Domain scope validation --------
    const checkedHost = (() => {
      try {
        return new URL(targetUrl).hostname || "";
      } catch {
        return "";
      }
    })();

    const configDomain = capturedConfig?.Domain ?? "";

    // Default values
    let domainScopeValid = null; // null means "cannot determine"
    let domainOutOfScope = null;

    if (usingTestScript) {
      // You said: behaviour does not apply if UDID has -test
      domainScopeValid = true;
      domainOutOfScope = false;
    } else if (configDomain && checkedHost) {
      domainScopeValid = isDomainMatching(checkedHost, configDomain);
      domainOutOfScope = !domainScopeValid;
    } else if (!capturedConfig) {
      domainScopeValid = null;
      domainOutOfScope = null;
      notes.push("Domain scope could not be validated because UDID config JSON was not captured.");
    } else {
      domainScopeValid = null;
      domainOutOfScope = null;
      notes.push("Domain scope could not be validated (missing host/domain).");
    }

    // -------- issues + recommendations --------
    const issues = [];
    const recommendations = [];

    if (isCspBlocked) {
      issues.push(mkFinding("HIGH", "Content Security Policy (CSP) appears to be blocking OneTrust resources or execution."));
      recommendations.push(mkFinding("HIGH", "Allowlist the OneTrust CDN and required directives in CSP (script-src / connect-src as needed)."));
    }

    if (accessDenied) {
      issues.push(mkFinding("HIGH", "Site appears blocked by CDN/WAF (Access Denied)."));
      recommendations.push(mkFinding("HIGH", "Ask customer to allowlist the scanner/requests or test from a non-blocked network."));
    }

    if (!otSDKStubFound) {
      issues.push(mkFinding("HIGH", "otSDKStub.js was not detected in DOM or network calls."));
      recommendations.push(mkFinding("HIGH", "Confirm OneTrust script is implemented on the page and not blocked by CSP/WAF."));
    }

    if (hasDuplicateOtSdkStub) {
      issues.push(mkFinding("HIGH", "Duplicate otSDKStub.js detected (DOM and/or network)."));
      recommendations.push(mkFinding("HIGH", "Remove duplicate OneTrust script to avoid unpredictable banner/consent behaviour."));
    }

    if (hasDuplicateAutoBlock) {
      issues.push(mkFinding("HIGH", "Duplicate otAutoBlock.js detected (DOM and/or network)."));
      recommendations.push(mkFinding("HIGH", "Remove duplicate AutoBlock include. Duplicate autoblock can break script injection."));
    }

    if (otSDKStubFound && !otSdkStubInHead) {
      issues.push(mkFinding("MEDIUM", "otSDKStub.js is not located in the <head> section."));
      recommendations.push(mkFinding("MEDIUM", "Move otSDKStub.js into <head> as early as possible (before other scripts)."));
    }

    if (autoBlockEnabled && !autoBlockInHead) {
      issues.push(mkFinding("MEDIUM", "otAutoBlock.js is not located in the <head> section."));
      recommendations.push(mkFinding("MEDIUM", "Move otAutoBlock.js into <head> and ensure it loads before tags it should block."));
    }

    if (scriptsBeforeOtSdkStub) {
      issues.push(mkFinding("MEDIUM", "There are scripts before otSDKStub.js in the DOM."));
      recommendations.push(mkFinding("MEDIUM", "Ensure otSDKStub.js loads before other JS to guarantee consent enforcement timing."));
    }

    if (scriptsBeforeAutoBlockFlag) {
      issues.push(mkFinding("MEDIUM", "There are scripts before otAutoBlock.js in the DOM."));
      recommendations.push(mkFinding("MEDIUM", "Ensure otAutoBlock.js loads before any scripts you expect it to block."));
    }

    if (domainOutOfScope === true) {
      issues.push(
        mkFinding(
          "HIGH",
          `Domain out of scope: UDID config Domain="${configDomain}" but site host="${checkedHost}". Production script scope is *.${configDomain}/*, so banner may reappear on refresh.`
        )
      );
      recommendations.push(
        mkFinding(
          "HIGH",
          "Use the correct production script for this domain (matching the site's root domain) or update the OneTrust domain configuration and re-publish scripts."
        )
      );
    }

    if (otSDKStubFound && !capturedConfig && productionUdid) {
      issues.push(mkFinding("LOW", "OneTrust script detected, but UDID config JSON was not captured."));
      recommendations.push(mkFinding("LOW", "Verify the domain script is reachable and not blocked; try extending wait time slightly."));
    }

    const severity = computeSeverity(issues);

    // -------- Debug artefacts (optional) --------
    if (DEBUG) {
      await page.screenshot({ path: "debug-screenshot.png", fullPage: true });
      fs.writeFileSync("debug-page.html", await page.content());
      fs.writeFileSync(
        "debug-json-responses.json",
        JSON.stringify(
          possibleJsonResponses.map(item => ({
            url: item.url,
            status: item.status,
            resourceType: item.resourceType,
            bodyPreview: extractBodyPreview(item.bodyText, 1000)
          })),
          null,
          2
        )
      );
      fs.writeFileSync("cookie-list.json", JSON.stringify(cookies, null, 2));
    }

    // ✅ Final response (Copilot-friendly + flags)
    return {
      checkedUrl: targetUrl,
      checkedAt: new Date().toISOString(),

      // config values from UDID json
      TenantGuid: capturedConfig?.TenantGuid ?? "",
      EnvId: capturedConfig?.EnvId ?? "",
      Domain: capturedConfig?.Domain ?? "",

      // script id details
      primaryUdid,
      productionUdid,
      usingTestScript,
      capturedConfigUrl,

      // core flags you asked for
      otSDKStubFound,
      autoBlockEnabled,
      hasDuplicateOtSdkStub,
      hasDuplicateAutoBlock,
      scriptsBeforeOtSdkStub,
      scriptsBeforeAutoBlock: scriptsBeforeAutoBlockFlag,
      otSdkStubInHead,
      autoBlockInHead,

      // CSP flags
      isCspBlocked,
      cspSignals: DEBUG
        ? {
            hasCspHeaderSeen,
            consoleViolations: cspConsoleViolations,
            networkFailures: cspNetworkFailures
          }
        : {
            hasCspHeaderSeen,
            consoleViolationCount: cspConsoleViolations.length,
            networkFailureCount: cspNetworkFailures.length
          },

      // NEW: domain scope validation
      checkedHost,
      configDomain,
      domainScopeValid,
      domainOutOfScope,

      apiCallCount: apiCalls.length,
      severity,
      issues,
      recommendations,

      accessDenied,
      notes
    };
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
    }
  }
}