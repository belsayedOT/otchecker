// agent.js — Version 1 (full-featured diagnostic engine)// agent.js — Version 1 (full-featured diagnostic engine("-test") ? udid.slice(0, -5) : udid;
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

function isDomainMatching(host, domain) {
  if (!host || !domain) return false;
  const h = host.toLowerCase();
  const d = domain.toLowerCase();
  return h === d || h.endsWith(`.${d}`);
}

/**
 * Exported for server.js:
 *   import { runCheck } from "./agent.js";
 */
export async function runCheck(inputUrl) {
  const targetUrl = normaliseUrl(inputUrl);
  if (!targetUrl) throw new Error("url is required");

  // Debug artefacts toggle (Version 1 includes this; set false in env to disable)
  const DEBUG = process.env.DEBUG_ARTIFACTS === "true";

  // Per-run state
  const notes = [];
  const apiCalls = [];
  const otStubNetworkCalls = [];
  const otAutoBlockNetworkCalls = [];
  const possibleJsonResponses = [];

  // CSP tracking
  const cspConsoleViolations = [];
  const cspNetworkFailures = [];
  let hasCspHeaderSeen = false;

  // Other tracking
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

    // CSP console signals
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

    // CSP request failures
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

    // Track responses + collect JSON bodies
    page.on("response", async response => {
      try {
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

        // Capture *.json responses for later parsing (UDID json)
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
          // ignore
        }
      } catch {
        // ignore handler failures
      }
    });

    // Navigation
    try {
      await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 60000 });

      await page.waitForLoadState("networkidle", { timeout: 30000 }).catch(() => {
        notes.push("Network did not become idle within 30 seconds.");
      });

      await page.waitForTimeout(8000);
    } catch (error) {
      notes.push(`Page navigation issue: ${error.message}`);
    }

    // Access denied heuristics
    const bodyText = await page.locator("body").innerText().catch(() => "");
    if (
      bodyText.includes("Access Denied") ||
      bodyText.includes("You don't have permission to access") ||
      page.url().includes("errors.edgesuite.net")
    ) {
      accessDenied = true;
      notes.push("Access denied by CDN/WAF. Playwright could not access the real page.");
    }

    // Script inspection across frames
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

    // UDID extraction
    const dataDomainScriptValues = stubScripts
      .map(s => s.dataDomainScript)
      .filter(Boolean);

    const primaryUdid = dataDomainScriptValues[0] || "";
    const productionUdid = cleanUdid(primaryUdid);
    const usingTestScript = isTestScript(primaryUdid);

    // Match & parse UDID json
    let capturedConfig = null;
    let capturedConfigUrl = "";

    for (const item of possibleJsonResponses) {
      try {
        const pathname = new URL(item.url).pathname.toLowerCase();
        const isTargetUdidJson =
          productionUdid && pathname.endsWith(`/${productionUdid.toLowerCase()}.json`);

        if (!isTargetUdidJson) continue;

        capturedConfig = JSON.parse(item.bodyText);
        capturedConfigUrl = item.url;
        break;
      } catch {
        notes.push(`Found possible UDID JSON but could not parse it: ${item.url}`);
      }
    }

    // Basic cookie + console checks (Version 1 includes these)
    const cookies = await page.context().cookies();
    const oneTrustConsoleChecks = {
      "OneTrust.GetDomainData()": await safeEvaluate(page, () =>
        window.OneTrust?.GetDomainData?.()
      )
    };

    // Requested flags
    const otSDKStubFound = stubScripts.length > 0 || otStubNetworkCalls.length > 0;
    const autoBlockEnabled = autoBlockScripts.length > 0 || otAutoBlockNetworkCalls.length > 0;

    const hasDuplicateOtSdkStub = stubScripts.length > 1 || otStubNetworkCalls.length > 1;
    const hasDuplicateAutoBlock = autoBlockScripts.length > 1 || otAutoBlockNetworkCalls.length > 1;

    const scriptsBeforeOtSdkStub = scriptsBeforeOtSDKStub.length > 0;
    const scriptsBeforeAutoBlockFlag = scriptsBeforeAutoBlock.length > 0;

    const otSdkStubInHead = firstStubScript?.inHead ?? false;
    const autoBlockInHead = firstAutoBlockScript?.inHead ?? false;

    // CSP flag
    const isCspBlocked = cspConsoleViolations.length > 0 || cspNetworkFailures.length > 0;
    if (isCspBlocked) {
      notes.push("CSP violation detected (console and/or request failure).");
      if (hasCspHeaderSeen) notes.push("CSP header observed in responses.");
    }

    // Domain scope validation (prod scripts only; test scripts exempt)
    const checkedHost = (() => {
      try {
        return new URL(targetUrl).hostname || "";
      } catch {
        return "";
      }
    })();
    const configDomain = capturedConfig?.Domain ?? "";

    let domainScopeValid = false;
    let domainOutOfScope = false;

    if (usingTestScript) {
      domainScopeValid = true;
      domainOutOfScope = false;
    } else if (configDomain && checkedHost) {
      domainScopeValid = isDomainMatching(checkedHost, configDomain);
      domainOutOfScope = !domainScopeValid;
    } else {
      domainScopeValid = false;
      domainOutOfScope = false;
      if (!capturedConfig) notes.push("Domain scope could not be validated because UDID config JSON was not captured.");
    }

    // Ensure boolean outputs
    domainScopeValid = Boolean(domainScopeValid);
    domainOutOfScope = Boolean(domainOutOfScope);

    // Findings + recommendations (Version 1: richer output)
    const issues = [];
    const recommendations = [];

    if (domainOutOfScope) {
      issues.push(
        mkFinding(
          "HIGH",
          `Domain out of scope: configDomain="${configDomain}" but host="${checkedHost}". Banner may reappear on refresh.`
        )
      );
      recommendations.push(
        mkFinding(
          "HIGH",
          "Use the correct production script for this domain or update OneTrust domain configuration and republish scripts."
        )
      );
    }

    if (isCspBlocked) {
      issues.push(mkFinding("HIGH", "CSP appears to be blocking OneTrust resources or execution."));
      recommendations.push(mkFinding("HIGH", "Allowlist OneTrust resources in CSP (script-src/connect-src as needed)."));
    }

    if (accessDenied) {
      issues.push(mkFinding("HIGH", "Site appears blocked by CDN/WAF (Access Denied)."));
      recommendations.push(mkFinding("HIGH", "Allowlist scanner/requests or test from a non-blocked network."));
    }

    if (!otSDKStubFound) {
      issues.push(mkFinding("HIGH", "otSDKStub.js was not detected in DOM or network calls."));
      recommendations.push(mkFinding("HIGH", "Verify OneTrust script is implemented and not blocked."));
    }

    if (hasDuplicateOtSdkStub) {
      issues.push(mkFinding("HIGH", "Duplicate otSDKStub.js detected."));
      recommendations.push(mkFinding("HIGH", "Remove duplicate OneTrust script to avoid unpredictable consent behaviour."));
    }

    if (hasDuplicateAutoBlock) {
      issues.push(mkFinding("HIGH", "Duplicate otAutoBlock.js detected."));
      recommendations.push(mkFinding("HIGH", "Remove duplicate AutoBlock include to avoid conflicts."));
    }

    if (otSDKStubFound && !otSdkStubInHead) {
      issues.push(mkFinding("MEDIUM", "otSDKStub.js is not located in the <head> section."));
      recommendations.push(mkFinding("MEDIUM", "Move otSDKStub.js into <head> as early as possible."));
    }

    if (autoBlockEnabled && !autoBlockInHead) {
      issues.push(mkFinding("MEDIUM", "otAutoBlock.js is not located in the <head> section."));
      recommendations.push(mkFinding("MEDIUM", "Move otAutoBlock.js into <head> before scripts it should block."));
    }

    if (scriptsBeforeOtSdkStub) {
      issues.push(mkFinding("MEDIUM", "There are scripts before otSDKStub.js in the DOM."));
      recommendations.push(mkFinding("MEDIUM", "Ensure otSDKStub.js loads before other JS to enforce consent timing."));
    }

    if (scriptsBeforeAutoBlockFlag) {
      issues.push(mkFinding("MEDIUM", "There are scripts before otAutoBlock.js in the DOM."));
      recommendations.push(mkFinding("MEDIUM", "Ensure otAutoBlock.js loads before scripts you expect it to block."));
    }

    if (otSDKStubFound && !capturedConfig && productionUdid) {
      issues.push(mkFinding("LOW", "OneTrust script detected, but UDID config JSON was not captured."));
      recommendations.push(mkFinding("LOW", "Verify domain script reachable; consider slightly longer wait."));
    }

    const severity = computeSeverity(issues);

    // Optional artefacts in debug mode (Version 1 includes; disable via env)
    if (DEBUG) {
      await page.screenshot({ path: "debug-screenshot.png", fullPage: true });
      fs.writeFileSync("debug-page.html", await page.content());
      fs.writeFileSync("cookie-list.json", JSON.stringify(cookies, null, 2));
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
    }

    return {
      checkedUrl: targetUrl,
      checkedAt: new Date().toISOString(),

      TenantGuid: capturedConfig?.TenantGuid ?? "",
      EnvId: capturedConfig?.EnvId ?? "",
      Domain: capturedConfig?.Domain ?? "",

      primaryUdid,
      productionUdid,
      usingTestScript,
      capturedConfigUrl,

      checkedHost,
      configDomain,
      domainScopeValid,
      domainOutOfScope,

      otSDKStubFound,
      autoBlockEnabled,
      hasDuplicateOtSdkStub,
      hasDuplicateAutoBlock,
      scriptsBeforeOtSdkStub,
      scriptsBeforeAutoBlock: scriptsBeforeAutoBlockFlag,
      otSdkStubInHead,
      autoBlockInHead,

      isCspBlocked,
      accessDenied,

      severity,
      issues,
      recommendations,
      notes,

      // Version 1 includes these optional diagnostics (Copilot can ignore)
      apiCallCount: apiCalls.length,
      oneTrustConsoleChecks,
      AutoblockConfig: autoBlockResponseDetails,
      geoLocation: geoLocationResponseDetails
    };
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
    }
  }
}


import { chromium } from "playwright";
import fs from "fs";

function normaliseUrl(url) {
  const trimmed = (url || "").trim();
  if (!trimmed) return "";
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function cleanUdid(udid = "") {
