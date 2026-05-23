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

function mkRecommendation(severity, message) {
  return { severity, message };
}

function computeSeverity(issues) {
  // Simple, practical scoring:
  // HIGH: access denied or duplicates
  // MED: not in head or scripts before OT
  // LOW: missing config only
  if (issues.some(i => i.severity === "HIGH")) return "HIGH";
  if (issues.some(i => i.severity === "MEDIUM")) return "MEDIUM";
  if (issues.length > 0) return "LOW";
  return "NONE";
}

/**
 * ✅ This is what server.js imports
 * import { runCheck } from "./agent.js";
 */
export async function runCheck(inputUrl) {
  const targetUrl = normaliseUrl(inputUrl);
  if (!targetUrl) throw new Error("url is required");

  const DEBUG = process.env.DEBUG_ARTIFACTS === "true";

  // Per-run state (never global)
  const notes = [];
  const apiCalls = [];
  const otStubNetworkCalls = [];
  const otAutoBlockNetworkCalls = [];
  const possibleJsonResponses = [];

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

      const responseSummary = {
        url,
        method: request.method(),
        resourceType: request.resourceType(),
        status: response.status()
      };

      // Keep lightweight log unless DEBUG
      apiCalls.push(responseSummary);

      // Capture AutoBlock body
      if (lowerUrl.includes("otautoblock.js")) {
        try {
          const bodyText = await response.text();
          autoBlockResponseDetails = {
            ...responseSummary,
            headers: DEBUG ? response.headers() : undefined,
            bodyPreview: extractBodyPreview(bodyText),
            bodyLength: bodyText.length
          };
        } catch (error) {
          autoBlockResponseDetails = { ...responseSummary, error: error.message };
        }
      }

      // Capture geolocation response (if present)
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
            headers: DEBUG ? response.headers() : undefined,
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

      // Some sites never settle; don't fail the run because of that.
      await page.waitForLoadState("networkidle", { timeout: 30000 }).catch(() => {
        notes.push("Network did not become idle within 30 seconds.");
      });

      // Give async OneTrust requests time
      await page.waitForTimeout(8000);
    } catch (error) {
      notes.push(`Page navigation issue: ${error.message}`);
    }

    // WAF/CDN detection (your original logic)
    const bodyText = await page.locator("body").innerText().catch(() => "");
    if (
      bodyText.includes("Access Denied") ||
      bodyText.includes("You don't have permission to access") ||
      page.url().includes("errors.edgesuite.net")
    ) {
      accessDenied = true;
      notes.push("Access denied by CDN/WAF. Playwright could not access the real page.");
    }

    // -------- SCRIPT INSPECTION (DOM + frames) --------
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

    // -------- Cookies + console checks (optional, useful) --------
    const cookies = await page.context().cookies();

    const oneTrustConsoleChecks = {
      "OneTrust.GetDomainData()": await safeEvaluate(page, () =>
        window.OneTrust?.GetDomainData?.()
      )
    };

    // -------- REQUIRED FLAGS (your ask) --------
    const otSDKStubFound = stubScripts.length > 0 || otStubNetworkCalls.length > 0;
    const autoBlockEnabled = autoBlockScripts.length > 0 || otAutoBlockNetworkCalls.length > 0;

    const hasDuplicateOtSdkStub = stubScripts.length > 1 || otStubNetworkCalls.length > 1;
    const hasDuplicateAutoBlock = autoBlockScripts.length > 1 || otAutoBlockNetworkCalls.length > 1;

    const scriptsBeforeOtSdkStub = scriptsBeforeOtSDKStub.length > 0;
    const scriptsBeforeAutoBlockFlag = scriptsBeforeAutoBlock.length > 0;

    const otSdkStubInHead = firstStubScript?.inHead ?? false;
    const autoBlockInHead = firstAutoBlockScript?.inHead ?? false;

    // -------- High value: issues + recommendations --------
    const issues = [];
    const recommendations = [];

    if (accessDenied) {
      issues.push(mkRecommendation("HIGH", "Site appears blocked by CDN/WAF (Access Denied)."));
      recommendations.push(
        mkRecommendation("HIGH", "Ask customer to allowlist the scanner/requests or test from a non-blocked network.")
      );
    }

    if (!otSDKStubFound) {
      issues.push(mkRecommendation("HIGH", "otSDKStub.js was not detected in DOM or network calls."));
      recommendations.push(
        mkRecommendation("HIGH", "Confirm OneTrust script is implemented on the page and not blocked by CSP/WAF.")
      );
    }

    if (hasDuplicateOtSdkStub) {
      issues.push(mkRecommendation("HIGH", "Duplicate otSDKStub.js detected (DOM and/or network)."));
      recommendations.push(
        mkRecommendation("HIGH", "Remove duplicate OneTrust script to avoid unpredictable banner/consent behaviour.")
      );
    }

    if (hasDuplicateAutoBlock) {
      issues.push(mkRecommendation("HIGH", "Duplicate otAutoBlock.js detected (DOM and/or network)."));
      recommendations.push(
        mkRecommendation("HIGH", "Remove duplicate AutoBlock include. Duplicate autoblock can break script injection.")
      );
    }

    if (otSDKStubFound && !otSdkStubInHead) {
      issues.push(mkRecommendation("MEDIUM", "otSDKStub.js is not located in the <head> section."));
      recommendations.push(
        mkRecommendation("MEDIUM", "Move otSDKStub.js into <head> as early as possible (before other scripts).")
      );
    }

    if (autoBlockEnabled && !autoBlockInHead) {
      issues.push(mkRecommendation("MEDIUM", "otAutoBlock.js is not located in the <head> section."));
      recommendations.push(
        mkRecommendation("MEDIUM", "Move otAutoBlock.js into <head> and ensure it loads before tags it should block.")
      );
    }

    if (scriptsBeforeOtSdkStub) {
      issues.push(mkRecommendation("MEDIUM", "There are scripts before otSDKStub.js in the DOM."));
      recommendations.push(
        mkRecommendation("MEDIUM", "Ensure otSDKStub.js loads before other JS to guarantee consent enforcement timing.")
      );
    }

    if (scriptsBeforeAutoBlockFlag) {
      issues.push(mkRecommendation("MEDIUM", "There are scripts before otAutoBlock.js in the DOM."));
      recommendations.push(
        mkRecommendation("MEDIUM", "Ensure otAutoBlock.js loads before any scripts you expect it to block.")
      );
    }

    if (otSDKStubFound && !capturedConfig && productionUdid) {
      issues.push(mkRecommendation("LOW", "OneTrust script detected, but UDID config JSON was not captured."));
      recommendations.push(
        mkRecommendation("LOW", "Verify the domain script is reachable and not blocked; try extending wait time slightly.")
      );
    }

    // Helpful notes mirroring your previous observations
    if (otSDKStubFound && scriptsBeforeOtSdkStub) {
      notes.push(
        `Observation: ${scriptsBeforeOtSDKStub.length} script tag(s) appear before otSDKStub.js in the DOM.`
      );
    }
    if (autoBlockEnabled && scriptsBeforeAutoBlockFlag) {
      notes.push(
        `Observation: ${scriptsBeforeAutoBlock.length} script tag(s) appear before otAutoBlock.js in the DOM.`
      );
    }

    const severity = computeSeverity(issues);

    // -------- Debug artefacts only when requested --------
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

    // ✅ Final response (Copilot-friendly + your flags)
    return {
      checkedUrl: targetUrl,
      checkedAt: new Date().toISOString(),

      // IDs you care about
      TenantGuid: capturedConfig?.TenantGuid ?? "",
      EnvId: capturedConfig?.EnvId ?? "",
      Domain: capturedConfig?.Domain ?? "",

      primaryUdid,
      productionUdid,
      usingTestScript,
      capturedConfigUrl,

      // ✅ flags you requested
      otSDKStubFound,
      autoBlockEnabled,
      hasDuplicateOtSdkStub,
      hasDuplicateAutoBlock,
      scriptsBeforeOtSdkStub,
      scriptsBeforeAutoBlock: scriptsBeforeAutoBlockFlag,
      otSdkStubInHead,
      autoBlockInHead,

      // lightweight stats (optional)
      apiCallCount: apiCalls.length,

      // high value output
      severity,
      issues,
      recommendations,

      // helpful debugging (keep – but not too huge)
      accessDenied,
      notes,

      // Optional: keep these if you still want them (Copilot can ignore)
      // cookies,
      // oneTrustConsoleChecks,
      // AutoblockConfig: autoBlockResponseDetails,
      // geoLocation: geoLocationResponseDetails
    };
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
    }
  }
}
``