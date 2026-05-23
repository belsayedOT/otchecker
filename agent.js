import { chromium } from "playwright";
import fs from "fs";

function normaliseUrl(url) {
  return url.startsWith("http") ? url : `https://${url}`;
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

/**
 * ✅ THIS IS WHAT server.js IMPORTS
 */
export async function runCheck(targetUrl) {
  if (!targetUrl) throw new Error("url is required");

  // ✅ move all “per run” vars INSIDE the function so requests don’t share state
  const notes = [];
  const apiCalls = [];
  const otStubNetworkCalls = [];
  const otAutoBlockNetworkCalls = [];
  const possibleJsonResponses = [];

  let accessDenied = false;
  let autoBlockResponseDetails = null;
  let geoLocationResponseDetails = null;

  const DEBUG = process.env.DEBUG_ARTIFACTS === "true";

  let browser = null;

  try {
    browser = await chromium.launch({
      headless: true,
      // important in hosted environments
      args: ["--no-sandbox", "--disable-dev-shm-usage"]
    });

    const page = await browser.newPage({
      viewport: { width: 1366, height: 768 },
      userAgent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    });

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

      apiCalls.push(responseSummary);

      if (lowerUrl.includes("otautoblock.js")) {
        try {
          const bodyText = await response.text();
          autoBlockResponseDetails = {
            ...responseSummary,
            headers: response.headers(),
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
          try { parsedBody = JSON.parse(bodyText); } catch { parsedBody = null; }

          geoLocationResponseDetails = {
            ...responseSummary,
            headers: response.headers(),
            body: parsedBody ?? bodyText,
            bodyLength: bodyText.length
          };
        } catch (error) {
          geoLocationResponseDetails = { ...responseSummary, error: error.message };
        }
      }

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
        notes.push(`Could not process JSON response body: ${url}`);
      }
    });

    // --- NAVIGATION ---
    try {
      await page.goto(normaliseUrl(targetUrl), {
        waitUntil: "domcontentloaded",
        timeout: 60000
      });

      await page.waitForLoadState("networkidle", { timeout: 30000 }).catch(() => {
        notes.push("Network did not become idle within 30 seconds.");
      });

      await page.waitForTimeout(15000);
    } catch (error) {
      notes.push(`Page navigation issue: ${error.message}`);
    }

    const bodyText = await page.locator("body").innerText().catch(() => "");

    if (
      bodyText.includes("Access Denied") ||
      bodyText.includes("You don't have permission to access") ||
      page.url().includes("errors.edgesuite.net")
    ) {
      accessDenied = true;
      notes.push("Access denied by CDN/WAF. Playwright could not access the real page.");
    }

    // --- SCRIPT INSPECTION ---
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

    const stubScripts = allFrameScripts.filter(script => {
      const src = script.src.toLowerCase();
      const outerHTML = script.outerHTML.toLowerCase();
      return src.includes("otsdkstub.js") || outerHTML.includes("otsdkstub.js");
    });

    const autoBlockScripts = allFrameScripts.filter(script => {
      const src = script.src.toLowerCase();
      const outerHTML = script.outerHTML.toLowerCase();
      return src.includes("otautoblock.js") || outerHTML.includes("otautoblock.js");
    });

    const dataDomainScriptValues = stubScripts
      .map(script => script.dataDomainScript)
      .filter(Boolean);

    const primaryUdid = dataDomainScriptValues[0] || "";
    const productionUdid = cleanUdid(primaryUdid);
    const usingTestScript = isTestScript(primaryUdid);

    // --- CAPTURE UDID JSON ---
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

    if (!capturedConfig && productionUdid) {
      notes.push(`No matching UDID JSON config response was captured for UDID: ${primaryUdid}.`);
    }

    const cookies = await page.context().cookies();

    const oneTrustConsoleChecks = {
      "OneTrust.GetDomainData()": await safeEvaluate(page, () =>
        window.OneTrust?.GetDomainData?.()
      )
    };

    // ✅ Debug artefacts only when needed
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

    // ✅ Return the result instead of console.log + exiting
    return {
      checkedUrl: normaliseUrl(targetUrl),
      checkedAt: new Date().toISOString(),
      accessDenied,

      capturedConfigUrl,

      TenantGuid: capturedConfig?.TenantGuid ?? "",
      EnvId: capturedConfig?.EnvId ?? "",
      Domain: capturedConfig?.Domain ?? "",

      otSDKStub: {
        found: stubScripts.length > 0 || otStubNetworkCalls.length > 0,
        domCount: stubScripts.length,
        networkCount: otStubNetworkCalls.length,
        dataDomainScriptValues,
        primaryUdid,
        productionUdid,
        usingTestScript
      },

      autoBlock: {
        enabled: autoBlockScripts.length > 0 || otAutoBlockNetworkCalls.length > 0
      },

      AutoblockConfig: autoBlockResponseDetails,
      geoLocation: geoLocationResponseDetails,

      cookies,
      oneTrustConsoleChecks,
      apiCalls,
      notes
    };
  } finally {
    // ✅ Always close browser even if errors happen
    if (browser) {
      await browser.close().catch(() => {});
    }
  }
}