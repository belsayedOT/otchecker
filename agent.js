import { chromium } from "playwright";
import fs from "fs";

const targetUrl = process.env.TARGET_URL;

if (!targetUrl) {
  throw new Error("TARGET_URL is required");
}

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
    return {
      success: true,
      value: await page.evaluate(expression)
    };
  } catch (error) {
    return {
      success: false,
      error: error.message
    };
  }
}

function extractBodyPreview(text = "", max = 3000) {
  return text.length > max ? `${text.slice(0, max)}... [truncated]` : text;
}

const notes = [];
const apiCalls = [];
const otStubNetworkCalls = [];
const otAutoBlockNetworkCalls = [];
const possibleJsonResponses = [];

let accessDenied = false;
let autoBlockResponseDetails = null;
let geoLocationResponseDetails = null;

const browser = await chromium.launch({
  headless: true
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
      autoBlockResponseDetails = {
        ...responseSummary,
        error: error.message
      };
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
        headers: response.headers(),
        body: parsedBody ?? bodyText,
        bodyLength: bodyText.length
      };
    } catch (error) {
      geoLocationResponseDetails = {
        ...responseSummary,
        error: error.message
      };
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

const mainFrameScripts = allFrameScripts.filter(s => s.frameUrl === page.url());

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

function getScriptsBefore(targetScript, scriptList) {
  if (!targetScript) return [];

  return scriptList
    .filter(script => script.frameUrl === targetScript.frameUrl)
    .filter(script => script.index < targetScript.index)
    .map(script => ({
      index: script.index,
      src: script.src,
      id: script.id,
      parentTagName: script.parentTagName,
      inHead: script.inHead,
      inBody: script.inBody
    }));
}

const firstStubScript = stubScripts[0] || null;
const firstAutoBlockScript = autoBlockScripts[0] || null;

const scriptsBeforeOtSDKStub = getScriptsBefore(firstStubScript, allFrameScripts);
const scriptsBeforeAutoBlock = getScriptsBefore(firstAutoBlockScript, allFrameScripts);

if (firstStubScript && !firstStubScript.inHead) {
  notes.push("Observation: otSDKStub.js is not loaded from the page <head> section.");
}

if (firstAutoBlockScript && !firstAutoBlockScript.inHead) {
  notes.push("Observation: otAutoBlock.js is not loaded from the page <head> section.");
}

if (firstStubScript && scriptsBeforeOtSDKStub.length > 0) {
  notes.push(
    `Observation: ${scriptsBeforeOtSDKStub.length} script tag(s) appear before otSDKStub.js in the DOM. Recommended placement is in <head> before other JS calls.`
  );
}

if (firstAutoBlockScript && scriptsBeforeAutoBlock.length > 0) {
  notes.push(
    `Observation: ${scriptsBeforeAutoBlock.length} script tag(s) appear before otAutoBlock.js in the DOM. Recommended placement is in <head> before other JS calls.`
  );
}

const dataDomainScriptValues = stubScripts
  .map(script => script.dataDomainScript)
  .filter(Boolean);

const primaryUdid = dataDomainScriptValues[0] || "";
const productionUdid = cleanUdid(primaryUdid);
const usingTestScript = isTestScript(primaryUdid);

let capturedConfig = null;
let capturedConfigUrl = "";

for (const item of possibleJsonResponses) {
  try {
    const pathname = new URL(item.url).pathname.toLowerCase();

    const isTargetUdidJson =
      productionUdid &&
      pathname.endsWith(`/${productionUdid.toLowerCase()}.json`);

    if (!isTargetUdidJson) {
      continue;
    }

    capturedConfig = JSON.parse(item.bodyText);
    capturedConfigUrl = item.url;
    break;
  } catch {
    notes.push(`Found possible UDID JSON but could not parse it: ${item.url}`);
  }
}

if (!capturedConfig && productionUdid) {
  notes.push(
    `No matching UDID JSON config response was captured for UDID: ${primaryUdid}.`
  );
}

if (stubScripts.length === 0 && otStubNetworkCalls.length === 0) {
  notes.push("otSDKStub.js was not found in DOM scripts or network calls.");
}

if (autoBlockScripts.length === 0 && otAutoBlockNetworkCalls.length === 0) {
  notes.push("otAutoBlock.js was not found. AutoBlock appears not enabled or not loaded on this page.");
}

if (stubScripts.length > 1 || otStubNetworkCalls.length > 1) {
  notes.push(
    `Alert: otSDKStub.js triggered more than once. DOM count: ${stubScripts.length}, network count: ${otStubNetworkCalls.length}.`
  );
}

if (autoBlockScripts.length > 1 || otAutoBlockNetworkCalls.length > 1) {
  notes.push(
    `Alert: otAutoBlock.js triggered more than once. DOM count: ${autoBlockScripts.length}, network count: ${otAutoBlockNetworkCalls.length}.`
  );
}

const cookies = await page.context().cookies();

const oneTrustConsoleChecks = {
  "OneTrust.GetDomainData().GeneralVendors": await safeEvaluate(page, () =>
    window.OneTrust?.GetDomainData?.()?.GeneralVendors
  ),
  "OneTrust.GetDomainData().GoogleConsent": await safeEvaluate(page, () =>
    window.OneTrust?.GetDomainData?.()?.GoogleConsent
  ),
  "OneTrust.GetDomainData().MCMData": await safeEvaluate(page, () =>
    window.OneTrust?.GetDomainData?.()?.MCMData
  ),
  "OneTrust.GetDomainData().ACMData": await safeEvaluate(page, () =>
    window.OneTrust?.GetDomainData?.()?.ACMData
  ),
  "OneTrust.GetDomainData()": await safeEvaluate(page, () =>
    window.OneTrust?.GetDomainData?.()
  )
};

await page.screenshot({
  path: "debug-screenshot.png",
  fullPage: true
});

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

fs.writeFileSync(
  "cookie-list.json",
  JSON.stringify(cookies, null, 2)
);

const result = {
  checkedUrl: normaliseUrl(targetUrl),
  checkedAt: new Date().toISOString(),

  accessDenied,

  otSDKStub: {
    found: stubScripts.length > 0 || otStubNetworkCalls.length > 0,
    domCount: stubScripts.length,
    networkCount: otStubNetworkCalls.length,
    scripts: stubScripts,
    networkCalls: otStubNetworkCalls,
    dataDomainScriptValues,
    primaryUdid,
    productionUdid,
    usingTestScript,
    scriptEnvironment: primaryUdid
      ? usingTestScript
        ? "test"
        : "production"
      : "unknown",
    firstScriptLocation: firstStubScript
      ? {
          frameUrl: firstStubScript.frameUrl,
          parentTagName: firstStubScript.parentTagName,
          inHead: firstStubScript.inHead,
          inBody: firstStubScript.inBody,
          domIndex: firstStubScript.index
        }
      : null,
    scriptsBeforeIt: scriptsBeforeOtSDKStub
  },

  autoBlock: {
    enabled: autoBlockScripts.length > 0 || otAutoBlockNetworkCalls.length > 0,
    status:
      autoBlockScripts.length > 0 || otAutoBlockNetworkCalls.length > 0
        ? "enabled_or_loaded"
        : "not_enabled_or_not_loaded",
    domCount: autoBlockScripts.length,
    networkCount: otAutoBlockNetworkCalls.length,
    scripts: autoBlockScripts,
    networkCalls: otAutoBlockNetworkCalls,
    firstScriptLocation: firstAutoBlockScript
      ? {
          frameUrl: firstAutoBlockScript.frameUrl,
          parentTagName: firstAutoBlockScript.parentTagName,
          inHead: firstAutoBlockScript.inHead,
          inBody: firstAutoBlockScript.inBody,
          domIndex: firstAutoBlockScript.index
        }
      : null,
    scriptsBeforeIt: scriptsBeforeAutoBlock
  },

  AutoblockConfig: autoBlockResponseDetails,

  capturedConfigUrl,

  TenantGuid: capturedConfig?.TenantGuid ?? "",
  EnvId: capturedConfig?.EnvId ?? "",
  Domain: capturedConfig?.Domain ?? "",

  config: capturedConfig ?? {},

  geoLocation: geoLocationResponseDetails,

  cookies,

  oneTrustConsoleChecks,

  apiCalls,

  notes
};

fs.writeFileSync("ot-check-result.json", JSON.stringify(result, null, 2));

console.log(JSON.stringify(result, null, 2));

await browser.close();