import { chromium } from "playwright";

function normaliseUrl(url) {
  const trimmed = (url || "").trim();
  if (!trimmed) return "";
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function looksLikeUdidJson(obj) {
  if (!obj || typeof obj !== "object") return false;

  return Boolean(
    obj.Domain &&
    obj.Version &&
    obj.ScriptType &&
    Array.isArray(obj.RuleSet)
  );
}

function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function lower(value) {
  return String(value || "").trim().toLowerCase();
}

function toArray(value) {
  if (!value) return [];

  if (Array.isArray(value)) {
    return value;
  }

  return [value];
}

function extractValues(value) {
  const arr = toArray(value);

  return arr
    .map((item) => {
      if (typeof item === "string") return item;
      if (typeof item === "number") return String(item);

      if (item && typeof item === "object") {
        return (
          item.Code ||
          item.code ||
          item.Country ||
          item.country ||
          item.Name ||
          item.name ||
          item.State ||
          item.state ||
          item.Value ||
          item.value ||
          ""
        );
      }

      return "";
    })
    .filter(Boolean)
    .map(lower);
}

function getRuleCountries(rule) {
  return extractValues(
    rule?.Countries ??
      rule?.countries ??
      rule?.Country ??
      rule?.country
  );
}

function getRuleStates(rule) {
  return extractValues(
    rule?.States ??
      rule?.states ??
      rule?.State ??
      rule?.state
  );
}

function getRuleTemplateName(rule) {
  return (
    rule?.TemplateName ||
    rule?.templateName ||
    rule?.Template ||
    rule?.template ||
    ""
  );
}

function findMatchingRuleSet(ruleSet, geoData) {
  const country = lower(
    geoData?.country ||
      geoData?.Country ||
      geoData?.countryCode ||
      geoData?.CountryCode
  );

  const state = lower(
    geoData?.state ||
      geoData?.State ||
      geoData?.stateCode ||
      geoData?.StateCode ||
      geoData?.region ||
      geoData?.Region
  );

  if (!country) {
    return {
      matched: false,
      matchReason: "No country was returned from OneTrust.getGeolocationData().",
      matchedRuleIndex: null,
      templateName: "",
    };
  }

  for (let i = 0; i < ruleSet.length; i += 1) {
    const rule = ruleSet[i];

    const countries = getRuleCountries(rule);
    const states = getRuleStates(rule);

    const countryMatches =
      countries.length === 0 || countries.includes(country);

    const stateMatches =
      states.length === 0 || states.includes(state);

    if (countryMatches && stateMatches) {
      return {
        matched: true,
        matchReason:
          states.length === 0
            ? "Matched by country. RuleSet States is empty, so state was not required."
            : "Matched by country and state.",
        matchedRuleIndex: i,
        templateName: getRuleTemplateName(rule),
      };
    }
  }

  return {
    matched: false,
    matchReason: "No RuleSet item matched the detected country/state.",
    matchedRuleIndex: null,
    templateName: "",
  };
}

export async function runCheck(inputUrl, options = {}) {
  const targetUrl = normaliseUrl(inputUrl);

  const {
    headless = true,
    navigationTimeoutMs = 30000,
    pageLoadWaitMs = 5000,
    oneTrustTimeoutMs = 10000,
    locale = "en-GB",
    timezoneId = "Europe/London",
    viewport = { width: 1366, height: 768 },
  } = options;

  let browser;
  let context;

  let capturedUdidJson = null;
  let capturedUdidJsonUrl = "";
  let accessDenied = false;

  if (!targetUrl) {
    return {
      checkedUrl: "",
      success: false,
      error: "No URL was provided.",
    };
  }

  try {
    browser = await chromium.launch({ headless });

    context = await browser.newContext({
      locale,
      timezoneId,
      viewport,
    });

    const page = await context.newPage();

    page.on("response", async (response) => {
      try {
        const request = response.request();
        const resourceType = request.resourceType();
        const status = response.status();
        const url = response.url();
        const lowerUrl = url.toLowerCase();

        if (
          resourceType === "document" &&
          (status === 401 || status === 403)
        ) {
          accessDenied = true;
        }

        if (!lowerUrl.includes("json")) return;

        const text = await response.text();
        const parsed = safeJsonParse(text);

        if (looksLikeUdidJson(parsed)) {
          capturedUdidJson = parsed;
          capturedUdidJsonUrl = url;
        }
      } catch {
        // Ignore parsing failures and continue the scan.
      }
    });

    let navigationError = "";

    try {
      await page.goto(targetUrl, {
        waitUntil: "domcontentloaded",
        timeout: navigationTimeoutMs,
      });
    } catch (err) {
      navigationError = err?.message || String(err);
    }

    if (navigationError) {
      return {
        checkedUrl: targetUrl,
        success: false,
        accessDenied,
        error: navigationError,
      };
    }

    await page.waitForTimeout(pageLoadWaitMs);

    const finalUrl = page.url();

    const scripts = await page.locator("script").evaluateAll((nodes) =>
      nodes.map((script, index) => ({
        index,
        src: script.src || "",
        inHead: document.head.contains(script),
        dataDomainScript: script.getAttribute("data-domain-script") || "",
      }))
    );

    const otSdkStubScripts = scripts.filter((script) =>
      script.src.toLowerCase().includes("otsdkstub")
    );

    const otAutoBlockScripts = scripts.filter((script) =>
      script.src.toLowerCase().includes("otautoblock")
    );

    const oneTrustScripts = [
      ...otSdkStubScripts,
      ...otAutoBlockScripts,
    ];

    const firstOneTrustScriptIndex =
      oneTrustScripts.length > 0
        ? Math.min(...oneTrustScripts.map((script) => script.index))
        : null;

    const jsScriptsBeforeOneTrust =
      firstOneTrustScriptIndex === null
        ? []
        : scripts.filter((script) => {
            const src = script.src.toLowerCase();

            return (
              script.index < firstOneTrustScriptIndex &&
              src &&
              src.includes(".js")
            );
          });

    const otSdkStubInHead = otSdkStubScripts.some((script) => script.inHead);
    const otAutoBlockInHead = otAutoBlockScripts.some((script) => script.inHead);

    const ruleSet = Array.isArray(capturedUdidJson?.RuleSet)
      ? capturedUdidJson.RuleSet
      : [];

    const skipGeolocation = capturedUdidJson?.SkipGeolocation === true;
    const ruleSetCount = ruleSet.length;

    const shouldSkipLocationInfo =
      ruleSetCount === 1 && skipGeolocation === true;

    let geolocationData = null;
    let detectedCountry = "";
    let detectedState = "";
    let matchedRuleSet = {
      matched: false,
      matchReason: "",
      matchedRuleIndex: null,
      templateName: "",
    };

    if (shouldSkipLocationInfo) {
      matchedRuleSet = {
        matched: true,
        matchReason:
          "SkipGeolocation is true and RuleSet has only one item, so RuleSet[0] was used.",
        matchedRuleIndex: 0,
        templateName: getRuleTemplateName(ruleSet[0]),
      };
    } else if (skipGeolocation === false) {
      try {
        await page.waitForFunction(
          () =>
            window.OneTrust &&
            typeof window.OneTrust.getGeolocationData === "function",
          { timeout: oneTrustTimeoutMs }
        );

        geolocationData = await page.evaluate(() => {
          try {
            return window.OneTrust.getGeolocationData();
          } catch {
            return null;
          }
        });

        detectedCountry =
          geolocationData?.country ||
          geolocationData?.Country ||
          geolocationData?.countryCode ||
          geolocationData?.CountryCode ||
          "";

        detectedState =
          geolocationData?.state ||
          geolocationData?.State ||
          geolocationData?.stateCode ||
          geolocationData?.StateCode ||
          geolocationData?.region ||
          geolocationData?.Region ||
          "";

        matchedRuleSet = findMatchingRuleSet(ruleSet, geolocationData);
      } catch {
        geolocationData = null;
        matchedRuleSet = {
          matched: false,
          matchReason:
            "SkipGeolocation is false, but OneTrust.getGeolocationData() was not available or did not return data.",
          matchedRuleIndex: null,
          templateName: "",
        };
      }
    }

    let googleConsentModeEnabled = null;
    let microsoftConsentModeEnabled = null;
    let amazonConsentModeEnabled = null;

    try {
      await page.waitForFunction(
        () =>
          window.OneTrust &&
          typeof window.OneTrust.GetDomainData === "function",
        { timeout: oneTrustTimeoutMs }
      );

      const consentModes = await page.evaluate(() => {
        try {
          const data = window.OneTrust.GetDomainData();

          return {
            google: data?.GoogleConsent?.GCEnable ?? null,
            microsoft: data?.MCMData?.Enabled ?? null,
            amazon: data?.ACMData?.Enabled ?? null,
          };
        } catch {
          return {
            google: null,
            microsoft: null,
            amazon: null,
          };
        }
      });

      googleConsentModeEnabled = consentModes.google;
      microsoftConsentModeEnabled = consentModes.microsoft;
      amazonConsentModeEnabled = consentModes.amazon;
    } catch {
      googleConsentModeEnabled = null;
      microsoftConsentModeEnabled = null;
      amazonConsentModeEnabled = null;
    }

    return {
      checkedUrl: targetUrl,
      finalUrl,
      success: true,
      accessDenied,

      udidJsonFound: Boolean(capturedUdidJson),
      udidJsonUrl: capturedUdidJsonUrl,

      udidJson: {
        Version: capturedUdidJson?.Version ?? "",
        ScriptType: capturedUdidJson?.ScriptType ?? "",
        LanguageDetectionByHtml:
          capturedUdidJson?.LanguageDetectionByHtml ?? "",
        LanguageDetectionEnabled:
          capturedUdidJson?.LanguageDetectionEnabled ?? "",
        GeoRuleGroupName: capturedUdidJson?.GeoRuleGroupName ?? "",
        RuleSetCount: ruleSetCount,
        SkipGeolocation: skipGeolocation,
      },

      scriptPlacement: {
        otSdkStubFound: otSdkStubScripts.length > 0,
        otAutoBlockFound: otAutoBlockScripts.length > 0,

        otSdkStubInHead,
        otAutoBlockInHead,

        oneTrustScriptInHead:
          otSdkStubInHead || otAutoBlockInHead,

        jsFilesBeforeOneTrust:
          jsScriptsBeforeOneTrust.length > 0,

        jsFilesBeforeOneTrustCount:
          jsScriptsBeforeOneTrust.length,

        jsFilesBeforeOneTrustList:
          jsScriptsBeforeOneTrust.map((script) => script.src),
      },

      geolocation: {
        skipped: shouldSkipLocationInfo,
        reason: shouldSkipLocationInfo
          ? "RuleSet has one item and SkipGeolocation is true."
          : "SkipGeolocation is false, so OneTrust.getGeolocationData() was checked.",
        data: shouldSkipLocationInfo ? null : geolocationData,
        country: shouldSkipLocationInfo ? "" : detectedCountry,
        state: shouldSkipLocationInfo ? "" : detectedState,
      },

      selectedRuleSet: {
        matched: matchedRuleSet.matched,
        matchReason: matchedRuleSet.matchReason,
        matchedRuleIndex: matchedRuleSet.matchedRuleIndex,
        templateName: matchedRuleSet.templateName,
      },

      consentModes: {
        googleConsentModeEnabled,
        microsoftConsentModeEnabled,
        amazonConsentModeEnabled,
      },
    };
  } finally {
    if (context) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
  }
}

export default runCheck;

On Sun, May 24, 2026 at 11:55 AM Bassem El-Sayed <bel-sayed@onetrust.com> wrote:
i want to code to perform the following checks and return the info in response:
 
Also capture and return values from udid.json:
Version
ScriptType
LanguageDetectionByHtml
LanguageDetectionEnabled
GeoRuleGroupName
 
otsdkstub.js or autoblock.js are running in head yes/no
Any script tags calls js files before otsdkstub.js r autoblock.js yes/no 
 
 
How many rules appearing in udid.json in RuleSet array in response : count
if RuleSet only has one value in array and UDID.id response has SkipGeolocation true do not return location information
if SkipGeolocation false return the resposnse details of OneTrust.getGeolocationData();
 
Confirm if Google consent mode  enabled by checking         OneTrust.GetDomainData().GoogleConsent.GCEnable
Confirm if Microsoft consent mode  enabled by checking         OneTrust.GetDomainData().MCMData.Enabled
Confirm if Amazon consent mode  enabled by checking         OneTrust.GetDomainData().ACMData.Enabled
 
 
if SkipGeolocation true, retrun template name from ruleset[0].TemplateName
 
if SkipGeolocation false, capture the response of OneTrust.getGeolocationData().country &  OneTrust.getGeolocationData().state and then fine the ruleset array element that has ruleset[x].countries = neTrust.getGeolocationData().country  and ruleset[x].States  =  OneTrust.getGeolocationData().state , remember  ruleset[x].States can be empty. if identified return template name 
 
 
 
 
From: Bassem Elsayed <belsayedg@gmail.com> 
Sent: 24 May 2026 11:44
To: Bassem El-Sayed <bel-sayed@onetrust.com>
Subject: 
 
	CAUTION: This email originated from outside OneTrust. Do not click links or open attachments unless you recognize the sender and know the content is safe. 
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

function mkFinding(severity, message, details = {}) {
  return { severity, message, details };
}

function computeSeverity(findings) {
  if (findings.some((f) => f.severity === "HIGH")) return "HIGH";
  if (findings.some((f) => f.severity === "MEDIUM")) return "MEDIUM";
  if (findings.length > 0) return "LOW";
  return "NONE";
}

function looksLikeUdidJson(obj) {
  if (!obj || typeof obj !== "object") return false;

  return Boolean(
    obj.Domain &&
      obj.Version &&
      obj.ScriptType &&
      (obj.TenantGuid ||
        obj.EnvId ||
        obj.RuleSet ||
        obj.Groups ||
        obj.BannerData ||
        obj.PreferenceCenterData)
  );
}

function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function safeIncludes(value = "", search = "") {
  return String(value || "").toLowerCase().includes(search.toLowerCase());
}

function isLikelyJsFile(src = "") {
  const value = String(src || "").toLowerCase();
  return value.includes(".js") || value.includes("javascript");
}

function createRecommendationSet(issues, context = {}) {
  const recommendations = [];

  if (!context.otSDKStubFound) {
    recommendations.push("Add the OneTrust otSDKStub.js script to the page.");
  }

  if (context.otSDKStubFound && !context.otSdkStubInHead) {
    recommendations.push("Move otSDKStub.js into the <head> before other non-essential JavaScript.");
  }

  if (context.autoBlockEnabled && !context.otAutoBlockInHead) {
    recommendations.push("Move otautoblock.js into the <head> before scripts that may set cookies.");
  }

  if (context.hasJsBeforeOt) {
    recommendations.push(
      "Review JavaScript files loaded before OneTrust. Scripts that set cookies should usually load after the CMP/autoblocking script."
    );
  }

  if (context.usingTestScript) {
    recommendations.push("The page is using a test UDID script. Confirm whether this is expected for this environment.");
  }

  if (context.accessDenied) {
    recommendations.push("Investigate the 401/403 response. The checker may not be able to validate a page that requires authentication or blocks automation.");
  }

  if (!context.udidJsonFound) {
    recommendations.push("Confirm that the UDID JSON configuration is loading successfully from the expected OneTrust/CDN location.");
  }

  if (context.failedOneTrustRequests?.length) {
    recommendations.push("Investigate failed OneTrust requests. CDN, CSP, ad-blocking, DNS, or firewall issues may prevent the CMP from loading correctly.");
  }

  if (context.consoleErrors?.length) {
    recommendations.push("Review browser console errors. JavaScript errors may prevent OneTrust from initialising correctly.");
  }

  if (context.bannerExpectedButNotVisible) {
    recommendations.push("Banner elements were not visible after page load. Check geolocation rules, consent state, template publishing, and whether a prior consent cookie exists.");
  }

  return [...new Set(recommendations)];
}

async function getStorageSnapshot(page) {
  return page.evaluate(() => {
    const local = {};
    const session = {};

    try {
      for (let i = 0; i < window.localStorage.length; i += 1) {
        const key = window.localStorage.key(i);
        local[key] = window.localStorage.getItem(key);
      }
    } catch {}

    try {
      for (let i = 0; i < window.sessionStorage.length; i += 1) {
        const key = window.sessionStorage.key(i);
        session[key] = window.sessionStorage.getItem(key);
      }
    } catch {}

    return {
      localStorage: local,
      sessionStorage: session,
    };
  });
}

async function getBannerState(page) {
  return page.evaluate(() => {
    const isVisible = (selector) => {
      const el = document.querySelector(selector);
      if (!el) return false;

      const style = window.getComputedStyle(el);
      const rect = el.getBoundingClientRect();

      return (
        style.display !== "none" &&
        style.visibility !== "hidden" &&
        Number(style.opacity || "1") !== 0 &&
        rect.width > 0 &&
        rect.height > 0
      );
    };

    return {
      bannerSdkExists: !!document.querySelector("#onetrust-banner-sdk"),
      bannerVisible: isVisible("#onetrust-banner-sdk"),
      preferenceCenterSdkExists: !!document.querySelector("#onetrust-pc-sdk"),
      preferenceCenterVisible: isVisible("#onetrust-pc-sdk"),
      acceptButtonExists: !!document.querySelector("#onetrust-accept-btn-handler"),
      rejectButtonExists: !!document.querySelector("#onetrust-reject-all-handler"),
      preferenceCenterButtonExists: !!document.querySelector("#onetrust-pc-btn-handler"),
      cookieSettingsButtonExists: !!document.querySelector("#ot-sdk-btn"),
    };
  });
}

async function getOneTrustAvailability(page) {
  return page.evaluate(() => ({
    hasOneTrust: !!window.OneTrust,
    hasOptanonWrapper: typeof window.OptanonWrapper === "function",
    hasOptanon: !!window.Optanon,
    hasGetDomainData: typeof window.OneTrust?.GetDomainData === "function",
    hasGetGeolocationData: typeof window.OneTrust?.getGeolocationData === "function",
    hasOnConsentChanged: typeof window.OneTrust?.OnConsentChanged === "function",
    hasToggleInfoDisplay: typeof window.OneTrust?.ToggleInfoDisplay === "function",
  }));
}

async function getOneTrustDomainData(page) {
  return page.evaluate(() => {
    try {
      const data = window.OneTrust?.GetDomainData?.();
      if (!data) return null;

      return {
        raw: data,
        groups: data?.Groups || [],
        generalVendors: data?.GeneralVendors || [],
        googleConsent: data?.GoogleConsent || null,
        microsoftConsent: data?.MCMData || null,
        amazonConsent: data?.ACMData || null,
        ruleSet: data?.RuleSet || [],
        domainId: data?.DomainId || "",
        consentModel: data?.ConsentModel || "",
        templateName: data?.TemplateName || "",
        defaultLanguage: data?.DefaultLanguage || "",
        activeLanguage: data?.Language || "",
        bannerData: data?.BannerData || null,
        preferenceCenterData: data?.PreferenceCenterData || null,
      };
    } catch {
      return null;
    }
  });
}

async function getGeoData(page, timeoutMs) {
  try {
    await page.waitForFunction(
      () => window.OneTrust && typeof window.OneTrust.getGeolocationData === "function",
      { timeout: timeoutMs }
    );

    return page.evaluate(() => {
      try {
        return window.OneTrust?.getGeolocationData?.() || null;
      } catch {
        return null;
      }
    });
  } catch {
    return null;
  }
}

async function maybeClickAndCapture(page, selector, label, waitMs = 1000) {
  const result = {
    label,
    selector,
    attempted: false,
    clicked: false,
    error: "",
    cookiesAfterClick: [],
    storageAfterClick: null,
    consentAfterClick: null,
  };

  try {
    const locator = page.locator(selector).first();
    const count = await locator.count();

    if (!count) return result;

    result.attempted = true;
    await locator.click({ timeout: 5000 });
    result.clicked = true;
    await page.waitForTimeout(waitMs);

    result.cookiesAfterClick = await page.context().cookies();
    result.storageAfterClick = await getStorageSnapshot(page);
    result.consentAfterClick = await getOneTrustDomainData(page);
  } catch (err) {
    result.error = err?.message || String(err);
  }

  return result;
}

export async function runCheck(inputUrl, options = {}) {
  const targetUrl = normaliseUrl(inputUrl);

  const {
    headless = true,
    pageLoadWaitMs = 5000,
    oneTrustTimeoutMs = 10000,
    navigationTimeoutMs = 30000,
    networkIdleTimeoutMs = 10000,
    locale = "en-GB",
    timezoneId = "Europe/London",
    viewport = { width: 1366, height: 768 },
    userAgent,
    captureScreenshots = false,
    screenshotPathPrefix = "onetrust-check",
    testConsentActions = false,
  } = options;

  const issues = [];
  const capturedConfigs = [];
  const oneTrustScriptResponses = [];
  const failedRequests = [];
  const consoleMessages = [];
  const pageErrors = [];

  let accessDenied = false;
  let mainDocumentResponse = null;
  let geoLocationResponse = null;
  let browser;
  let context;

  if (!targetUrl) {
    return {
      checkedUrl: targetUrl,
      finalUrl: "",
      summary: {
        severity: "HIGH",
        issueCount: 1,
        accessDenied: false,
        otSDKStubFound: false,
        autoBlockEnabled: false,
        usingTestScript: false,
      },
      severity: "HIGH",
      issues: [mkFinding("HIGH", "No URL was provided.")],
      recommendations: ["Provide a valid URL or domain to scan."],
    };
  }

  try {
    browser = await chromium.launch({ headless });

    context = await browser.newContext({
      locale,
      timezoneId,
      viewport,
      ...(userAgent ? { userAgent } : {}),
    });

    const page = await context.newPage();

    page.on("console", (msg) => {
      consoleMessages.push({
        type: msg.type(),
        text: msg.text(),
        location: msg.location?.() || null,
      });
    });

    page.on("pageerror", (error) => {
      pageErrors.push({
        message: error.message,
        stack: error.stack || "",
      });
    });

    page.on("requestfailed", (request) => {
      failedRequests.push({
        url: request.url(),
        method: request.method(),
        resourceType: request.resourceType(),
        failure: request.failure()?.errorText || "",
      });
    });

    page.on("response", async (response) => {
      try {
        const status = response.status();
        const request = response.request();
        const resourceType = request.resourceType();
        const responseUrl = response.url();
        const lowerUrl = responseUrl.toLowerCase();
        const headers = response.headers();

        if (resourceType === "document") {
          mainDocumentResponse = {
            url: responseUrl,
            status,
            headers,
          };

          if (status === 401 || status === 403) {
            accessDenied = true;
          }
        }

        if (lowerUrl.includes("otsdkstub") || lowerUrl.includes("otautoblock")) {
          oneTrustScriptResponses.push({
            url: responseUrl,
            status,
            headers,
            resourceType,
          });
        }

        if (lowerUrl.includes("/v1/geo/location")) {
          let body = null;
          try {
            body = await response.json();
          } catch {
            try {
              body = await response.text();
            } catch {
              body = null;
            }
          }

          geoLocationResponse = {
            url: responseUrl,
            status,
            headers,
            body,
          };
        }

        if (!lowerUrl.includes("json")) return;

        const text = await response.text();
        const parsed = safeJsonParse(text);

        if (looksLikeUdidJson(parsed)) {
          capturedConfigs.push({
            url: responseUrl,
            status,
            headers,
            body: parsed,
          });
        }
      } catch {
        // Ignore parsing errors so the scan can continue.
      }
    });

    let navError = null;

    try {
      await page.goto(targetUrl, {
        waitUntil: "domcontentloaded",
        timeout: navigationTimeoutMs,
      });
    } catch (err) {
      navError = err?.message || String(err);
    }

    if (navError) {
      issues.push(mkFinding("HIGH", navError));

      return {
        checkedUrl: targetUrl,
        finalUrl: page.url?.() || "",
        summary: {
          severity: computeSeverity(issues),
          issueCount: issues.length,
          accessDenied,
          otSDKStubFound: false,
          autoBlockEnabled: false,
          usingTestScript: false,
        },
        severity: computeSeverity(issues),
        issues,
        recommendations: createRecommendationSet(issues, { accessDenied }),
        network: {
          mainDocumentResponse,
          failedRequests,
          oneTrustScriptResponses,
          geoLocationResponse,
        },
        browser: {
          consoleMessages,
          pageErrors,
        },
      };
    }

    await page.waitForLoadState("networkidle", { timeout: networkIdleTimeoutMs }).catch(() => {});
    await page.waitForTimeout(pageLoadWaitMs);

    const finalUrl = page.url();

    const screenshots = {};
    if (captureScreenshots) {
      try {
        screenshots.pageLoaded = `${screenshotPathPrefix}-page-loaded.png`;
        await page.screenshot({ path: screenshots.pageLoaded, fullPage: true });
      } catch (err) {
        screenshots.pageLoadedError = err?.message || String(err);
      }
    }

    const scripts = await page.locator("script").evaluateAll((nodes) =>
      nodes.map((s, i) => ({
        index: i,
        src: s.src || "",
        inHead: document.head.contains(s),
        async: !!s.async,
        defer: !!s.defer,
        type: s.type || "",
        id: s.id || "",
        dataDomainScript: s.getAttribute("data-domain-script") || "",
        udid: s.getAttribute("data-domain-script") || "",
      }))
    );

    const stub = scripts.filter((s) => safeIncludes(s.src, "otsdkstub"));
    const autoblock = scripts.filter((s) => safeIncludes(s.src, "otautoblock"));
    const otScripts = [...stub, ...autoblock];

    const firstOt = otScripts.length ? Math.min(...otScripts.map((s) => s.index)) : null;

    const jsBefore =
      firstOt === null ? [] : scripts.filter((s) => s.index < firstOt && s.src && isLikelyJsFile(s.src));

    const primaryUdid = stub.find((s) => s.udid)?.udid || "";
    const productionUdid = cleanUdid(primaryUdid);
    const usingTestScript = isTestScript(primaryUdid);

    const primaryCapturedConfig = capturedConfigs[0] || null;
    const capturedConfig = primaryCapturedConfig?.body || null;

    const ruleSet = capturedConfig?.RuleSet || [];
    const skipGeo = capturedConfig?.SkipGeolocation === true;
    const shouldSkipGeoLookup = ruleSet.length === 1 && skipGeo;

    let oneTrustAvailability = null;
    try {
      oneTrustAvailability = await getOneTrustAvailability(page);
    } catch {
      oneTrustAvailability = null;
    }

    let geolocation = null;
    if (!shouldSkipGeoLookup) {
      geolocation = await getGeoData(page, oneTrustTimeoutMs);
    }

    let oneTrustDomainData = null;
    try {
      await page
        .waitForFunction(
          () => window.OneTrust && typeof window.OneTrust.GetDomainData === "function",
          { timeout: oneTrustTimeoutMs }
        )
        .catch(() => {});
      oneTrustDomainData = await getOneTrustDomainData(page);
    } catch {
      oneTrustDomainData = null;
    }

    const consent = oneTrustDomainData?.raw || {};

    const cookies = await context.cookies();
    const storage = await getStorageSnapshot(page);
    const bannerState = await getBannerState(page);

    if (captureScreenshots && bannerState.bannerVisible) {
      try {
        screenshots.banner = `${screenshotPathPrefix}-banner.png`;
        await page.locator("#onetrust-banner-sdk").screenshot({ path: screenshots.banner });
      } catch (err) {
        screenshots.bannerError = err?.message || String(err);
      }
    }

    const consentActionTests = [];
    if (testConsentActions) {
      consentActionTests.push(
        await maybeClickAndCapture(page, "#onetrust-accept-btn-handler", "Accept All")
      );
      consentActionTests.push(
        await maybeClickAndCapture(page, "#onetrust-reject-all-handler", "Reject All")
      );
      consentActionTests.push(
        await maybeClickAndCapture(page, "#onetrust-pc-btn-handler", "Open Preference Center")
      );
    }

    const otSDKStubFound = stub.length > 0;
    const autoBlockEnabled = autoblock.length > 0;
    const otSdkStubInHead = stub.some((s) => s.inHead);
    const otAutoBlockInHead = autoblock.some((s) => s.inHead);
    const hasJsBeforeOt = jsBefore.length > 0;
    const udidJsonFound = capturedConfigs.length > 0;

    const oneTrustConsoleMessages = consoleMessages.filter((m) => {
      const text = m.text.toLowerCase();
      return text.includes("onetrust") || text.includes("cmp") || text.includes("consent") || text.includes("ot-sdk");
    });

    const consoleErrors = consoleMessages.filter((m) => m.type === "error");

    const failedOneTrustRequests = failedRequests.filter((r) => {
      const url = r.url.toLowerCase();
      return (
        url.includes("onetrust") ||
        url.includes("cookielaw") ||
        url.includes("cookiepro") ||
        url.includes("otsdkstub") ||
        url.includes("otautoblock")
      );
    });

    if (!otSDKStubFound) {
      issues.push(mkFinding("HIGH", "otSDKStub.js was not found on the page."));
    }

    if (!otScripts.length) {
      issues.push(mkFinding("HIGH", "No OneTrust script was found on the page."));
    }

    if (otSDKStubFound && !otSdkStubInHead) {
      issues.push(mkFinding("LOW", "otSDKStub.js was found but not loaded in the <head>."));
    }

    if (autoBlockEnabled && !otAutoBlockInHead) {
      issues.push(mkFinding("LOW", "otautoblock.js was found but not loaded in the <head>."));
    }

    if (hasJsBeforeOt) {
      issues.push(
        mkFinding("LOW", `${jsBefore.length} JavaScript file(s) loaded before the first OneTrust script.`, {
          previousScripts: jsBefore.map((s) => s.src),
        })
      );
    }

    if (accessDenied) {
      issues.push(mkFinding("HIGH", "The page returned a 401 or 403 access denied response."));
    }

    if (!udidJsonFound) {
      issues.push(mkFinding("MEDIUM", "No OneTrust UDID JSON configuration response was detected."));
    }

    if (usingTestScript) {
      issues.push(mkFinding("LOW", "The page is using a test UDID script ending in -test."));
    }

    const failedScriptResponses = oneTrustScriptResponses.filter((r) => r.status >= 400);
    if (failedScriptResponses.length) {
      issues.push(
        mkFinding("HIGH", "One or more OneTrust script responses returned an error status.", {
          failedScriptResponses,
        })
      );
    }

    if (failedOneTrustRequests.length) {
      issues.push(
        mkFinding("HIGH", "One or more OneTrust-related network requests failed.", {
          failedOneTrustRequests,
        })
      );
    }

    if (consoleErrors.length) {
      issues.push(
        mkFinding("LOW", `${consoleErrors.length} browser console error(s) were detected.`, {
          consoleErrors,
        })
      );
    }

    if (pageErrors.length) {
      issues.push(
        mkFinding("LOW", `${pageErrors.length} page runtime error(s) were detected.`, {
          pageErrors,
        })
      );
    }

    const bannerExpectedButNotVisible = otSDKStubFound && !bannerState.bannerVisible && !bannerState.bannerSdkExists;
    if (bannerExpectedButNotVisible) {
      issues.push(
        mkFinding("LOW", "The OneTrust banner element was not detected or visible after page load.", {
          bannerState,
        })
      );
    }

    const contextForRecommendations = {
      otSDKStubFound,
      autoBlockEnabled,
      otSdkStubInHead,
      otAutoBlockInHead,
      hasJsBeforeOt,
      usingTestScript,
      accessDenied,
      udidJsonFound,
      failedOneTrustRequests,
      consoleErrors,
      bannerExpectedButNotVisible,
    };

    const severity = computeSeverity(issues);
    const recommendations = createRecommendationSet(issues, contextForRecommendations);

    return {
      checkedUrl: targetUrl,
      finalUrl,

      summary: {
        severity,
        issueCount: issues.length,
        accessDenied,
        otSDKStubFound,
        autoBlockEnabled,
        usingTestScript,
        udidJsonFound,
        bannerVisible: bannerState.bannerVisible,
        hasJsBeforeOt,
      },

      severity,
      issues,
      recommendations,

      oneTrust: {
        TenantGuid: capturedConfig?.TenantGuid ?? "",
        EnvId: capturedConfig?.EnvId ?? "",
        Domain: capturedConfig?.Domain ?? "",
        primaryUdid,
        productionUdid,
        usingTestScript,
        udidJson: {
          Version: capturedConfig?.Version ?? "",
          ScriptType: capturedConfig?.ScriptType ?? "",
          LanguageDetectionByHtml: capturedConfig?.LanguageDetectionByHtml ?? "",
          LanguageDetectionEnabled: capturedConfig?.LanguageDetectionEnabled ?? "",
          GeoRuleGroupName: capturedConfig?.GeoRuleGroupName ?? "",
          RuleSetCount: ruleSet.length,
          SkipGeolocation: skipGeo,
        },
        capturedConfigs,
        primaryCapturedConfig,
        availability: oneTrustAvailability,
        domainData: oneTrustDomainData,
      },

      scripts: {
        allScripts: scripts,
        otSDKStub: stub,
        otAutoBlock: autoblock,
        otSdkStubInHead,
        otAutoBlockInHead,
        hasJsBeforeOt,
        previousScripts: jsBefore.map((s) => s.src),
      },

      network: {
        mainDocumentResponse,
        contentSecurityPolicy: mainDocumentResponse?.headers?.["content-security-policy"] || "",
        failedRequests,
        failedOneTrustRequests,
        oneTrustScriptResponses,
        geoLocationResponse,
      },

      browser: {
        consoleMessages,
        oneTrustConsoleMessages,
        consoleErrors,
        pageErrors,
        cookies: cookies.map((c) => ({
          name: c.name,
          value: c.value,
          domain: c.domain,
          path: c.path,
          expires: c.expires,
          httpOnly: c.httpOnly,
          secure: c.secure,
          sameSite: c.sameSite,
        })),
        storage,
      },

      bannerState,
      screenshots,
      geolocation,

      consentModes: {
        google: consent?.GoogleConsent?.GCEnable ?? null,
        microsoft: consent?.MCMData?.Enabled ?? null,
        amazon: consent?.ACMData?.Enabled ?? null,
        raw: {
          GoogleConsent: consent?.GoogleConsent ?? null,
          MCMData: consent?.MCMData ?? null,
          ACMData: consent?.ACMData ?? null,
        },
      },

      consentActionTests,
    };
  } finally {
    if (context) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
  }
}

export default runCheck;

