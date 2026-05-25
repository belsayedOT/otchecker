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

function normaliseConsentModel(consentModel) {
  if (!consentModel) return "";

  if (typeof consentModel === "string") {
    return consentModel;
  }

  if (typeof consentModel === "object") {
    return (
      consentModel.Name ||
      consentModel.name ||
      consentModel.Value ||
      consentModel.value ||
      consentModel.Id ||
      consentModel.id ||
      JSON.stringify(consentModel)
    );
  }

  return String(consentModel);
}

const EXPECTED_WORKFLOW_VERSION_REGEX = /\b(?:202[3-9]|20[3-9]\d)(?:0[1-9]|1[0-2])\.[12]\.0\b/;
const LATEST_AVAILABLE_WORKFLOW_VERSION = "2026.05.0";

function parseSemverVersion(version) {
  const match = /^([0-9]+)\.([0-9]+)\.([0-9]+)$/.exec(
    String(version || "").trim()
  );
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  };
}

function getExpectedWorkflowVersionAgeMonths(version) {
  const match = /^([0-9]{4})\.(0[1-9]|1[0-2])\.[12]\.0$/.exec(
    String(version || "").trim()
  );

  if (!match) return null;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const versionDate = new Date(year, month - 1, 1);
  const now = new Date();

  return (
    (now.getFullYear() - versionDate.getFullYear()) * 12 +
    now.getMonth() -
    versionDate.getMonth()
  );
}

function toArray(value) {
  if (!value) return [];

  if (Array.isArray(value)) {
    return value;
  }

  if (typeof value === "object") {
    return Object.values(value);
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

function getRuleLanguages(rule) {
  const languageSwitcher =
    rule?.LanguageSwitcherPlaceholder ||
    rule?.languageSwitcherPlaceholder ||
    {};

  const available = Object.values(languageSwitcher)
    .filter(Boolean)
    .map((value) => String(value).toLowerCase());

  const uniqueAvailable = [...new Set(available)];

  return {
    default:
      languageSwitcher?.default ||
      rule?.DefaultLanguage ||
      rule?.defaultLanguage ||
      "",
    available: uniqueAvailable,
  };
}

function isGlobalRule(rule) {
  return lower(rule?.Name) === "global" || rule?.Global === true;
}

function summariseRuleSet(ruleSet) {
  return ruleSet.map((rule, index) => {
    const globalRule = isGlobalRule(rule);

    return {
      index,
      Id: rule?.Id ?? "",
      Name: rule?.Name ?? "",
      IsGPPEnabled: rule?.IsGPPEnabled ?? false,
      GCEnable: rule?.GCEnable ?? false,
      TemplateName: getRuleTemplateName(rule),
      Type: rule?.Type ?? "",
      VariantEnabled: rule?.VariantEnabled ?? false,
      Default: rule?.Default ?? false,
      Global: rule?.Global ?? false,
      languages: getRuleLanguages(rule),

      countries: globalRule
        ? []
        : getRuleCountries(rule),

      states: globalRule
        ? []
        : getRuleStates(rule),

      countriesSummary: globalRule
        ? "Global rule - countries hidden from summary."
        : `${getRuleCountries(rule).length} country value(s).`,

      statesSummary: globalRule
        ? "Global rule - states hidden from summary."
        : `${getRuleStates(rule).length} state value(s).`,
    };
  });
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
      rule: null,
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
        rule,
      };
    }
  }

  return {
    matched: false,
    matchReason: "No RuleSet item matched the detected country/state.",
    matchedRuleIndex: null,
    rule: null,
  };
}

function summariseTriggeredRuleSet(matchResult) {
  const rule = matchResult?.rule;

  if (!rule) {
    return {
      matched: false,
      matchReason: matchResult?.matchReason || "",
      matchedRuleIndex: matchResult?.matchedRuleIndex ?? null,
      Id: "",
      Name: "",
      TemplateName: "",
      Type: "",
      IsGPPEnabled: false,
      GCEnable: false,
      VariantEnabled: false,
      Default: false,
      languages: {
        default: "",
        available: [],
      },
    };
  }

  return {
    matched: matchResult.matched,
    matchReason: matchResult.matchReason,
    matchedRuleIndex: matchResult.matchedRuleIndex,
    Id: rule?.Id ?? "",
    Name: rule?.Name ?? "",
    TemplateName: getRuleTemplateName(rule),
    Type: rule?.Type ?? "",
    IsGPPEnabled: rule?.IsGPPEnabled ?? false,
    GCEnable: rule?.GCEnable ?? false,
    VariantEnabled: rule?.VariantEnabled ?? false,
    Default: rule?.Default ?? false,
    languages: getRuleLanguages(rule),
  };
}

function getHostname(value) {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function isOneTrustCdnHost(hostname) {
  const host = lower(hostname);

  return (
    host.includes("cdn.cookielaw.org") ||
    host.includes("cookie-cdn.cookiepro.com") ||
    host.includes("geolocation.onetrust.com") ||
    host.includes("privacyportal.onetrust.com")
  );
}

function classifyScriptHosting(scriptUrl, pageUrl) {
  if (!scriptUrl) {
    return {
      url: "",
      hostingType: "NOT_FOUND",
      flagged: false,
      message: "Script was not found.",
    };
  }

  const scriptHost = getHostname(scriptUrl);
  const pageHost = getHostname(pageUrl);

  if (!scriptHost) {
    return {
      url: scriptUrl,
      hostingType: "UNKNOWN",
      flagged: true,
      message: "Could not identify script host.",
    };
  }

  if (scriptHost === pageHost || scriptHost.endsWith(`.${pageHost}`)) {
    return {
      url: scriptUrl,
      hostingType: "LOCAL_SITE",
      flagged: false,
      message: "Script appears to be hosted on the scanned website domain.",
    };
  }

  if (isOneTrustCdnHost(scriptHost)) {
    return {
      url: scriptUrl,
      hostingType: "ONETRUST_CDN",
      flagged: false,
      message: "Script appears to be hosted on a recognised OneTrust CDN/domain.",
    };
  }

  return {
    url: scriptUrl,
    hostingType: "EXTERNAL_NON_ONETRUST",
    flagged: true,
    message:
      "Script is hosted externally but not on a recognised OneTrust CDN/domain.",
  };
}

function findScriptByName(scripts, filename) {
  const target = lower(filename);

  return scripts.filter((script) =>
    lower(script.src).includes(target)
  );
}

function getCookieByName(cookies, name) {
  const target = lower(name);
  return cookies.find((cookie) => lower(cookie.name) === target) || null;
}

function getCookieNamesByPrefix(cookies, prefix) {
  const target = lower(prefix);
  return cookies
    .filter((cookie) => lower(cookie.name).startsWith(target))
    .map((cookie) => cookie.name);
}

function extractQueryParam(url, paramName) {
  try {
    const parsed = new URL(url);
    const exact = parsed.searchParams.get(paramName);
    if (exact !== null) return exact;

    const lowerName = lower(paramName);
    for (const [key, value] of parsed.searchParams.entries()) {
      if (lower(key) === lowerName) {
        return value;
      }
    }

    return null;
  } catch {
    return null;
  }
}

function isGoogleAnalyticsOrTagUrl(url) {
  const value = lower(url);

  return (
    value.includes("google-analytics.com/g/collect") ||
    value.includes("google-analytics.com/collect") ||
    value.includes("googletagmanager.com/gtag/js") ||
    value.includes("googletagmanager.com/gtm.js")
  );
}

function isGoogleAnalyticsCollectionUrl(url) {
  const value = lower(url);

  return (
    value.includes("google-analytics.com/g/collect") ||
    value.includes("google-analytics.com/collect") ||
    value.includes("/g/collect") ||
    (value.includes("tid=g-") && value.includes("gtm="))
  );
}

function evaluateGcmDefaultsFromDataLayer(dataLayer) {
  const entries = Array.isArray(dataLayer) ? dataLayer : [];

  const defaultEntries = entries.filter((entry) => {
    const text = JSON.stringify(entry || {}).toLowerCase();

    return (
      text.includes("consent") &&
      text.includes("default")
    );
  });

  return {
    gcmDefaultsFound: defaultEntries.length > 0,
    gcmDefaultEntries: defaultEntries,
  };
}

function evaluateGcmMode({
  gtagDetectedBeforeConsent,
  optanonAlertBoxClosedExists,
}) {
  if (optanonAlertBoxClosedExists) {
    return {
      inferredMode: "CONSENT_ALREADY_GIVEN_OR_CLOSED",
      message:
        "OptanonAlertBoxClosed cookie exists, so this is not a clean pre-consent state.",
    };
  }

  if (gtagDetectedBeforeConsent) {
    return {
      inferredMode: "ADVANCED_MODE_LIKELY",
      message:
        "Google tag/analytics activity was detected before OptanonAlertBoxClosed existed. This likely indicates Google Consent Mode advanced mode.",
    };
  }

  return {
    inferredMode: "BASIC_MODE_LIKELY",
    message:
      "Google tag/analytics activity was not detected before OptanonAlertBoxClosed existed. This potentially indicates Google Consent Mode basic mode.",
  };
}

function validateGcsDefault({
  gcsValues,
  optanonAlertBoxClosedExists,
  consentModel,
  location,
  triggerRuleSet,
}) {
  const uniqueGcsValues = [...new Set((gcsValues || []).filter(Boolean))];
  const normalisedConsentModel = lower(normaliseConsentModel(consentModel));

  if (optanonAlertBoxClosedExists) {
    return {
      status: "NOT_PRE_CONSENT",
      message:
        "OptanonAlertBoxClosed exists, so GCS default validation was not evaluated as a clean pre-consent state.",
      location,
      triggerRuleSet,
    };
  }

  if (uniqueGcsValues.length === 0) {
    return {
      status: "GCS_NOT_FOUND",
      message:
        "Google Analytics collection calls were detected without a GCS parameter, or no GA collection call with GCS was found. Review whether Consent Mode is enabled in GTM/GA.",
      location,
      triggerRuleSet,
    };
  }

  if (uniqueGcsValues.includes("G100") && normalisedConsentModel === "opt-in") {
    return {
      status: "CORRECT_DEFAULT",
      message:
        "GCS is G100 before consent and ConsentModel is opt-in. Consent default appears correctly set.",
      location,
      triggerRuleSet,
    };
  }

  if (uniqueGcsValues.includes("G111") && normalisedConsentModel === "opt-out") {
    return {
      status: "CORRECT_DEFAULT",
      message:
        "GCS is G111 before consent and ConsentModel is opt-out. Consent default appears correctly set.",
      location,
      triggerRuleSet,
    };
  }

  return {
    status: "REVIEW_REQUIRED",
    message:
      "GCS value does not match the expected default for the detected OneTrust ConsentModel. Review GCM consent defaults or OneTrust Google Consent Mode backend configuration for this region.",
    location,
    triggerRuleSet,
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

  const googleNetworkRequests = [];
  const googleAnalyticsCollectionCalls = [];

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

    page.on("request", (request) => {
      try {
        const url = request.url();

        if (isGoogleAnalyticsOrTagUrl(url)) {
          googleNetworkRequests.push({
            url,
            resourceType: request.resourceType(),
            method: request.method(),
          });
        }

        if (isGoogleAnalyticsCollectionUrl(url)) {
          googleAnalyticsCollectionCalls.push({
            url,
            resourceType: request.resourceType(),
            method: request.method(),
            gcs: extractQueryParam(url, "gcs"),
            gcd: extractQueryParam(url, "gcd"),
          });
        }
      } catch {
        // Continue scan.
      }
    });

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

    const isFirewallTimeout = /timed out|timeout|http request timed out|HttpRequestTimeout|ERR_CONNECTION_RESET|ECONNRESET|ECONNREFUSED|ENOTFOUND/i.test(
      navigationError
    );
    const botNotice = isFirewallTimeout
      ? "🤖 The bot cannot access the website due to Site Firewall restrictions."
      : "";

    if (navigationError) {
      return {
        checkedUrl: targetUrl,
        success: false,
        accessDenied: accessDenied || isFirewallTimeout,
        error: navigationError,
        botNotice,
      };
    }

    await page.waitForTimeout(pageLoadWaitMs);

    const oneTrustApiState = await page.evaluate(() => ({
      oneTrustGlobalFound: typeof window.OneTrust === "object",
      getDomainDataAvailable:
        typeof window.OneTrust?.GetDomainData === "function",
      getGeolocationDataAvailable:
        typeof window.OneTrust?.getGeolocationData === "function",
    }));

    const finalUrl = page.url();

    const udidIdValue = String(capturedUdidJson?.Id ?? capturedUdidJson?.id ?? "").trim();
    const udidTenantGuidValue = String(
      capturedUdidJson?.TenantGuid ??
      capturedUdidJson?.tenantGuid ??
      ""
    ).trim();
    const udidDomainValue = String(capturedUdidJson?.Domain ?? capturedUdidJson?.domain ?? "").trim();
    const udidFileNameValue = (() => {
      try {
        const url = new URL(capturedUdidJsonUrl);
        const filename = url.pathname.split("/").pop() || "";
        const match = filename.match(/^(.+?)\.json$/i);
        return match ? match[1] : "";
      } catch {
        return "";
      }
    })();
    const isTestUdidScript = udidIdValue.toLowerCase().endsWith("-test");

    const pageHost = (() => {
      try {
        return new URL(finalUrl).hostname.toLowerCase();
      } catch {
        return "";
      }
    })();

    const normalizedUdidDomain = udidDomainValue.replace(/^\*\./, "").toLowerCase();
    let udidScriptScopeValid = false;
    let udidScriptScopeMessage = "";

    if (isTestUdidScript) {
      udidScriptScopeValid = false;
      udidScriptScopeMessage =
        "UDID id indicates a test script is used instead of production.";
    } else if (!normalizedUdidDomain) {
      udidScriptScopeValid = false;
      udidScriptScopeMessage =
        "No UDID domain value is available to determine script scope.";
    } else {
      udidScriptScopeValid =
        pageHost === normalizedUdidDomain ||
        pageHost.endsWith(`.${normalizedUdidDomain}`);

      udidScriptScopeMessage = udidScriptScopeValid
        ? `Production script domain scope ${udidDomainValue} covers page host ${pageHost}.`
        : `Production script domain scope ${udidDomainValue} does not cover page host ${pageHost}. This script is invalid on this page and may not be able to save consent across page refreshes.`;
    }

    const cookies = await context.cookies();
    const optanonConsentCookie = getCookieByName(cookies, "OptanonConsent");
    const optanonActiveGroupsCookie = getCookieByName(
      cookies,
      "OptanonActiveGroups"
    );
    const optanonCookieNames = getCookieNamesByPrefix(cookies, "optanon");
    const optanonAlertBoxClosedCookie = getCookieByName(
      cookies,
      "OptanonAlertBoxClosed"
    );

    const optanonAlertBoxClosedExists = Boolean(optanonAlertBoxClosedCookie);

    const scripts = await page.locator("script").evaluateAll((nodes) =>
      nodes.map((script, index) => ({
        index,
        src: script.src || "",
        inHead: document.head.contains(script),
        dataDomainScript: script.getAttribute("data-domain-script") || "",
      }))
    );

    const otSdkStubScripts = findScriptByName(scripts, "otsdkstub");
    const otAutoBlockScripts = findScriptByName(scripts, "otautoblock");
    const otCCPAiabScripts = findScriptByName(scripts, "otCCPAiab.js");
    const otBannerSdkScripts = findScriptByName(scripts, "otBannerSdk.js");
    const otTCFScripts = findScriptByName(scripts, "otTCF.js");
    const otGPPScripts = findScriptByName(scripts, "otGPP.js");

    const oneTrustScripts = [
      ...otSdkStubScripts,
      ...otAutoBlockScripts,
    ];

    const firstOneTrustScriptIndex =
      oneTrustScripts.length > 0
        ? Math.min(...oneTrustScripts.map((script) => script.index))
        : null;

    const firstOtautoblockScriptIndex =
      otAutoBlockScripts.length > 0
        ? Math.min(...otAutoBlockScripts.map((script) => script.index))
        : null;

    const jsScriptsBeforeOneTrust =
      firstOneTrustScriptIndex === null
        ? []
        : scripts.filter((script) => {
            const src = String(script.src || "").toLowerCase();

            return (
              script.index < firstOneTrustScriptIndex &&
              src &&
              src.includes(".js")
            );
          });

    const excludedAdsConsentFrameworks = [
      "otccpaiab.js",
      "otgpp.js",
      "otbannersdk.js",
      "ottcf.js",
    ];

    const adsConsentFrameworkScripts =
      firstOtautoblockScriptIndex === null
        ? []
        : scripts.filter((script) => {
            const src = String(script.src || "").toLowerCase();

            return (
              script.index < firstOtautoblockScriptIndex &&
              src &&
              src.includes(".js") &&
              !excludedAdsConsentFrameworks.some((excluded) =>
                src.includes(excluded)
              )
            );
          });

    const adsConsentFrameworksBeforeAutoBlock = {
      found: adsConsentFrameworkScripts.length > 0,
      count: adsConsentFrameworkScripts.length,
      urls: adsConsentFrameworkScripts.map((script) => script.src),
    };

    const otSdkStubInHead = otSdkStubScripts.some((script) => script.inHead);
    const otAutoBlockInHead = otAutoBlockScripts.some((script) => script.inHead);

    const otSdkStubPrimaryUrl = otSdkStubScripts[0]?.src || "";
    const otAutoBlockPrimaryUrl = otAutoBlockScripts[0]?.src || "";

    const otSdkStubUrlHasQuery =
      otSdkStubPrimaryUrl && otSdkStubPrimaryUrl.includes("?");
    const cmpTemplateTagDetected = otSdkStubUrlHasQuery;
    const cmpBannerSetupMethod =
      otSdkStubScripts.length === 0
        ? "Unknown"
        : cmpTemplateTagDetected
        ? "GTM CMP template tag"
        : "Normal script";

    const scriptHosting = {
      otSdkStub: classifyScriptHosting(otSdkStubPrimaryUrl, finalUrl),
      otAutoBlock: classifyScriptHosting(otAutoBlockPrimaryUrl, finalUrl),
    };

    const cookieAudit = {
      optanonConsentExists: Boolean(optanonConsentCookie),
      optanonConsentSameSite: optanonConsentCookie?.sameSite ?? "",
      optanonConsentSecure: Boolean(optanonConsentCookie?.secure),
      optanonActiveGroupsExists: Boolean(optanonActiveGroupsCookie),
      optanonAlertBoxClosedExists: Boolean(optanonAlertBoxClosedCookie),
      optanonCookieNames,
    };

    const ruleSet = Array.isArray(capturedUdidJson?.RuleSet)
      ? capturedUdidJson.RuleSet
      : [];

    const skipGeolocation = capturedUdidJson?.SkipGeolocation === true;
    const ruleSetCount = ruleSet.length;
    const ruleSetSummary = summariseRuleSet(ruleSet);

    const versionValue = capturedUdidJson?.Version ?? "";
    const numericVersion = parseSemverVersion(versionValue);
    const isLegacyWorkflow =
      numericVersion &&
      (numericVersion.major < 6 ||
        (numericVersion.major === 6 && numericVersion.minor < 30));
    const versionAgeMonths = getExpectedWorkflowVersionAgeMonths(versionValue);
    const isExpectedVersion = EXPECTED_WORKFLOW_VERSION_REGEX.test(versionValue);
    const isMoreThanOneYearOld =
      versionAgeMonths !== null && versionAgeMonths > 12;

    const displayVersion = isLegacyWorkflow
      ? "6.6.0 (old workflow)"
      : versionValue;

    const versionCheck = {
      version: versionValue,
      displayVersion,
      isVersionSupported:
        Boolean(versionValue) && isExpectedVersion && !isMoreThanOneYearOld,
      latestAvailableVersion: LATEST_AVAILABLE_WORKFLOW_VERSION,
      status: versionValue
        ? isLegacyWorkflow
          ? "OUT_OF_DATE"
          : isExpectedVersion
          ? isMoreThanOneYearOld
            ? "UPGRADE_RECOMMENDED"
            : "SUPPORTED"
          : "OUT_OF_DATE"
        : "UNKNOWN",
      warning: versionValue
        ? isLegacyWorkflow
          ? "High level warning: the banner is out of date and using old workflow version. Recommend upgrading the banner to the latest available version."
          : isExpectedVersion && isMoreThanOneYearOld
          ? "High level warning: the banner workflow version is more than one year old. Recommend upgrading to the latest available version."
          : ""
        : "",
    };

    const shouldSkipLocationInfo =
      ruleSetCount === 1 && skipGeolocation === true;

    let geolocationData = null;
    let detectedCountry = "";
    let detectedState = "";

    let triggerRuleMatch = {
      matched: false,
      matchReason: "",
      matchedRuleIndex: null,
      rule: null,
    };

    if (shouldSkipLocationInfo) {
      triggerRuleMatch = {
        matched: true,
        matchReason:
          "SkipGeolocation is true and RuleSet has only one item, so RuleSet[0] was used.",
        matchedRuleIndex: 0,
        rule: ruleSet[0] || null,
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

        triggerRuleMatch = findMatchingRuleSet(ruleSet, geolocationData);
      } catch {
        geolocationData = null;
        triggerRuleMatch = {
          matched: false,
          matchReason:
            "SkipGeolocation is false, but OneTrust.getGeolocationData() was not available or did not return data.",
          matchedRuleIndex: null,
          rule: null,
        };
      }
    }

    const triggerRuleSet = summariseTriggeredRuleSet(triggerRuleMatch);

    let googleConsentModeEnabled = false;
    let microsoftConsentModeEnabled = false;
    let amazonConsentModeEnabled = false;
    let consentModel = "";
    let enabledSdkDetails = {};

    try {
      await page.waitForFunction(
        () =>
          window.OneTrust &&
          typeof window.OneTrust.GetDomainData === "function",
        { timeout: oneTrustTimeoutMs }
      );

      const consentModeData = await page.evaluate(() => {
        function normaliseConsentModelInBrowser(consentModel) {
          if (!consentModel) return "";

          if (typeof consentModel === "string") {
            return consentModel;
          }

          if (typeof consentModel === "object") {
            return (
              consentModel.Name ||
              consentModel.name ||
              consentModel.Value ||
              consentModel.value ||
              consentModel.Id ||
              consentModel.id ||
              JSON.stringify(consentModel)
            );
          }

          return String(consentModel);
        }

        try {
          const data = window.OneTrust.GetDomainData();

          return {
            consentModel: normaliseConsentModelInBrowser(data?.ConsentModel),
            googleEnabled: data?.GoogleConsent?.GCEnable ?? null,
            microsoftEnabled: data?.MCMData?.Enabled ?? null,
            amazonEnabled: data?.ACMData?.Enabled ?? null,

            GoogleConsent:
              data?.GoogleConsent?.GCEnable === true
                ? data?.GoogleConsent
                : null,

            GoogleConsentRaw: data?.GoogleConsent ?? null,
            Groups: Array.isArray(data?.Groups) ? data.Groups : [],

            MCMData:
              data?.MCMData?.Enabled === true
                ? data?.MCMData
                : null,

            ACMData:
              data?.ACMData?.Enabled === true
                ? data?.ACMData
                : null,
          };
        } catch {
          return {
            consentModel: "",
            googleEnabled: null,
            microsoftEnabled: null,
            amazonEnabled: null,
            GoogleConsent: null,
            MCMData: null,
            ACMData: null,
          };
        }
      });

      consentModel = normaliseConsentModel(consentModeData.consentModel);
      googleConsentModeEnabled = consentModeData.googleEnabled === true;
      microsoftConsentModeEnabled = consentModeData.microsoftEnabled === true;
      amazonConsentModeEnabled = consentModeData.amazonEnabled === true;

      if (consentModeData.GoogleConsent) {
        enabledSdkDetails.GoogleConsent = consentModeData.GoogleConsent;
      }

      if (consentModeData.MCMData) {
        enabledSdkDetails.MCMData = consentModeData.MCMData;
      }

      if (consentModeData.ACMData) {
        enabledSdkDetails.ACMData = consentModeData.ACMData;
      }
    } catch {
      googleConsentModeEnabled = false;
      microsoftConsentModeEnabled = false;
      amazonConsentModeEnabled = false;
      consentModel = "";
      enabledSdkDetails = {};
    }

    const gtagAndDataLayerState = await page.evaluate(() => {
      const dataLayer = Array.isArray(window.dataLayer)
        ? window.dataLayer
        : [];

      return {
        hasGtagFunction: typeof window.gtag === "function",
        hasDataLayer: Array.isArray(window.dataLayer),
        dataLayer,
      };
    });

    const gtagDetected =
      gtagAndDataLayerState.hasGtagFunction ||
      googleNetworkRequests.length > 0;
    const collectionCallsDetected =
      googleAnalyticsCollectionCalls.length > 0;
    const collectionCallsBeforeConsent =
      !optanonAlertBoxClosedExists && collectionCallsDetected;

    const gcmDefaults = evaluateGcmDefaultsFromDataLayer(
      gtagAndDataLayerState.dataLayer
    );

    const gtagDetectedBeforeConsent =
      !optanonAlertBoxClosedExists &&
      (
        gtagAndDataLayerState.hasGtagFunction ||
        googleNetworkRequests.length > 0
      );

    const gcmMode = evaluateGcmMode({
      gtagDetectedBeforeConsent,
      optanonAlertBoxClosedExists,
    });

    const gcsValues = googleAnalyticsCollectionCalls
      .map((call) => call.gcs)
      .filter(Boolean);

    const gaCollectionCallsFound =
      googleAnalyticsCollectionCalls.length > 0;

    const gaCollectionCallsWithoutGcs =
      googleAnalyticsCollectionCalls.filter((call) => !call.gcs);

    const gcsValidation = validateGcsDefault({
      gcsValues,
      optanonAlertBoxClosedExists,
      consentModel,
      location: {
        country: detectedCountry,
        state: detectedState,
      },
      triggerRuleSet,
    });

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
        CDNLocation: capturedUdidJson?.CDNLocation ?? "",
        EnvId: capturedUdidJson?.EnvId ?? "",
        Domain: udidDomainValue,
        Id: udidIdValue,
        TenantGuid: udidTenantGuidValue,
        UdidFileNameValue: udidFileNameValue,
        isTestScript: isTestUdidScript,
        scriptScopeValid: udidScriptScopeValid,
        scriptScopeMessage: udidScriptScopeMessage,
        CookieSPAEnabled:
          capturedUdidJson?.CookieSPAEnabled === true,
        CookieSameSiteNoneEnabled:
          capturedUdidJson?.CookieSameSiteNoneEnabled === true,
        RuleSetCount: ruleSetCount,
        SkipGeolocation: skipGeolocation,
      },

      scriptChecks: {
        otSdkStubFound: otSdkStubScripts.length > 0,
        otAutoBlockFound: otAutoBlockScripts.length > 0,

        otCCPAiabFound: otCCPAiabScripts.length > 0,
        otBannerSdkFound: otBannerSdkScripts.length > 0,
        otTCFFound: otTCFScripts.length > 0,
        otGPPFound: otGPPScripts.length > 0,

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

        adsConsentFrameworksBeforeAutoBlock: {
          found: adsConsentFrameworksBeforeAutoBlock.found,
          count: adsConsentFrameworksBeforeAutoBlock.count,
          urls: adsConsentFrameworksBeforeAutoBlock.urls,
        },
      },

      scriptHosting,

      cookieAudit,

      oneTrustApiChecks: {
        oneTrustGlobalFound: oneTrustApiState.oneTrustGlobalFound,
        getDomainDataAvailable: oneTrustApiState.getDomainDataAvailable,
        getGeolocationDataAvailable: oneTrustApiState.getGeolocationDataAvailable,
        dataLayerEventCount: gtagAndDataLayerState.dataLayer.length,
      },

      versionCheck,

      ruleSetSummary,

      geolocation: {
        skipped: shouldSkipLocationInfo,
        reason: shouldSkipLocationInfo
          ? "RuleSet has one item and SkipGeolocation is true."
          : "SkipGeolocation is false, so OneTrust.getGeolocationData() was checked.",
        data: shouldSkipLocationInfo ? null : geolocationData,
        country: shouldSkipLocationInfo ? "" : detectedCountry,
        state: shouldSkipLocationInfo ? "" : detectedState,
      },

      triggerRuleSet,

      consentModes: {
        googleConsentModeEnabled,
        microsoftConsentModeEnabled,
        amazonConsentModeEnabled,
        enabledSdkDetails,
      },

      googleConsentModeAudit: {
        optanonAlertBoxClosedExists,
        gtagDetectedBeforeConsent,
        gtagDetected,
        collectionCallsDetected,
        collectionCallsBeforeConsent,
        collectionCallUrls: googleAnalyticsCollectionCalls.map((call) => call.url),

        hasGtagFunction: gtagAndDataLayerState.hasGtagFunction,
        hasDataLayer: gtagAndDataLayerState.hasDataLayer,

        inferredMode: gcmMode.inferredMode,
        inferredModeMessage: gcmMode.message,

        cmpTemplateTagDetected,
        cmpBannerSetupMethod,
        cmpTemplateTagUrl: cmpTemplateTagDetected ? otSdkStubPrimaryUrl : "",

        gcmDefaultsFound: gcmDefaults.gcmDefaultsFound,
        gcmDefaultEntries: gcmDefaults.gcmDefaultEntries,

        gaCollectionCallsFound,
        gaCollectionCallCount: googleAnalyticsCollectionCalls.length,

        gcsParameterFound: gcsValues.length > 0,
        gcsValues: [...new Set(gcsValues)],

        gaCollectionCallsWithoutGcsCount:
          gaCollectionCallsWithoutGcs.length,

        gaCollectionCallsWithoutGcs:
          gaCollectionCallsWithoutGcs.map((call) => call.url),

        consentModel,

        defaultValidationStatus: gcsValidation.status,
        defaultValidationMessage: gcsValidation.message,

        location: {
          country: detectedCountry,
          state: detectedState,
        },

        triggerRuleSet: {
          matched: triggerRuleSet.matched,
          matchedRuleIndex: triggerRuleSet.matchedRuleIndex,
          Name: triggerRuleSet.Name,
          TemplateName: triggerRuleSet.TemplateName,
          Type: triggerRuleSet.Type,
          GCEnable: triggerRuleSet.GCEnable,
          IsGPPEnabled: triggerRuleSet.IsGPPEnabled,
        },
      },
    };
  } finally {
    if (context) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
  }
}

export default runCheck;
