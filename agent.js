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
        checkedUrl: targetUrl
