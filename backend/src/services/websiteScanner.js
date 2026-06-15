const axios = require('axios');
const cheerio = require('cheerio');

// Security headers we check for, with weight (impact on risk score) and descriptions
const SECURITY_HEADERS = {
  'content-security-policy': {
    weight: 20,
    name: 'Content-Security-Policy',
    description: 'Prevents XSS by controlling which resources can be loaded.',
  },
  'strict-transport-security': {
    weight: 15,
    name: 'Strict-Transport-Security (HSTS)',
    description: 'Forces browsers to use HTTPS, preventing downgrade attacks.',
  },
  'x-frame-options': {
    weight: 10,
    name: 'X-Frame-Options',
    description: 'Prevents clickjacking by controlling iframe embedding.',
  },
  'x-content-type-options': {
    weight: 10,
    name: 'X-Content-Type-Options',
    description: 'Prevents MIME-sniffing attacks.',
  },
  'referrer-policy': {
    weight: 5,
    name: 'Referrer-Policy',
    description: 'Controls how much referrer information is leaked on navigation.',
  },
  'permissions-policy': {
    weight: 5,
    name: 'Permissions-Policy',
    description: 'Restricts use of browser features like camera, mic, geolocation.',
  },
};

/**
 * Fetch a URL and return response headers + HTML body.
 */
async function fetchTarget(url) {
  const normalizedUrl = url.startsWith('http') ? url : `https://${url}`;
  const response = await axios.get(normalizedUrl, {
    timeout: 10000,
    maxRedirects: 5,
    validateStatus: () => true, // accept any status code, we just want headers/body
    headers: {
      'User-Agent': 'VulnVision-AI-Scanner/1.0 (Security Audit Tool)',
    },
  });
  return {
    finalUrl: response.request?.res?.responseUrl || normalizedUrl,
    status: response.status,
    headers: response.headers,
    body: typeof response.data === 'string' ? response.data : '',
  };
}

/**
 * Check response headers against our security header checklist.
 */
function analyzeHeaders(headers) {
  const lowerHeaders = {};
  Object.keys(headers).forEach((k) => {
    lowerHeaders[k.toLowerCase()] = headers[k];
  });

  const findings = [];
  let missingWeight = 0;

  Object.entries(SECURITY_HEADERS).forEach(([key, meta]) => {
    const present = lowerHeaders[key] !== undefined;
    if (!present) {
      missingWeight += meta.weight;
      findings.push({
        type: 'missing_header',
        severity: meta.weight >= 15 ? 'High' : meta.weight >= 10 ? 'Medium' : 'Low',
        title: `Missing ${meta.name} header`,
        description: meta.description,
        weight: meta.weight,
      });
    }
  });

  // Check for header info disclosure (Server / X-Powered-By)
  if (lowerHeaders['server']) {
    findings.push({
      type: 'info_disclosure',
      severity: 'Low',
      title: `Server header reveals: ${lowerHeaders['server']}`,
      description: 'Revealing server software/version can help attackers target known exploits.',
      weight: 3,
    });
    missingWeight += 3;
  }

  if (lowerHeaders['x-powered-by']) {
    findings.push({
      type: 'info_disclosure',
      severity: 'Low',
      title: `X-Powered-By header reveals: ${lowerHeaders['x-powered-by']}`,
      description: 'Revealing the underlying framework can help attackers target known exploits.',
      weight: 3,
    });
    missingWeight += 3;
  }

  return { findings, missingWeight };
}

/**
 * Very lightweight XSS surface detection — looks for forms/inputs without
 * obvious sanitization markers, and reflected-parameter style patterns.
 * This is a HEURISTIC, not a real exploit scanner.
 */
function analyzeXssSurface(html, finalUrl) {
  const findings = [];
  if (!html) return findings;

  const $ = cheerio.load(html);

  // Find forms with input fields that POST/GET without visible CSRF token
  $('form').each((i, el) => {
    const action = $(el).attr('action') || finalUrl;
    const method = ($(el).attr('method') || 'GET').toUpperCase();
    const inputs = $(el).find('input, textarea');
    const hasCsrfToken = inputs.toArray().some((inp) => {
      const name = ($(inp).attr('name') || '').toLowerCase();
      return name.includes('csrf') || name.includes('token') || name.includes('_token');
    });

    if (inputs.length > 0) {
      findings.push({
        type: 'form_input_surface',
        severity: hasCsrfToken ? 'Low' : 'Medium',
        title: `Form #${i + 1} (${method} to ${action}) accepts ${inputs.length} input field(s)${
          hasCsrfToken ? '' : ' with no CSRF token detected'
        }`,
        description:
          'Forms that accept user input and reflect it back without proper encoding/sanitization can be vectors for XSS or CSRF.',
        weight: hasCsrfToken ? 2 : 5,
      });
    }
  });

  // Detect inline event handlers / inline scripts (raises XSS risk if user input reaches them)
  const inlineScripts = $('script:not([src])').length;
  if (inlineScripts > 0) {
    findings.push({
      type: 'inline_script',
      severity: 'Low',
      title: `${inlineScripts} inline <script> block(s) detected`,
      description:
        'Inline scripts make it harder to enforce a strict Content-Security-Policy and can increase XSS blast radius.',
      weight: 3,
    });
  }

  // Detect URL query params being reflected in HTML (potential reflected XSS)
  try {
    const url = new URL(finalUrl);
    url.searchParams.forEach((value, key) => {
      if (value.length > 2 && html.includes(value)) {
        findings.push({
          type: 'reflected_param',
          severity: 'Medium',
          title: `Query parameter "${key}" appears reflected in page content`,
          description:
            'If user-controllable input is rendered back into the page without encoding, this can lead to reflected XSS.',
          weight: 8,
        });
      }
    });
  } catch (e) {
    // ignore URL parse errors
  }

  return findings;
}

/**
 * Main entry point: scan a website for header misconfigurations and XSS surface.
 */
async function scanWebsite(url) {
  const target = await fetchTarget(url);
  const { findings: headerFindings, missingWeight: headerWeight } = analyzeHeaders(target.headers);
  const xssFindings = analyzeXssSurface(target.body, target.finalUrl);
  const xssWeight = xssFindings.reduce((sum, f) => sum + f.weight, 0);

  return {
    target: target.finalUrl,
    statusCode: target.status,
    findings: [...headerFindings, ...xssFindings],
    rawHeaders: target.headers,
    weightTotal: headerWeight + xssWeight,
  };
}

module.exports = { scanWebsite, analyzeHeaders, analyzeXssSurface, SECURITY_HEADERS };
