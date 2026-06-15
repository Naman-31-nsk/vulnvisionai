const axios = require('axios');

const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';
const MODEL = process.env.OPENROUTER_MODEL || 'meta-llama/llama-3.1-8b-instruct:free';

/**
 * Call the OpenRouter chat completions endpoint.
 * Returns the assistant's text content as a string.
 */
async function callOpenRouter(systemPrompt, userMessage, maxTokens = 1500) {
  const response = await axios.post(
    OPENROUTER_URL,
    {
      model: MODEL,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userMessage },
      ],
      max_tokens: maxTokens,
      temperature: 0.3,
    },
    {
      headers: {
        Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
        'Content-Type': 'application/json',
        // Optional but recommended by OpenRouter for analytics/rate-limit tracking
        'HTTP-Referer': 'https://vulnvision.local',
        'X-Title': 'VulnVision AI',
      },
      timeout: 60000,
      validateStatus: () => true,
    }
  );

  if (response.status !== 200) {
    const errMsg = response.data?.error?.message || JSON.stringify(response.data);
    throw new Error(`OpenRouter API error (${response.status}): ${errMsg}`);
  }

  const choice = response.data?.choices?.[0];
  return choice?.message?.content || '';
}

/**
 * Strip markdown code fences if the model wraps JSON in ```json ... ```
 */
function stripFences(text) {
  return text.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim();
}

/**
 * Extract a JSON array/object from text even if the model adds
 * stray commentary before/after (common with smaller free models).
 */
function extractJson(text) {
  const cleaned = stripFences(text);
  try {
    return JSON.parse(cleaned);
  } catch (e) {
    // Try to find the first { or [ and the matching last } or ]
    const firstObj = cleaned.indexOf('{');
    const firstArr = cleaned.indexOf('[');
    let start = -1;
    let endChar = '}';
    if (firstArr !== -1 && (firstObj === -1 || firstArr < firstObj)) {
      start = firstArr;
      endChar = ']';
    } else if (firstObj !== -1) {
      start = firstObj;
      endChar = '}';
    }
    if (start === -1) throw e;
    const end = cleaned.lastIndexOf(endChar);
    if (end === -1) throw e;
    return JSON.parse(cleaned.slice(start, end + 1));
  }
}

/**
 * Given a list of raw findings (from website + repo scans), ask the model to:
 * - explain each in plain English
 * - generate a concrete fix (code/config snippet)
 * - note the impact
 *
 * Returns an array aligned with the input findings.
 */
async function explainAndFix(findings) {
  if (!findings || findings.length === 0) return [];

  const systemPrompt = `You are a security analyst assistant. You will be given a JSON array of raw vulnerability scan findings.
For EACH finding, return an object with:
- "plain_english": a 1-2 sentence explanation a non-technical person would understand
- "fix": a concrete, actionable fix. If it's a code/config fix, include a short code snippet (e.g. an Express middleware line, an nginx directive, or a package.json version bump).
- "impact": 1 sentence on what an attacker could realistically do if this is left unfixed

Respond ONLY with a valid JSON array of objects in the same order as the input, with no preamble, no markdown fences, and no extra commentary.`;

  const userMessage = `Findings:\n${JSON.stringify(findings, null, 2)}`;

  const text = await callOpenRouter(systemPrompt, userMessage, 4000);

  try {
    const parsed = extractJson(text);
    if (Array.isArray(parsed) && parsed.length === findings.length) return parsed;
    // If the model returned a differently-shaped array, pad/truncate to match
    if (Array.isArray(parsed)) {
      const result = [];
      for (let i = 0; i < findings.length; i++) {
        result.push(
          parsed[i] || {
            plain_english: 'Explanation unavailable for this finding.',
            fix: 'See finding details for manual remediation guidance.',
            impact: 'Unknown',
          }
        );
      }
      return result;
    }
    throw new Error('Unexpected response shape');
  } catch (e) {
    console.error('explainAndFix JSON parse error:', e.message);
    return findings.map(() => ({
      plain_english: 'Could not generate explanation (AI parsing error).',
      fix: 'See finding details for manual remediation guidance.',
      impact: 'Unknown',
    }));
  }
}

/**
 * Generate an attack simulation narrative + Mermaid sequence diagram
 * based on the top findings.
 */
async function generateAttackSimulation(findings, targetLabel) {
  if (!findings || findings.length === 0) {
    return {
      narrative: 'No significant findings were detected, so no attack simulation was generated.',
      mermaid: null,
    };
  }

  // Use top 3 highest-severity findings for the simulation
  const severityOrder = { Critical: 4, High: 3, Medium: 2, Low: 1 };
  const topFindings = [...findings]
    .sort((a, b) => (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0))
    .slice(0, 3);

  const systemPrompt = `You are a security analyst creating an educational attack simulation for an executive report.
Given a target name and a list of top vulnerability findings, produce:
1. "narrative": A 3-5 sentence story describing how an attacker could chain these issues to compromise the target. Keep it realistic but non-actionable (no exact exploit payloads or working code).
2. "mermaid": A valid Mermaid.js "sequenceDiagram" definition (as a string) showing the attack flow between Attacker, Target System, and any relevant components (e.g. Browser, Server, Database). Keep it to 5-8 steps.

Respond ONLY with a valid JSON object: {"narrative": "...", "mermaid": "..."}. No markdown fences, no extra commentary.`;

  const userMessage = `Target: ${targetLabel}\nTop findings:\n${JSON.stringify(topFindings, null, 2)}`;

  const text = await callOpenRouter(systemPrompt, userMessage, 1500);

  try {
    const parsed = extractJson(text);
    if (parsed && typeof parsed.narrative === 'string') return parsed;
    throw new Error('Unexpected response shape');
  } catch (e) {
    console.error('generateAttackSimulation JSON parse error:', e.message);
    return {
      narrative:
        'An attacker could exploit the combination of missing security headers and vulnerable dependencies to compromise this target.',
      mermaid: null,
    };
  }
}

/**
 * Generate an executive summary paragraph for the PDF report.
 */
async function generateExecutiveSummary({ target, riskScore, riskBand, websiteFindings, repoFindings }) {
  const systemPrompt = `You are a security analyst writing the executive summary section of a security audit report for a non-technical executive audience.
Write 3-4 sentences summarizing the overall security posture, the risk level, and the top 1-2 priorities to address.
Respond with ONLY the summary text, no headers, no markdown, no preamble like "Here is the summary".`;

  const userMessage = `Target: ${target}
Overall Risk Score: ${riskScore}/100 (${riskBand})
Website findings count: ${websiteFindings?.length || 0}
Repository findings count: ${repoFindings?.length || 0}
Top website findings: ${JSON.stringify((websiteFindings || []).slice(0, 3))}
Top repo findings: ${JSON.stringify((repoFindings || []).slice(0, 3))}`;

  const text = await callOpenRouter(systemPrompt, userMessage, 500);
  return text.trim();
}

module.exports = { explainAndFix, generateAttackSimulation, generateExecutiveSummary };
