const express = require('express');
const router = express.Router();

const { scanWebsite } = require('../services/websiteScanner');
const { scanRepo } = require('../services/githubScanner');
const { calculateRiskScore } = require('../utils/riskScore');
const { explainAndFix, generateAttackSimulation, generateExecutiveSummary } = require('../services/aiService');
const { generateReport } = require('../services/reportService');

/**
 * In-memory store for the last scan result so /report can reuse it
 * without re-scanning. For a hackathon demo this is sufficient;
 * swap for Redis/DB for production.
 */
const lastScans = new Map(); // key: scanId, value: scan result

/**
 * POST /api/scan
 * body: { websiteUrl?: string, repoUrl?: string }
 * Runs website + repo scans (whichever are provided), gets AI explanations/fixes,
 * computes risk score, and generates an attack simulation.
 */
router.post('/scan', async (req, res) => {
  const { websiteUrl, repoUrl } = req.body;

  if (!websiteUrl && !repoUrl) {
    return res.status(400).json({ error: 'Provide at least one of websiteUrl or repoUrl' });
  }

  try {
    const result = {
      target: websiteUrl || repoUrl,
      scanDate: new Date().toISOString(),
      website: null,
      repo: null,
    };

    let websiteWeight = 0;
    let repoWeight = 0;

    // Run scans in parallel where possible
    const tasks = [];

    if (websiteUrl) {
      tasks.push(
        scanWebsite(websiteUrl)
          .then((r) => {
            result.website = r;
            websiteWeight = r.weightTotal;
          })
          .catch((err) => {
            result.website = { error: err.message, findings: [], weightTotal: 0 };
          })
      );
    }

    if (repoUrl) {
      tasks.push(
        scanRepo(repoUrl)
          .then((r) => {
            result.repo = r;
            repoWeight = r.weightTotal;
          })
          .catch((err) => {
            result.repo = { error: err.message, findings: [], weightTotal: 0 };
          })
      );
    }

    await Promise.all(tasks);

    // Risk score
    const risk = calculateRiskScore(websiteWeight, repoWeight);
    result.riskScore = risk.score;
    result.riskBand = risk.band;

    // AI explanations + fixes (only if API key configured)
    const allFindings = [...(result.website?.findings || []), ...(result.repo?.findings || [])];

    if (process.env.OPENROUTER_API_KEY && allFindings.length > 0) {
      try {
        const explanations = await explainAndFix(allFindings);
        // Merge explanations back into findings, splitting by source
        let cursor = 0;
        if (result.website?.findings) {
          result.website.findings = result.website.findings.map((f) => ({
            ...f,
            ...(explanations[cursor++] || {}),
          }));
        }
        if (result.repo?.findings) {
          result.repo.findings = result.repo.findings.map((f) => ({
            ...f,
            ...(explanations[cursor++] || {}),
          }));
        }
      } catch (err) {
        console.error('AI explanation error:', err.message);
      }

      // Attack simulation
      try {
        result.attackSimulation = await generateAttackSimulation(allFindings, result.target);
      } catch (err) {
        console.error('Attack simulation error:', err.message);
        result.attackSimulation = { narrative: 'Attack simulation unavailable.', mermaid: null };
      }

      // Executive summary
      try {
        result.executiveSummary = await generateExecutiveSummary({
          target: result.target,
          riskScore: result.riskScore,
          riskBand: result.riskBand,
          websiteFindings: result.website?.findings,
          repoFindings: result.repo?.findings,
        });
      } catch (err) {
        console.error('Executive summary error:', err.message);
      }
    } else if (!process.env.OPENROUTER_API_KEY) {
      result.aiDisabled = true;
      result.aiDisabledReason = 'OPENROUTER_API_KEY not configured — AI features (explanations, fixes, attack simulation) are disabled.';
    }

    // Store for report generation
    const scanId = `scan_${Date.now()}`;
    lastScans.set(scanId, result);
    result.scanId = scanId;

    res.json(result);
  } catch (err) {
    console.error('Scan error:', err);
    res.status(500).json({ error: err.message || 'Internal scan error' });
  }
});

/**
 * GET /api/report/:scanId
 * Generates and streams a PDF report for a previously run scan.
 */
router.get('/report/:scanId', async (req, res) => {
  const result = lastScans.get(req.params.scanId);
  if (!result) {
    return res.status(404).json({ error: 'Scan result not found. Run a scan first.' });
  }

  try {
    const pdfBuffer = await generateReport({
      target: result.target,
      scanDate: new Date(result.scanDate).toLocaleString(),
      riskScore: result.riskScore,
      riskBand: result.riskBand,
      executiveSummary: result.executiveSummary,
      websiteFindings: result.website?.findings || [],
      repoFindings: result.repo?.findings || [],
      attackSimulation: result.attackSimulation,
    });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="vulnvision-report-${req.params.scanId}.pdf"`);
    res.send(pdfBuffer);
  } catch (err) {
    console.error('Report generation error:', err);
    res.status(500).json({ error: err.message || 'Failed to generate report' });
  }
});

module.exports = router;
