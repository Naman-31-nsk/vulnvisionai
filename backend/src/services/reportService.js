const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');

const PAGE_WIDTH = 612; // US Letter
const PAGE_HEIGHT = 792;
const MARGIN = 50;

const SEVERITY_COLORS = {
  Critical: rgb(0.86, 0.15, 0.15),
  High: rgb(0.92, 0.35, 0.05),
  Medium: rgb(0.79, 0.55, 0.02),
  Low: rgb(0.09, 0.64, 0.29),
};

const BAND_COLORS = {
  Critical: rgb(0.86, 0.15, 0.15),
  High: rgb(0.92, 0.35, 0.05),
  Medium: rgb(0.79, 0.55, 0.02),
  Low: rgb(0.09, 0.64, 0.29),
};

/**
 * Word-wrap text to fit within a max width given a font and size.
 */
function wrapText(text, font, fontSize, maxWidth) {
  const words = (text || '').split(/\s+/);
  const lines = [];
  let current = '';

  for (const word of words) {
    const test = current ? `${current} ${word}` : word;
    if (font.widthOfTextAtSize(test, fontSize) > maxWidth && current) {
      lines.push(current);
      current = word;
    } else {
      current = test;
    }
  }
  if (current) lines.push(current);
  return lines;
}

/**
 * Generate the executive PDF report. Returns a Buffer.
 *
 * data = {
 *   target, scanDate, riskScore, riskBand,
 *   executiveSummary,
 *   websiteFindings: [{title, severity, description, plain_english, fix, impact}],
 *   repoFindings: [{...}],
 *   attackSimulation: { narrative }
 * }
 */
async function generateReport(data) {
  const pdfDoc = await PDFDocument.create();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

  let page = pdfDoc.addPage([PAGE_WIDTH, PAGE_HEIGHT]);
  let y = PAGE_HEIGHT - MARGIN;

  function newPageIfNeeded(minSpace = 60) {
    if (y < MARGIN + minSpace) {
      page = pdfDoc.addPage([PAGE_WIDTH, PAGE_HEIGHT]);
      y = PAGE_HEIGHT - MARGIN;
    }
  }

  function drawText(text, { size = 11, bold = false, color = rgb(0.1, 0.1, 0.1), indent = 0, gap = 4 } = {}) {
    const useFont = bold ? fontBold : font;
    const maxWidth = PAGE_WIDTH - MARGIN * 2 - indent;
    const lines = wrapText(text, useFont, size, maxWidth);
    for (const line of lines) {
      newPageIfNeeded(size + gap);
      page.drawText(line, { x: MARGIN + indent, y, size, font: useFont, color });
      y -= size + gap;
    }
  }

  function drawSpacer(h = 10) {
    y -= h;
  }

  function drawDivider() {
    newPageIfNeeded(20);
    page.drawLine({
      start: { x: MARGIN, y },
      end: { x: PAGE_WIDTH - MARGIN, y },
      thickness: 0.5,
      color: rgb(0.8, 0.8, 0.8),
    });
    drawSpacer(15);
  }

  // ---- Title ----
  drawText('VulnVision AI — Security Audit Report', { size: 22, bold: true, color: rgb(0.06, 0.36, 0.78) });
  drawSpacer(6);
  drawText(`Target: ${data.target}`, { size: 12 });
  drawText(`Scan Date: ${data.scanDate}`, { size: 12 });
  drawSpacer(15);
  drawDivider();

  // ---- Risk Score Box ----
  const bandColor = BAND_COLORS[data.riskBand] || rgb(0.4, 0.4, 0.4);
  drawText('Overall Risk Score', { size: 14, bold: true });
  drawSpacer(4);
  newPageIfNeeded(40);
  page.drawRectangle({
    x: MARGIN,
    y: y - 30,
    width: 120,
    height: 36,
    color: bandColor,
    opacity: 0.15,
    borderColor: bandColor,
    borderWidth: 1,
  });
  page.drawText(`${data.riskScore}/100`, { x: MARGIN + 12, y: y - 10, size: 18, font: fontBold, color: bandColor });
  page.drawText(data.riskBand, { x: MARGIN + 12, y: y - 26, size: 11, font, color: bandColor });
  y -= 50;
  drawSpacer(10);
  drawDivider();

  // ---- Executive Summary ----
  drawText('Executive Summary', { size: 14, bold: true });
  drawSpacer(4);
  drawText(data.executiveSummary || 'No summary available.', { size: 11 });
  drawSpacer(10);
  drawDivider();

  // ---- Website Findings ----
  drawText('Website Findings', { size: 14, bold: true });
  drawSpacer(4);
  if (!data.websiteFindings || data.websiteFindings.length === 0) {
    drawText('No website findings detected.', { size: 11, color: rgb(0.4, 0.4, 0.4) });
  } else {
    data.websiteFindings.forEach((f, idx) => {
      newPageIfNeeded(80);
      const sevColor = SEVERITY_COLORS[f.severity] || rgb(0.4, 0.4, 0.4);
      drawText(`${idx + 1}. ${f.title}`, { size: 12, bold: true });
      drawText(`Severity: ${f.severity}`, { size: 10, color: sevColor, indent: 12 });
      if (f.plain_english) drawText(`What this means: ${f.plain_english}`, { size: 10, indent: 12 });
      if (f.impact) drawText(`Potential impact: ${f.impact}`, { size: 10, indent: 12 });
      if (f.fix) drawText(`Recommended fix: ${f.fix}`, { size: 10, indent: 12, color: rgb(0.06, 0.4, 0.2) });
      drawSpacer(8);
    });
  }
  drawSpacer(10);
  drawDivider();

  // ---- Repository Findings ----
  drawText('Repository Findings', { size: 14, bold: true });
  drawSpacer(4);
  if (!data.repoFindings || data.repoFindings.length === 0) {
    drawText('No repository findings detected.', { size: 11, color: rgb(0.4, 0.4, 0.4) });
  } else {
    data.repoFindings.forEach((f, idx) => {
      newPageIfNeeded(80);
      const sevColor = SEVERITY_COLORS[f.severity] || rgb(0.4, 0.4, 0.4);
      const titleText = f.package ? `${f.package}@${f.version} — ${f.id}` : f.title;
      drawText(`${idx + 1}. ${titleText}`, { size: 12, bold: true });
      drawText(`Severity: ${f.severity}`, { size: 10, color: sevColor, indent: 12 });
      if (f.plain_english) drawText(`What this means: ${f.plain_english}`, { size: 10, indent: 12 });
      if (f.impact) drawText(`Potential impact: ${f.impact}`, { size: 10, indent: 12 });
      if (f.fix) drawText(`Recommended fix: ${f.fix}`, { size: 10, indent: 12, color: rgb(0.06, 0.4, 0.2) });
      drawSpacer(8);
    });
  }
  drawSpacer(10);
  drawDivider();

  // ---- Attack Simulation ----
  drawText('Attack Simulation', { size: 14, bold: true });
  drawSpacer(4);
  drawText(data.attackSimulation?.narrative || 'No attack simulation generated.', { size: 11 });
  drawSpacer(15);

  // ---- Footer ----
  newPageIfNeeded(30);
  drawText('Generated by VulnVision AI — AI-Powered Security Auditor', {
    size: 9,
    color: rgb(0.6, 0.6, 0.6),
  });

  const pdfBytes = await pdfDoc.save();
  return Buffer.from(pdfBytes);
}

module.exports = { generateReport };
