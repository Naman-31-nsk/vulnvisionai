/**
 * Calculates an overall risk score (0-100, where 100 = highest risk)
 * based on combined weight from website and repo scan findings.
 *
 * The raw weight total is mapped onto a 0-100 scale using a soft cap,
 * so a handful of critical issues quickly push the score into "Critical".
 */
function calculateRiskScore(websiteWeight = 0, repoWeight = 0) {
  const totalWeight = websiteWeight + repoWeight;

  // Soft-cap mapping: diminishing returns after ~80 points of raw weight
  const score = Math.min(100, Math.round(100 * (1 - Math.exp(-totalWeight / 40))));

  let band;
  if (score >= 75) band = 'Critical';
  else if (score >= 50) band = 'High';
  else if (score >= 25) band = 'Medium';
  else band = 'Low';

  return { score, band, totalWeight };
}

const BAND_COLORS = {
  Critical: '#dc2626',
  High: '#ea580c',
  Medium: '#ca8a04',
  Low: '#16a34a',
};

module.exports = { calculateRiskScore, BAND_COLORS };
