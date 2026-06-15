import React from 'react';

/**
 * Renders a single vulnerability finding card, including AI-generated
 * plain-English explanation, impact, and fix (when available).
 */
export default function FindingCard({ finding }) {
  const severity = finding.severity || 'Low';

  // Build a display title depending on whether this is a website or repo finding
  const title = finding.package
    ? `${finding.package}@${finding.version} — ${finding.id || 'Unknown CVE'}`
    : finding.title;

  return (
    <div className={`finding-card sev-${severity}`}>
      <div className="finding-header">
        <div className="finding-title">{title}</div>
        <div className={`severity-tag sev-${severity}`}>{severity}</div>
      </div>

      {finding.description && (
        <div className="finding-detail">{finding.description}</div>
      )}

      {finding.summary && (
        <div className="finding-detail">{finding.summary}</div>
      )}

      {finding.plain_english && (
        <div className="finding-detail">
          <span className="label">In plain English: </span>
          {finding.plain_english}
        </div>
      )}

      {finding.impact && (
        <div className="finding-detail">
          <span className="label">Potential impact: </span>
          {finding.impact}
        </div>
      )}

      {finding.fix && <div className="fix-block">{finding.fix}</div>}
    </div>
  );
}
