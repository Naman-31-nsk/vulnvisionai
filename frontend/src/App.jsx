import React, { useState } from 'react';
import RiskGauge from './components/RiskGauge.jsx';
import FindingCard from './components/FindingCard.jsx';
import AttackSimulation from './components/AttackSimulation.jsx';

const API_BASE = '/api';

const LOADING_MESSAGES = [
  'Probing security headers...',
  'Crawling for XSS surface area...',
  'Cross-referencing dependencies against OSV...',
  'Asking Claude to explain findings in plain English...',
  'Drafting fix recommendations...',
  'Simulating attack chains...',
];

export default function App() {
  const [websiteUrl, setWebsiteUrl] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingMsgIndex, setLoadingMsgIndex] = useState(0);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [reportLoading, setReportLoading] = useState(false);

  async function handleScan(e) {
    e.preventDefault();
    setError(null);
    setResult(null);

    if (!websiteUrl.trim() && !repoUrl.trim()) {
      setError('Enter at least a website URL or a GitHub repository URL.');
      return;
    }

    setLoading(true);
    setLoadingMsgIndex(0);

    const msgInterval = setInterval(() => {
      setLoadingMsgIndex((i) => (i + 1) % LOADING_MESSAGES.length);
    }, 1800);

    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          websiteUrl: websiteUrl.trim() || undefined,
          repoUrl: repoUrl.trim() || undefined,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Scan failed');
      }
      setResult(data);
    } catch (err) {
      setError(err.message || 'Something went wrong during the scan.');
    } finally {
      clearInterval(msgInterval);
      setLoading(false);
    }
  }

  async function handleDownloadReport() {
    if (!result?.scanId) return;
    setReportLoading(true);
    try {
      const res = await fetch(`${API_BASE}/report/${result.scanId}`);
      if (!res.ok) throw new Error('Failed to generate report');
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnvision-report-${result.scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.message || 'Failed to download report');
    } finally {
      setReportLoading(false);
    }
  }

  const websiteFindings = result?.website?.findings || [];
  const repoFindings = result?.repo?.findings || [];
  const totalFindings = websiteFindings.length + repoFindings.length;

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-title">
          <span className="brand-mark" />
          Vuln<span className="vision">Vision</span> AI
        </div>
        <div className="app-tagline">// security auditor with ai-powered fix recommendations</div>
      </header>

      <form className="input-panel" onSubmit={handleScan}>
        <div className="input-row">
          <div className="field-group">
            <label className="field-label" htmlFor="websiteUrl">Website URL</label>
            <input
              id="websiteUrl"
              className="field-input"
              type="text"
              placeholder="https://example.com"
              value={websiteUrl}
              onChange={(e) => setWebsiteUrl(e.target.value)}
            />
          </div>
          <div className="field-group">
            <label className="field-label" htmlFor="repoUrl">GitHub Repository URL</label>
            <input
              id="repoUrl"
              className="field-input"
              type="text"
              placeholder="https://github.com/owner/repo"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
            />
          </div>
        </div>
        <button className="scan-button" type="submit" disabled={loading}>
          {loading ? 'Scanning...' : 'Run Security Scan'}
        </button>
      </form>

      {error && <div className="error-banner">{error}</div>}

      {loading && (
        <div className="loading-panel">
          <div className="scan-line" />
          <div className="loading-text">{LOADING_MESSAGES[loadingMsgIndex]}</div>
        </div>
      )}

      {result && !loading && (
        <>
          {result.aiDisabled && (
            <div className="info-banner">{result.aiDisabledReason}</div>
          )}

          {result.website?.error && (
            <div className="error-banner">Website scan error: {result.website.error}</div>
          )}
          {result.repo?.error && (
            <div className="error-banner">Repository scan error: {result.repo.error}</div>
          )}

          <div className="report-bar">
            <button className="report-button" onClick={handleDownloadReport} disabled={reportLoading}>
              {reportLoading ? 'Generating PDF...' : 'Download Executive PDF Report'}
            </button>
          </div>

          <div className="results-grid">
            <div className="gauge-card">
              <RiskGauge score={result.riskScore} band={result.riskBand} />
              <div className="gauge-label" style={{ color: severityColor(result.riskBand) }}>
                {result.riskBand} Risk
              </div>
              <div className="gauge-target">{result.target}</div>
              <div className="gauge-meta">{totalFindings} finding{totalFindings !== 1 ? 's' : ''} detected</div>
            </div>

            <div className="summary-card">
              <h3>Executive Summary</h3>
              <p className="summary-text">
                {result.executiveSummary ||
                  'AI-generated summary is currently unavailable.'}
              </p>
              <div className="summary-stats">
                <div className="stat-block">
                  <div className="stat-value">{websiteFindings.length}</div>
                  <div className="stat-label">Website Issues</div>
                </div>
                <div className="stat-block">
                  <div className="stat-value">{repoFindings.length}</div>
                  <div className="stat-label">Repo Issues</div>
                </div>
                <div className="stat-block">
                  <div className="stat-value">
                    {result.repo?.dependenciesChecked ?? '—'}
                  </div>
                  <div className="stat-label">Dependencies Checked</div>
                </div>
              </div>
            </div>
          </div>

          {result.website && (
            <div className="section">
              <div className="section-header">
                <div className="section-title">
                  Website Findings
                  <span className="count-badge">{websiteFindings.length}</span>
                </div>
              </div>
              {websiteFindings.length === 0 ? (
                <div className="empty-state">No website security issues detected.</div>
              ) : (
                websiteFindings.map((f, i) => <FindingCard key={i} finding={f} />)
              )}
            </div>
          )}

          {result.repo && (
            <div className="section">
              <div className="section-header">
                <div className="section-title">
                  Repository Findings
                  <span className="count-badge">{repoFindings.length}</span>
                </div>
              </div>
              {repoFindings.length === 0 ? (
                <div className="empty-state">No vulnerable dependencies detected.</div>
              ) : (
                repoFindings.map((f, i) => <FindingCard key={i} finding={f} />)
              )}
            </div>
          )}

          {result.attackSimulation && (
            <div className="section">
              <div className="section-header">
                <div className="section-title">Attack Simulation</div>
              </div>
              <AttackSimulation simulation={result.attackSimulation} />
            </div>
          )}
        </>
      )}
    </div>
  );
}

function severityColor(band) {
  const colors = {
    Critical: '#ee0f29',
    High: '#c15e0d',
    Medium: '#cea708',
    Low: '#17e261',
  };
  return colors[band] || '#4ade80';
}
