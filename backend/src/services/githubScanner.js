const axios = require('axios');

const GITHUB_API = 'https://api.github.com';
const OSV_API = 'https://api.osv.dev/v1/querybatch';

function githubHeaders() {
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'VulnVision-AI-Scanner',
  };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  return headers;
}

/**
 * Parse a GitHub URL like https://github.com/owner/repo into { owner, repo }
 */
function parseGithubUrl(repoUrl) {
  const cleaned = repoUrl.replace(/\.git$/, '').replace(/\/$/, '');
  const match = cleaned.match(/github\.com[/:]([^/]+)\/([^/]+)/i);
  if (!match) throw new Error('Invalid GitHub repository URL');
  return { owner: match[1], repo: match[2] };
}

/**
 * Fetch a file's raw content from a GitHub repo (default branch).
 */
async function fetchRepoFile(owner, repo, path) {
  try {
    const res = await axios.get(
      `${GITHUB_API}/repos/${owner}/${repo}/contents/${path}`,
      { headers: githubHeaders(), validateStatus: () => true }
    );
    if (res.status !== 200 || !res.data.content) return null;
    return Buffer.from(res.data.content, 'base64').toString('utf-8');
  } catch (e) {
    return null;
  }
}

/**
 * Parse package.json dependencies into OSV query format (npm ecosystem).
 */
function parsePackageJson(content) {
  const pkg = JSON.parse(content);
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  return Object.entries(deps).map(([name, versionRange]) => ({
    name,
    ecosystem: 'npm',
    // strip ^, ~, >=, etc to get a concrete version for OSV lookup
    version: versionRange.replace(/^[^\d]*/, ''),
  }));
}

/**
 * Parse requirements.txt dependencies into OSV query format (PyPI ecosystem).
 */
function parseRequirementsTxt(content) {
  const lines = content.split('\n');
  const deps = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const match = trimmed.match(/^([A-Za-z0-9._-]+)\s*(==|>=|~=)\s*([A-Za-z0-9._-]+)/);
    if (match) {
      deps.push({ name: match[1], ecosystem: 'PyPI', version: match[3] });
    }
  }
  return deps;
}

/**
 * Query OSV.dev for known vulnerabilities affecting a list of packages.
 */
async function queryOsv(deps) {
  if (deps.length === 0) return [];

  const queries = deps.map((d) => ({
    package: { name: d.name, ecosystem: d.ecosystem },
    version: d.version,
  }));

  const res = await axios.post(OSV_API, { queries }, { timeout: 15000, validateStatus: () => true });
  if (res.status !== 200) return [];

  const results = res.data.results || [];
  const findings = [];

  results.forEach((result, i) => {
    const dep = deps[i];
    const vulns = result.vulns || [];
    vulns.forEach((v) => {
      findings.push({
        type: 'vulnerable_dependency',
        package: dep.name,
        version: dep.version,
        ecosystem: dep.ecosystem,
        id: v.id,
        summary: v.summary || v.details?.slice(0, 200) || 'No summary available',
        severity: estimateSeverity(v),
      });
    });
  });

  return findings;
}

/**
 * Best-effort severity estimation from OSV vulnerability data.
 */
function estimateSeverity(vuln) {
  if (vuln.severity && vuln.severity.length > 0) {
    const score = parseFloat(vuln.severity[0].score) || 0;
    if (score >= 9) return 'Critical';
    if (score >= 7) return 'High';
    if (score >= 4) return 'Medium';
    return 'Low';
  }
  // Fallback: use database-specific severity if available
  const dbSeverity = vuln.database_specific?.severity;
  if (dbSeverity) return dbSeverity.charAt(0) + dbSeverity.slice(1).toLowerCase();
  return 'Medium';
}

const SEVERITY_WEIGHT = { Critical: 25, High: 15, Medium: 8, Low: 3 };

/**
 * Main entry: scan a GitHub repo for outdated/vulnerable dependencies.
 */
async function scanRepo(repoUrl) {
  const { owner, repo } = parseGithubUrl(repoUrl);

  // Verify repo exists
  const repoMeta = await axios.get(`${GITHUB_API}/repos/${owner}/${repo}`, {
    headers: githubHeaders(),
    validateStatus: () => true,
  });
  if (repoMeta.status === 404) {
    throw new Error('Repository not found (it may be private or misspelled)');
  }
  if (repoMeta.status === 403) {
    throw new Error('GitHub API rate limit exceeded. Add a GITHUB_TOKEN to increase limits.');
  }

  let allDeps = [];
  const filesFound = [];

  const packageJson = await fetchRepoFile(owner, repo, 'package.json');
  if (packageJson) {
    filesFound.push('package.json');
    try {
      allDeps = allDeps.concat(parsePackageJson(packageJson));
    } catch (e) {
      // malformed json, skip
    }
  }

  const requirementsTxt = await fetchRepoFile(owner, repo, 'requirements.txt');
  if (requirementsTxt) {
    filesFound.push('requirements.txt');
    allDeps = allDeps.concat(parseRequirementsTxt(requirementsTxt));
  }

  const vulnFindings = await queryOsv(allDeps);
  const weightTotal = vulnFindings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] || 5), 0);

  return {
    repo: `${owner}/${repo}`,
    defaultBranch: repoMeta.data.default_branch,
    filesScanned: filesFound,
    dependenciesChecked: allDeps.length,
    findings: vulnFindings,
    weightTotal,
  };
}

module.exports = { scanRepo, parseGithubUrl };
