function extractCveId(title = "") {
  const match = title.match(/CVE-\d{4}-\d+/i);
  return match ? match[0].toUpperCase() : "";
}

function extractPackageFromTitle(title = "") {
  const parts = title.trim().split(/\s+/);
  if (parts.length >= 2 && parts[0].toUpperCase().startsWith("CVE-")) {
    return parts[1];
  }
  return "";
}

function extractInstalledVersion(title = "") {
  const parts = title.trim().split(/\s+/);
  if (parts.length >= 3 && parts[0].toUpperCase().startsWith("CVE-")) {
    return parts[2];
  }
  return "";
}

function extractFixedVersion(description = "") {
  const match = description.match(/\*\*Fixed version:\*\*\s*([^\n]+)/i);
  return match ? match[1].trim() : "";
}

function chunkArray(array, size) {
  const chunks = [];

  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }

  return chunks;
}

function normalizeFinding(f, epssMap, kevMap) {
  const scanner = (f.scanner || "").toLowerCase();

  const isTrivy =
    scanner.includes("trivy") ||
    (f.title || "").toUpperCase().startsWith("CVE-");

  const isZap = scanner.includes("zap");

  if (isTrivy) {
    const cveId = extractCveId(f.title);
    const epss = epssMap.get(cveId) || {};
    const kev = kevMap.get(cveId) || {};

    return {
      finding_id: f.id,
      scanner_type: "trivy",
      vulnerability_type: "dependency_cve",

      title: f.title,
      severity: f.severity,
      description_summary: (f.description || "")
        .split("\n")
        .slice(0, 3)
        .join(" "),

      cve_id: cveId,
      package_name: extractPackageFromTitle(f.title),
      installed_version: extractInstalledVersion(f.title),
      fixed_version: extractFixedVersion(f.description || ""),

      epss_score: epss.epss_score || 0,
      epss_percentile: epss.epss_percentile || 0,
      is_kev: kev.is_kev || false,
      kev_due_date: kev.kev_due_date || "",
      kev_vulnerability_name: kev.kev_vulnerability_name || "",
    };
  }

  if (isZap) {
    return {
      finding_id: f.id,
      scanner_type: "zap",
      vulnerability_type: "web_vulnerability",

      title: f.title,
      severity: f.severity,
      description_summary: (f.description || "").slice(0, 200),

      url: f.url || "",
      method: f.method || "",
      parameter: f.parameter || "",
      attack: f.attack || "",
      evidence: f.evidence || "",
      cwe: f.cwe || "",
      plugin_id: f.plugin_id || "",
    };
  }

  return {
    finding_id: f.id,
    scanner_type: "unknown",
    vulnerability_type: "unknown",
    title: f.title,
    severity: f.severity,
    description: f.description || "",
  };
}

module.exports = {
  extractCveId,
  extractPackageFromTitle,
  extractInstalledVersion,
  extractFixedVersion,
  chunkArray,
  normalizeFinding,
};
