const fs = require("fs");
const cheerio = require("cheerio");

function cleanText(value) {
  return (value || "").replace(/\s+/g, " ").trim();
}

function parseZapHtmlFile(filePath) {
  const html = fs.readFileSync(filePath, "utf-8");
  const $ = cheerio.load(html);

  const findings = [];

  $("table.results").each((_, table) => {
    const rows = $(table).find("tr");

    if (rows.length === 0) return;

    const headerRow = rows.first();
    const headerThs = headerRow.find("th");

    if (headerThs.length < 2) return;

    const severity = cleanText($(headerThs[0]).text());
    const title = cleanText($(headerThs[1]).text());

    const finding = {
      finding_id: null,
      severity,
      title,
      description: "",
      url: "",
      method: "",
      parameter: "",
      attack: "",
      evidence: "",
      instances: 0,
      solution: "",
      reference: "",
      cwe: "",
      plugin_id: "",
      scanner: "OWASP ZAP",
    };

    rows.slice(1).each((_, row) => {
      const tds = $(row).find("td");
      if (tds.length < 2) return;

      const key = cleanText($(tds[0]).text()).toLowerCase();
      const value = cleanText($(tds[1]).text());

      if (key === "description") finding.description = value;
      else if (key === "url") finding.url = value;
      else if (key === "method") finding.method = value;
      else if (key === "parameter") finding.parameter = value;
      else if (key === "attack") finding.attack = value;
      else if (key === "evidence") finding.evidence = value;
      else if (key === "instances") finding.instances = Number(value) || 0;
      else if (key === "solution") finding.solution = value;
      else if (key === "reference") finding.reference = value;
      else if (key === "cwe id") finding.cwe = value;
      else if (key === "plugin id") finding.plugin_id = value;
    });

    findings.push(finding);
  });

  return findings;
}

module.exports = { parseZapHtmlFile };
