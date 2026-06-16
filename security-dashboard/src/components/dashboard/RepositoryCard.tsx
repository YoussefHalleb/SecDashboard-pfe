import type { Repository } from "../../types/dashboard";

interface RepositoryCardProps {
  repo: Repository;
  onViewDetails: (repo: Repository) => void;
  onDelete: (repoId: number) => void;
}

export default function RepositoryCard({
  repo,
  onViewDetails,
  onDelete,
}: RepositoryCardProps) {
  const counts = {
    Critical: repo.vulnerabilities.filter((v) => v.severity === "Critical")
      .length,
    High: repo.vulnerabilities.filter((v) => v.severity === "High").length,
    Medium: repo.vulnerabilities.filter((v) => v.severity === "Medium").length,
    Low: repo.vulnerabilities.filter((v) => v.severity === "Low").length,
  };

  const trivy = repo.vulnerabilities.filter((v) => v.scanner === "Trivy Scan");
  const zap = repo.vulnerabilities.filter((v) => v.scanner === "ZAP Scan");

  const total = repo.vulnerabilities.length;

  const riskScore =
    counts.Critical * 10 + counts.High * 5 + counts.Medium * 2 + counts.Low;

  const riskColor =
    counts.Critical > 0
      ? "text-red-400"
      : counts.High > 0
        ? "text-orange-400"
        : "text-emerald-400";

  return (
    <div className="bg-slate-900/95 border border-slate-800 rounded-2xl overflow-hidden hover:border-slate-700 transition group shadow-xl">
      <div className="h-[3px] bg-gradient-to-r from-emerald-500 via-blue-500 to-violet-500" />

      <div className="p-6">
        <div className="flex items-start justify-between mb-5">
          <div>
            <h3 className="font-bold text-white text-lg leading-tight">
              {repo.name}
            </h3>
            <p className="text-slate-500 text-xs mt-0.5">
              {total} vulnerabilities total
            </p>
          </div>

          <div className="text-right">
            <div className={`text-2xl font-black font-mono ${riskColor}`}>
              {riskScore}
            </div>
            <div className="text-slate-600 text-xs">risk score</div>
          </div>
        </div>

        <div className="flex gap-2 mb-5">
          {[
            {
              label: "Critical",
              count: counts.Critical,
              cls: "bg-red-500/10 text-red-400 border-red-500/20",
            },
            {
              label: "High",
              count: counts.High,
              cls: "bg-orange-500/10 text-orange-400 border-orange-500/20",
            },
            {
              label: "Medium",
              count: counts.Medium,
              cls: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
            },
            {
              label: "Low",
              count: counts.Low,
              cls: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
            },
          ].map(({ label, count, cls }) => (
            <div
              key={label}
              className={`flex-1 border rounded-xl p-2 text-center ${cls}`}
            >
              <div className="font-bold text-base leading-none">{count}</div>
              <div className="text-xs mt-0.5 opacity-70">{label}</div>
            </div>
          ))}
        </div>

        <div className="bg-slate-800/40 rounded-xl overflow-hidden mb-5 border border-slate-700/50">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-700/50">
                <th className="px-3 py-2 text-left text-slate-500 font-semibold">
                  Scanner
                </th>
                <th className="px-3 py-2 text-center text-red-400/70">C</th>
                <th className="px-3 py-2 text-center text-orange-400/70">H</th>
                <th className="px-3 py-2 text-center text-yellow-400/70">M</th>
                <th className="px-3 py-2 text-center text-emerald-400/70">L</th>
              </tr>
            </thead>

            <tbody>
              {[
                { label: "🛡️ Trivy", data: trivy },
                { label: "⚡ ZAP", data: zap },
              ].map(({ label, data }) => (
                <tr key={label} className="border-t border-slate-700/30">
                  <td className="px-3 py-2 text-slate-300 font-medium">
                    {label}
                  </td>

                  {["Critical", "High", "Medium", "Low"].map((sev) => (
                    <td
                      key={sev}
                      className="px-3 py-2 text-center text-slate-400 font-mono"
                    >
                      {data.filter((v) => v.severity === sev).length}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="flex gap-2">
          <button
            onClick={() => onViewDetails(repo)}
            className="flex-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-slate-300 hover:text-white text-sm font-semibold py-2.5 rounded-xl transition"
          >
            View Details →
          </button>

          <button
            onClick={() => onDelete(repo.id)}
            className="bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 text-sm font-semibold px-3 py-2.5 rounded-xl transition"
          >
            🗑️
          </button>
        </div>
      </div>
    </div>
  );
}
