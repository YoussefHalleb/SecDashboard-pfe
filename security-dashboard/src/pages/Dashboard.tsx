import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, logout } from "../services/api";
import PipelinePage from "./PipelinePage";

interface Recommendation {
  id: string;
  finding_id: number;
  content: string;
  status: RecommendationStatus;
  title?: string;
  cvss_score?: number;
  cvss_vector?: string;
  ai_risk_score?: number;
  confidence?: number;
  false_positive_likelihood?: string;
  priority?: string;
  attack_complexity?: string;
  privileges_required?: string;
  user_interaction?: string;
  owasp_category?: string;
  code_fix_example?: string;
}
interface Vulnerability {
  id: number;
  title: string;
  severity: string;
  component_name: string;
  scanner: string;
  description?: string;
}
interface Repository {
  id: number;
  name: string;
  vulnerabilities: Vulnerability[];
}

type RecommendationStatus = "proposed" | "approved" | "rejected";

export default function Dashboard() {
  const [selectedRepo, setSelectedRepo] = useState<Repository | null>(null);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [loadingAI, setLoadingAI] = useState(false);
  const [aiMessage, setAiMessage] = useState<string>("");
  const [aiSource, setAiSource] = useState<"" | "generated" | "database">("");
  const [perfResults, setPerfResults] = useState<any[]>([]);
  const [loadingPerf, setLoadingPerf] = useState(false);
  const handleLogout = async () => {
    try {
      await logout();
      window.location.reload();
    } catch (e) {
      console.error(e);
    }
  };

  const { data = [], isLoading } = useQuery({
    queryKey: ["repositories"],
    queryFn: async () => {
      const res = await api.get("/api/repositories");
      return res.data;
    },
  });

  const approve = async (recId: string) => {
    try {
      const res = await api.post(`/api/recommendations/${recId}/approve`);
      const updated: Recommendation = res.data;
      setRecommendations((prev) =>
        prev.map((r) =>
          r.finding_id === updated.finding_id
            ? { ...r, status: r.id === updated.id ? "approved" : "proposed" }
            : r,
        ),
      );
    } catch (e) {
      console.error(e);
      alert("Approve failed");
    }
  };

  const loadPerformance = async (repoId: number) => {
    setLoadingPerf(true);
    try {
      const res = await api.get(`/api/performance/${repoId}`);
      setPerfResults(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingPerf(false);
    }
  };

  const reject = async (recId: string) => {
    try {
      const res = await api.post(`/api/recommendations/${recId}/reject`);
      const updated: Recommendation = res.data;
      setRecommendations((prev) =>
        prev.map((r) =>
          r.id === updated.id ? { ...r, status: "rejected" } : r,
        ),
      );
    } catch (e) {
      console.error(e);
      alert("Reject failed");
    }
  };

  const generateAI = async () => {
    if (!selectedRepo || loadingAI) return;
    setLoadingAI(true);
    setAiMessage("");
    setAiSource("");
    try {
      const zapOnly = selectedRepo.vulnerabilities.filter(
        (v) => v.scanner === "ZAP Scan",
      );
      const filtered = zapOnly.filter(
        (v) => v.severity === "High" || v.severity === "Medium",
      );
      const sorted = [...filtered].sort((a, b) => {
        if (a.severity === b.severity) return 0;
        return a.severity === "High" ? -1 : 1;
      });
      const limited = sorted.slice(0, 7);

      if (limited.length === 0) {
        setRecommendations([]);
        setAiMessage("No High or Medium ZAP vulnerabilities found.");
        setLoadingAI(false);
        return;
      }

      const res = await api.post("/api/ai/recommendations", {
        product: selectedRepo.name,
        vulnerabilities: limited.map((v) => ({
          id: v.id,
          title: v.title,
          severity: v.severity,
          scanner: v.scanner,
          description: v.description || "",
        })),
      });

      const items: Recommendation[] = res.data.items || [];
      const source: "generated" | "database" | "" = res.data.source || "";
      setRecommendations(items);
      setAiSource(source);

      if (items.length === 0) setAiMessage("AI returned no items.");
      else if (source === "generated")
        setAiMessage("AI recommendations generated and saved.");
      else if (source === "database")
        setAiMessage("Existing AI recommendations loaded from database.");
    } catch (err) {
      console.error(err);
      setAiMessage("Failed to generate AI recommendations");
    } finally {
      setLoadingAI(false);
    }
  };

  if (isLoading)
    return (
      <div className="flex justify-center items-center min-h-screen bg-slate-950">
        <div className="flex items-center gap-3 text-slate-400">
          <svg
            className="w-5 h-5 animate-spin text-emerald-500"
            viewBox="0 0 24 24"
            fill="none"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8v8z"
            />
          </svg>
          Loading...
        </div>
      </div>
    );

  return (
    <div className="min-h-screen bg-slate-700 text-white">
      {/* Top Nav */}
      <nav className="border-b border-slate-600 bg-slate-700/80 backdrop-blur sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-emerald-500 flex items-center justify-center text-sm font-bold text-slate-900">
              D
            </div>
            <span className="font-bold text-white tracking-tight">
              DevSecOps
            </span>
            <span className="text-slate-600 text-sm hidden sm:block">
              / Dashboard
            </span>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 text-slate-400 hover:text-white text-sm px-3 py-1.5 rounded-lg hover:bg-slate-800 transition"
          >
            <span>⎋</span> Logout
          </button>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {/* Pipeline */}
        <PipelinePage onFinish={() => {}} />

        {/* Section title */}
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-bold text-white">Repositories</h2>
          <span className="bg-slate-800 text-slate-400 text-xs font-mono px-2 py-0.5 rounded-full">
            {data.length}
          </span>
        </div>

        {/* Repository Cards */}
        <div className="grid md:grid-cols-2 gap-6">
          {data.map((repo: Repository) => {
            const counts = {
              Critical: repo.vulnerabilities.filter(
                (v) => v.severity === "Critical",
              ).length,
              High: repo.vulnerabilities.filter((v) => v.severity === "High")
                .length,
              Medium: repo.vulnerabilities.filter(
                (v) => v.severity === "Medium",
              ).length,
              Low: repo.vulnerabilities.filter((v) => v.severity === "Low")
                .length,
            };
            const trivy = repo.vulnerabilities.filter(
              (v) => v.scanner === "Trivy Scan",
            );
            const zap = repo.vulnerabilities.filter(
              (v) => v.scanner === "ZAP Scan",
            );
            const total = repo.vulnerabilities.length;
            const riskScore =
              counts.Critical * 10 +
              counts.High * 5 +
              counts.Medium * 2 +
              counts.Low;
            const riskColor =
              counts.Critical > 0
                ? "text-red-400"
                : counts.High > 0
                  ? "text-orange-400"
                  : "text-emerald-400";

            return (
              <div
                key={repo.id}
                className="bg-slate-900 border border-slate-800 rounded-2xl p-6 hover:border-slate-700 transition group"
              >
                {/* Card Header */}
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
                    <div
                      className={`text-2xl font-black font-mono ${riskColor}`}
                    >
                      {riskScore}
                    </div>
                    <div className="text-slate-600 text-xs">risk score</div>
                  </div>
                </div>

                {/* Severity pills */}
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
                      <div className="font-bold text-base leading-none">
                        {count}
                      </div>
                      <div className="text-xs mt-0.5 opacity-70">{label}</div>
                    </div>
                  ))}
                </div>

                {/* Scanner table */}
                <div className="bg-slate-800/50 rounded-xl overflow-hidden mb-5 border border-slate-700/50">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-slate-700/50">
                        <th className="px-3 py-2 text-left text-slate-500 font-semibold">
                          Scanner
                        </th>
                        <th className="px-3 py-2 text-center text-red-400/70">
                          C
                        </th>
                        <th className="px-3 py-2 text-center text-orange-400/70">
                          H
                        </th>
                        <th className="px-3 py-2 text-center text-yellow-400/70">
                          M
                        </th>
                        <th className="px-3 py-2 text-center text-emerald-400/70">
                          L
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {[
                        { label: "🛡️ Trivy", data: trivy },
                        { label: "⚡ ZAP", data: zap },
                      ].map(({ label, data: scanData }) => (
                        <tr
                          key={label}
                          className="border-t border-slate-700/30"
                        >
                          <td className="px-3 py-2 text-slate-300 font-medium">
                            {label}
                          </td>
                          {["Critical", "High", "Medium", "Low"].map((sev) => (
                            <td
                              key={sev}
                              className="px-3 py-2 text-center text-slate-400 font-mono"
                            >
                              {
                                scanData.filter((v) => v.severity === sev)
                                  .length
                              }
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <button
                  onClick={() => {
                    setSelectedRepo(repo);
                    setRecommendations([]);
                    setAiMessage("");
                    loadPerformance(repo.id);
                  }}
                  className="w-full bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-slate-300 hover:text-white text-sm font-semibold py-2.5 rounded-xl transition"
                >
                  View Details →
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* MODAL */}
      {selectedRepo && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex justify-center items-center z-50 p-4">
          <div className="bg-slate-900 border border-slate-700 w-full max-w-6xl rounded-2xl shadow-2xl flex flex-col max-h-[90vh]">
            {/* Modal Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div>
                <h2 className="font-bold text-white text-lg">
                  {selectedRepo.name}
                </h2>
                <p className="text-slate-500 text-xs">Vulnerability Details</p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() =>
                    window.open(
                      `http://localhost:5000/api/products/${selectedRepo.id}/zap-report`,
                      "_blank",
                    )
                  }
                  className="flex items-center gap-1.5 bg-orange-500/10 border border-orange-500/30 text-orange-400 hover:bg-orange-500/20 text-xs font-semibold px-3 py-1.5 rounded-lg transition"
                >
                  📄 ZAP Report
                </button>
                <button
                  onClick={generateAI}
                  disabled={loadingAI}
                  className="flex items-center gap-1.5 bg-violet-500/10 border border-violet-500/30 text-violet-400 hover:bg-violet-500/20 disabled:opacity-50 text-xs font-semibold px-3 py-1.5 rounded-lg transition"
                >
                  {loadingAI ? (
                    <>
                      <svg
                        className="w-3 h-3 animate-spin"
                        viewBox="0 0 24 24"
                        fill="none"
                      >
                        <circle
                          className="opacity-25"
                          cx="12"
                          cy="12"
                          r="10"
                          stroke="currentColor"
                          strokeWidth="4"
                        />
                        <path
                          className="opacity-75"
                          fill="currentColor"
                          d="M4 12a8 8 0 018-8v8z"
                        />
                      </svg>
                      Generating...
                    </>
                  ) : (
                    <>🤖 AI Recommendations</>
                  )}
                </button>
                <button
                  onClick={() => setSelectedRepo(null)}
                  className="w-8 h-8 flex items-center justify-center rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition text-lg"
                >
                  ×
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="overflow-y-auto flex-1 p-6 space-y-5">
              {/* AI Status */}
              {!!aiMessage && (
                <div
                  className={`flex items-center gap-2 text-xs px-4 py-2.5 rounded-xl border ${
                    aiMessage.includes("Failed") || aiMessage.includes("❌")
                      ? "bg-red-500/10 border-red-500/20 text-red-400"
                      : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                  }`}
                >
                  <span>{aiMessage}</span>
                  {!!aiSource && !loadingAI && (
                    <span className="ml-auto text-slate-500">
                      {aiSource === "generated"
                        ? "Generated now"
                        : "From database"}
                    </span>
                  )}
                </div>
              )}

              {/* AI Recommendations */}
              {recommendations.length > 0 && (
                <div className="bg-slate-800/50 border border-violet-500/20 rounded-xl p-4">
                  <h3 className="font-bold text-violet-400 text-sm mb-3">
                    🛡️ AI Security Recommendations
                  </h3>
                  <div className="space-y-3 pr-1">
                    {recommendations.map((rec) => (
                      <div
                        key={rec.id}
                        className="bg-slate-900 border border-slate-700 rounded-xl p-4"
                      >
                        {/* Header */}
                        <div className="flex items-start justify-between gap-3 mb-3">
                          <div>
                            <div className="font-bold text-sm text-violet-300 mb-1">
                              {rec.title || "Vulnerability"}
                            </div>
                            <div className="text-xs text-slate-500">
                              Finding #{rec.finding_id}
                            </div>
                          </div>

                          {/* Priority badge */}
                          {rec.priority && (
                            <span
                              className={`text-xs font-bold px-2 py-1 rounded-lg border ${
                                rec.priority === "Critical"
                                  ? "bg-red-500/10 border-red-500/30 text-red-400"
                                  : rec.priority === "High"
                                    ? "bg-orange-500/10 border-orange-500/30 text-orange-400"
                                    : rec.priority === "Medium"
                                      ? "bg-yellow-500/10 border-yellow-500/30 text-yellow-400"
                                      : "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                              }`}
                            >
                              {rec.priority}
                            </span>
                          )}
                        </div>

                        {/* Scores row */}
                        <div className="grid grid-cols-6 gap-4 w-full bg-slate-800/50 rounded-xl px-4 py-3">
                          {rec.cvss_score && (
                            <div className="text-center">
                              <div className="text-lg font-black text-orange-400 font-mono">
                                {rec.cvss_score}
                              </div>
                              <div className="text-xs text-slate-500">CVSS</div>
                            </div>
                          )}
                          {rec.ai_risk_score && (
                            <div className="text-center">
                              <div className="text-lg font-black text-violet-400 font-mono">
                                {rec.ai_risk_score}
                              </div>
                              <div className="text-xs text-slate-500">
                                AI Risk
                              </div>
                            </div>
                          )}
                          {rec.confidence && (
                            <div className="text-center">
                              <div className="text-lg font-black text-emerald-400 font-mono">
                                {rec.confidence}%
                              </div>
                              <div className="text-xs text-slate-500">
                                Confidence
                              </div>
                            </div>
                          )}
                          {rec.false_positive_likelihood && (
                            <div className="text-center">
                              <div
                                className={`text-sm font-bold ${
                                  rec.false_positive_likelihood === "Low"
                                    ? "text-emerald-400"
                                    : rec.false_positive_likelihood === "Medium"
                                      ? "text-yellow-400"
                                      : "text-red-400"
                                }`}
                              >
                                {rec.false_positive_likelihood}
                              </div>
                              <div className="text-xs text-slate-500">
                                False Positive
                              </div>
                            </div>
                          )}
                          {rec.attack_complexity && (
                            <div className="text-center">
                              <div className="text-sm font-bold text-slate-300">
                                {rec.attack_complexity}
                              </div>
                              <div className="text-xs text-slate-500">
                                Complexity
                              </div>
                            </div>
                          )}
                          {rec.owasp_category && (
                            <div className="text-center">
                              <div className="text-sm font-bold text-blue-400">
                                {rec.owasp_category}
                              </div>
                              <div className="text-xs text-slate-500">
                                OWASP
                              </div>
                            </div>
                          )}
                        </div>

                        {/* CVSS Vector */}
                        {rec.cvss_vector && (
                          <div className="text-xs font-mono text-slate-500 bg-slate-800 px-3 py-1.5 rounded-lg mb-3">
                            {rec.cvss_vector}
                          </div>
                        )}

                        {/* Content */}
                        <div
                          className="text-xs text-slate-400 leading-relaxed mb-3"
                          dangerouslySetInnerHTML={{
                            __html: rec.content
                              .replace(
                                /\*\*(.*?)\*\*/g,
                                "<strong class='text-slate-200'>$1</strong>",
                              )
                              .replace(/\n/g, "<br/>"),
                          }}
                        />
                        {/* 🔥 CODE FIX */}
                        {rec.code_fix_example && (
                          <div className="mt-3">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-xs text-slate-500">
                                💻 Secure Code Fix
                              </span>
                              <button
                                onClick={() => {
                                  if (rec.code_fix_example) {
                                    navigator.clipboard.writeText(
                                      rec.code_fix_example,
                                    );
                                    alert("Copied!");
                                  }
                                }}
                                className="text-xs text-blue-400 hover:underline"
                              >
                                Copy
                              </button>
                            </div>

                            <div className="bg-black/40 border border-slate-700 rounded-lg p-3 font-mono text-xs text-green-400 overflow-x-auto">
                              <pre>{rec.code_fix_example}</pre>
                            </div>
                          </div>
                        )}
                        {/* Approve / Reject */}
                        <div className="flex items-center gap-2 pt-2 border-t border-slate-700/50">
                          {rec.status === "approved" ? (
                            <span className="text-xs bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-2 py-1 rounded-lg">
                              ✓ Approved
                            </span>
                          ) : rec.status === "rejected" ? (
                            <span className="text-xs bg-slate-700 text-slate-500 px-2 py-1 rounded-lg">
                              Rejected
                            </span>
                          ) : (
                            <>
                              <button
                                onClick={() => approve(rec.id)}
                                className="text-xs bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1 rounded-lg transition"
                              >
                                Approve
                              </button>
                              <button
                                onClick={() => reject(rec.id)}
                                className="text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 px-3 py-1 rounded-lg transition"
                              >
                                Reject
                              </button>
                              <span className="text-xs text-violet-500 ml-auto">
                                Proposed
                              </span>
                            </>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {/* ← AJOUTER ICI — Performance Results */}
              {loadingPerf && (
                <div className="flex items-center gap-2 text-xs text-blue-400">
                  <svg
                    className="w-3 h-3 animate-spin"
                    viewBox="0 0 24 24"
                    fill="none"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                    />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8v8z"
                    />
                  </svg>
                  Loading performance data...
                </div>
              )}

              {perfResults.length > 0 && (
                <div className="bg-slate-800/50 border border-blue-500/20 rounded-xl p-4">
                  <h3 className="font-bold text-blue-400 text-sm mb-3">
                    ⚡ Performance Results
                  </h3>
                  {perfResults.slice(0, 1).map((perf) => (
                    <div key={perf.id}>
                      <div className="grid grid-cols-4 gap-3 mb-3">
                        {[
                          {
                            label: "Avg Response",
                            value: `${Math.round(perf.avg_response_ms)}ms`,
                            color:
                              perf.avg_response_ms < 500
                                ? "text-emerald-400"
                                : perf.avg_response_ms < 1500
                                  ? "text-yellow-400"
                                  : "text-red-400",
                          },
                          {
                            label: "Throughput",
                            value: `${parseFloat(perf.throughput || 0).toFixed(1)} req/s`,
                            color: "text-blue-400",
                          },
                          {
                            label: "Error Rate",
                            value: `${parseFloat(perf.error_rate || 0).toFixed(1)}%`,
                            color:
                              perf.error_rate < 1
                                ? "text-emerald-400"
                                : perf.error_rate < 5
                                  ? "text-yellow-400"
                                  : "text-red-400",
                          },
                          {
                            label: "Total Requests",
                            value: perf.total_requests,
                            color: "text-slate-300",
                          },
                        ].map(({ label, value, color }) => (
                          <div
                            key={label}
                            className="bg-slate-900 rounded-lg p-2 text-center"
                          >
                            <div
                              className={`font-bold text-lg font-mono ${color}`}
                            >
                              {value}
                            </div>
                            <div className="text-xs text-slate-500">
                              {label}
                            </div>
                          </div>
                        ))}
                      </div>

                      <div className="grid grid-cols-3 gap-2">
                        {[
                          {
                            label: "P90",
                            value: `${Math.round(perf.p90_response_ms)}ms`,
                          },
                          {
                            label: "P95",
                            value: `${Math.round(perf.p95_response_ms)}ms`,
                          },
                          {
                            label: "Max",
                            value: `${Math.round(perf.max_response_ms)}ms`,
                          },
                        ].map(({ label, value }) => (
                          <div
                            key={label}
                            className="bg-slate-800 rounded-lg px-3 py-1.5 flex justify-between"
                          >
                            <span className="text-xs text-slate-500">
                              {label}
                            </span>
                            <span className="text-xs font-mono text-slate-300">
                              {value}
                            </span>
                          </div>
                        ))}
                      </div>

                      <div className="text-xs text-slate-600 mt-2">
                        Last run: {new Date(perf.run_at).toLocaleString()}
                      </div>
                    </div>
                  ))}
                </div>
              )}
              {/* Vulnerability Sections */}
              {[
                {
                  title: "⚡ ZAP",
                  color: "text-orange-400",
                  scanner: "ZAP Scan",
                },
                {
                  title: "🛡️ Trivy",
                  color: "text-blue-400",
                  scanner: "Trivy Scan",
                },
              ].map(({ title, color, scanner }) => {
                const vulns = selectedRepo.vulnerabilities.filter(
                  (v) => v.scanner === scanner,
                );
                return (
                  <div key={scanner}>
                    <div className="flex items-center gap-2 mb-3">
                      <h3 className={`font-bold text-sm ${color}`}>{title}</h3>
                      <span className="text-slate-600 text-xs bg-slate-800 px-2 py-0.5 rounded-full">
                        {vulns.length}
                      </span>
                    </div>
                    <div className="space-y-1.5">
                      {vulns.map((v) => (
                        <div
                          key={v.id}
                          className="flex items-center justify-between bg-slate-800/50 border border-slate-700/50 rounded-xl px-4 py-2.5 hover:border-slate-600 transition"
                        >
                          <div>
                            <p className="text-sm text-slate-200 font-medium leading-tight">
                              {v.title}
                            </p>
                            <p className="text-xs text-slate-500">
                              {v.component_name}
                            </p>
                          </div>
                          <SeverityBadge severity={v.severity} />
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const cls: any = {
    Critical: "bg-red-500/10 border-red-500/30 text-red-400",
    High: "bg-orange-500/10 border-orange-500/30 text-orange-400",
    Medium: "bg-yellow-500/10 border-yellow-500/30 text-yellow-400",
    Low: "bg-emerald-500/10 border-emerald-500/30 text-emerald-400",
  };
  return (
    <span
      className={`border text-xs font-semibold px-2.5 py-1 rounded-lg ${cls[severity] || "bg-slate-700 text-slate-300"}`}
    >
      {severity}
    </span>
  );
}
