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
  const [prioritizedFindings, setPrioritizedFindings] = useState<any[]>([]);
  const [aiRankedFindings, setAiRankedFindings] = useState<any[]>([]);
  const [loadingAI, setLoadingAI] = useState(false);
  const [aiMessage, setAiMessage] = useState<string>("");
  const [aiSource, setAiSource] = useState<"" | "generated" | "database">("");
  const [perfResults, setPerfResults] = useState<any[]>([]);
  const [loadingPerf, setLoadingPerf] = useState(false);
  const [savingFeedbackId, setSavingFeedbackId] = useState<number | null>(null);
  const [feedbackMessage, setFeedbackMessage] = useState<string>("");

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

  const saveDeveloperPriority = async (
  finding: any,
  developerPriority: string,
) => {
  if (!selectedRepo) return;

  const scoreMap: Record<string, number> = {
    Critical: 95,
    High: 75,
    Medium: 50,
    Low: 25,
    "False Positive": 0,
    "Accepted Risk": 10,
  };

  setSavingFeedbackId(finding.id);
  setFeedbackMessage("");

  try {
    await api.post(`/api/findings/${finding.id}/feedback`, {
      product_id: selectedRepo.id,
      scanner_severity: finding.severity,
      scanner: finding.scanner,
      system_priority: finding.priority_label,
      system_score: finding.priority_score,
      developer_priority: developerPriority,
      developer_score: scoreMap[developerPriority],
      developer_reason: "",
      is_false_positive: developerPriority === "False Positive",
      accepted_risk: developerPriority === "Accepted Risk",
    });

    setPrioritizedFindings((prev) =>
      prev.map((item) =>
        item.id === finding.id
          ? {
              ...item,
              developer_priority: developerPriority,
              developer_score: scoreMap[developerPriority],
            }
          : item,
      ),
    );

    setFeedbackMessage(`Developer priority saved for #${finding.id}`);
  } catch (e) {
    console.error(e);
    setFeedbackMessage("Failed to save developer priority");
    alert("Failed to save developer priority");
  } finally {
    setSavingFeedbackId(null);
  }
};
  const loadAiRanking = async (repoId: number) => {
  const res = await api.get(`/api/repositories/${repoId}/ai-rank-findings`);
  setAiRankedFindings(res.data.items || []);
};

const moveFinding = (index: number, direction: "up" | "down") => {
  setAiRankedFindings((prev) => {
    const items = [...prev];
    const targetIndex = direction === "up" ? index - 1 : index + 1;

    if (targetIndex < 0 || targetIndex >= items.length) return prev;

    [items[index], items[targetIndex]] = [items[targetIndex], items[index]];

    return items.map((item, i) => ({
      ...item,
      developer_rank: i + 1,
    }));
  });
};

  const saveDeveloperOrder = async () => {
  if (!selectedRepo) return;

  try {
    await api.post(`/api/repositories/${selectedRepo.id}/developer-rank-feedback`, {
      items: aiRankedFindings.map((f, index) => ({
        finding_id: f.id,
        ai_rank: f.ai_rank,
        developer_rank: f.developer_rank || index + 1,
        ai_priority_label: f.ai_priority_label,
        developer_reason: "",
      })),
    });

    setFeedbackMessage("Developer order saved successfully.");
  } catch (e) {
    console.error(e);
    setFeedbackMessage("Failed to save developer order.");
  }
};
  const deleteRepo = async (repoId: number) => {
    if (!confirm("Supprimer ce repository et toutes ses données ?")) return;
    try {
      await api.delete(`/api/products/${repoId}`);
      window.location.reload();
    } catch (e) {
      console.error(e);
      alert("Delete failed");
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
          <svg className="w-5 h-5 animate-spin text-emerald-500" viewBox="0 0 24 24" fill="none">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
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
            <span className="font-bold text-white tracking-tight">DevSecOps</span>
            <span className="text-slate-600 text-sm hidden sm:block">/ Dashboard</span>
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
        <PipelinePage onFinish={() => {}} />

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
              Critical: repo.vulnerabilities.filter((v) => v.severity === "Critical").length,
              High: repo.vulnerabilities.filter((v) => v.severity === "High").length,
              Medium: repo.vulnerabilities.filter((v) => v.severity === "Medium").length,
              Low: repo.vulnerabilities.filter((v) => v.severity === "Low").length,
            };
            const trivy = repo.vulnerabilities.filter((v) => v.scanner === "Trivy Scan");
            const zap = repo.vulnerabilities.filter((v) => v.scanner === "ZAP Scan");
            const total = repo.vulnerabilities.length;
            const riskScore = counts.Critical * 10 + counts.High * 5 + counts.Medium * 2 + counts.Low;
            const riskColor =
              counts.Critical > 0 ? "text-red-400" : counts.High > 0 ? "text-orange-400" : "text-emerald-400";

            return (
              <div key={repo.id} className="bg-slate-900 border border-slate-800 rounded-2xl p-6 hover:border-slate-700 transition group">
                <div className="flex items-start justify-between mb-5">
                  <div>
                    <h3 className="font-bold text-white text-lg leading-tight">{repo.name}</h3>
                    <p className="text-slate-500 text-xs mt-0.5">{total} vulnerabilities total</p>
                  </div>
                  <div className="text-right">
                    <div className={`text-2xl font-black font-mono ${riskColor}`}>{riskScore}</div>
                    <div className="text-slate-600 text-xs">risk score</div>
                  </div>
                </div>

                <div className="flex gap-2 mb-5">
                  {[
                    { label: "Critical", count: counts.Critical, cls: "bg-red-500/10 text-red-400 border-red-500/20" },
                    { label: "High", count: counts.High, cls: "bg-orange-500/10 text-orange-400 border-orange-500/20" },
                    { label: "Medium", count: counts.Medium, cls: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20" },
                    { label: "Low", count: counts.Low, cls: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" },
                  ].map(({ label, count, cls }) => (
                    <div key={label} className={`flex-1 border rounded-xl p-2 text-center ${cls}`}>
                      <div className="font-bold text-base leading-none">{count}</div>
                      <div className="text-xs mt-0.5 opacity-70">{label}</div>
                    </div>
                  ))}
                </div>

                <div className="bg-slate-800/50 rounded-xl overflow-hidden mb-5 border border-slate-700/50">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-slate-700/50">
                        <th className="px-3 py-2 text-left text-slate-500 font-semibold">Scanner</th>
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
                      ].map(({ label, data: scanData }) => (
                        <tr key={label} className="border-t border-slate-700/30">
                          <td className="px-3 py-2 text-slate-300 font-medium">{label}</td>
                          {["Critical", "High", "Medium", "Low"].map((sev) => (
                            <td key={sev} className="px-3 py-2 text-center text-slate-400 font-mono">
                              {scanData.filter((v) => v.severity === sev).length}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="flex gap-2">
                  <button
                    onClick={async () => {
  setSelectedRepo(repo);
  setRecommendations([]);
  setPrioritizedFindings([]);
  setAiRankedFindings([]);
  setAiMessage("");
  loadPerformance(repo.id);
  await loadAiRanking(repo.id);
}}
                    className="flex-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-slate-300 hover:text-white text-sm font-semibold py-2.5 rounded-xl transition"
                  >
                    View Details →
                  </button>
                  <button
                    onClick={() => deleteRepo(repo.id)}
                    className="bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 text-sm font-semibold px-3 py-2.5 rounded-xl transition"
                  >
                    🗑️
                  </button>
                </div>
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
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 shrink-0">
              <div>
                <h2 className="font-bold text-white text-lg">{selectedRepo.name}</h2>
                <p className="text-slate-500 text-xs">Vulnerability Details</p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => window.open(`/api/products/${selectedRepo.id}/zap-report`, "_blank")}
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
                      <svg className="w-3 h-3 animate-spin" viewBox="0 0 24 24" fill="none">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
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

            {/* Modal Body — scrollable */}
            <div className="overflow-y-auto flex-1 p-6 space-y-5">
            {!!feedbackMessage && (
  <div
    className={`text-xs px-4 py-2.5 rounded-xl border ${
      feedbackMessage.includes("Failed")
        ? "bg-red-500/10 border-red-500/20 text-red-400"
        : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
    }`}
  >
    {feedbackMessage}
  </div>
)}
              {aiRankedFindings.length > 0 && (
  <div className="bg-slate-800/50 border border-emerald-500/20 rounded-xl p-4">
    <div className="flex items-center justify-between mb-3">
      <div>
        <h3 className="text-sm font-bold text-emerald-400">
          🤖 Vertex AI Ranked Vulnerabilities
        </h3>
        <p className="text-xs text-slate-500 mt-1">
          Initial ranking from Vertex AI. Developer can reorder items manually.
        </p>
      </div>

     <div className="flex items-center gap-2">
  <button
    onClick={() => selectedRepo && loadAiRanking(selectedRepo.id)}
    className="text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 px-3 py-1.5 rounded-lg"
  >
    Refresh
  </button>

  <button
    onClick={saveDeveloperOrder}
    className="text-xs bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1.5 rounded-lg"
  >
    Save developer order
  </button>
</div>
    </div>

    <div className="space-y-2">
      {aiRankedFindings.map((f, index) => (
        <div
          key={f.id}
          className="bg-slate-900 border border-slate-700 rounded-lg px-4 py-3"
        >
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0 flex-1">
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center font-mono text-sm font-bold">
                {index + 1}
              </div>

              <div className="min-w-0">
                <div className="text-sm font-semibold text-white truncate">
                  {f.title}
                </div>
                <div className="text-xs text-slate-500 mt-0.5">
                  #{f.id} · {f.severity} · {f.scanner}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <span
                className={`text-xs font-bold px-2 py-0.5 rounded border ${
                  f.ai_priority_label === "Critical"
                    ? "bg-red-500/10 border-red-500/30 text-red-400"
                    : f.ai_priority_label === "High"
                    ? "bg-orange-500/10 border-orange-500/30 text-orange-400"
                    : f.ai_priority_label === "Medium"
                    ? "bg-yellow-500/10 border-yellow-500/30 text-yellow-400"
                    : "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                }`}
              >
                {f.ai_priority_label}
              </span>

              <button
                onClick={() => moveFinding(index, "up")}
                disabled={index === 0}
                className="text-xs bg-slate-800 hover:bg-slate-700 disabled:opacity-30 text-slate-300 px-2 py-1 rounded"
              >
                ↑
              </button>

              <button
                onClick={() => moveFinding(index, "down")}
                disabled={index === aiRankedFindings.length - 1}
                className="text-xs bg-slate-800 hover:bg-slate-700 disabled:opacity-30 text-slate-300 px-2 py-1 rounded"
              >
                ↓
              </button>
            </div>
          </div>

          <p className="text-xs text-slate-400 mt-2">
            {f.ai_ranking_reason}
          </p>

          {f.developer_rank && (
            <div className="text-xs text-blue-400 mt-2">
              Developer reordered rank: {f.developer_rank}
            </div>
          )}
        </div>
      ))}
    </div>
  </div>
)}
              {/* 🔥 AI PRIORITIZATION — multi-criteria model */}
              {prioritizedFindings.length > 0 && (
                <div className="bg-slate-800/50 border border-purple-500/20 rounded-xl p-4">
                  <div className="flex items-center justify-between mb-1">
                    <h3 className="text-sm font-bold text-purple-400">🔥 Adaptive Prioritized Vulnerabilities</h3>
                    <span className="text-xs text-slate-500">Score /100 · CVSS·Exploit·Business·Evidence·OWASP·URL·Scanner</span>
                  </div>
                  <p className="text-xs text-slate-500 mb-4">
                    Initial score from AI/rules. Developer feedback will be stored and used to train the adaptive prioritization model. + Scanner (5pts)
                  </p>

                  <div className="space-y-2">
                    {Array.from(
  new Map(
    prioritizedFindings.map((f) => [
      `${f.title}-${f.scanner}`,
      f,
    ])
  ).values()
)
  .slice(0, 15)
  .map((f) => (
                      <div key={f.id} className="bg-slate-800 border border-slate-700 rounded-lg px-4 py-3">
                        {/* Header row */}
                        <div className="flex items-center justify-between mb-2">
                          <div className="min-w-0 flex-1">
                            <div className="text-sm font-semibold text-white truncate">{f.title}</div>
                            <div className="text-xs text-slate-500 mt-0.5">
                              #{f.id} · {f.severity} · {f.scanner}
                            </div>
                          </div>
                          <div className="text-right shrink-0 ml-4">
                            <div className="text-xl font-black text-purple-400 font-mono">{f.priority_score}</div>
                            <span className={`text-xs font-bold px-2 py-0.5 rounded border ${
                              f.priority_label === "Critical" ? "bg-red-500/10 border-red-500/30 text-red-400"
                              : f.priority_label === "High" ? "bg-orange-500/10 border-orange-500/30 text-orange-400"
                              : f.priority_label === "Medium" ? "bg-yellow-500/10 border-yellow-500/30 text-yellow-400"
                              : "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                            }`}>
                              {f.priority_label}
                            </span>
                          </div>
                        </div>

                        {/* Progress bar */}
                        <div className="w-full bg-slate-700 rounded-full h-1.5 mb-2">
                          <div
                            className={`h-1.5 rounded-full transition-all ${
                              f.priority_score >= 85 ? "bg-red-500"
                              : f.priority_score >= 65 ? "bg-orange-500"
                              : f.priority_score >= 40 ? "bg-yellow-500"
                              : "bg-emerald-500"
                            }`}
                            style={{ width: `${f.priority_score}%` }}
                          />
                        </div>

                        {/* Reasons tags */}
                        {f.priority_reasons?.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1">
                            {f.priority_reasons.map((r: string, i: number) => (
                              <span key={i} className="text-xs bg-slate-700 text-slate-400 px-2 py-0.5 rounded-full">
                                {r}
                              </span>
                            ))}
                          </div>
                        )}
                        <div className="mt-3 pt-3 border-t border-slate-700/50">
  <div className="flex items-center justify-between gap-3 mb-2">
    <span className="text-xs font-semibold text-slate-400">
      Developer priority
    </span>

    {f.developer_priority && (
      <span className="text-xs bg-blue-500/10 border border-blue-500/30 text-blue-400 px-2 py-0.5 rounded-full">
        Saved: {f.developer_priority}
      </span>
    )}
  </div>

  <div className="flex flex-wrap gap-1.5">
    {["Critical", "High", "Medium", "Low", "False Positive", "Accepted Risk"].map(
      (priority) => (
        <button
          key={priority}
          disabled={savingFeedbackId === f.id}
          onClick={() => saveDeveloperPriority(f, priority)}
          className={`text-xs font-semibold px-2 py-1 rounded-lg border transition disabled:opacity-50 ${
            f.developer_priority === priority
              ? "bg-blue-500/20 border-blue-500/40 text-blue-300"
              : priority === "Critical"
              ? "bg-red-500/10 border-red-500/30 text-red-400 hover:bg-red-500/20"
              : priority === "High"
              ? "bg-orange-500/10 border-orange-500/30 text-orange-400 hover:bg-orange-500/20"
              : priority === "Medium"
              ? "bg-yellow-500/10 border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/20"
              : priority === "Low"
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20"
              : "bg-slate-700 border-slate-600 text-slate-300 hover:bg-slate-600"
          }`}
        >
          {savingFeedbackId === f.id ? "Saving..." : priority}
        </button>
      ),
    )}
  </div>
</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* AI Status */}
              {!!aiMessage && (
                <div className={`flex items-center gap-2 text-xs px-4 py-2.5 rounded-xl border ${
                  aiMessage.includes("Failed") || aiMessage.includes("❌")
                    ? "bg-red-500/10 border-red-500/20 text-red-400"
                    : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                }`}>
                  <span>{aiMessage}</span>
                  {!!aiSource && !loadingAI && (
                    <span className="ml-auto text-slate-500">
                      {aiSource === "generated" ? "Generated now" : "From database"}
                    </span>
                  )}
                </div>
              )}

              {/* 🛡️ AI Recommendations */}
              {recommendations.length > 0 && (
                <div className="bg-slate-800/50 border border-violet-500/20 rounded-xl p-4">
                  <h3 className="font-bold text-violet-400 text-sm mb-3">🛡️ AI Security Recommendations</h3>
                  <div className="space-y-3">
                    {recommendations.map((rec) => (
                      <div key={rec.id} className="bg-slate-900 border border-slate-700 rounded-xl p-4">
                        {/* Header */}
                        <div className="flex items-start justify-between gap-3 mb-3">
                          <div>
                            <div className="font-bold text-sm text-violet-300 mb-1">
                              {rec.title || "Vulnerability"}
                            </div>
                            <div className="text-xs text-slate-500">Finding #{rec.finding_id}</div>
                          </div>
                          {rec.priority && (
                            <span className={`text-xs font-bold px-2 py-1 rounded-lg border ${
                              rec.priority === "Critical" ? "bg-red-500/10 border-red-500/30 text-red-400"
                              : rec.priority === "High" ? "bg-orange-500/10 border-orange-500/30 text-orange-400"
                              : rec.priority === "Medium" ? "bg-yellow-500/10 border-yellow-500/30 text-yellow-400"
                              : "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                            }`}>
                              {rec.priority}
                            </span>
                          )}
                        </div>

                        {/* Scores row */}
                        <div className="grid grid-cols-6 gap-4 w-full bg-slate-800/50 rounded-xl px-4 py-3 mb-3">
                          {rec.cvss_score && (
                            <div className="text-center">
                              <div className="text-lg font-black text-orange-400 font-mono">{rec.cvss_score}</div>
                              <div className="text-xs text-slate-500">CVSS</div>
                            </div>
                          )}
                          {rec.ai_risk_score && (
                            <div className="text-center">
                              <div className="text-lg font-black text-violet-400 font-mono">{rec.ai_risk_score}</div>
                              <div className="text-xs text-slate-500">AI Risk</div>
                            </div>
                          )}
                          {rec.confidence && (
                            <div className="text-center">
                              <div className="text-lg font-black text-emerald-400 font-mono">{rec.confidence}%</div>
                              <div className="text-xs text-slate-500">Confidence</div>
                            </div>
                          )}
                          {rec.false_positive_likelihood && (
                            <div className="text-center">
                              <div className={`text-sm font-bold ${
                                rec.false_positive_likelihood === "Low" ? "text-emerald-400"
                                : rec.false_positive_likelihood === "Medium" ? "text-yellow-400"
                                : "text-red-400"
                              }`}>
                                {rec.false_positive_likelihood}
                              </div>
                              <div className="text-xs text-slate-500">False Positive</div>
                            </div>
                          )}
                          {rec.attack_complexity && (
                            <div className="text-center">
                              <div className="text-sm font-bold text-slate-300">{rec.attack_complexity}</div>
                              <div className="text-xs text-slate-500">Complexity</div>
                            </div>
                          )}
                          {rec.owasp_category && (
                            <div className="text-center">
                              <div className="text-sm font-bold text-blue-400">{rec.owasp_category}</div>
                              <div className="text-xs text-slate-500">OWASP</div>
                            </div>
                          )}
                        </div>

                        {rec.cvss_vector && (
                          <div className="text-xs font-mono text-slate-500 bg-slate-800 px-3 py-1.5 rounded-lg mb-3">
                            {rec.cvss_vector}
                          </div>
                        )}

                        <div
                          className="text-xs text-slate-400 leading-relaxed mb-3"
                          dangerouslySetInnerHTML={{
                            __html: rec.content
                              .replace(/\*\*(.*?)\*\*/g, "<strong class='text-slate-200'>$1</strong>")
                              .replace(/\n/g, "<br/>"),
                          }}
                        />

                        {rec.code_fix_example && (
                          <div className="mt-3">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-xs text-slate-500">💻 Secure Code Fix</span>
                              <button
                                onClick={() => {
                                  if (rec.code_fix_example) {
                                    navigator.clipboard.writeText(rec.code_fix_example);
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

                        <div className="flex items-center gap-2 pt-2 border-t border-slate-700/50 mt-3">
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
                              <span className="text-xs text-violet-500 ml-auto">Proposed</span>
                            </>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Performance */}
              {loadingPerf && (
                <div className="flex items-center gap-2 text-xs text-blue-400">
                  <svg className="w-3 h-3 animate-spin" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                  </svg>
                  Loading performance data...
                </div>
              )}

              {perfResults.length > 0 && (
                <div className="bg-slate-800/50 border border-blue-500/20 rounded-xl p-4">
                  <h3 className="font-bold text-blue-400 text-sm mb-3">⚡ Performance Results</h3>
                  {perfResults.slice(0, 1).map((perf) => {
                    const issues = [];
                    if (perf.avg_response_ms > 1000) issues.push("Avg response trop lent");
                    if (perf.p95_response_ms > 2000) issues.push("P95 critique");
                    if (parseFloat(perf.error_rate) > 5) issues.push("Taux d'erreur élevé");
                    if (parseFloat(perf.throughput) < 5) issues.push("Débit trop faible");

                    const stable = issues.length === 0;
                    const warning = !stable && issues.length <= 1;
                    const stabilityColor = stable
                      ? "text-emerald-400 border-emerald-500/30 bg-emerald-500/10"
                      : warning
                      ? "text-yellow-400 border-yellow-500/30 bg-yellow-500/10"
                      : "text-red-400 border-red-500/30 bg-red-500/10";
                    const stabilityLabel = stable ? "Stable" : warning ? "Instable" : "Critique";

                    return (
                      <div key={perf.id}>
                        <div className={`flex items-center justify-between border rounded-xl px-4 py-2.5 mb-4 ${stabilityColor}`}>
                          <div>
                            <div className="font-bold text-sm">
                              {stable ? "✅" : warning ? "⚠️" : "❌"} Application {stabilityLabel}
                            </div>
                            {issues.length > 0 && (
                              <div className="text-xs mt-1 opacity-80">{issues.join(" · ")}</div>
                            )}
                          </div>
                          <div className="text-xs opacity-70">{perf.vus} VUs · {perf.duration_secs}s</div>
                        </div>

                        <div className="grid grid-cols-4 gap-3 mb-3">
                          {[
                            { label: "Avg Response", value: `${Math.round(perf.avg_response_ms)}ms`, color: perf.avg_response_ms < 200 ? "text-emerald-400" : perf.avg_response_ms < 500 ? "text-yellow-400" : "text-red-400" },
                            { label: "Throughput", value: `${parseFloat(perf.throughput || 0).toFixed(1)} req/s`, color: parseFloat(perf.throughput) > 50 ? "text-emerald-400" : parseFloat(perf.throughput) > 10 ? "text-yellow-400" : "text-red-400" },
                            { label: "Error Rate", value: `${parseFloat(perf.error_rate || 0).toFixed(1)}%`, color: perf.error_rate < 0.1 ? "text-emerald-400" : perf.error_rate < 1 ? "text-yellow-400" : "text-red-400" },
                            { label: "Total Requests", value: perf.total_requests, color: "text-slate-300" },
                          ].map(({ label, value, color }) => (
                            <div key={label} className="bg-slate-900 rounded-lg p-2 text-center">
                              <div className={`font-bold text-lg font-mono ${color}`}>{value}</div>
                              <div className="text-xs text-slate-500">{label}</div>
                            </div>
                          ))}
                        </div>

                        <div className="grid grid-cols-3 gap-2">
                          {[
                            { label: "P90", value: `${Math.round(perf.p90_response_ms)}ms`, color: perf.p90_response_ms < 500 ? "text-emerald-400" : perf.p90_response_ms < 1000 ? "text-yellow-400" : "text-red-400" },
                            { label: "P95", value: `${Math.round(perf.p95_response_ms)}ms`, color: perf.p95_response_ms < 1000 ? "text-emerald-400" : perf.p95_response_ms < 2000 ? "text-yellow-400" : "text-red-400" },
                            { label: "Max", value: `${Math.round(perf.max_response_ms)}ms`, color: "text-slate-300" },
                          ].map(({ label, value, color }) => (
                            <div key={label} className="bg-slate-800 rounded-lg px-3 py-1.5 flex justify-between">
                              <span className="text-xs text-slate-500">{label}</span>
                              <span className={`text-xs font-mono ${color}`}>{value}</span>
                            </div>
                          ))}
                        </div>

                        <div className="text-xs text-slate-600 mt-2">
                          Last run: {new Date(perf.run_at).toLocaleString()}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Vulnerability Sections */}
              {[
                { title: "⚡ ZAP", color: "text-orange-400", scanner: "ZAP Scan" },
                { title: "🛡️ Trivy", color: "text-blue-400", scanner: "Trivy Scan" },
              ].map(({ title, color, scanner }) => {
                const vulns = selectedRepo.vulnerabilities.filter((v) => v.scanner === scanner);
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
                            <p className="text-sm text-slate-200 font-medium leading-tight">{v.title}</p>
                            <p className="text-xs text-slate-500">{v.component_name}</p>
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
    <span className={`border text-xs font-semibold px-2.5 py-1 rounded-lg ${cls[severity] || "bg-slate-700 text-slate-300"}`}>
      {severity}
    </span>
  );
}
