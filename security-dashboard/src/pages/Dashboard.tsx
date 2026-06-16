import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, logout } from "../services/api";
import PipelinePage from "./PipelinePage";
import type { Repository, Recommendation } from "../types/dashboard";
import SeverityBadge from "../components/dashboard/SeverityBadge";
import RepositoryCard from "../components/dashboard/RepositoryCard";
import UserManagerModal from "../components/dashboard/UserManagerModal";

export default function Dashboard() {
  const [selectedRepo, setSelectedRepo] = useState<Repository | null>(null);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [prioritizedFindings, setPrioritizedFindings] = useState<any[]>([]);
  const [aiRankedFindings, setAiRankedFindings] = useState<any[]>([]);
  const [rankingTab, setRankingTab] = useState<"trivy" | "zap">("zap");
  const [loadingAI, setLoadingAI] = useState(false);
  const [rankingReasons, setRankingReasons] = useState<Record<number, string>>(
    {},
  );
  const [aiMessage, setAiMessage] = useState<string>("");
  const [aiSource, setAiSource] = useState<"" | "generated" | "database">("");
  const [loadingRankRun, setLoadingRankRun] = useState(false);
  const [savingFeedbackId, setSavingFeedbackId] = useState<number | null>(null);
  const [feedbackMessage, setFeedbackMessage] = useState<string>("");
  const [jiraAssigneeId, setJiraAssigneeId] = useState<string>("");
  const [showUserManager, setShowUserManager] = useState(false);
  const [users, setUsers] = useState<any[]>([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [adaptiveStats, setAdaptiveStats] = useState<any>(null);

  const handleLogout = async () => {
    try {
      await logout();
      window.location.reload();
    } catch (e) {
      console.error(e);
    }
  };

  const { data: me } = useQuery({
    queryKey: ["me"],
    queryFn: async () => {
      const res = await api.get("/auth/me");
      return res.data;
    },
  });

  const isAdmin = me?.role === "admin";

  const { data = [], isLoading } = useQuery({
    queryKey: ["repositories"],
    queryFn: async () => {
      const res = await api.get("/api/repositories");
      return res.data;
    },
  });

  const approve = async (recId: string) => {
    try {
      const res = await api.post(`/api/recommendations/${recId}/approve`, {
        jira_assignee_id: jiraAssigneeId || undefined,
      });
      const updated: Recommendation = res.data;
      setRecommendations((prev) =>
        prev.map((r) => {
          if (r.finding_id === updated.finding_id) {
            if (r.id === updated.id)
              return { ...r, status: "approved", jira_pending: true };
            return { ...r, status: "proposed" };
          }
          return r;
        }),
      );
      let attempts = 0;
      const poll = setInterval(async () => {
        attempts++;
        try {
          const check = await api.get(
            `/api/findings/${updated.finding_id}/recommendations`,
          );
          const fresh = (check.data as Recommendation[]).find(
            (r) => r.id === recId,
          );
          if (fresh?.jira_issue_key) {
            setRecommendations((prev) =>
              prev.map((r) =>
                r.id === recId
                  ? {
                      ...r,
                      jira_issue_key: fresh.jira_issue_key,
                      jira_issue_url: fresh.jira_issue_url,
                      jira_pending: false,
                    }
                  : r,
              ),
            );
            clearInterval(poll);
          }
        } catch (_) {}
        if (attempts >= 10) clearInterval(poll);
      }, 1000);
    } catch (e) {
      console.error(e);
      alert("Approve failed");
    }
  };

  const retryJira = async (recId: string) => {
    try {
      const res = await api.post(`/api/recommendations/${recId}/create-jira`);
      const data = res.data;
      if (data.jira_issue_key) {
        setRecommendations((prev) =>
          prev.map((r) =>
            r.id === recId
              ? {
                  ...r,
                  jira_issue_key: data.jira_issue_key,
                  jira_issue_url: data.jira_issue_url,
                  jira_pending: false,
                }
              : r,
          ),
        );
      }
    } catch (e) {
      console.error(e);
      alert("Jira ticket creation failed");
    }
  };

  const normalizeScannerType = (f: any) => {
    const value = (f.scanner_type || f.scanner || "").toLowerCase();
    if (value.includes("zap") || value.includes("owasp")) return "zap";
    if (value.includes("trivy")) return "trivy";
    return "unknown";
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
  const loadAdaptiveStats = async (repoId: number) => {
    const res = await api.get(
      `/api/repositories/${repoId}/adaptive-ranking-stats`,
    );
    setAdaptiveStats(res.data);
    return res.data;
  };
  const loadAiRanking = async (repoId: number) => {
    const res = await api.get(
      `/api/repositories/${repoId}/dataset-rank-findings`,
    );
    const items = res.data.items || [];
    setAiRankedFindings(items);
    return items;
  };

  const loadDeveloperRanking = async (repoId: number) => {
    const res = await api.get(
      `/api/repositories/${repoId}/developer-rank-feedback`,
    );
    const items = res.data.items || [];
    setAiRankedFindings(items);
    const reasons: Record<number, string> = {};
    items.forEach((f: any) => {
      if (f.developer_reason) reasons[f.id] = f.developer_reason;
    });
    setRankingReasons(reasons);
    setFeedbackMessage("Developer order loaded.");
  };

  const moveFinding = (index: number, direction: "up" | "down") => {
    setAiRankedFindings((prev) => {
      const items = [...prev];
      const targetIndex = direction === "up" ? index - 1 : index + 1;
      if (targetIndex < 0 || targetIndex >= items.length) return prev;
      [items[index], items[targetIndex]] = [items[targetIndex], items[index]];
      return items.map((item, i) => ({ ...item, developer_rank: i + 1 }));
    });
  };

  const saveDeveloperOrder = async () => {
    if (!selectedRepo) return;
    try {
      await api.post(
        `/api/repositories/${selectedRepo.id}/developer-rank-feedback`,
        {
          items: aiRankedFindings.map((f, index) => ({
            finding_id: f.id,
            ai_rank: f.ai_rank,
            developer_rank: f.developer_rank || index + 1,
            ai_priority_label: f.ai_priority_label,
            developer_reason: rankingReasons[f.id] || "",
          })),
        },
      );
      setFeedbackMessage("Developer order saved successfully.");
      await loadAiRanking(selectedRepo.id);
      await loadAdaptiveStats(selectedRepo.id);
    } catch (e) {
      console.error(e);
      setFeedbackMessage("Failed to save developer order.");
    }
  };

  const loadUsers = async () => {
    setLoadingUsers(true);
    try {
      const res = await api.get("/api/admin/users");
      setUsers(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingUsers(false);
    }
  };

  const changeUserRole = async (userId: number, newRole: string) => {
    try {
      await api.patch(`/api/admin/users/${userId}/role`, { role: newRole });
      setUsers((prev) =>
        prev.map((u) => (u.id === userId ? { ...u, role: newRole } : u)),
      );
    } catch (e) {
      console.error(e);
      alert("Failed to change role");
    }
  };

  const deleteUser = async (userId: number) => {
    if (!confirm("Supprimer cet utilisateur ?")) return;
    try {
      await api.delete(`/api/admin/users/${userId}`);
      setUsers((prev) => prev.filter((u) => u.id !== userId));
    } catch (e) {
      console.error(e);
      alert("Failed to delete user");
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
    <div className="min-h-screen bg-slate-950 text-white relative overflow-hidden">
      {/* ── Background layers (same as Login) ── */}
      <div className="absolute inset-0 bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900" />
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl pointer-events-none" />
      <div
        className="absolute inset-0 opacity-[0.03] pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      {/* ── Top Nav (with accent bar like Login card) ── */}
      <nav className="border-b border-slate-800 bg-slate-950/85 backdrop-blur sticky top-0 z-10">
        {/* Accent line */}
        <div className="h-[3px] bg-gradient-to-r from-emerald-500 via-blue-500 to-violet-500" />
        <div className="max-w-7xl mx-auto px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-400 to-emerald-600 flex items-center justify-center text-sm font-black text-slate-900 shadow-lg shadow-emerald-500/20">
              C
            </div>
            <span className="font-bold text-white tracking-tight">
              CodeCure
            </span>
            <span className="text-slate-700 text-sm hidden sm:block">/</span>
            <span className="text-slate-500 text-sm hidden sm:block">
              Dashboard
            </span>
          </div>
          <div className="flex items-center gap-2">
            {isAdmin && (
              <button
                onClick={() => {
                  setShowUserManager(true);
                  loadUsers();
                }}
                className="flex items-center gap-2 text-slate-400 hover:text-white text-sm px-3 py-1.5 rounded-lg hover:bg-slate-800 border border-transparent hover:border-slate-700 transition"
              >
                👥 Users
              </button>
            )}
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 text-slate-400 hover:text-white text-sm px-3 py-1.5 rounded-lg hover:bg-slate-800 border border-transparent hover:border-slate-700 transition"
            >
              <span>⎋</span> Logout
            </button>
          </div>
        </div>
      </nav>

      {/* ── Main Content ── */}
      <div className="relative z-10 max-w-7xl mx-auto px-6 py-8 space-y-8">
        <PipelinePage onFinish={() => {}} />

        <div className="flex items-center gap-3">
          <h2 className="text-lg font-bold text-white">Repositories</h2>
          <span className="bg-slate-900 border border-slate-800 text-slate-500 text-xs font-mono px-2 py-0.5 rounded-full">
            {data.length}
          </span>
        </div>

        {/* ── Repository Cards ── */}
        <div className="grid md:grid-cols-2 gap-6">
          {data.map((repo: Repository) => (
            <RepositoryCard
              key={repo.id}
              repo={repo}
              onViewDetails={(repo) => {
                setSelectedRepo(repo);
                setRecommendations([]);
                setPrioritizedFindings([]);
                setAiRankedFindings([]);
                setRankingReasons({});
                setAiMessage("");
                setRankingTab("zap");
                loadAiRanking(repo.id);
                loadAdaptiveStats(repo.id);
              }}
              onDelete={deleteRepo}
            />
          ))}
        </div>
      </div>

      {/* ── MODAL: Repo Details ── */}
      {selectedRepo && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm flex justify-center items-center z-50 p-4">
          <div className="bg-slate-900/98 border border-slate-800 w-full max-w-6xl rounded-2xl shadow-2xl flex flex-col max-h-[90vh] overflow-hidden">
            {/* Modal accent line */}
            <div className="h-[3px] bg-gradient-to-r from-emerald-500 via-blue-500 to-violet-500 shrink-0" />

            {/* Modal Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 shrink-0">
              <div>
                <h2 className="font-bold text-white text-lg">
                  {selectedRepo.name}
                </h2>
                <p className="text-slate-500 text-xs">Vulnerability Details</p>
              </div>
              <div className="flex items-center gap-2 flex-wrap justify-end">
                <div className="flex items-center gap-1.5">
                  <label className="text-xs text-slate-500 whitespace-nowrap">
                    Jira Assignee ID
                  </label>
                  <input
                    type="text"
                    value={jiraAssigneeId}
                    onChange={(e) => setJiraAssigneeId(e.target.value)}
                    placeholder="ex: 5b10a2844c20165700ede21g"
                    className="bg-slate-800 border border-slate-700 text-xs text-slate-200 placeholder-slate-600 rounded-lg px-2.5 py-1.5 w-48 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/20 transition"
                  />
                </div>
                <button
                  onClick={() =>
                    window.open(
                      `/api/products/${selectedRepo.id}/zap-report`,
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
                  onClick={async () => {
                    if (!selectedRepo || loadingRankRun) return;
                    setLoadingRankRun(true);
                    try {
                      await api.post(
                        `/api/repositories/${selectedRepo.id}/ai-rank-run`,
                      );
                      const poll = setInterval(async () => {
                        const items = await loadAiRanking(selectedRepo.id);
                        await loadAdaptiveStats(selectedRepo.id);

                        if (items.length > 0) {
                          clearInterval(poll);
                          setLoadingRankRun(false);
                        }
                      }, 3000);
                      setTimeout(() => {
                        clearInterval(poll);
                        setLoadingRankRun(false);
                      }, 60000);
                    } catch (e) {
                      console.error(e);
                      setLoadingRankRun(false);
                    }
                  }}
                  disabled={loadingRankRun}
                  className="flex items-center gap-1.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20 disabled:opacity-50 text-xs font-semibold px-3 py-1.5 rounded-lg transition"
                >
                  {loadingRankRun ? (
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
                      Ranking...
                    </>
                  ) : (
                    <>🔄 Run AI Ranking</>
                  )}
                </button>
                <button
                  onClick={() => setSelectedRepo(null)}
                  className="w-8 h-8 flex items-center justify-center rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-400 hover:text-white transition text-lg"
                >
                  ×
                </button>
              </div>
            </div>

            {/* Modal Body */}
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

              {/* AI Ranked Findings */}
              {aiRankedFindings.length > 0 && (
                <div className="bg-slate-800/40 border border-emerald-500/20 rounded-2xl overflow-hidden">
                  <div className="h-[2px] bg-gradient-to-r from-emerald-500 to-teal-400" />
                  <div className="p-4">
                    <div className="flex items-center justify-between mb-3">
                      <div>
                        <h3 className="text-sm font-bold text-emerald-400">
                          🤖 Dataset-based Vertex AI Ranking
                        </h3>
                        <p className="text-xs text-slate-500 mt-1">
                          Trivy and ZAP ranked separately by the AI.
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() =>
                            selectedRepo && loadAiRanking(selectedRepo.id)
                          }
                          className="text-xs bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 px-3 py-1.5 rounded-lg transition"
                        >
                          Refresh
                        </button>
                        <button
                          onClick={() =>
                            selectedRepo &&
                            loadDeveloperRanking(selectedRepo.id)
                          }
                          className="text-xs bg-blue-600 hover:bg-blue-500 text-white px-3 py-1.5 rounded-lg transition"
                        >
                          Dev order
                        </button>
                        <button
                          onClick={saveDeveloperOrder}
                          className="text-xs bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1.5 rounded-lg transition"
                        >
                          Save developer order
                        </button>
                      </div>
                    </div>

                    {/* AI learning explanation */}
                    <div className="bg-slate-900/80 border border-slate-700/50 rounded-xl px-4 py-3 mb-4">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-xs font-bold text-slate-300">
                          🧠 How AI learns from your feedback
                        </span>
                        {aiRankedFindings.some((f) => f.developer_rank) ? (
                          <span className="text-xs bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-2 py-0.5 rounded-full">
                            Active — dev corrections applied
                          </span>
                        ) : (
                          <span className="text-xs bg-slate-800 border border-slate-700 text-slate-500 px-2 py-0.5 rounded-full">
                            No corrections yet
                          </span>
                        )}
                      </div>
                      <div className="space-y-1.5 text-xs text-slate-400">
                        {[
                          {
                            color: "text-emerald-400",
                            text: "AI ranks findings using CVSS, EPSS, KEV, evidence, and sensitive URLs by default.",
                          },
                          {
                            color: "text-blue-400",
                            text: "When you reorder findings and save, the AI receives your corrections on the next ranking run.",
                          },
                          {
                            color: "text-violet-400",
                            text: "The AI extracts patterns from your corrections — not just individual cases.",
                          },
                          {
                            color: "text-orange-400",
                            text: "Your corrections always override the default rules when there is a conflict.",
                          },
                        ].map(({ color, text }, i) => (
                          <div key={i} className="flex items-start gap-2">
                            <span className={`${color} mt-0.5`}>{i + 1}.</span>
                            <span>{text}</span>
                          </div>
                        ))}
                      </div>
                      {aiRankedFindings.some((f) => f.developer_rank) && (
                        <div className="mt-3 pt-3 border-t border-slate-700/50 flex items-center gap-4 flex-wrap">
                          <div className="text-xs text-slate-500">
                            Corrections applied:{" "}
                            <span className="text-white font-bold">
                              {
                                aiRankedFindings.filter(
                                  (f) =>
                                    f.developer_rank &&
                                    f.developer_rank !== f.ai_rank,
                                ).length
                              }
                            </span>{" "}
                            findings reranked by dev
                          </div>
                          {aiRankedFindings.filter(
                            (f) =>
                              f.developer_rank && f.developer_rank < f.ai_rank,
                          ).length > 0 && (
                            <div className="text-xs text-emerald-400">
                              ↑{" "}
                              {
                                aiRankedFindings.filter(
                                  (f) =>
                                    f.developer_rank &&
                                    f.developer_rank < f.ai_rank,
                                ).length
                              }{" "}
                              promoted
                            </div>
                          )}
                          {aiRankedFindings.filter(
                            (f) =>
                              f.developer_rank && f.developer_rank > f.ai_rank,
                          ).length > 0 && (
                            <div className="text-xs text-red-400">
                              ↓{" "}
                              {
                                aiRankedFindings.filter(
                                  (f) =>
                                    f.developer_rank &&
                                    f.developer_rank > f.ai_rank,
                                ).length
                              }{" "}
                              demoted
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                    {adaptiveStats && (
                      <div className="bg-slate-900/80 border border-violet-500/30 rounded-xl px-4 py-3 mb-4">
                        <div className="text-xs font-bold text-violet-300 mb-2">
                          🧠 Adaptive Ranking Memory
                        </div>

                        <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                          <div className="bg-slate-800 border border-slate-700 rounded-lg p-2 text-center">
                            <div className="text-lg font-black text-teal-400">
                              {adaptiveStats.trivy?.feedback_examples || 0}
                            </div>
                            <div className="text-xs text-slate-500">
                              Trivy examples
                            </div>
                          </div>

                          <div className="bg-slate-800 border border-slate-700 rounded-lg p-2 text-center">
                            <div className="text-lg font-black text-orange-400">
                              {adaptiveStats.owasp?.feedback_examples || 0}
                            </div>
                            <div className="text-xs text-slate-500">
                              OWASP examples
                            </div>
                          </div>

                          <div className="bg-slate-800 border border-slate-700 rounded-lg p-2 text-center">
                            <div className="text-lg font-black text-emerald-400">
                              {Number(adaptiveStats.trivy?.promoted || 0) +
                                Number(adaptiveStats.owasp?.promoted || 0)}
                            </div>
                            <div className="text-xs text-slate-500">
                              Promoted
                            </div>
                          </div>

                          <div className="bg-slate-800 border border-slate-700 rounded-lg p-2 text-center">
                            <div className="text-lg font-black text-red-400">
                              {Number(adaptiveStats.trivy?.demoted || 0) +
                                Number(adaptiveStats.owasp?.demoted || 0)}
                            </div>
                            <div className="text-xs text-slate-500">
                              Demoted
                            </div>
                          </div>

                          <div className="bg-slate-800 border border-slate-700 rounded-lg p-2 text-center">
                            <div className="text-lg font-black text-blue-400">
                              {Number(adaptiveStats.trivy?.accepted || 0) +
                                Number(adaptiveStats.owasp?.accepted || 0)}
                            </div>
                            <div className="text-xs text-slate-500">
                              Accepted
                            </div>
                          </div>
                        </div>

                        <p className="text-xs text-slate-500 mt-3">
                          Vertex AI uses these scanner-specific feedback
                          examples from Trivy and OWASP datasets during ranking.
                        </p>
                      </div>
                    )}
                    {/* Tabs ZAP / Trivy */}
                    <div className="flex gap-2 mb-4">
                      {(["zap", "trivy"] as const).map((tab) => {
                        const count = aiRankedFindings.filter(
                          (f) => normalizeScannerType(f) === tab,
                        ).length;
                        return (
                          <button
                            key={tab}
                            onClick={() => setRankingTab(tab)}
                            className={`flex items-center gap-2 text-xs font-semibold px-4 py-2 rounded-lg border transition ${
                              rankingTab === tab
                                ? tab === "zap"
                                  ? "bg-orange-500/20 border-orange-500/40 text-orange-300"
                                  : "bg-teal-500/20 border-teal-500/40 text-teal-300"
                                : "bg-slate-800 border-slate-700 text-slate-400 hover:text-white"
                            }`}
                          >
                            {tab === "zap" ? "🌐 ZAP" : "🐳 Trivy"}
                            <span className="bg-slate-700 text-slate-300 px-1.5 py-0.5 rounded-full text-xs">
                              {count}
                            </span>
                          </button>
                        );
                      })}
                    </div>

                    {/* Ranked findings list */}
                    <div className="space-y-2">
                      {aiRankedFindings
                        .filter((f) => normalizeScannerType(f) === rankingTab)
                        .map((f, index) => {
                          const globalIndex = aiRankedFindings.indexOf(f);
                          const filteredLength = aiRankedFindings.filter(
                            (x) => normalizeScannerType(x) === rankingTab,
                          ).length;
                          return (
                            <div
                              key={f.id}
                              className="bg-slate-900/80 border border-slate-700/60 rounded-xl px-4 py-3"
                            >
                              <div className="flex items-center justify-between gap-3">
                                <div className="flex items-center gap-3 min-w-0 flex-1">
                                  <div
                                    className={`w-8 h-8 rounded-lg flex items-center justify-center font-mono text-sm font-bold border ${
                                      rankingTab === "zap"
                                        ? "bg-orange-500/10 border-orange-500/30 text-orange-400"
                                        : "bg-teal-500/10 border-teal-500/30 text-teal-400"
                                    }`}
                                  >
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
                                    onClick={() =>
                                      moveFinding(globalIndex, "up")
                                    }
                                    disabled={index === 0}
                                    className="text-xs bg-slate-800 hover:bg-slate-700 border border-slate-700 disabled:opacity-30 text-slate-300 px-2 py-1 rounded-lg transition"
                                  >
                                    ↑
                                  </button>
                                  <button
                                    onClick={() =>
                                      moveFinding(globalIndex, "down")
                                    }
                                    disabled={index === filteredLength - 1}
                                    className="text-xs bg-slate-800 hover:bg-slate-700 border border-slate-700 disabled:opacity-30 text-slate-300 px-2 py-1 rounded-lg transition"
                                  >
                                    ↓
                                  </button>
                                </div>
                              </div>
                              <p className="text-xs text-slate-400 mt-2">
                                {f.ai_ranking_reason}
                              </p>
                              <textarea
                                rows={2}
                                placeholder="Why did you reorder this? (optional)"
                                value={
                                  rankingReasons[f.id] ??
                                  f.developer_reason ??
                                  ""
                                }
                                onChange={(e) =>
                                  setRankingReasons((prev) => ({
                                    ...prev,
                                    [f.id]: e.target.value,
                                  }))
                                }
                                className="w-full mt-2 bg-slate-800 border border-slate-700 text-xs text-slate-300 placeholder-slate-600 rounded-lg px-3 py-2 resize-none focus:outline-none focus:border-slate-500 transition"
                              />
                              {f.developer_rank && (
                                <div className="flex items-center gap-2 mt-1 flex-wrap">
                                  <span className="text-xs text-blue-400">
                                    Developer rank: {f.developer_rank}
                                  </span>
                                  {f.developer_email && (
                                    <span className="text-xs bg-slate-800 border border-slate-700 text-slate-300 px-2 py-0.5 rounded-full">
                                      👤 {f.developer_email}
                                    </span>
                                  )}
                                </div>
                              )}
                            </div>
                          );
                        })}
                      {aiRankedFindings.filter(
                        (f) => normalizeScannerType(f) === rankingTab,
                      ).length === 0 && (
                        <div className="text-xs text-slate-500 text-center py-8">
                          No{" "}
                          {rankingTab === "zap" ? "ZAP web" : "Trivy container"}{" "}
                          findings ranked yet.
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Adaptive Prioritized Vulnerabilities */}
              {prioritizedFindings.length > 0 && (
                <div className="bg-slate-800/40 border border-purple-500/20 rounded-2xl overflow-hidden">
                  <div className="h-[2px] bg-gradient-to-r from-violet-500 to-purple-400" />
                  <div className="p-4">
                    <div className="flex items-center justify-between mb-1">
                      <h3 className="text-sm font-bold text-purple-400">
                        🔥 Adaptive Prioritized Vulnerabilities
                      </h3>
                      <span className="text-xs text-slate-500">
                        Score /100 ·
                        CVSS·Exploit·Business·Evidence·OWASP·URL·Scanner
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 mb-4">
                      Initial score from AI/rules. Developer feedback will be
                      stored and used to train the adaptive prioritization
                      model.
                    </p>
                    <div className="space-y-2">
                      {Array.from(
                        new Map(
                          prioritizedFindings.map((f) => [
                            `${f.title}-${f.scanner}`,
                            f,
                          ]),
                        ).values(),
                      )
                        .slice(0, 15)
                        .map((f) => (
                          <div
                            key={f.id}
                            className="bg-slate-900/80 border border-slate-700/60 rounded-xl px-4 py-3"
                          >
                            <div className="flex items-center justify-between mb-2">
                              <div className="min-w-0 flex-1">
                                <div className="text-sm font-semibold text-white truncate">
                                  {f.title}
                                </div>
                                <div className="text-xs text-slate-500 mt-0.5">
                                  #{f.id} · {f.severity} · {f.scanner}
                                </div>
                              </div>
                              <div className="text-right shrink-0 ml-4">
                                <div className="text-xl font-black text-purple-400 font-mono">
                                  {f.priority_score}
                                </div>
                                <span
                                  className={`text-xs font-bold px-2 py-0.5 rounded border ${
                                    f.priority_label === "Critical"
                                      ? "bg-red-500/10 border-red-500/30 text-red-400"
                                      : f.priority_label === "High"
                                        ? "bg-orange-500/10 border-orange-500/30 text-orange-400"
                                        : f.priority_label === "Medium"
                                          ? "bg-yellow-500/10 border-yellow-500/30 text-yellow-400"
                                          : "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                                  }`}
                                >
                                  {f.priority_label}
                                </span>
                              </div>
                            </div>
                            <div className="w-full bg-slate-700/50 rounded-full h-1.5 mb-2">
                              <div
                                className={`h-1.5 rounded-full transition-all ${
                                  f.priority_score >= 85
                                    ? "bg-red-500"
                                    : f.priority_score >= 65
                                      ? "bg-orange-500"
                                      : f.priority_score >= 40
                                        ? "bg-yellow-500"
                                        : "bg-emerald-500"
                                }`}
                                style={{ width: `${f.priority_score}%` }}
                              />
                            </div>
                            {f.priority_reasons?.length > 0 && (
                              <div className="flex flex-wrap gap-1 mt-1">
                                {f.priority_reasons.map(
                                  (r: string, i: number) => (
                                    <span
                                      key={i}
                                      className="text-xs bg-slate-800 border border-slate-700 text-slate-400 px-2 py-0.5 rounded-full"
                                    >
                                      {r}
                                    </span>
                                  ),
                                )}
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
                                {[
                                  "Critical",
                                  "High",
                                  "Medium",
                                  "Low",
                                  "False Positive",
                                  "Accepted Risk",
                                ].map((priority) => (
                                  <button
                                    key={priority}
                                    disabled={savingFeedbackId === f.id}
                                    onClick={() =>
                                      saveDeveloperPriority(f, priority)
                                    }
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
                                                : "bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700"
                                    }`}
                                  >
                                    {savingFeedbackId === f.id
                                      ? "Saving..."
                                      : priority}
                                  </button>
                                ))}
                              </div>
                            </div>
                          </div>
                        ))}
                    </div>
                  </div>
                </div>
              )}

              {/* AI Status message */}
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
                <div className="bg-slate-800/40 border border-violet-500/20 rounded-2xl overflow-hidden">
                  <div className="h-[2px] bg-gradient-to-r from-violet-500 to-blue-400" />
                  <div className="p-4">
                    <h3 className="font-bold text-violet-400 text-sm mb-3">
                      🛡️ AI Security Recommendations
                    </h3>
                    <div className="space-y-3">
                      {recommendations.map((rec) => (
                        <div
                          key={rec.id}
                          className="bg-slate-900/80 border border-slate-700/60 rounded-xl p-4"
                        >
                          <div className="flex items-start justify-between gap-3 mb-3">
                            <div>
                              <div className="font-bold text-sm text-violet-300 mb-1">
                                {rec.title || "Vulnerability"}
                              </div>
                              <div className="text-xs text-slate-500">
                                Finding #{rec.finding_id}
                              </div>
                            </div>
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

                          <div className="grid grid-cols-6 gap-4 w-full bg-slate-800/50 rounded-xl px-4 py-3 mb-3">
                            {rec.cvss_score && (
                              <div className="text-center">
                                <div className="text-lg font-black text-orange-400 font-mono">
                                  {rec.cvss_score}
                                </div>
                                <div className="text-xs text-slate-500">
                                  CVSS
                                </div>
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
                                      : rec.false_positive_likelihood ===
                                          "Medium"
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

                          {rec.cvss_vector && (
                            <div className="text-xs font-mono text-slate-500 bg-slate-800/60 border border-slate-700/50 px-3 py-1.5 rounded-lg mb-3">
                              {rec.cvss_vector}
                            </div>
                          )}

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
                                  className="text-xs text-blue-400 hover:text-blue-300 transition"
                                >
                                  Copy
                                </button>
                              </div>
                              <div className="bg-black/50 border border-slate-700/50 rounded-lg p-3 font-mono text-xs text-green-400 overflow-x-auto">
                                <pre>{rec.code_fix_example}</pre>
                              </div>
                            </div>
                          )}

                          <div className="flex items-center gap-2 pt-2 border-t border-slate-700/50 mt-3">
                            {rec.status === "approved" ? (
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-xs bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-2 py-1 rounded-lg">
                                  ✓ Approved
                                </span>
                                {rec.jira_pending && !rec.jira_issue_key && (
                                  <span className="text-xs text-slate-500 flex items-center gap-1">
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
                                    Creating Jira ticket…
                                  </span>
                                )}
                                {rec.jira_issue_key && rec.jira_issue_url && (
                                  <a
                                    href={rec.jira_issue_url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-xs bg-blue-500/10 border border-blue-500/30 text-blue-400 hover:bg-blue-500/20 px-2 py-1 rounded-lg transition flex items-center gap-1"
                                  >
                                    🔗 {rec.jira_issue_key}
                                  </a>
                                )}
                                {rec.status === "approved" &&
                                  !rec.jira_issue_key &&
                                  !rec.jira_pending && (
                                    <button
                                      onClick={() => retryJira(rec.id)}
                                      className="text-xs bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 px-2 py-1 rounded-lg transition"
                                    >
                                      ↺ Retry Jira
                                    </button>
                                  )}
                              </div>
                            ) : rec.status === "rejected" ? (
                              <span className="text-xs bg-slate-800 border border-slate-700 text-slate-500 px-2 py-1 rounded-lg">
                                Rejected
                              </span>
                            ) : (
                              <>
                                {isAdmin && (
                                  <button
                                    onClick={() => approve(rec.id)}
                                    className="text-xs bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1 rounded-lg transition"
                                  >
                                    Approve
                                  </button>
                                )}
                                <button
                                  onClick={() => reject(rec.id)}
                                  className="text-xs bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 px-3 py-1 rounded-lg transition"
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
                </div>
              )}

              {/* Vulnerability Sections */}
              {[
                {
                  title: "⚡ ZAP",
                  color: "text-orange-400",
                  scanner: "ZAP Scan",
                  accent: "from-orange-500 to-yellow-400",
                },
                {
                  title: "🛡️ Trivy",
                  color: "text-blue-400",
                  scanner: "Trivy Scan",
                  accent: "from-blue-500 to-teal-400",
                },
              ].map(({ title, color, scanner, accent }) => {
                const vulns = selectedRepo.vulnerabilities.filter(
                  (v) => v.scanner === scanner,
                );
                return (
                  <div
                    key={scanner}
                    className="bg-slate-800/40 border border-slate-700/50 rounded-2xl overflow-hidden"
                  >
                    <div className={`h-[2px] bg-gradient-to-r ${accent}`} />
                    <div className="p-4">
                      <div className="flex items-center gap-2 mb-3">
                        <h3 className={`font-bold text-sm ${color}`}>
                          {title}
                        </h3>
                        <span className="text-slate-500 text-xs bg-slate-800 border border-slate-700 px-2 py-0.5 rounded-full">
                          {vulns.length}
                        </span>
                      </div>
                      <div className="space-y-1.5">
                        {vulns.map((v) => (
                          <div
                            key={v.id}
                            className="flex items-center justify-between bg-slate-900/60 border border-slate-700/40 rounded-xl px-4 py-2.5 hover:border-slate-600 transition"
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
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {showUserManager && (
        <UserManagerModal
          me={me}
          users={users}
          loadingUsers={loadingUsers}
          onClose={() => setShowUserManager(false)}
          onChangeUserRole={changeUserRole}
          onDeleteUser={deleteUser}
        />
      )}
    </div>
  );
}
