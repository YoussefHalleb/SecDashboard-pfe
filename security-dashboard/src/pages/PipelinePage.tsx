import { useState } from "react";

type Props = {
  onFinish: () => void;
};

export default function PipelinePage({ onFinish }: Props) {
  const [repoUrl, setRepoUrl] = useState("");
  const [repoBranch, setRepoBranch] = useState("main");
  const [appPort, setAppPort] = useState("80");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage("");
    setError("");

    try {
      const res = await fetch("http://localhost:5000/api/pipeline/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          repo_url: repoUrl,
          repo_branch: repoBranch,
          app_port: appPort,
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Erreur lors du lancement");

      setMessage("Pipeline lancé avec succès.");
      setRepoUrl("");
      setRepoBranch("main");
      setAppPort("80");

      setTimeout(() => onFinish(), 1000);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 rounded-2xl p-6 border border-slate-700/50 shadow-xl">
      {/* Header */}
      <div className="flex items-center gap-3 mb-5">
        <div className="w-8 h-8 rounded-lg bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-base">
          ⚡
        </div>
        <div>
          <h2 className="text-white font-bold text-base leading-tight">
            Lancer un Pipeline
          </h2>
          <p className="text-slate-400 text-xs">DevSecOps · Scan automatisé</p>
        </div>

        {/* Status dots */}
        <div className="ml-auto flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-emerald-400 text-xs font-mono">READY</span>
        </div>
      </div>

      {/* Form */}
      <form onSubmit={handleSubmit} className="space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Repo URL */}
          <div className="md:col-span-1 relative group">
            <label className="block text-xs font-semibold text-slate-400 mb-1 uppercase tracking-wider">
              Repository URL
            </label>
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-sm">
                🔗
              </span>
              <input
                type="text"
                placeholder="https://github.com/..."
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                required
                className="w-full bg-slate-800/80 border border-slate-600/60 text-white placeholder-slate-500 text-sm rounded-lg pl-9 pr-3 py-2.5 focus:outline-none focus:border-emerald-500/70 focus:ring-1 focus:ring-emerald-500/30 transition"
              />
            </div>
          </div>

          {/* Branch */}
          <div className="relative group">
            <label className="block text-xs font-semibold text-slate-400 mb-1 uppercase tracking-wider">
              Branch
            </label>
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-sm">
                🌿
              </span>
              <input
                type="text"
                placeholder="main"
                value={repoBranch}
                onChange={(e) => setRepoBranch(e.target.value)}
                className="w-full bg-slate-800/80 border border-slate-600/60 text-white placeholder-slate-500 text-sm rounded-lg pl-9 pr-3 py-2.5 focus:outline-none focus:border-emerald-500/70 focus:ring-1 focus:ring-emerald-500/30 transition"
              />
            </div>
          </div>

          {/* Port */}
          <div className="relative group">
            <label className="block text-xs font-semibold text-slate-400 mb-1 uppercase tracking-wider">
              Port
            </label>
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-sm">
                🔌
              </span>
              <input
                type="text"
                placeholder="80"
                value={appPort}
                onChange={(e) => setAppPort(e.target.value)}
                className="w-full bg-slate-800/80 border border-slate-600/60 text-white placeholder-slate-500 text-sm rounded-lg pl-9 pr-3 py-2.5 focus:outline-none focus:border-emerald-500/70 focus:ring-1 focus:ring-emerald-500/30 transition"
              />
            </div>
          </div>
        </div>

        {/* Submit */}
        <div className="flex items-center gap-3 pt-1">
          <button
            type="submit"
            disabled={loading}
            className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-600 disabled:cursor-not-allowed text-white font-semibold text-sm px-5 py-2.5 rounded-lg transition-all duration-200 shadow-lg shadow-emerald-900/30"
          >
            {loading ? (
              <>
                <svg
                  className="w-4 h-4 animate-spin"
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
                Lancement...
              </>
            ) : (
              <>
                <span>▶</span>
                Lancer le pipeline
              </>
            )}
          </button>

          {/* Feedback inline */}
          {message && (
            <span className="flex items-center gap-1.5 text-emerald-400 text-sm font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              {message}
            </span>
          )}
          {error && (
            <span className="flex items-center gap-1.5 text-red-400 text-sm font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
              {error}
            </span>
          )}
        </div>
      </form>
    </div>
  );
}
