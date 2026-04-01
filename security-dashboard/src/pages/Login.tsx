import { useState } from "react";
import { login } from "../services/api";

type LoginProps = {
  onSwitchToRegister: () => void;
};

export default function Login({ onSwitchToRegister }: LoginProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(email, password);
      window.location.reload();
    } catch (err: any) {
      setError(err.response?.data?.error || "Email ou mot de passe incorrect");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 relative overflow-hidden">
      {/* Background effects */}
      <div className="absolute inset-0 bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900" />
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl" />

      {/* Card */}
      <div className="relative w-full max-w-md mx-4">
        {/* Top accent */}
        <div className="h-1 bg-gradient-to-r from-emerald-500 via-blue-500 to-violet-500 rounded-t-2xl" />

        <div className="bg-slate-900 border border-slate-800 border-t-0 rounded-b-2xl p-8 shadow-2xl">
          {/* Logo */}
          <div className="flex items-center justify-center gap-3 mb-8">
            <div className="w-10 h-10 rounded-xl bg-emerald-500 flex items-center justify-center text-slate-900 font-black text-lg">
              D
            </div>
            <div>
              <div className="font-bold text-white text-lg leading-none">
                DevSecOps
              </div>
              <div className="text-slate-500 text-xs">Security Platform</div>
            </div>
          </div>

          <h2 className="text-xl font-bold text-white mb-1">Connexion</h2>
          <p className="text-slate-500 text-sm mb-6">
            Bienvenue, entrez vos identifiants
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email */}
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Email
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-sm">
                  ✉
                </span>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  placeholder="vous@exemple.com"
                  className="w-full bg-slate-800/80 border border-slate-700 text-white placeholder-slate-600 text-sm rounded-xl pl-9 pr-4 py-2.5 focus:outline-none focus:border-emerald-500/70 focus:ring-1 focus:ring-emerald-500/30 transition"
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Mot de passe
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-sm">
                  🔒
                </span>
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  placeholder="••••••••"
                  className="w-full bg-slate-800/80 border border-slate-700 text-white placeholder-slate-600 text-sm rounded-xl pl-9 pr-10 py-2.5 focus:outline-none focus:border-emerald-500/70 focus:ring-1 focus:ring-emerald-500/30 transition"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 text-xs transition"
                >
                  {showPassword ? "🙈" : "👁"}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 text-red-400 text-xs px-3 py-2.5 rounded-xl">
                <span>⚠</span>
                <span>{error}</span>
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 disabled:cursor-not-allowed text-white font-semibold text-sm py-2.5 rounded-xl transition-all duration-200 flex items-center justify-center gap-2 mt-2"
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
                  Connexion...
                </>
              ) : (
                "Se connecter →"
              )}
            </button>
          </form>

          {/* Switch */}
          <div className="mt-6 pt-5 border-t border-slate-800 text-center">
            <span className="text-slate-500 text-sm">
              Pas encore de compte ?{" "}
            </span>
            <button
              type="button"
              onClick={onSwitchToRegister}
              className="text-emerald-400 hover:text-emerald-300 text-sm font-semibold transition"
            >
              S'inscrire
            </button>
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-slate-600 text-xs mt-4">
          DevSecOps Platform © 2025
        </p>
      </div>
    </div>
  );
}
