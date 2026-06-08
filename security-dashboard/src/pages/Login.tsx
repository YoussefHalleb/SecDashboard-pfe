import { useState } from "react";
import { login, forgotPassword } from "../services/api";

type LoginProps = {
  onSwitchToRegister: () => void;
};

export default function Login({ onSwitchToRegister }: LoginProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [resetEmailSent, setResetEmailSent] = useState(false);

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
  async function handleForgotPassword() {
    setError("");
    setResetEmailSent(false);

    if (!email) {
      setError(
        "Veuillez entrer votre email avant de cliquer sur mot de passe oublié.",
      );
      return;
    }

    setLoading(true);

    try {
      await forgotPassword(email);
      setResetEmailSent(true);
    } catch (err: any) {
      setError(
        err.response?.data?.error ||
          "Impossible d’envoyer l’email de réinitialisation.",
      );
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
      {/* Subtle grid overlay */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage:
            "linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      {/* Card */}
      <div className="relative w-full max-w-md mx-4">
        {/* Top accent */}
        <div className="h-[3px] bg-gradient-to-r from-emerald-500 via-blue-500 to-violet-500 rounded-t-2xl" />

        <div className="bg-slate-900/95 border border-slate-800 border-t-0 rounded-b-2xl p-8 shadow-2xl backdrop-blur-sm">
          {/* Logo */}
          <div className="flex items-center justify-center gap-3 mb-8">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-400 to-emerald-600 flex items-center justify-center text-slate-900 font-black text-lg shadow-lg shadow-emerald-500/20">
              C
            </div>
            <div>
              <div className="font-bold text-white text-lg leading-none tracking-tight">
                CodeCure
              </div>
              <div className="text-slate-500 text-xs">Security Platform</div>
            </div>
          </div>

          <h2 className="text-xl font-bold text-white mb-1">Connexion</h2>
          <p className="text-slate-500 text-sm mb-6">
            Bienvenue, entrez vos identifiants
          </p>

          {/* ── GOOGLE BUTTON ── */}
          <a
            href={`${import.meta.env.VITE_API_URL || ""}/auth/google`}
            className="w-full flex items-center justify-center gap-3 bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-slate-200 font-semibold text-sm py-2.5 rounded-xl transition-all duration-200 mb-5 group"
          >
            {/* Google SVG logo */}
            <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
              />
            </svg>
            Continuer avec Google
          </a>

          {/* Divider */}
          <div className="flex items-center gap-3 mb-5">
            <div className="flex-1 h-px bg-slate-800" />
            <span className="text-slate-600 text-xs font-medium">
              ou par email
            </span>
            <div className="flex-1 h-px bg-slate-800" />
          </div>
          {resetEmailSent && (
            <div className="mb-4 flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs px-3 py-2.5 rounded-xl">
              <span>✓</span>
              <span>
                Email de réinitialisation envoyé. Vérifiez votre boîte mail.
              </span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email */}
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Email
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-sm select-none">
                  ✉
                </span>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  placeholder="vous@exemple.com"
                  className="w-full bg-slate-800 border border-slate-700 text-white placeholder-slate-600 text-sm rounded-xl pl-9 pr-4 py-2.5 focus:outline-none focus:border-emerald-500/70 focus:ring-1 focus:ring-emerald-500/20 transition"
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Mot de passe
                </label>
                <button
                  type="button"
                  onClick={handleForgotPassword}
                  disabled={loading}
                  className="text-xs text-emerald-500 hover:text-emerald-400 disabled:text-slate-600 transition"
                >
                  Mot de passe oublié ?
                </button>
              </div>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-sm select-none">
                  🔒
                </span>
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  placeholder="••••••••"
                  className="w-full bg-slate-800 border border-slate-700 text-white placeholder-slate-600 text-sm rounded-xl pl-9 pr-10 py-2.5 focus:outline-none focus:border-emerald-500/70 focus:ring-1 focus:ring-emerald-500/20 transition"
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
              className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 disabled:cursor-not-allowed text-white font-semibold text-sm py-2.5 rounded-xl transition-all duration-200 flex items-center justify-center gap-2 mt-1 shadow-lg shadow-emerald-500/10 hover:shadow-emerald-500/20"
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

          {/* Switch to register */}
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
          CodeCure Platform © 2025
        </p>
      </div>
    </div>
  );
}
