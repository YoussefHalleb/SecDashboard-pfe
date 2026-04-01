import { useState } from "react";
import { register } from "../services/api";

type RegisterProps = {
  onSwitchToLogin: () => void;
};

export default function Register({ onSwitchToLogin }: RegisterProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");

    if (password !== confirm) {
      setError("Les mots de passe ne correspondent pas");
      return;
    }

    if (password.length < 8) {
      setError("Le mot de passe doit contenir au moins 8 caractères");
      return;
    }

    setLoading(true);
    try {
      await register(email, password);
      window.location.reload();
    } catch (err: any) {
      setError(err.response?.data?.error || "Erreur lors de l'inscription");
    } finally {
      setLoading(false);
    }
  }

  const passwordStrength = () => {
    if (password.length === 0) return null;
    if (password.length < 6)
      return { label: "Faible", color: "bg-red-500", width: "w-1/4" };
    if (password.length < 8)
      return { label: "Moyen", color: "bg-yellow-500", width: "w-2/4" };
    if (password.length < 12)
      return { label: "Bon", color: "bg-emerald-500", width: "w-3/4" };
    return { label: "Fort", color: "bg-emerald-400", width: "w-full" };
  };

  const strength = passwordStrength();

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 relative overflow-hidden">
      {/* Background effects */}
      <div className="absolute inset-0 bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900" />
      <div className="absolute top-1/4 right-1/4 w-96 h-96 bg-violet-500/5 rounded-full blur-3xl" />
      <div className="absolute bottom-1/4 left-1/4 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl" />

      {/* Card */}
      <div className="relative w-full max-w-md mx-4">
        {/* Top accent */}
        <div className="h-1 bg-gradient-to-r from-violet-500 via-blue-500 to-emerald-500 rounded-t-2xl" />

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

          <h2 className="text-xl font-bold text-white mb-1">Créer un compte</h2>
          <p className="text-slate-500 text-sm mb-6">
            Rejoignez la plateforme DevSecOps
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

              {/* Password strength */}
              {strength && (
                <div className="mt-2">
                  <div className="h-1 bg-slate-700 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-300 ${strength.color} ${strength.width}`}
                    />
                  </div>
                  <p
                    className={`text-xs mt-1 ${
                      strength.label === "Faible"
                        ? "text-red-400"
                        : strength.label === "Moyen"
                          ? "text-yellow-400"
                          : "text-emerald-400"
                    }`}
                  >
                    Force : {strength.label}
                  </p>
                </div>
              )}
            </div>

            {/* Confirm password */}
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Confirmer le mot de passe
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-sm">
                  🔒
                </span>
                <input
                  type={showConfirm ? "text" : "password"}
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  required
                  placeholder="••••••••"
                  className={`w-full bg-slate-800/80 border text-white placeholder-slate-600 text-sm rounded-xl pl-9 pr-10 py-2.5 focus:outline-none focus:ring-1 transition ${
                    confirm && password !== confirm
                      ? "border-red-500/50 focus:border-red-500/70 focus:ring-red-500/30"
                      : confirm && password === confirm
                        ? "border-emerald-500/50 focus:border-emerald-500/70 focus:ring-emerald-500/30"
                        : "border-slate-700 focus:border-emerald-500/70 focus:ring-emerald-500/30"
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirm(!showConfirm)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 text-xs transition"
                >
                  {showConfirm ? "🙈" : "👁"}
                </button>
                {confirm && (
                  <span className="absolute right-8 top-1/2 -translate-y-1/2 text-sm">
                    {password === confirm ? "✅" : "❌"}
                  </span>
                )}
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
                  Création...
                </>
              ) : (
                "Créer mon compte →"
              )}
            </button>
          </form>

          {/* Switch */}
          <div className="mt-6 pt-5 border-t border-slate-800 text-center">
            <span className="text-slate-500 text-sm">Déjà un compte ? </span>
            <button
              type="button"
              onClick={onSwitchToLogin}
              className="text-emerald-400 hover:text-emerald-300 text-sm font-semibold transition"
            >
              Se connecter
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
