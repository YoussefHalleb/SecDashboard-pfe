import { useState } from "react";
import { resetPassword } from "../services/api";

export default function ResetPassword() {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const token = new URLSearchParams(window.location.search).get("token");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    setError("");
    setMessage("");

    if (!token) {
      setError("Token manquant.");
      return;
    }

    if (password.length < 8) {
      setError("Le mot de passe doit contenir au moins 8 caractères.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Les mots de passe ne correspondent pas.");
      return;
    }

    setLoading(true);

    try {
      await resetPassword(token, password);
      setMessage(
        "Mot de passe modifié avec succès. Vous pouvez maintenant vous connecter.",
      );
    } catch (err: any) {
      setError(
        err.response?.data?.error || "Erreur lors de la réinitialisation.",
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950">
      <div className="w-full max-w-md mx-4 bg-slate-900 border border-slate-800 rounded-2xl p-8">
        <h2 className="text-xl font-bold text-white mb-2">
          Nouveau mot de passe
        </h2>

        <p className="text-slate-500 text-sm mb-6">
          Entrez votre nouveau mot de passe.
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="password"
            placeholder="Nouveau mot de passe"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full bg-slate-800 border border-slate-700 text-white placeholder-slate-500 rounded-xl px-4 py-2.5"
          />

          <input
            type="password"
            placeholder="Confirmer le mot de passe"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            className="w-full bg-slate-800 border border-slate-700 text-white placeholder-slate-500 rounded-xl px-4 py-2.5"
          />

          {error && (
            <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-xs px-3 py-2.5 rounded-xl">
              {error}
            </div>
          )}

          {message && (
            <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs px-3 py-2.5 rounded-xl">
              {message}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 text-white font-semibold text-sm py-2.5 rounded-xl"
          >
            {loading ? "Modification..." : "Modifier le mot de passe"}
          </button>
        </form>
      </div>
    </div>
  );
}
