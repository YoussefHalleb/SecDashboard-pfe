export default function SeverityBadge({ severity }: { severity: string }) {
  const cls: Record<string, string> = {
    Critical: "bg-red-500/10 border-red-500/30 text-red-400",
    High: "bg-orange-500/10 border-orange-500/30 text-orange-400",
    Medium: "bg-yellow-500/10 border-yellow-500/30 text-yellow-400",
    Low: "bg-emerald-500/10 border-emerald-500/30 text-emerald-400",
  };

  return (
    <span
      className={`border text-xs font-semibold px-2.5 py-1 rounded-lg ${
        cls[severity] || "bg-slate-800 border-slate-700 text-slate-300"
      }`}
    >
      {severity}
    </span>
  );
}
