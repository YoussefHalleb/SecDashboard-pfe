type DashboardHeaderProps = {
  isAdmin: boolean;
  onOpenUsers: () => void;
  onLogout: () => void;
};

export default function DashboardHeader({
  isAdmin,
  onOpenUsers,
  onLogout,
}: DashboardHeaderProps) {
  return (
    <nav className="border-b border-slate-800 bg-slate-950/85 backdrop-blur sticky top-0 z-10">
      <div className="h-[3px] bg-gradient-to-r from-emerald-500 via-blue-500 to-violet-500" />

      <div className="max-w-7xl mx-auto px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-400 to-emerald-600 flex items-center justify-center text-sm font-black text-slate-900 shadow-lg shadow-emerald-500/20">
            C
          </div>

          <span className="font-bold text-white tracking-tight">CodeCure</span>

          <span className="text-slate-700 text-sm hidden sm:block">/</span>

          <span className="text-slate-500 text-sm hidden sm:block">
            Dashboard
          </span>
        </div>

        <div className="flex items-center gap-2">
          {isAdmin && (
            <button
              onClick={onOpenUsers}
              className="flex items-center gap-2 text-slate-400 hover:text-white text-sm px-3 py-1.5 rounded-lg hover:bg-slate-800 border border-transparent hover:border-slate-700 transition"
            >
              👥 Users
            </button>
          )}

          <button
            onClick={onLogout}
            className="flex items-center gap-2 text-slate-400 hover:text-white text-sm px-3 py-1.5 rounded-lg hover:bg-slate-800 border border-transparent hover:border-slate-700 transition"
          >
            <span>⎋</span> Logout
          </button>
        </div>
      </div>
    </nav>
  );
}
