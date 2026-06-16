interface UserManagerModalProps {
  me: any;
  users: any[];
  loadingUsers: boolean;
  onClose: () => void;
  onChangeUserRole: (userId: number, newRole: string) => void;
  onDeleteUser: (userId: number) => void;
}

export default function UserManagerModal({
  me,
  users,
  loadingUsers,
  onClose,
  onChangeUserRole,
  onDeleteUser,
}: UserManagerModalProps) {
  return (
    <div className="fixed inset-0 bg-black/75 backdrop-blur-sm flex justify-center items-center z-50 p-4">
      <div className="bg-slate-900/98 border border-slate-800 w-full max-w-2xl rounded-2xl shadow-2xl flex flex-col max-h-[80vh] overflow-hidden">
        <div className="h-[3px] bg-gradient-to-r from-emerald-500 via-blue-500 to-violet-500 shrink-0" />

        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 shrink-0">
          <div>
            <h2 className="font-bold text-white text-lg">👥 User Manager</h2>
            <p className="text-slate-500 text-xs">Gérer les rôles et accès</p>
          </div>

          <button
            onClick={onClose}
            className="w-8 h-8 flex items-center justify-center rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-400 hover:text-white transition text-lg"
          >
            ×
          </button>
        </div>

        <div className="overflow-y-auto flex-1 p-6">
          {loadingUsers ? (
            <div className="flex items-center gap-2 text-slate-400 text-sm">
              <svg
                className="w-4 h-4 animate-spin text-emerald-500"
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
              Loading users...
            </div>
          ) : (
            <div className="space-y-3">
              {users.map((u) => (
                <div
                  key={u.id}
                  className="bg-slate-800/60 border border-slate-700/60 rounded-xl px-4 py-3 flex items-center justify-between gap-4"
                >
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-semibold text-white truncate">
                      {u.email}
                    </div>
                    <div className="text-xs text-slate-500 mt-0.5">
                      Créé le {new Date(u.created_at).toLocaleDateString()}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span
                      className={`text-xs font-bold px-2 py-0.5 rounded border ${
                        u.role === "admin"
                          ? "bg-violet-500/10 border-violet-500/30 text-violet-400"
                          : "bg-slate-700 border-slate-600 text-slate-300"
                      }`}
                    >
                      {u.role}
                    </span>

                    {u.id !== me?.id && (
                      <button
                        onClick={() =>
                          onChangeUserRole(
                            u.id,
                            u.role === "admin" ? "developer" : "admin",
                          )
                        }
                        className="text-xs bg-blue-500/10 border border-blue-500/30 text-blue-400 hover:bg-blue-500/20 px-2 py-1 rounded-lg transition"
                      >
                        {u.role === "admin" ? "→ Developer" : "→ Admin"}
                      </button>
                    )}

                    {u.id !== me?.id && (
                      <button
                        onClick={() => onDeleteUser(u.id)}
                        className="text-xs bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20 px-2 py-1 rounded-lg transition"
                      >
                        🗑️
                      </button>
                    )}

                    {u.id === me?.id && (
                      <span className="text-xs text-slate-500 px-2">vous</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
