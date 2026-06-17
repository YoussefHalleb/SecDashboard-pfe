import type { Repository } from "../../types/dashboard";
import RepositoryCard from "./RepositoryCard";

type RepositoryGridProps = {
  repositories: Repository[];
  onViewDetails: (repo: Repository) => void;
  onDelete: (repoId: number) => void;
};

export default function RepositoryGrid({
  repositories,
  onViewDetails,
  onDelete,
}: RepositoryGridProps) {
  return (
    <>
      <div className="flex items-center gap-3">
        <h2 className="text-lg font-bold text-white">Repositories</h2>
        <span className="bg-slate-900 border border-slate-800 text-slate-500 text-xs font-mono px-2 py-0.5 rounded-full">
          {repositories.length}
        </span>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        {repositories.map((repo) => (
          <RepositoryCard
            key={repo.id}
            repo={repo}
            onViewDetails={onViewDetails}
            onDelete={onDelete}
          />
        ))}
      </div>
    </>
  );
}
