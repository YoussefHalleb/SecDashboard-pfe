import { api } from "./api";

export const rankingService = {
  getAiRanking: async (repoId: number) => {
    const res = await api.get(`/api/repositories/${repoId}/ai-rank-findings`);
    return res.data.items || [];
  },

  runAiRanking: async (repoId: number) => {
    const res = await api.post(`/api/repositories/${repoId}/ai-rank-run`);
    return res.data;
  },

  getDeveloperRanking: async (repoId: number) => {
    const res = await api.get(
      `/api/repositories/${repoId}/developer-rank-feedback`,
    );
    return res.data.items || [];
  },

  saveDeveloperRanking: async (repoId: number, items: any[]) => {
    const res = await api.post(
      `/api/repositories/${repoId}/developer-rank-feedback`,
      { items },
    );
    return res.data;
  },
};
