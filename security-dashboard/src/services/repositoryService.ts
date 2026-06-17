import { api } from "./api";

export const repositoryService = {
  getAll: async () => {
    const res = await api.get("/api/repositories");
    return res.data;
  },

  delete: async (repoId: number) => {
    const res = await api.delete(`/api/products/${repoId}`);
    return res.data;
  },

  getZapReportUrl: (repoId: number) => {
    return `/api/products/${repoId}/zap-report`;
  },
};
