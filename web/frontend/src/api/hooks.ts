import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";

export function useConfig() {
  return useQuery({
    queryKey: ["config"],
    queryFn: api.getConfig,
  });
}

export function useUpdateConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.updateConfig,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["config"] }),
  });
}

export function useResetConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.resetConfig,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["config"] }),
  });
}

export function useStatus() {
  return useQuery({
    queryKey: ["status"],
    queryFn: api.getStatus,
    refetchInterval: 15_000,
  });
}

export function useEvents(params?: Record<string, string>) {
  return useQuery({
    queryKey: ["events", params],
    queryFn: () => api.getEvents(params),
    refetchInterval: 10_000,
  });
}

export function useChartEvents() {
  return useQuery({
    queryKey: ["events", "chart"],
    queryFn: () => api.getEvents({ limit: "500" }),
    refetchInterval: 30_000,
  });
}

export function useSkills() {
  return useQuery({
    queryKey: ["skills"],
    queryFn: api.getSkills,
  });
}

export function useRemoveSkill() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.removeSkill,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["skills"] }),
  });
}

export function useSkillScans(params?: Record<string, string>) {
  return useQuery({
    queryKey: ["skillScans", params],
    queryFn: () => api.getSkillScans(params),
    refetchInterval: 10_000,
  });
}
