import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ContainerLogsSchema, OverviewSchema } from "@/lib/contracts";
import { getContainerLogs, getContainerStats, getJobs, getOverview, getResource, isPcOffline } from "@/lib/api";
import { getPowerStatus } from "@/lib/power-client";

function usePageVisible() {
  const [visible, setVisible] = useState(true);
  useEffect(() => {
    const update = () => setVisible(document.visibilityState === "visible");
    update();
    document.addEventListener("visibilitychange", update);
    return () => document.removeEventListener("visibilitychange", update);
  }, []);
  return visible;
}

export function useOverviewQuery() {
  const queryClient = useQueryClient();
  const visible = usePageVisible();
  const [streamConnected, setStreamConnected] = useState(false);
  const query = useQuery({
    queryKey: ["overview"],
    queryFn: ({ signal }) => getOverview(signal),
    retry: (count, error) => isPcOffline(error) ? false : count < 3,
    refetchInterval: (current) => current.state.data?.mode === "live" && current.state.data.status !== "not_configured" && !streamConnected ? 10_000 : false,
  });
  useEffect(() => {
    if (!visible || query.data?.mode !== "live" || query.data.status === "not_configured") return;
    let active = true;
    const source = new EventSource("/api/v1/metrics/overview/stream");
    source.onopen = () => { if (active) setStreamConnected(true); };
    source.onerror = () => { if (active) setStreamConnected(false); };
    source.onmessage = (event) => {
      try {
        queryClient.setQueryData(["overview"], OverviewSchema.parse(JSON.parse(event.data)));
      } catch {
        if (active) setStreamConnected(false);
      }
    };
    return () => { active = false; source.close(); };
  }, [query.data?.mode, query.data?.status, queryClient, visible]);
  return query;
}

export function useResourceQuery(key: string) {
  return useQuery({
    queryKey: ["resource", key],
    queryFn: ({ signal }) => getResource(key, signal),
    retry: (count, error) => isPcOffline(error) ? false : count < 3,
    refetchInterval: (query) => query.state.data?.mode === "live" && query.state.data.status !== "not_configured" ? 30_000 : false,
  });
}

export function useContainerLogsQuery(containerId: string, enabled: boolean, paused = false) {
  const queryClient = useQueryClient();
  const visible = usePageVisible();
  const [streamConnected, setStreamConnected] = useState(false);
  const query = useQuery({
    queryKey: ["container-logs", containerId],
    queryFn: ({ signal }) => getContainerLogs(containerId, signal),
    enabled,
    refetchInterval: enabled && !paused && visible && !streamConnected ? 3_000 : false,
    refetchIntervalInBackground: false,
  });
  const hasData = query.data !== undefined;
  useEffect(() => {
    if (!enabled || paused || !visible || !hasData) return;
    let active = true;
    const source = new EventSource(`/api/v1/containers/${encodeURIComponent(containerId)}/logs/stream?tail=200`);
    source.onopen = () => { if (active) setStreamConnected(true); };
    source.onerror = () => { if (active) setStreamConnected(false); };
    source.onmessage = (event) => {
      try {
        queryClient.setQueryData(
          ["container-logs", containerId],
          ContainerLogsSchema.parse(JSON.parse(event.data)),
        );
      } catch {
        if (active) setStreamConnected(false);
      }
    };
    return () => { active = false; source.close(); };
  }, [containerId, enabled, hasData, paused, query.data?.mode, queryClient, visible]);
  return query;
}

export function useContainerStatsQuery(containerId: string, enabled: boolean) {
  return useQuery({
    queryKey: ["container-stats", containerId],
    queryFn: ({ signal }) => getContainerStats(containerId, signal),
    enabled,
    refetchInterval: (query) => enabled && query.state.data?.mode === "live" && query.state.data.status === "connected" ? 10_000 : false,
    refetchIntervalInBackground: false,
  });
}

export function usePowerStatusQuery() {
  return useQuery({
    queryKey: ["power-status"],
    queryFn: ({ signal }) => getPowerStatus(signal),
    refetchInterval: 5_000,
    retry: false,
  });
}

export function useJobsQuery(enabled: boolean) {
  return useQuery({
    queryKey: ["jobs"],
    queryFn: ({ signal }) => getJobs(signal),
    enabled,
  });
}

