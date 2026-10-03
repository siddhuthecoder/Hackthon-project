'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

export interface UseApiResult<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

export function useApi<T>(
  fetcher: () => Promise<T>,
  deps: ReadonlyArray<unknown> = [],
  pollMs?: number
): UseApiResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  useEffect(() => {
    let cancelled = false;
    const run = async (initial: boolean) => {
      if (initial) setLoading(true);
      try {
        const result = await fetcherRef.current();
        if (cancelled) return;
        setData(result);
        setError(null);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Request failed');
      } finally {
        if (!cancelled && initial) setLoading(false);
      }
    };
    void run(true);
    const timer = pollMs ? setInterval(() => void run(false), pollMs) : null;
    return () => {
      cancelled = true;
      if (timer) clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, pollMs, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading, reload };
}
