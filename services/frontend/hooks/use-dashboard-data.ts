import { useState, useEffect } from 'react';
import { fetchDashboard } from '@/lib/api';
import { DashboardData } from '@/lib/types';
import { useDashboardContext } from '@/contexts/dashboard-context';


export function useDashboardData() {
  const { selectedTarget, setSelectedTarget, refreshKey } = useDashboardContext();
  const [data, setData] = useState<DashboardData>({ targets: [], findings: [], metrics: { critical: 0, intel: 0, shadow: 0 } });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    
    const load = async () => {
      try {
        const result = await fetchDashboard(selectedTarget);
        if (isMounted) {
          setData(result);
          // Auto-select first target
          if (!selectedTarget && result.targets.length > 0) {
            setSelectedTarget(result.targets[0].domain);
          }
        }
      } catch (e) {
        console.error(e);
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    load();
    const interval = setInterval(load, 4000); // Poll every 4s
    return () => { isMounted = false; clearInterval(interval); };
  }, [selectedTarget, refreshKey, setSelectedTarget]);

  return { data, loading };
}