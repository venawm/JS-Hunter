'use client';

import { createContext, useContext, useState, ReactNode } from 'react';

interface DashboardContextType {
  refreshKey: number;
  triggerRefresh: () => void;
  selectedTarget: string;
  setSelectedTarget: (t: string) => void;
}

const DashboardContext = createContext<DashboardContextType | undefined>(undefined);

export function DashboardProvider({ children }: { children: ReactNode }) {
  const [refreshKey, setRefreshKey] = useState(0);
  const [selectedTarget, setSelectedTarget] = useState('');

  return (
    <DashboardContext.Provider value={{ 
      refreshKey, 
      triggerRefresh: () => setRefreshKey(p => p + 1),
      selectedTarget,
      setSelectedTarget
    }}>
      {children}
    </DashboardContext.Provider>
  );
}

export const useDashboardContext = () => {
  const context = useContext(DashboardContext);
  if (!context) throw new Error("useDashboardContext must be used within provider");
  return context;
};