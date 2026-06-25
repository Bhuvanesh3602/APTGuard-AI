'use client';

import { useEffect, useState } from 'react';
import { usePathname } from 'next/navigation';
import { SWRConfig } from 'swr';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { CommandPalette } from './CommandPalette';
import { TimeWindowProvider } from './TimeWindowProvider';
import { TenantProvider } from './TenantProvider';
import { CopilotDock } from '@/components/copilot/CopilotDock';
import { DemoBanner } from '@/components/demo/DemoBanner';
import { DemoAutoLogin } from '@/components/demo/DemoAutoLogin';
import { ClientOnly } from '@/components/util/ClientOnly';
import { isDemoMode } from '@/lib/demoMode';

// Thin top progress bar that fires on every route change
function NavProgressBar() {
  const pathname = usePathname();
  const [width, setWidth] = useState(0);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    setVisible(true);
    setWidth(0);
    // Quick ramp: 0 → 30 → 75 → 100, then fade out
    const t1 = setTimeout(() => setWidth(30), 10);
    const t2 = setTimeout(() => setWidth(75), 150);
    const t3 = setTimeout(() => setWidth(100), 400);
    const t4 = setTimeout(() => setVisible(false), 600);
    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
    };
  }, [pathname]);

  return (
    <div
      className="fixed top-0 left-0 z-[9999] h-[2px] bg-brand-400 transition-all ease-out"
      style={{
        width: `${width}%`,
        transitionDuration: width === 100 ? '200ms' : '400ms',
        opacity: visible ? 1 : 0,
      }}
    />
  );
}

interface AppShellProps {
  children: React.ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  const demo = isDemoMode();
  const topPadClass = demo ? 'pt-[100px]' : 'pt-16';

  return (
    <SWRConfig value={{ revalidateOnMount: true, revalidateIfStale: true }}>
      <NavProgressBar />
      <DemoAutoLogin />
      <TimeWindowProvider>
        <TenantProvider>
          <div className="min-h-screen bg-surface-base">
            <ClientOnly>
              <DemoBanner />
            </ClientOnly>
            <Sidebar />
            <div className="md:ml-60">
              <TopBar demoOffset={demo} />
              <main className={`${topPadClass} min-h-screen`}>
                <div className="p-6">{children}</div>
              </main>
            </div>
            <ClientOnly>
              <CopilotDock />
            </ClientOnly>
            <ClientOnly>
              <CommandPalette />
            </ClientOnly>
          </div>
        </TenantProvider>
      </TimeWindowProvider>
    </SWRConfig>
  );
}
