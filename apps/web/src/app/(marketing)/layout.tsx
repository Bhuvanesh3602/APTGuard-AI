import type { ReactNode } from 'react';
import { velvetFontVariables } from '@/lib/marketing-fonts';

/**
 * Marketing route-group layout (T7.1 VelvetEdge retheme).
 *
 * Scopes the velvet jewel-tone fonts (DM Serif Display / Poppins /
 * Source Code Pro) and the `.velvet-root` CSS-variable boundary to
 * the marketing surfaces (`/sovereign`, `/customers`, `/blog`,
 * `/waitlist`) so they share the look of the root landing at `/`.
 *
 * The console (`/alerts`, `/cases`, …) lives in the `(app)` route
 * group, which has its own layout.tsx and is unaffected.
 */
export default function MarketingLayout({ children }: { children: ReactNode }) {
  return (
    <div
      data-theme="dark"
      className={`velvet-root relative min-h-screen bg-velvet-surface-base font-velvet-body text-velvet-content-primary ${velvetFontVariables}`}
    >
      {children}
    </div>
  );
}
