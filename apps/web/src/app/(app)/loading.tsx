/**
 * Route-segment loading fallback shared by every page under (app).
 *
 * The App Router renders this on the client the instant a sidebar link is
 * clicked, while the destination route's RSC payload — and, under `next dev`,
 * its just-in-time compilation — resolves. The persistent shell (Sidebar /
 * TopBar) stays mounted from the layout; only this content area swaps to the
 * skeleton. Without it, a click felt unresponsive in dev because nothing
 * painted until the new route was fully ready. The skeleton makes navigation
 * feel immediate.
 */
export default function Loading() {
  return (
    <div className="p-6 animate-pulse" aria-busy="true" aria-label="Loading page">
      {/* Title + subtitle */}
      <div className="mb-6">
        <div className="h-7 w-56 rounded-md bg-surface-hover" />
        <div className="mt-2 h-4 w-80 rounded bg-surface-hover/60" />
      </div>

      {/* KPI tiles */}
      <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="h-24 rounded-xl border border-surface-border bg-surface-card"
          />
        ))}
      </div>

      {/* Content panels */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="h-72 rounded-xl border border-surface-border bg-surface-card lg:col-span-2" />
        <div className="h-72 rounded-xl border border-surface-border bg-surface-card" />
      </div>
    </div>
  );
}
