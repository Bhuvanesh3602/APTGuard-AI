'use client';

import dynamic from 'next/dynamic';

const AttackGraphView = dynamic(
  () =>
    import('@/components/graph/AttackGraphView').then(
      (m) => m.AttackGraphView,
    ),
  {
    ssr: false,
    loading: () => (
      <div className="flex h-[60vh] items-center justify-center text-gray-400">
        Loading attack graph…
      </div>
    ),
  },
);

export default function AttackGraphClient() {
  return <AttackGraphView />;
}
