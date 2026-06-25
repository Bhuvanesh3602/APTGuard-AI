import { CorrelationView } from '@/components/cni/CorrelationView';

export const metadata = { title: 'Cross-Signal Correlation' };
export const dynamic = 'force-dynamic';
export const revalidate = 0;

export default function CorrelationPage() {
  return <CorrelationView />;
}
