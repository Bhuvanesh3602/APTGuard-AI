import { APTIntelligenceView } from '@/components/cni/APTIntelligenceView';

export const metadata = { title: 'India APT Intelligence' };
export const dynamic = 'force-dynamic';
export const revalidate = 0;

export default function APTIntelligencePage() {
  return <APTIntelligenceView />;
}
