import { RemediationQueueView } from '@/components/cni/RemediationQueueView';

export const metadata = { title: 'Vulnerability Prioritisation Queue' };
export const dynamic = 'force-dynamic';
export const revalidate = 0;

export default function RemediationPage() {
  return <RemediationQueueView />;
}
