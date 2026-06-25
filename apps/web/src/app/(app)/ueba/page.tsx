import { UEBAView } from '@/components/cni/UEBAView';

export const metadata = { title: 'Behavioural Anomaly Detection (UEBA)' };
export const dynamic = 'force-dynamic';
export const revalidate = 0;

export default function UEBAPage() {
  return <UEBAView />;
}
