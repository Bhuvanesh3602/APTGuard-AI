import { CERTInComplianceView } from '@/components/cni/CERTInComplianceView';

export const metadata = { title: 'CERT-In 6-Hour Compliance' };
export const dynamic = 'force-dynamic';
export const revalidate = 0;

export default function CERTInCompliancePage() {
  return <CERTInComplianceView />;
}
