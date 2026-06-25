import { OTTopologyView } from '@/components/cni/OTTopologyView';

export const metadata = { title: 'OT/ICS Network Topology' };
export const dynamic = 'force-dynamic';
export const revalidate = 0;

export default function OTTopologyPage() {
  return <OTTopologyView />;
}
