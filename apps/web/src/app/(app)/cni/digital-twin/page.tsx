import { DigitalTwinView } from '@/components/cni/DigitalTwinView';

export const metadata = {
  title: 'Digital Twin Attack Simulator',
};

export const dynamic = 'force-dynamic';
export const revalidate = 0;

export default function DigitalTwinPage() {
  return <DigitalTwinView />;
}
