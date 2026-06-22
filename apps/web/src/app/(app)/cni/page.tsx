import { CNIDashboard } from '@/components/cni/CNIDashboard';

export const metadata = {
  title: 'India CNI Threat Dashboard',
};

export const dynamic = 'force-dynamic';
export const revalidate = 0;

export default function CNIPage() {
  return <CNIDashboard />;
}
