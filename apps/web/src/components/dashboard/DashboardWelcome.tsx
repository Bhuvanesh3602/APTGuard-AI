'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

/**
 * Empty-state coaching banner shown after the "Skip & explore" CTA on the
 * onboarding root page (WS-A2). Triggered by `?welcome=1`.
 *
 * The banner explains the three highest-leverage next steps an operator can
 * take from a cold dashboard, then self-clears the querystring so a refresh
 * doesn't re-trigger it. We deliberately keep this lightweight — WS-F5 owns
 * the deep empty-state polish for every list view.
 */
export function DashboardWelcome() {
  const router = useRouter();
  const params = useSearchParams();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (params?.get('welcome') === '1') setOpen(true);
  }, [params]);

  const dismiss = () => {
    setOpen(false);
    // Drop the querystring so a refresh / share-link doesn't keep re-mounting
    // the banner. We keep the path intact and use a shallow replace so the
    // dashboard doesn't re-fetch its SWR data.
    if (typeof window !== 'undefined') {
      const url = new URL(window.location.href);
      url.searchParams.delete('welcome');
      router.replace(`${url.pathname}${url.search ? `?${url.searchParams.toString()}` : ''}`);
    }
  };

  if (!open) return null;

  return (
    <section
      role="region"
      aria-label="Welcome to AiSOC"
      data-testid="dashboard-welcome"
      className="rounded-xl border border-brand-400/30 bg-gradient-to-br from-brand-500/10 to-brand-700/5 p-5"
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-brand-300">
            Welcome to AiSOC
          </p>
          <h2 className="mt-1 text-lg font-semibold text-fg-primary">
            You&apos;re looking at a clean console. Here&apos;s how to make it useful.
          </h2>
        </div>
        <button
          type="button"
          onClick={dismiss}
          aria-label="Dismiss welcome message"
          className="rounded-md p-1.5 text-fg-muted transition hover:bg-surface-hover hover:text-fg-primary"
        >
          <svg viewBox="0 0 20 20" className="h-4 w-4" fill="currentColor" aria-hidden="true">
            <path d="M6.28 5.22a.75.75 0 011.06 0L10 7.88l2.66-2.66a.75.75 0 111.06 1.06L11.06 8.94l2.66 2.66a.75.75 0 11-1.06 1.06L10 10l-2.66 2.66a.75.75 0 11-1.06-1.06l2.66-2.66-2.66-2.66a.75.75 0 010-1.06z" />
          </svg>
        </button>
      </div>

      <ul className="mt-4 grid gap-3 sm:grid-cols-3">
        <Tip
          step="1"
          title="Connect a source"
          body="Pick from 26 vendors. EDR + cloud + IAM gives the agent enough signal to start triaging."
          cta={{ label: 'Open the connector gallery →', href: '/onboarding' }}
        />
        <Tip
          step="2"
          title="Or load the demo seed"
          body="Run pnpm seed:demo and refresh. You'll get an in-flight LockBit case to investigate."
          cta={{ label: 'Open a sample case →', href: '/cases/INC-RT-001?tab=ledger' }}
        />
        <Tip
          step="3"
          title="Browse playbooks"
          body="25 named runbooks for ransomware, BEC, account takeover, cloud-TO, and more."
          cta={{ label: 'Open the playbook gallery →', href: '/playbooks' }}
        />
      </ul>
    </section>
  );
}

function Tip({
  step,
  title,
  body,
  cta,
}: {
  step: string;
  title: string;
  body: string;
  cta: { label: string; href: string };
}) {
  return (
    <li className="rounded-lg border border-surface-border bg-surface-card/60 p-4">
      <div className="flex items-center gap-2">
        <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-brand-500/20 text-xs font-bold text-brand-200">
          {step}
        </span>
        <h3 className="text-sm font-semibold text-fg-primary">{title}</h3>
      </div>
      <p className="mt-2 text-xs leading-relaxed text-fg-muted">{body}</p>
      <Link href={cta.href} className="mt-3 inline-block text-xs font-semibold text-brand-300 hover:text-brand-200">
        {cta.label}
      </Link>
    </li>
  );
}
