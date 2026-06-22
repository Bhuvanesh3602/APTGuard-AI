'use client';

/**
 * Proof / logo strip — `proof-strip` from §6.2 of the brief.
 *
 * Renders two horizontal rows:
 *
 *   1. "Built on the open-source stack you already trust" — six line-art
 *      brand wordmarks (LangGraph, Apache Kafka, Neo4j, PostgreSQL,
 *      Qdrant, Ollama) inside a Marquee, paused on hover/focus.
 *
 *   2. "Design partners" — four greyed partner-outline pills that read
 *      "Reference partners onboarding through Q2 2026", matching the
 *      content doc's empty-state treatment until real customer logos
 *      are licensed.
 *
 * The Marquee primitive (`MagicUI`) already collapses to a static row
 * under `prefers-reduced-motion` via the `animate-marquee` keyframe
 * guard in `globals.css`, so this surface is fully accessible without
 * any extra branching here.
 */

import { Marquee } from '@/components/magicui/Marquee';
import { cn } from '@/lib/utils';

const STACK_WORDMARKS: ReadonlyArray<{
  name: string;
  caption: string;
}> = [
  { name: 'LangGraph', caption: 'Agent runtime' },
  { name: 'Apache Kafka', caption: 'Streaming' },
  { name: 'Neo4j', caption: 'Entity graph' },
  { name: 'PostgreSQL', caption: 'Source of truth' },
  { name: 'Qdrant', caption: 'Vector store' },
  { name: 'Ollama', caption: 'Local LLM' },
];

const PARTNER_PLACEHOLDERS = [
  'Partner A',
  'Partner B',
  'Partner C',
  'Partner D',
] as const;

function StackWordmark({ name, caption }: { name: string; caption: string }) {
  return (
    <div
      className={cn(
        'flex items-center gap-3 rounded-md px-4 py-3 text-velvet-content-tertiary',
        'border border-transparent hover:border-velvet-border hover:text-velvet-content-secondary',
        'transition-colors duration-200 ease-landing-out-quart',
      )}
    >
      <span className="text-sm font-semibold tracking-[-0.005em] text-velvet-content-secondary">
        {name}
      </span>
      <span className="hidden text-xs font-medium text-velvet-content-tertiary sm:inline">
        {caption}
      </span>
    </div>
  );
}

export function ProofStrip() {
  return (
    <section
      id="proof-strip"
      aria-labelledby="proof-strip-heading"
      className="relative border-y border-velvet-border/60 bg-velvet-surface-base/60 py-12 sm:py-14"
    >
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <h2
          id="proof-strip-heading"
          className="font-velvet-display font-normal text-center text-xs uppercase tracking-[0.18em] text-velvet-content-tertiary"
        >
          Built on the open-source stack you already trust
        </h2>

        <div className="relative mt-6">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-y-0 left-0 z-10 w-16 bg-gradient-to-r from-velvet-surface-base to-transparent sm:w-24"
          />
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-y-0 right-0 z-10 w-16 bg-gradient-to-l from-velvet-surface-base to-transparent sm:w-24"
          />
          <Marquee className="[--gap:0.5rem] sm:[--gap:2rem]">
            {STACK_WORDMARKS.map((stack) => (
              <StackWordmark key={stack.name} {...stack} />
            ))}
          </Marquee>
        </div>

        <div className="mt-10 flex flex-col items-center gap-4">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-velvet-content-tertiary">
            Design partners
          </p>
          <ul
            aria-label="Reference partners onboarding through Q2 2026"
            className="flex flex-wrap items-center justify-center gap-2 sm:gap-3"
          >
            {PARTNER_PLACEHOLDERS.map((partner) => (
              <li
                key={partner}
                className="inline-flex items-center gap-2 rounded-full border border-dashed border-velvet-border bg-velvet-surface-raised/30 px-4 py-1.5 text-xs font-medium text-velvet-content-tertiary"
              >
                <span
                  aria-hidden="true"
                  className="inline-block h-1.5 w-1.5 rounded-full bg-velvet-content-tertiary/40"
                />
                {partner}
              </li>
            ))}
          </ul>
          <p className="text-xs text-velvet-content-tertiary">
            Reference partners onboarding through Q2 2026
          </p>
        </div>
      </div>
    </section>
  );
}
