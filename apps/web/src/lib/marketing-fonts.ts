import { DM_Serif_Display, Poppins, Source_Code_Pro } from 'next/font/google';

/**
 * VelvetEdge marketing fonts (T7.1).
 *
 * Loaded only by the marketing surfaces — the root `app/page.tsx` landing
 * and the `(marketing)/layout.tsx` route group. Importing these here from
 * one shared module guarantees both consumers get byte-identical
 * `next/font` instances and that the console chrome (which never imports
 * this module) stays on Inter / JetBrains Mono.
 *
 * The CSS variables exposed below resolve at runtime through the
 * `font-velvet-display` / `font-velvet-body` / `font-velvet-mono`
 * Tailwind utilities declared in `tailwind.config.ts`.
 */

export const velvetDisplay = DM_Serif_Display({
  subsets: ['latin'],
  weight: '400',
  style: ['normal', 'italic'],
  variable: '--font-velvet-display',
  display: 'swap',
});

export const velvetBody = Poppins({
  subsets: ['latin'],
  weight: ['300', '400', '500', '600', '700'],
  variable: '--font-velvet-body',
  display: 'swap',
});

export const velvetMono = Source_Code_Pro({
  subsets: ['latin'],
  weight: ['400', '500'],
  variable: '--font-velvet-mono',
  display: 'swap',
  preload: false,
});

export const velvetFontVariables = [
  velvetDisplay.variable,
  velvetBody.variable,
  velvetMono.variable,
].join(' ');
