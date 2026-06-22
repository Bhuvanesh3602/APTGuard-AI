export async function safeFetcher<T = unknown>(url: string): Promise<T> {
  const r = await fetch(url);
  if (!r.ok) {
    const body = await r.text().catch(() => '');
    throw new Error(`HTTP ${r.status} ${r.statusText} — ${body.slice(0, 120)}`);
  }
  return r.json();
}
