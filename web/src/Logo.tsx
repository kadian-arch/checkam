export default function Logo({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden className="logo">
      <rect width="64" height="64" rx="15" fill="var(--ink-2)" />
      <path d="M32 11 50 18v14c0 11-7.5 18.5-18 22-10.5-3.5-18-11-18-22V18z" fill="none" stroke="var(--signal)" strokeWidth="4" strokeLinejoin="round" />
      <path d="m24 33 6 6 11-12" fill="none" stroke="var(--paper)" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
