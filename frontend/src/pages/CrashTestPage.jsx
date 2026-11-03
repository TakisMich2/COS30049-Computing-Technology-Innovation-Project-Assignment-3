// Development-only page (/dev/crash) that throws while rendering, to demonstrate
// the fallback page shown for unexpected errors.
export default function CrashTestPage() {
  throw new Error('Simulated rendering failure from /dev/crash');
}
