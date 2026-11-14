/**
 * kronicle-lite's src/version.ts reads its package.json at load time. The standalone verifier has
 * no kronicle-lite package.json, and the version is only used by store-writing code it never runs
 * (chain metadata); verification output does not include it. The build injects the verifier's own
 * name and version.
 */
declare const __VERIFY_VERSION__: string;
export const VERSION: string = __VERIFY_VERSION__;
