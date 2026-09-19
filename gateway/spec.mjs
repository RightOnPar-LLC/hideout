// Dev indirection: the one guide spec lives in the app. pack.mjs replaces this file with
// the real spec when building the deploy bundle, so the gateway enforces exactly it.
export * from "../app/src/guide-spec.mjs";
