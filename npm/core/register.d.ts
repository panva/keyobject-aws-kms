/**
 * Side-effect only: importing this activates the provider in the current
 * process. Equivalent to calling `register()` from the main entry point.
 * Import it only during startup, before crypto work or Workers: OpenSSL
 * default-property mutation is process-wide and not thread-safe.
 *
 *   import '@keyobject/aws-kms/register';
 *
 * Declared as an empty module so a bare `import` type-checks. There is nothing
 * to export -- exporting something would invite `import { x } from` and defeat
 * the point of a side-effect subpath.
 */
export {};
