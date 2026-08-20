/** The version of the core npm package. */
export declare const version: string;

/** Stable failure codes returned by {@link isSupported}. */
export type AwsKmsSupportFailureCode =
  | 'ERR_AWSKMS_UNSUPPORTED_RUNTIME'
  | 'ERR_AWSKMS_PERMISSION_DENIED'
  | 'ERR_AWSKMS_RUNTIME_PROBE_FAILED'
  | 'ERR_AWSKMS_MODULE_NOT_FOUND'
  | 'ERR_AWSKMS_VERSION_MISMATCH'
  | 'ERR_AWSKMS_INVALID_PLATFORM_PACKAGE'
  | 'ERR_AWSKMS_PACKAGE_INTEGRITY'
  | 'ERR_AWSKMS_TEMP_INTEGRITY'
  | 'ERR_AWSKMS_BAD_CONFIG_TEMPLATE'
  | 'ERR_AWSKMS_UNSAFE_MODULE_PATH'
  | 'ERR_AWSKMS_UNKNOWN';

export type AwsKmsSupport =
  | { ok: true; code?: undefined; reason?: undefined }
  | { ok: false; code: AwsKmsSupportFailureCode; reason: string };

/**
 * Absolute path to the native provider module for this platform.
 *
 * The platform package name, version, platform metadata, native module, and
 * OpenSSL config template are validated before the path is returned. Yarn PnP
 * archives are copied to a private, owner-only process directory because
 * `dlopen` cannot load a file from a zip archive.
 *
 * @throws {Error} with a stable `ERR_AWSKMS_*` code when the package is absent,
 * mismatched, malformed, or changes after it is resolved.
 */
export declare function modulePath(): string;

/**
 * Absolute path to an owner-readable, process-shared `openssl.cnf` that
 * activates the provider.
 *
 * The path is stable across the main thread and every Worker in this process.
 * The file is generated with exclusive, no-follow creation and validated on
 * every call. Its encoded module path is self-contained, so pass it to
 * `node --openssl-config=<path>` or set `OPENSSL_CONF`.
 *
 * @throws {Error} with a stable `ERR_AWSKMS_*` code if the installed config
 * template or private runtime file fails validation.
 */
export declare function opensslConfigPath(): string;

/**
 * Activate the provider in this process without an OpenSSL config flag.
 * Idempotent after a successful registration. Call only during startup, before
 * crypto work or Workers: OpenSSL default-property mutation is not thread-safe.
 *
 * @throws {Error} with code `ERR_AWSKMS_OPENSSL_VERSION` when the process uses
 * OpenSSL 3.0 through 3.4, or another `ERR_AWSKMS_*` code if the module cannot
 * be verified or loaded.
 */
export declare function register(): void;

/**
 * Check both the Node runtime capability and the platform package without
 * throwing. Support is detected functionally rather than by Node version.
 */
export declare function isSupported(): AwsKmsSupport;
