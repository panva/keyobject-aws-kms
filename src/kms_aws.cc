/*
 * The AWS backend: the only translation unit that knows AWS exists.
 *
 * Credentials, region and endpoint resolution are the SDK's own. That is a hard
 * requirement, not a convenience -- the chain covers environment variables,
 * ~/.aws/config profiles with SSO, `aws login`, assume-role and
 * credential_process, ECS and EKS task roles, and IMDS, and every one of those
 * has behaviour users depend on. Reimplementing any of it would be a bug factory.
 *
 * In aws-sdk-cpp 1.11.855 DefaultAWSCredentialsProviderChain is
 * Environment -> Profile -> STS web identity -> SSO -> Login -> ECS/HTTP -> IMDS,
 * and its Profile provider delegates to aws-c-auth (ProfileCredentialsProviderImp
 * derives from CrtCredentialsProvider), which is what supplies credential_process
 * and profile assume-role. So the default chain is already complete and there is
 * nothing for us to compose on top of it.
 *
 * The one thing we do add is region resolution from a key ARN, because the SDK
 * deliberately does not: the KMS endpoint ruleset has no ARN-based region
 * resolution, so a Frankfurt key ARN on a us-east-1 client just fails to be
 * found. That happens in uri.c; by the time we get here `uri->region` is already
 * the effective answer, or NULL to mean "let the SDK decide".
 */
#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/utils/Outcome.h>
#include <aws/core/utils/memory/stl/AWSString.h>
#include <aws/kms/KMSClient.h>
#include <aws/kms/model/GetPublicKeyRequest.h>
#include <aws/kms/model/SignRequest.h>

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

extern "C" {
#include <openssl/crypto.h>

#include "err.h"
#include "kms.h"
}

extern "C" const char *awskms_kms_backend(void) { return "aws"; }

extern "C" void awskms_public_key_cleanup(AWSKMS_PUBLIC_KEY *p) {
  if (p == nullptr) return;
  OPENSSL_free(p->key_spec);
  OPENSSL_free(p->spki);
  memset(p, 0, sizeof(*p));
}

namespace {

/*
 * Aws::InitAPI is process-global and not reference counted, so it happens exactly
 * once and Aws::ShutdownAPI is never called.
 *
 * That is deliberate. Constructing a KMSClient during OSSL_provider_init makes
 * the process abort at exit with "mutex lock failed" in every host tried, and
 * destroying the client in provider teardown does not fix it -- teardown races
 * process exit, and the CRT leaves event-loop threads behind. Leaking the SDK is
 * the safe end of that trade: a provider is unloaded at process exit anyway.
 */
Aws::SDKOptions &sdk_options() {
  static Aws::SDKOptions options;
  return options;
}

void init_sdk_once() {
  static std::once_flag flag;
  std::call_once(flag, [] { Aws::InitAPI(sdk_options()); });
}

/* Clients are expensive (connection pools, DNS, credential caches) and safe to
 * share across threads, so one is kept per distinct configuration. Node calls
 * sign from several libuv threadpool threads at once. */
struct ClientKey {
  std::string region, profile, endpoint;
  bool operator==(const ClientKey &o) const {
    return region == o.region && profile == o.profile && endpoint == o.endpoint;
  }
};

struct ClientKeyHash {
  size_t operator()(const ClientKey &k) const {
    std::hash<std::string> h;
    return h(k.region) ^ (h(k.profile) << 1) ^ (h(k.endpoint) << 2);
  }
};

std::mutex &clients_mutex() {
  static std::mutex m;
  return m;
}

std::unordered_map<ClientKey, std::shared_ptr<Aws::KMS::KMSClient>,
                   ClientKeyHash> &
clients() {
  static std::unordered_map<ClientKey, std::shared_ptr<Aws::KMS::KMSClient>,
                            ClientKeyHash>
      map;
  return map;
}

std::shared_ptr<Aws::KMS::KMSClient> client_for(AWSKMS_PROV_CTX *provctx,
                                                const AWSKMS_URI *uri) {
  ClientKey key{uri->region ? uri->region : "",
                uri->profile ? uri->profile : "",
                uri->endpoint ? uri->endpoint : ""};

  std::lock_guard<std::mutex> guard(clients_mutex());
  auto it = clients().find(key);
  if (it != clients().end()) return it->second;

  init_sdk_once();

  /* Passing the profile through ClientConfiguration is what makes the whole
   * chain -- credentials AND region AND endpoint overrides -- resolve against
   * that profile, rather than only the credentials. */
  Aws::Client::ClientConfiguration config(
      key.profile.empty() ? nullptr : key.profile.c_str());
  if (!key.region.empty()) config.region = key.region;
  /* Ours wins over AWS_ENDPOINT_URL_KMS, which the SDK honours by itself from
   * 1.11.685; setting it here also covers older SDKs. */
  if (!key.endpoint.empty()) config.endpointOverride = key.endpoint;

  /* Unreachable with aws-sdk-cpp 1.11.855: every ClientConfiguration constructor
   * ends by substituting us-east-1 when its own resolution comes up empty
   * (ClientConfiguration.cpp:428-433 and :488-492), so an unset region is
   * indistinguishable from a deliberate us-east-1 by the time it reaches here.
   * Telling the two apart would mean duplicating the SDK's resolution order, which
   * this file exists to avoid. The branch is retained because it costs nothing and
   * becomes correct if the SDK stops silently defaulting. */
  if (config.region.empty()) {
    AWSKMS_raise(provctx->handle, AWSKMS_R_NO_REGION,
                 "no AWS region resolved for \"%s\"; set one in the URI "
                 "(;region=...), in AWS_REGION, or in the profile",
                 uri->key_id);
    return nullptr;
  }

  auto c = Aws::MakeShared<Aws::KMS::KMSClient>("awskms", config);
  clients().emplace(key, c);
  return c;
}

/* Maps a KMS error onto one of our reason codes, so `err.code` in Node says
 * something actionable instead of a generic failure. */
uint32_t reason_for(const Aws::KMS::KMSError &err) {
  using Aws::KMS::KMSErrors;
  switch (err.GetErrorType()) {
    case KMSErrors::NOT_FOUND:
      return AWSKMS_R_KEY_NOT_FOUND;
    case KMSErrors::DISABLED:
      return AWSKMS_R_KEY_DISABLED;
    case KMSErrors::K_M_S_INVALID_STATE:
      return AWSKMS_R_KEY_PENDING_DELETION;
    case KMSErrors::INVALID_KEY_USAGE:
      return AWSKMS_R_INVALID_KEY_USAGE;
    case KMSErrors::ACCESS_DENIED:
      return AWSKMS_R_ACCESS_DENIED;
    case KMSErrors::THROTTLING:
    case KMSErrors::SLOW_DOWN:
    case KMSErrors::LIMIT_EXCEEDED:
      return AWSKMS_R_THROTTLED;
    case KMSErrors::MISSING_AUTHENTICATION_TOKEN:
    case KMSErrors::INVALID_SIGNATURE:
      return AWSKMS_R_NO_CREDENTIALS;
    default:
      return 0; /* caller supplies its own operation-specific reason */
  }
}

void raise_kms(const AWSKMS_PROV_CTX *provctx, const Aws::KMS::KMSError &err,
               uint32_t fallback, const char *what, const char *key_id) {
  uint32_t reason = reason_for(err);
  if (reason == 0) reason = fallback;
  /* One error, at the point of failure: Node peeks the newest on the STORE path
   * and the oldest on sign, so exactly one is what surfaces cleanly on both. */
  awskms_err_raise(provctx->handle, reason, OPENSSL_FILE, OPENSSL_LINE,
                   OPENSSL_FUNC, "%s for \"%s\": %s: %s", what, key_id,
                   err.GetExceptionName().c_str(), err.GetMessage().c_str());
}

char *dup_c(const Aws::String &s) {
  char *out = static_cast<char *>(OPENSSL_malloc(s.size() + 1));
  if (out == nullptr) return nullptr;
  memcpy(out, s.c_str(), s.size() + 1);
  return out;
}

}  // namespace

extern "C" int awskms_kms_get_public_key(AWSKMS_PROV_CTX *provctx,
                                         const AWSKMS_URI *uri,
                                         AWSKMS_PUBLIC_KEY *out) {
  try {
    auto client = client_for(provctx, uri);
    if (!client) return 0;
    Aws::KMS::Model::GetPublicKeyRequest request;
    request.SetKeyId(uri->key_id);

    auto outcome = client->GetPublicKey(request);
    if (!outcome.IsSuccess()) {
      raise_kms(provctx, outcome.GetError(), AWSKMS_R_GET_PUBLIC_KEY_FAILED,
                "kms:GetPublicKey", uri->key_id);
      return 0;
    }

    const auto &result = outcome.GetResult();

    /* Only signing keys are usable here, and saying so at load time is far
     * kinder than a failure on first sign. */
    if (result.GetKeyUsage() != Aws::KMS::Model::KeyUsageType::SIGN_VERIFY) {
      AWSKMS_raise(provctx->handle, AWSKMS_R_INVALID_KEY_USAGE,
                   "\"%s\" has KeyUsage %s; this provider only handles "
                   "SIGN_VERIFY keys",
                   uri->key_id,
                   Aws::KMS::Model::KeyUsageTypeMapper::GetNameForKeyUsageType(
                       result.GetKeyUsage())
                       .c_str());
      return 0;
    }

    /* KeySpec, never the deprecated CustomerMasterKeySpec: that field was never
     * extended for ML-DSA or Ed25519. */
    const Aws::String spec =
        Aws::KMS::Model::KeySpecMapper::GetNameForKeySpec(result.GetKeySpec());
    const auto &blob = result.GetPublicKey();

    if ((out->key_spec = dup_c(spec)) == nullptr) return 0;
    out->spki_len = blob.GetLength();
    if ((out->spki = static_cast<unsigned char *>(
             OPENSSL_malloc(out->spki_len ? out->spki_len : 1))) == nullptr) {
      awskms_public_key_cleanup(out);
      return 0;
    }
    memcpy(out->spki, blob.GetUnderlyingData(), out->spki_len);
    return 1;
  } catch (const std::exception &e) {
    /* Nothing may propagate across the provider boundary: libcrypto is C. */
    AWSKMS_raise(provctx->handle, AWSKMS_R_GET_PUBLIC_KEY_FAILED,
                 "kms:GetPublicKey for \"%s\" threw: %s", uri->key_id,
                 e.what());
    return 0;
  }
}

extern "C" int awskms_kms_sign(AWSKMS_PROV_CTX *provctx, const AWSKMS_URI *uri,
                               const char *signing_algorithm,
                               const char *message_type,
                               const unsigned char *msg, size_t msg_len,
                               unsigned char *sig, size_t sig_size,
                               size_t *sig_len) {
  try {
    auto client = client_for(provctx, uri);
    if (!client) return 0;
    Aws::KMS::Model::SignRequest request;

    request.SetKeyId(uri->key_id);
    request.SetSigningAlgorithm(
        Aws::KMS::Model::SigningAlgorithmSpecMapper::
            GetSigningAlgorithmSpecForName(signing_algorithm));
    request.SetMessageType(
        Aws::KMS::Model::MessageTypeMapper::GetMessageTypeForName(
            message_type));
    request.SetMessage(Aws::Utils::ByteBuffer(msg, msg_len));

    auto outcome = client->Sign(request);
    if (!outcome.IsSuccess()) {
      raise_kms(provctx, outcome.GetError(), AWSKMS_R_SIGN_FAILED, "kms:Sign",
                uri->key_id);
      return 0;
    }

    const auto &blob = outcome.GetResult().GetSignature();
    if (blob.GetLength() > sig_size) {
      /* Would mean our OSSL_PKEY_PARAM_MAX_SIZE disagrees with KMS, which would
       * otherwise show up as a truncated signature. */
      AWSKMS_raise(provctx->handle, AWSKMS_R_SIGN_FAILED,
                   "kms:Sign returned %zu bytes but only %zu were reserved",
                   static_cast<size_t>(blob.GetLength()), sig_size);
      return 0;
    }
    memcpy(sig, blob.GetUnderlyingData(), blob.GetLength());
    *sig_len = blob.GetLength();
    return 1;
  } catch (const std::exception &e) {
    AWSKMS_raise(provctx->handle, AWSKMS_R_SIGN_FAILED,
                 "kms:Sign for \"%s\" threw: %s", uri->key_id, e.what());
    return 0;
  }
}
