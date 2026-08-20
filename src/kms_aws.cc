/*
 * The AWS backend: the only translation unit that knows AWS exists.
 *
 * Credentials, region and endpoint resolution are the SDK's own. That is a hard
 * requirement, not a convenience -- the chain covers environment variables,
 * ~/.aws/config profiles with SSO, `aws login`, assume-role and
 * credential_process, ECS and EKS task roles, and IMDS, and every one of those
 * has behaviour users depend on. Reimplementing any of it would be a bug factory.
 *
 * The SDK default chain remains intact. An explicit URI profile is tried before
 * that ambient chain, while an OpenSSL provider profile is tried only after it.
 * ProfileCredentialsProvider delegates to aws-c-auth and therefore retains
 * credential_process and assume-role support.
 *
 * The one thing we do add is region resolution from a key ARN, because the SDK
 * deliberately does not: the KMS endpoint ruleset has no ARN-based region
 * resolution, so a Frankfurt key ARN on a us-east-1 client just fails to be
 * found. That happens in uri.c; by the time we get here `uri->region` is already
 * the effective answer, or NULL to mean "let the SDK decide".
 */
#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/auth/ProfileCredentialsProvider.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/config/ConfigAndCredentialsCacheManager.h>
#include <aws/core/config/EndpointResolver.h>
#include <aws/core/platform/Environment.h>
#include <aws/core/utils/Outcome.h>
#include <aws/core/utils/memory/stl/AWSString.h>
#include <aws/kms/KMSClient.h>
#include <aws/kms/model/GetPublicKeyRequest.h>
#include <aws/kms/model/SignRequest.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
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
 * Aws::InitAPI is process-global and not reference counted, so one intentionally
 * process-owned state initializes it exactly once.  Provider teardown destroys
 * this module's clients, but does not call ShutdownAPI: another libctx or the host
 * application may still be using the same SDK global state.
 */
struct ClientKey {
  std::string region, profile, endpoint, ambient_profile, provider_profile;
  bool fips = false;
  bool uri_profile = false;

  bool operator==(const ClientKey &o) const {
    return region == o.region && profile == o.profile &&
           endpoint == o.endpoint && ambient_profile == o.ambient_profile &&
           provider_profile == o.provider_profile && fips == o.fips &&
           uri_profile == o.uri_profile;
  }
};

struct ClientKeyHash {
  size_t operator()(const ClientKey &k) const {
    std::hash<std::string> h;
    return h(k.region) ^ (h(k.profile) << 1) ^ (h(k.endpoint) << 2) ^
           (h(k.ambient_profile) << 3) ^ (h(k.provider_profile) << 4) ^
           (std::hash<bool>{}(k.fips) << 5) ^
           (std::hash<bool>{}(k.uri_profile) << 6);
  }
};

/* A URI profile is trusted, explicit connection configuration and therefore
 * precedes ambient credentials. The ordinary AWS chain remains intact after
 * it, and an OpenSSL provider profile is only a final fallback. */
class PrecedenceCredentialsProviderChain final
    : public Aws::Auth::AWSCredentialsProviderChain {
 public:
  PrecedenceCredentialsProviderChain(
      const char *uri_profile,
      const Aws::Client::ClientConfiguration::CredentialProviderConfiguration
          &ambient_config,
      const char *provider_profile) {
    if (uri_profile != nullptr) {
      auto explicit_config = ambient_config;
      explicit_config.profile = uri_profile;
      AddProvider(Aws::MakeShared<Aws::Auth::ProfileCredentialsProvider>(
          "awskms", explicit_config));
    }

    AddProvider(Aws::MakeShared<Aws::Auth::DefaultAWSCredentialsProviderChain>(
        "awskms", ambient_config));

    if (provider_profile != nullptr &&
        (uri_profile == nullptr ||
         strcmp(provider_profile, uri_profile) != 0) &&
        ambient_config.profile != provider_profile) {
      auto fallback_config = ambient_config;
      fallback_config.profile = provider_profile;
      AddProvider(Aws::MakeShared<Aws::Auth::ProfileCredentialsProvider>(
          "awskms", fallback_config));
    }
  }
};

using Lru = std::list<ClientKey>;

struct ClientEntry {
  std::shared_ptr<Aws::KMS::KMSClient> client;
  Lru::iterator lru;
};

struct ProcessState {
  std::mutex clients_mutex;
  Lru lru;
  std::unordered_map<ClientKey, ClientEntry, ClientKeyHash> clients;

  ~ProcessState() {
    /* Client executors must stop before provider code is unloaded.  The SDK's
     * process-global state intentionally survives until the OS tears down the
     * process; calling ShutdownAPI from provider teardown can race other users
     * of the SDK in the same host. */
    clients.clear();
    lru.clear();
  }
};

struct SdkState {
  Aws::SDKOptions options;
  std::once_flag once;
};

/* SDK global state is intentionally process-owned.  It cannot be shut down by
 * one provider instance because another libctx (or the host application itself)
 * may still be using it. */
SdkState &sdk_state() {
  static auto *state = new SdkState();
  return *state;
}

/* The bounded client cache is process-wide across provider contexts, but unlike
 * the SDK global state it owns threads and must be destroyed on DSO teardown. */
ProcessState &process_state() {
  static ProcessState state;
  return state;
}

void init_sdk_once() {
  SdkState &state = sdk_state();
  std::call_once(state.once, [&state] { Aws::InitAPI(state.options); });
}

bool profile_exists(const Aws::String &profile) {
  return Aws::Config::HasCachedConfigProfile(profile) ||
         Aws::Config::HasCachedCredentialsProfile(profile);
}

Aws::String environment_region() {
  Aws::String region = Aws::Environment::GetEnv("AWS_DEFAULT_REGION");
  if (region.empty()) region = Aws::Environment::GetEnv("AWS_REGION");
  return region;
}

Aws::String profile_region(const Aws::String &profile) {
  if (!Aws::Config::HasCachedConfigProfile(profile)) return {};
  return Aws::Config::GetCachedConfigProfile(profile).GetRegion();
}

bool is_china_region(const Aws::String &region) {
  return region.size() > 3 && (region[0] == 'c' || region[0] == 'C') &&
         (region[1] == 'n' || region[1] == 'N') && region[2] == '-';
}

void touch_lru(
    ProcessState &state,
    std::unordered_map<ClientKey, ClientEntry, ClientKeyHash>::iterator entry) {
  state.lru.splice(state.lru.begin(), state.lru, entry->second.lru);
  entry->second.lru = state.lru.begin();
}

std::shared_ptr<Aws::KMS::KMSClient> cached_client(const ClientKey &key) {
  ProcessState &state = process_state();
  std::lock_guard<std::mutex> guard(state.clients_mutex);
  auto found = state.clients.find(key);
  if (found == state.clients.end()) return nullptr;
  touch_lru(state, found);
  return found->second.client;
}

std::shared_ptr<Aws::KMS::KMSClient> publish_client(
    const ClientKey &key, std::shared_ptr<Aws::KMS::KMSClient> candidate) {
  static constexpr size_t kMaxClients = 64;
  ProcessState &state = process_state();
  std::shared_ptr<Aws::KMS::KMSClient> evicted;

  {
    std::lock_guard<std::mutex> guard(state.clients_mutex);
    auto found = state.clients.find(key);
    if (found != state.clients.end()) {
      touch_lru(state, found);
      return found->second.client;
    }

    if (state.clients.size() == kMaxClients) {
      auto oldest = state.clients.find(state.lru.back());
      if (oldest != state.clients.end()) {
        evicted = std::move(oldest->second.client);
        state.clients.erase(oldest);
      }
      state.lru.pop_back();
    }

    state.lru.push_front(key);
    state.clients.emplace(key, ClientEntry{candidate, state.lru.begin()});
  }
  /* Destroying an SDK client can join threads; do it after releasing the global
   * cache lock. */
  evicted.reset();
  return candidate;
}

std::shared_ptr<Aws::KMS::KMSClient> client_for(AWSKMS_PROV_CTX *provctx,
                                                const AWSKMS_URI *uri,
                                                bool fips_required) {
  init_sdk_once();

  const Aws::String ambient_profile = Aws::Auth::GetConfigProfileName();
  const bool ambient_profile_selected =
      !Aws::Environment::GetEnv("AWS_DEFAULT_PROFILE").empty() ||
      !Aws::Environment::GetEnv("AWS_PROFILE").empty() ||
      profile_exists(ambient_profile);
  Aws::String profile;

  if (uri->profile != nullptr)
    profile = uri->profile;
  else if (ambient_profile_selected)
    profile = ambient_profile;
  else if (provctx->profile != nullptr)
    profile = provctx->profile;
  else
    profile = ambient_profile;

  Aws::Client::ClientConfiguration config(profile.empty() ? nullptr
                                                          : profile.c_str());
  /* The SDK's explicit-profile constructor falls back silently when the named
   * profile has credentials but no config section. Retain the selected profile
   * for the default credential chain in that case. */
  if (!profile.empty()) {
    config.profileName = profile;
    config.credentialProviderConfig.profile = profile;
  }

  Aws::String region;
  if (uri->region != nullptr) region = uri->region;
  if (region.empty()) region = environment_region();
  if (region.empty()) region = profile_region(profile);
  if (region.empty() && provctx->region != nullptr) region = provctx->region;
  if (region.empty()) region = config.region;
  config.region = region;
  config.credentialProviderConfig.region = region;

  Aws::String endpoint;
  if (uri->endpoint != nullptr) endpoint = uri->endpoint;
  if (endpoint.empty())
    endpoint = Aws::Config::EndpointResolver::EndpointSource("kms", profile);
  if (endpoint.empty() && provctx->endpoint != nullptr)
    endpoint = provctx->endpoint;

  if (fips_required && !endpoint.empty()) {
    AWSKMS_raise(provctx->handle, AWSKMS_R_FIPS_ROUTING,
                 "FIPS mode rejects endpoint override \"%s\" for \"%s\"; "
                 "remove URI, AWS, profile, and provider endpoint overrides",
                 endpoint.c_str(), uri->key_id);
    return nullptr;
  }
  if (fips_required && is_china_region(region)) {
    AWSKMS_raise(provctx->handle, AWSKMS_R_FIPS_ROUTING,
                 "FIPS mode rejects China region \"%s\" for \"%s\" because "
                 "AWS KMS HSMs there are not CMVP validated",
                 region.c_str(), uri->key_id);
    return nullptr;
  }

  config.useFIPS = fips_required;
  if (!endpoint.empty()) config.endpointOverride = endpoint;

  ClientKey key{
      region.c_str(),
      profile.c_str(),
      endpoint.c_str(),
      ambient_profile.c_str(),
      provctx->profile == nullptr ? "" : provctx->profile,
      fips_required,
      uri->profile != nullptr,
  };
  if (auto existing = cached_client(key)) return existing;

  /* Client construction can load credentials, resolve proxies and start CRT
   * machinery, so it must happen outside the cache lock. */
  Aws::Client::ClientConfiguration ambient_config(
      ambient_profile.empty() ? nullptr : ambient_profile.c_str());
  auto credentials = Aws::MakeShared<PrecedenceCredentialsProviderChain>(
      "awskms", uri->profile, ambient_config.credentialProviderConfig,
      provctx->profile);
  auto candidate = Aws::MakeShared<Aws::KMS::KMSClient>(
      "awskms", std::move(credentials), config);
  return publish_client(key, std::move(candidate));
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
      return AWSKMS_R_INVALID_KEY_STATE;
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

bool aws_error_logging_enabled() noexcept {
  static const bool enabled = []() noexcept {
    const char *value = std::getenv("AWSKMS_AWS_LOG_ERRORS");
    return value != nullptr && strcmp(value, "1") == 0;
  }();
  return enabled;
}

std::string log_safe(std::string_view input) {
  static constexpr size_t kMaxInputBytes = 4096;
  static constexpr char kHex[] = "0123456789abcdef";
  const size_t length = std::min(input.size(), kMaxInputBytes);
  std::string output;
  output.reserve(length);
  for (size_t index = 0; index < length; index++) {
    const unsigned char byte = static_cast<unsigned char>(input[index]);
    if (byte < 0x20 || byte == 0x7f) {
      output.append("\\x");
      output.push_back(kHex[byte >> 4]);
      output.push_back(kHex[byte & 0x0f]);
    } else {
      output.push_back(input[index]);
    }
  }
  if (length != input.size()) output.append("...");
  return output;
}

void raise_kms(const AWSKMS_PROV_CTX *provctx, const Aws::KMS::KMSError &err,
               uint32_t fallback, const char *what, const char *key_id) {
  uint32_t reason = reason_for(err);
  if (reason == 0) reason = fallback;
  /* Node exposes the stable reason string but drops OpenSSL's attached detail.
   * Keep production silent; this opt-in diagnostic makes the AWS SDK exception
   * visible when investigating transport, endpoint, or service failures. */
  if (aws_error_logging_enabled()) {
    const std::string exception = log_safe(err.GetExceptionName().c_str());
    const std::string message = log_safe(err.GetMessage().c_str());
    std::fprintf(stderr, "aws-kms AWS SDK error during %s: %s: %s\n", what,
                 exception.c_str(), message.c_str());
    std::fflush(stderr);
  }
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
                                         int fips_required,
                                         AWSKMS_PUBLIC_KEY *out) {
  try {
    auto client = client_for(provctx, uri, fips_required != 0);
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
                               int fips_required, const char *signing_algorithm,
                               const char *message_type,
                               const unsigned char *msg, size_t msg_len,
                               unsigned char *sig, size_t sig_size,
                               size_t *sig_len) {
  try {
    auto client = client_for(provctx, uri, fips_required != 0);
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
