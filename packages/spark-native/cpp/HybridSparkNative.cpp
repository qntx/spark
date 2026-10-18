#include "HybridSparkNative.hpp"
#include "qntx_spark.h"

#include <cmath>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>

namespace margelo::nitro::sparknative {

namespace {

// Every qs_* call shares this shape: inputs go in as (data, size) pointers with no copy; the
// library-owned output buffer is copied into an ArrayBuffer and then wiped + freed with qs_free.
// A nonzero code throws `qntx_spark:<code>` — the JS wrapper maps it back to SparkCryptoError.
template <typename Invoke>
std::shared_ptr<ArrayBuffer> callOut(Invoke&& invoke) {
  uint8_t* out = nullptr;
  size_t outLen = 0;
  const int32_t code = invoke(&out, &outLen);
  if (code != 0) {
    if (out != nullptr) {
      qs_free(out, outLen);
    }
    throw std::runtime_error("qntx_spark:" + std::to_string(code));
  }
  auto result = ArrayBuffer::allocate(outLen);
  if (outLen > 0) {
    std::memcpy(result->data(), out, outLen);
  }
  if (out != nullptr) {
    qs_free(out, outLen);
  }
  return result;
}

// JS `number` arrives as a double; casting an out-of-range or fractional value to uint32_t is
// undefined behavior, so reject it before the ABI can do its own semantic range check (error 5).
uint32_t toUint32(double value, const char* name) {
  if (!std::isfinite(value) || std::floor(value) != value || value < 0 || value > 0xFFFFFFFF) {
    throw std::invalid_argument(std::string(name) + " must be an integer in [0, 2^32)");
  }
  return static_cast<uint32_t>(value);
}

} // namespace

double HybridSparkNative::abiVersion() {
  return static_cast<double>(qs_abi_version());
}

std::shared_ptr<ArrayBuffer>
HybridSparkNative::frostCommit(const std::shared_ptr<ArrayBuffer>& hedge,
                               const std::shared_ptr<ArrayBuffer>& random) {
  return callOut([&](uint8_t** out, size_t* outLen) {
    return qs_frost_commit(hedge->data(), hedge->size(), random->data(), random->size(), out,
                           outLen);
  });
}

std::shared_ptr<ArrayBuffer>
HybridSparkNative::frostSign(const std::shared_ptr<ArrayBuffer>& request) {
  return callOut([&](uint8_t** out, size_t* outLen) {
    return qs_frost_sign(request->data(), request->size(), out, outLen);
  });
}

std::shared_ptr<ArrayBuffer>
HybridSparkNative::frostAggregate(const std::shared_ptr<ArrayBuffer>& request) {
  return callOut([&](uint8_t** out, size_t* outLen) {
    return qs_frost_aggregate(request->data(), request->size(), out, outLen);
  });
}

std::shared_ptr<ArrayBuffer>
HybridSparkNative::eciesEncrypt(const std::shared_ptr<ArrayBuffer>& publicKey,
                                const std::shared_ptr<ArrayBuffer>& plaintext,
                                const std::shared_ptr<ArrayBuffer>& random) {
  return callOut([&](uint8_t** out, size_t* outLen) {
    return qs_ecies_encrypt(publicKey->data(), publicKey->size(), plaintext->data(),
                            plaintext->size(), random->data(), random->size(), out, outLen);
  });
}

std::shared_ptr<ArrayBuffer>
HybridSparkNative::eciesDecrypt(const std::shared_ptr<ArrayBuffer>& privateKey,
                                const std::shared_ptr<ArrayBuffer>& ciphertext) {
  return callOut([&](uint8_t** out, size_t* outLen) {
    return qs_ecies_decrypt(privateKey->data(), privateKey->size(), ciphertext->data(),
                            ciphertext->size(), out, outLen);
  });
}

std::shared_ptr<ArrayBuffer>
HybridSparkNative::splitSecretWithProofs(const std::shared_ptr<ArrayBuffer>& secret,
                                         double threshold, double shares,
                                         const std::shared_ptr<ArrayBuffer>& random) {
  const uint32_t thresholdValue = toUint32(threshold, "threshold");
  const uint32_t sharesValue = toUint32(shares, "shares");
  return callOut([&](uint8_t** out, size_t* outLen) {
    return qs_split_secret_with_proofs(secret->data(), secret->size(), thresholdValue, sharesValue,
                                       random->data(), random->size(), out, outLen);
  });
}

} // namespace margelo::nitro::sparknative
