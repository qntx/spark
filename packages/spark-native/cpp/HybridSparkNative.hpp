#pragma once

#include "HybridSparkNativeSpec.hpp"

namespace margelo::nitro::sparknative {

class HybridSparkNative final : public HybridSparkNativeSpec {
public:
  // HybridObject is a virtual base, so the most-derived class must pass TAG itself.
  HybridSparkNative() : HybridObject(TAG) {}

  double abiVersion() override;
  std::shared_ptr<ArrayBuffer> frostCommit(const std::shared_ptr<ArrayBuffer>& hedge,
                                           const std::shared_ptr<ArrayBuffer>& random) override;
  std::shared_ptr<ArrayBuffer> frostSign(const std::shared_ptr<ArrayBuffer>& request) override;
  std::shared_ptr<ArrayBuffer>
  frostAggregate(const std::shared_ptr<ArrayBuffer>& request) override;
  std::shared_ptr<ArrayBuffer> eciesEncrypt(const std::shared_ptr<ArrayBuffer>& publicKey,
                                            const std::shared_ptr<ArrayBuffer>& plaintext,
                                            const std::shared_ptr<ArrayBuffer>& random) override;
  std::shared_ptr<ArrayBuffer>
  eciesDecrypt(const std::shared_ptr<ArrayBuffer>& privateKey,
               const std::shared_ptr<ArrayBuffer>& ciphertext) override;
  std::shared_ptr<ArrayBuffer>
  splitSecretWithProofs(const std::shared_ptr<ArrayBuffer>& secret, double threshold, double shares,
                        const std::shared_ptr<ArrayBuffer>& random) override;
};

} // namespace margelo::nitro::sparknative
