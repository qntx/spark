require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "SparkNative"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"] || package.dig("repository", "url") || "https://github.com/qntx/spark"
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/qntx/spark.git", :tag => "v#{s.version}" }

  s.source_files = [
    # C++ HybridObject implementation plus the qntx_spark C header (the symbols
    # themselves come from the vendored xcframework below).
    "cpp/**/*.{h,hpp,c,cpp}",
    "include/**/*.h",
  ]

  # Prebuilt spark-ffi cdylib (aarch64 device + arm64/x86_64 simulator), built by
  # `bun run build:native` at the repository root.
  s.public_header_files = "include/qntx_spark.h"

  s.vendored_frameworks = "ios/QntxSpark.xcframework"

  load 'nitrogen/generated/ios/SparkNative+autolinking.rb'
  add_nitrogen_files(s)

  s.dependency 'React-jsi'
  s.dependency 'React-callinvoker'
  install_modules_dependencies(s)
end
