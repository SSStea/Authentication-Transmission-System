add_library(tesla_crypto INTERFACE)

target_compile_features(tesla_crypto INTERFACE cxx_std_17)
target_link_libraries(tesla_crypto INTERFACE OpenSSL::Crypto)
