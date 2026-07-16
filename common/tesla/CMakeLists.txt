add_library(tesla_core INTERFACE)

target_compile_features(tesla_core INTERFACE cxx_std_17)
target_link_libraries(tesla_core
    INTERFACE
        tesla_crypto
        tesla_protocol
)
