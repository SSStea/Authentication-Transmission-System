set(TESLA_CRYPTO_HEADERS
    include/tesla/crypto/CryptoProvider.h
    include/tesla/crypto/CryptoTypes.h
    include/tesla/crypto/CryptoUtilities.h
    include/tesla/crypto/KeyChain.h
    include/tesla/crypto/OpenSslCryptoProvider.h
    include/tesla/crypto/OpenSslSecureRandomProvider.h
    include/tesla/crypto/SecureRandomProvider.h
)

set(TESLA_CRYPTO_SOURCES
    src/CryptoUtilities.cpp
    src/KeyChain.cpp
    src/OpenSslCryptoProvider.cpp
    src/OpenSslSecureRandomProvider.cpp
)

add_library(tesla_crypto STATIC
    ${TESLA_CRYPTO_HEADERS}
    ${TESLA_CRYPTO_SOURCES}
    CMakeLists.txt
)

source_group("Header Files" FILES ${TESLA_CRYPTO_HEADERS})
source_group("Source Files" FILES ${TESLA_CRYPTO_SOURCES})
source_group("Build Files" FILES CMakeLists.txt)

target_include_directories(tesla_crypto
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(tesla_crypto PUBLIC cxx_std_17)
target_link_libraries(tesla_crypto PUBLIC OpenSSL::Crypto)

set_target_properties(tesla_crypto
    PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
        FOLDER "Libraries"
)
