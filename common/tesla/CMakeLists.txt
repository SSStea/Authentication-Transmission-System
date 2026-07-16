set(TESLA_CORE_HEADERS
    include/tesla/core/AuthenticationAuthority.h
    include/tesla/core/AuthenticationGroupInput.h
    include/tesla/core/AuthenticationInputEncoder.h
    include/tesla/core/AuthenticationPacketInput.h
    include/tesla/core/AuthenticationRoundParameters.h
    include/tesla/core/ImprovedAuthenticationDetails.h
    include/tesla/core/ImprovedTeslaParameters.h
    include/tesla/core/ImprovedTeslaStrategy.h
    include/tesla/core/ImprovedVerificationDetails.h
    include/tesla/core/ImprovedVerificationPath.h
    include/tesla/core/KsRsMatrix.h
    include/tesla/core/KsRsVerificationResult.h
    include/tesla/core/KsRsVerifier.h
    include/tesla/core/NativeAuthenticationDetails.h
    include/tesla/core/NativePacketStatus.h
    include/tesla/core/NativeTeslaStrategy.h
    include/tesla/core/NativeVerificationDetails.h
    include/tesla/core/ReceiverAuthenticationContext.h
    include/tesla/core/ReceiverAuthenticationContextStore.h
    include/tesla/core/SamdAggregator.h
    include/tesla/core/TeslaAuthenticationDetails.h
    include/tesla/core/TeslaMac.h
    include/tesla/core/TeslaStrategy.h
    include/tesla/core/TeslaAuthenticationMode.h
    include/tesla/core/TeslaVerificationDetails.h
    include/tesla/core/TeslaVerificationResult.h
    include/tesla/core/UdpAuthenticationInputMapper.h
    include/tesla/core/SenderAuthenticationContext.h
    include/tesla/core/SenderAuthenticationMaterial.h
)

set(TESLA_CORE_SOURCES
    src/AuthenticationAuthority.cpp
    src/AuthenticationGroupInput.cpp
    src/AuthenticationInputEncoder.cpp
    src/AuthenticationPacketInput.cpp
    src/AuthenticationRoundParameters.cpp
    src/ImprovedAuthenticationDetails.cpp
    src/ImprovedTeslaParameters.cpp
    src/ImprovedTeslaStrategy.cpp
    src/ImprovedVerificationDetails.cpp
    src/KsRsMatrix.cpp
    src/KsRsVerificationResult.cpp
    src/KsRsVerifier.cpp
    src/NativeAuthenticationDetails.cpp
    src/NativeTeslaStrategy.cpp
    src/NativeVerificationDetails.cpp
    src/ReceiverAuthenticationContext.cpp
    src/ReceiverAuthenticationContextStore.cpp
    src/SamdAggregator.cpp
    src/TeslaMac.cpp
    src/TeslaVerificationResult.cpp
    src/UdpAuthenticationInputMapper.cpp
    src/SenderAuthenticationContext.cpp
    src/SenderAuthenticationMaterial.cpp
)

add_library(tesla_core STATIC
    ${TESLA_CORE_HEADERS}
    ${TESLA_CORE_SOURCES}
    CMakeLists.txt
)

source_group("Header Files" FILES ${TESLA_CORE_HEADERS})
source_group("Source Files" FILES ${TESLA_CORE_SOURCES})
source_group("Build Files" FILES CMakeLists.txt)

target_include_directories(tesla_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(tesla_core PUBLIC cxx_std_17)
target_link_libraries(tesla_core
    PUBLIC
        tesla_crypto
        tesla_protocol
)

set_target_properties(tesla_core
    PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
        FOLDER "Libraries"
)
