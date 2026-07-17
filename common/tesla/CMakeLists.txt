set(TESLA_CORE_HEADERS
    include/tesla/core/AuthenticationAuthority.h
    include/tesla/core/AuthenticationInputEncoder.h
    include/tesla/core/AuthenticationNodeRuntime.h
    include/tesla/core/AuthenticationObservationFactory.h
    include/tesla/core/AuthenticationObservationStore.h
    include/tesla/core/AuthenticationPacketInput.h
    include/tesla/core/AuthenticationReceiverRuntime.h
    include/tesla/core/AuthenticationRoundParameters.h
    include/tesla/core/AuthenticationRuntimeTypes.h
    include/tesla/core/AuthenticationSenderRuntime.h
    include/tesla/core/FileUploadSession.h
    include/tesla/core/ImprovedTeslaDetails.h
    include/tesla/core/ImprovedTeslaStrategy.h
    include/tesla/core/KsRsMatrix.h
    include/tesla/core/LocalSenderKeyChainObservation.h
    include/tesla/core/NativeTeslaDetails.h
    include/tesla/core/NativeTeslaStrategy.h
    include/tesla/core/ReceiverAuthenticationContextStore.h
    include/tesla/core/SamdAggregator.h
    include/tesla/core/TeslaMac.h
    include/tesla/core/TeslaStrategy.h
    include/tesla/core/UdpAuthenticationInputMapper.h
    include/tesla/core/SenderAuthenticationContext.h
)

set(TESLA_CORE_SOURCES
    src/AuthenticationAuthority.cpp
    src/AuthenticationInputEncoder.cpp
    src/AuthenticationNodeRuntime.cpp
    src/AuthenticationObservationFactory.cpp
    src/AuthenticationObservationStore.cpp
    src/AuthenticationPacketInput.cpp
    src/AuthenticationReceiverRuntime.cpp
    src/AuthenticationRoundParameters.cpp
    src/AuthenticationRuntimeTypes.cpp
    src/AuthenticationSenderRuntime.cpp
    src/FileUploadSession.cpp
    src/ImprovedTeslaDetails.cpp
    src/ImprovedTeslaStrategy.cpp
    src/KsRsMatrix.cpp
    src/LocalSenderKeyChainObservation.cpp
    src/NativeTeslaDetails.cpp
    src/NativeTeslaStrategy.cpp
    src/ReceiverAuthenticationContextStore.cpp
    src/SamdAggregator.cpp
    src/TeslaMac.cpp
    src/TeslaStrategy.cpp
    src/UdpAuthenticationInputMapper.cpp
    src/SenderAuthenticationContext.cpp
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
        tesla_workload
)

set_target_properties(tesla_core
    PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
        FOLDER "Libraries"
)
