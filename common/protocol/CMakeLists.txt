set(TESLA_PROTOCOL_HEADERS
    include/tesla/protocol/AuthenticationControl.h
    include/tesla/protocol/NodeControlJsonCodec.h
    include/tesla/protocol/NodeControlMessage.h
    include/tesla/protocol/NodeDiscoveryMessage.h
    include/tesla/protocol/ProtocolTypes.h
    include/tesla/protocol/TcpFrame.h
    include/tesla/protocol/UdpAuthenticationPacket.h
    include/tesla/protocol/UdpAuthenticationPacketCodec.h
)

set(TESLA_PROTOCOL_SOURCES
    src/AuthenticationControl.cpp
    src/NodeControlJsonCodec.cpp
    src/NodeControlMessage.cpp
    src/NodeDiscoveryMessage.cpp
    src/ProtocolTypes.cpp
    src/TcpFrame.cpp
    src/UdpAuthenticationPacket.cpp
    src/UdpAuthenticationPacketCodec.cpp
)

add_library(tesla_protocol STATIC
    ${TESLA_PROTOCOL_HEADERS}
    ${TESLA_PROTOCOL_SOURCES}
    src/BinaryCodecUtilities.h
    CMakeLists.txt
)

source_group("Header Files" FILES ${TESLA_PROTOCOL_HEADERS})
source_group("Source Files" FILES ${TESLA_PROTOCOL_SOURCES})
source_group("Private Header Files" FILES src/BinaryCodecUtilities.h)
source_group("Build Files" FILES CMakeLists.txt)

target_include_directories(tesla_protocol
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(tesla_protocol PUBLIC cxx_std_17)
target_link_libraries(tesla_protocol PUBLIC nlohmann_json::nlohmann_json)

set_target_properties(tesla_protocol
    PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
        FOLDER "Libraries"
)
