add_library(tesla_common_gui STATIC
    AuthenticationMonitorWidget.cpp
    AuthenticationMonitorWidget.h
    CMakeLists.txt
)

source_group("Header Files" FILES AuthenticationMonitorWidget.h)
source_group("Source Files" FILES AuthenticationMonitorWidget.cpp)
source_group("Build Files" FILES CMakeLists.txt)

target_include_directories(tesla_common_gui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(tesla_common_gui
    PUBLIC
        Qt6::Core
        Qt6::Widgets
        tesla_metrics
        tesla_protocol
)

set_target_properties(tesla_common_gui PROPERTIES FOLDER "Common")
