cmake_minimum_required(VERSION 3.16)
project(ShadowOps VERSION 2.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Project options
option(BUILD_TESTS "Build test suite" OFF)
option(ENABLE_DEBUG "Enable debug mode" OFF)
option(ENABLE_OPTIMIZATION "Enable optimization" ON)
option(ENABLE_SANITIZERS "Enable sanitizers" OFF)
option(ENABLE_COVERAGE "Enable code coverage" OFF)
option(ENABLE_DOCS "Generate documentation" OFF)

# Set build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Od /Zi /RTC1")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /Oi /GL /Gy")

# Windows-specific settings
if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DUNICODE)
    add_definitions(-D_UNICODE)
    
    # Enable advanced evasion features
    add_definitions(-DENABLE_ANTI_DEBUG)
    add_definitions(-DENABLE_ANTI_VM)
    add_definitions(-DENABLE_ANTI_ANALYSIS)
    add_definitions(-DENABLE_POLYMORPHIC_ENGINE)
    add_definitions(-DENABLE_MEMORY_OBFUSCATION)
endif()

# Find required packages
find_package(PkgConfig QUIET)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# Source files
set(SOURCES
    src/ShadowOps.cpp
    src/Logger.cpp
    src/Configuration.cpp
    src/EvasionEngine.cpp
    src/ProcessManager.cpp
    src/PayloadManager.cpp
    src/NetworkManager.cpp
    src/AntiAnalysis.cpp
    src/HashEngine.cpp
    src/Utils.cpp
)

# Header files
set(HEADERS
    include/ShadowOps.h
    include/Logger.h
    include/Configuration.h
    include/EvasionEngine.h
    include/ProcessManager.h
    include/PayloadManager.h
    include/NetworkManager.h
    include/AntiAnalysis.h
    include/HashEngine.h
    include/Utils.h
)

# Create executable
add_executable(ShadowOps ${SOURCES} ${HEADERS})

# Set target properties
set_target_properties(ShadowOps PROPERTIES
    VERSION ${PROJECT_VERSION}
    DESCRIPTION "Advanced Cybersecurity Framework"
    OUTPUT_NAME "shadowops"
)

# Link libraries
target_link_libraries(ShadowOps
    kernel32
    user32
    advapi32
    crypt32
    ws2_32
    iphlpapi
    psapi
)

# Install rules
install(TARGETS ShadowOps
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES ${HEADERS} DESTINATION include/shadowops)
install(FILES shadowops.conf DESTINATION etc/shadowops)
install(FILES README.md LICENSE DESTINATION share/doc/shadowops)

# Create package
include(CPack)
set(CPACK_PACKAGE_NAME "ShadowOps")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Advanced Cybersecurity Framework")
set(CPACK_PACKAGE_VENDOR "ShadowOps Team")
set(CPACK_PACKAGE_CONTACT "team@shadowops.com")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

# Windows-specific packaging
if(WIN32)
    set(CPACK_GENERATOR "NSIS")
    set(CPACK_NSIS_PACKAGE_NAME "ShadowOps")
    set(CPACK_NSIS_DISPLAY_NAME "ShadowOps Advanced Cybersecurity Framework")
    set(CPACK_NSIS_CONTACT "team@shadowops.com")
    set(CPACK_NSIS_URL "https://github.com/Kumarabhijeet1608/ShadowOps")
    set(CPACK_NSIS_ENABLE_DIR "ON")
    set(CPACK_NSIS_MODIFY_PATH "ON"
endif()

# Testing
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Documentation
if(ENABLE_DOCS)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
        
        configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
        
        add_custom_target(docs ALL
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM
        )
    endif()
endif()

# Print configuration summary
message(STATUS "ShadowOps Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Tests: ${BUILD_TESTS}")
message(STATUS "  Enable Debug: ${ENABLE_DEBUG}")
message(STATUS "  Enable Optimization: ${ENABLE_OPTIMIZATION}")
message(STATUS "  Enable Sanitizers: ${ENABLE_SANITIZERS}")
message(STATUS "  Enable Coverage: ${ENABLE_COVERAGE}")
message(STATUS "  Enable Documentation: ${ENABLE_DOCS}")
