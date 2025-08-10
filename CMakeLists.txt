cmake_minimum_required(VERSION 3.10)
project(TOTP_Authenticator)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Platform-specific settings
if(WIN32)
    # Windows-specific settings
    set(PLATFORM_LIBS )
elseif(APPLE)
    # macOS-specific settings
    set(PLATFORM_LIBS )
else()
    # Unix-like systems (Linux, Haiku, etc.)
    set(PLATFORM_LIBS )
endif()

# Source files
set(SOURCES
    src/main.cpp
    src/totp.cpp
    src/base32.cpp
    src/storage.cpp
)

# Header files
set(HEADERS
    src/totp.h
    src/base32.h
    src/storage.h
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(${PROJECT_NAME} 
    OpenSSL::SSL 
    OpenSSL::Crypto
    ${PLATFORM_LIBS}
)

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE src)

# Platform-specific definitions
if(HAIKU)
    target_compile_definitions(${PROJECT_NAME} PRIVATE HAIKU_PLATFORM)
endif()

# Installation rules
install(TARGETS ${PROJECT_NAME} DESTINATION bin)