cmake_minimum_required(VERSION 3.10)

# Set the project name
project(PFS_Cpp_Implementation VERSION 1.0)

# Specify C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Specify the source files
file(GLOB_RECURSE SOURCES "cpp/*.cpp")

# Add the executable
add_executable(app ${SOURCES})

# Include directories
include_directories(${PROJECT_SOURCE_DIR}/cpp/Design)
include_directories(${PROJECT_SOURCE_DIR}/cpp/Lib)

# Link libraries if needed
# target_link_libraries(app some_library)
