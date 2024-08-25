cmake_minimum_required(VERSION 3.10)

# Set the project name
project(PFS_Cpp_Implementation VERSION 1.0)

# Specify C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the executable
add_executable(app main.cpp Key.cpp TA.cpp Vehicle.cpp Message.cpp)

# Include directories
include_directories(${PROJECT_SOURCE_DIR}/include)

# Link libraries if needed
# target_link_libraries(app some_library)
