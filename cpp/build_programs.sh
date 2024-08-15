#!/bin/bash

# Directories
SRC_DIR="./"  # Change this to the directory with your source files if needed
LIB_DIR="./Lib"
BUILD_DIR="./build"

# Create directories if they don't exist
mkdir -p $LIB_DIR
mkdir -p $BUILD_DIR

# Source files (make sure these files exist in the current directory)
SRC_FILES=("core.cpp" "randapi.cpp" "big_B256_56.cpp" "ecp_Ed25519.cpp" "ecdh_Ed25519.cpp" "eddsa_Ed25519.cpp" "config_big_B256_56.cpp")

# Compile source files into object files
echo "Compiling source files..."
for src in "${SRC_FILES[@]}"; do
    g++ -fPIC -c -I$LIB_DIR "$SRC_DIR/$src" -o "$BUILD_DIR/${src%.cpp}.o"
done

# Create static libraries
echo "Creating static libraries..."
for src in "${SRC_FILES[@]}"; do
    lib_name=$(basename "${src%.cpp}")
    ar rcs "$LIB_DIR/lib${lib_name}.a" "$BUILD_DIR/${lib_name}.o"
done

# Compile the main program
echo "Compiling the main program..."
g++ -Wall -std=c++17 -I$LIB_DIR -o my_program main.cpp Vehicle.cpp Message.cpp Key.cpp TA.cpp \
    -L$LIB_DIR -lcore -lrandapi -lbig_B256_56 -lecp_Ed25519 -lecdh_Ed25519 -leddsa_Ed25519 -lconfig_big_B256_56

echo "Build complete."
