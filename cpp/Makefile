# Compiler
CXX = g++
CXXFLAGS = -std=c++17 -Wall -I./Lib -I. 

# Directories
SRC_DIR = .
OBJ_DIR = obj
BIN_DIR = bin

# MIRACL Core Library Source Files
MIRACL_SRCS = $(SRC_DIR)/Lib/big.cpp \
              $(SRC_DIR)/Lib/ecp.cpp \
              $(SRC_DIR)/Lib/ecdh.cpp \
			  $(SRC_DIR)/Lib/eddsa.cpp \
			  $(SRC_DIR)/Lib/oct.cpp \
			  $(SRC_DIR)/Lib/fp.cpp \
			  $(SRC_DIR)/Lib/hash.cpp \
			  $(SRC_DIR)/Lib/rand.cpp \
			  $(SRC_DIR)/Lib/aes.cpp \
			  $(SRC_DIR)/Lib/hmac.cpp \
			  $(SRC_DIR)/Lib/rom_curve_Ed25519.cpp \
			  $(SRC_DIR)/Lib/rom_field_F25519.cpp \
              $(SRC_DIR)/Lib/randapi.cpp

# Project Source Files
SRCS = $(SRC_DIR)/main.cpp \
       $(SRC_DIR)/Key.cpp \
       $(SRC_DIR)/TA.cpp \
       $(SRC_DIR)/Vehicle.cpp \
       $(SRC_DIR)/Message.cpp

# All source files (project + MIRACL)
ALL_SRCS = $(SRCS) $(MIRACL_SRCS)

# Object files
OBJS = $(ALL_SRCS:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)

# Executable
TARGET = $(BIN_DIR)/app

# Create directories if they do not exist
$(shell mkdir -p $(OBJ_DIR)/Lib $(BIN_DIR))

# Default target
all: $(TARGET)

# Link the object files to create the executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS)

# Compile source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean object files and executable
clean:
	rm -f $(OBJ_DIR)/*.o $(OBJ_DIR)/Lib/*.o $(TARGET)

.PHONY: all clean
