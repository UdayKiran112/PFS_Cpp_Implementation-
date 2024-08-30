# Compiler
CXX = g++
CXXFLAGS = -std=c++17 -Wall -I$(SRC_DIR)/Lib -I$(SRC_DIR)

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

# Detect Operating System
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
else
    DETECTED_OS := $(shell uname -s)
endif

# Adjust paths and commands based on OS
ifeq ($(DETECTED_OS),Windows)
    TARGET = $(BIN_DIR)\app.exe
    DEL_CMD = del /Q
    MKDIR_CMD = if not exist $(subst /,\,$(1)) mkdir $(subst /,\,$(1))
    SLASH := \\
else
    TARGET = $(BIN_DIR)/app
    DEL_CMD = rm -f
    MKDIR_CMD = mkdir -p $(1)
    SLASH := /
endif

# Create directories if they do not exist
$(shell $(call MKDIR_CMD,$(OBJ_DIR)/Lib))
$(shell $(call MKDIR_CMD,$(BIN_DIR)))

# Enable debug mode
ifeq ($(DEBUG),1)
    CXXFLAGS += -g -O0
else
    CXXFLAGS += -O2
endif

# Default target
all: $(TARGET)

# Link the object files to create the executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS)

# Compile project source files to object files (with warnings)
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@$(call MKDIR_CMD,$(dir $@))
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile MIRACL Core Library source files to object files (suppress warnings)
$(OBJ_DIR)/Lib/%.o: $(SRC_DIR)/Lib/%.cpp
	@$(call MKDIR_CMD,$(dir $@))
	$(CXX) $(CXXFLAGS) -w -c $< -o $@

# Clean object files and executable
clean:
	$(DEL_CMD) $(OBJ_DIR)$(SLASH)*.o $(OBJ_DIR)$(SLASH)Lib$(SLASH)*.o $(TARGET)

.PHONY: all clean
