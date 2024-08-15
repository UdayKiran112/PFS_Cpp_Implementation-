# Compiler and Flags
CXX = g++
CXXFLAGS = -Wall -std=c++17 -I./Lib
LDFLAGS = -L./Lib -lcore -lrandapi -lbig_B256_56 -lecp_Ed25519 -lecdh_Ed25519 -leddsa_Ed25519 -lconfgi_big_B256_56

# Source Files
SRCS = main.cpp Vehicle.cpp Message.cpp Key.cpp TA.cpp
OBJS = $(SRCS:.cpp=.o)

# Target Executable
TARGET = my_program

# Default Rule
all: $(TARGET)

# Link Object Files into Executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# Compile Source Files into Object Files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean Up
clean:
	rm -f $(OBJS) $(TARGET)
