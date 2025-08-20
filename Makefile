CXX = clang++
CXXFLAGS = -Wall -std=c++17 -Iinclude -I/opt/homebrew/include
LDFLAGS = -L/opt/homebrew/lib
LIBS = -lpcap

SRC = main.cpp \
      src/PacketSniffer.cpp \
      src/PacketHandler.cpp \
      src/PacketParser.cpp \
	  src/Logger.cpp

# Create obj/ file list from source list
OBJ = $(patsubst %.cpp,obj/%.o,$(SRC))

TARGET = PacketSniffing

# Default target
all: $(TARGET)

# Link target
$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

# Compile source files into obj/ directory
obj/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -rf obj $(TARGET)
