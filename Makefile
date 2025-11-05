CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O3 -pthread -march=native -D_GNU_SOURCE
LDFLAGS = -pthread

# Source files
SOURCES = main.cpp config.cpp dns.cpp backend_manager.cpp worker.cpp
OBJECTS = $(SOURCES:.cpp=.o)
HEADERS = config.hpp dns.hpp backend_manager.hpp worker.hpp shared.hpp

# Target executable
TARGET = dns_loadbalancer

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Compile source files
%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET)
	@echo "Clean complete"

# Install (optional - copies to /usr/local/bin)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	@echo "Installed to /usr/local/bin/$(TARGET)"

# Uninstall
uninstall:
	rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstalled from /usr/local/bin/$(TARGET)"

# Debug build
debug: CXXFLAGS = -std=c++17 -Wall -Wextra -g -O0 -pthread -DDEBUG
debug: $(TARGET)

# Release build with additional optimizations
release: CXXFLAGS = -std=c++17 -Wall -Wextra -O3 -pthread -march=native -flto -DNDEBUG
release: $(TARGET)

# Help target
help:
	@echo "DNS Load Balancer Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the load balancer (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  debug     - Build with debug symbols"
	@echo "  release   - Build optimized release version"
	@echo "  install   - Install to /usr/local/bin"
	@echo "  uninstall - Remove from /usr/local/bin"
	@echo "  help      - Show this help message"

.PHONY: all clean install uninstall debug release help

