# Makefile for DNS Load Balancer

CC := gcc
# High-performance optimizations for maximum throughput
CFLAGS := -O3 -march=native -mtune=native -flto -funroll-loops -ffast-math -Wall -Wextra -DNDEBUG -D_GNU_SOURCE
LDFLAGS := -lpthread -flto

# Conservative build (use only if high-performance build fails)
# CFLAGS := -O2 -Wall -Wextra -DNDEBUG -D_GNU_SOURCE
# LDFLAGS := -lpthread

# Output binaries
TARGET := dns_load_balancer
MOCK_SERVER := mock_dns_server

.PHONY: all clean

all: $(TARGET) $(MOCK_SERVER)


# Main load balancer
$(TARGET): main.o backend_manager.o health_checker.o dns_parser.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Mock DNS server - FIXED: Link with dns_parser.o
$(MOCK_SERVER): mock_dns_server.o dns_parser.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile all object files
main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o

backend_manager.o: backend_manager.c
	$(CC) $(CFLAGS) -c backend_manager.c -o backend_manager.o

health_checker.o: health_checker.c
	$(CC) $(CFLAGS) -c health_checker.c -o health_checker.o

dns_parser.o: dns_parser.c
	$(CC) $(CFLAGS) -c dns_parser.c -o dns_parser.o



mock_dns_server.o: mock_dns_server.c
	$(CC) $(CFLAGS) -c mock_dns_server.c -o mock_dns_server.o

clean:
	rm -f $(TARGET) $(MOCK_SERVER) *.o

debug: CFLAGS += -g -DDEBUG
debug: clean all

test: all
	@echo "Starting mock DNS servers..."
	./$(MOCK_SERVER) --port 5353 &
	./$(MOCK_SERVER) --port 5354 &
	@sleep 2
	@echo "Starting load balancer (requires root)..."
	sudo ./$(TARGET) -v
	@pkill -f $(MOCK_SERVER)

.PHONY: test