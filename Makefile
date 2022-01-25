all: ncsi

CFLAGS := -std=gnu17 -O0 -g -Wall -Werror
CXXFLAGS := -std=c++17 -O0 -g -Wall -Werror -fno-exceptions

ncsi.o: ncsi.c ncsi.h
	$(CC) $(CFLAGS) -c $< -o $@

main.o: main.cpp ncsi.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

ncsi: ncsi.o main.o
	$(CXX) $(CXXFLAGS) $^ -o $@

.PHONY: test

test: ncsi
	sudo ./ncsi tap0
