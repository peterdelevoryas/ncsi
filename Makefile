all: ncsi

CXXFLAGS := -std=c++17 -O0 -g -Wall -Werror -fno-exceptions

ncsi: main.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

.PHONY: test

test: ncsi
	sudo ./ncsi tap0
