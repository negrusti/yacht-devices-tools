CXX ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -pedantic
TARGET := ydconfig
SRC := ydconfig.cpp
AARCH64_CXX ?= aarch64-linux-gnu-g++
AARCH64_FLAGS ?= -O2 -std=c++17 -Wall -Wextra -pedantic -static
AARCH64_TARGET := ydconfig_aarch64_static

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(SRC)

aarch64-static: $(SRC)
	$(AARCH64_CXX) $(AARCH64_FLAGS) -o $(AARCH64_TARGET) $(SRC)

clean:
	rm -f $(TARGET) $(AARCH64_TARGET)
