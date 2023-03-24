CXX=g++

CXXFLAGS_UNSANITARY = \
	-Iinclude \
	-fPIC \
	-std=c++17 \
	-O2 -flto -g -Wall #-Werror

CXXFLAGS= \
	$(CXXFLAGS_UNSANITARY) \
	-fsanitize=address \
	-fsanitize=leak \
	-fsanitize=undefined \
	-fsanitize=bounds-strict \
	-fstack-protector-all

EXAMPLE_FLAGS_UNSANITARY= \
	$(CXXFLAGS_UNSANITARY) examples/common.cpp -L. -lcrypto -lporc

EXAMPLE_FLAGS= \
	$(CXXFLAGS) examples/common.cpp -L. -lcrypto -lporc-san

all: simple timing timing-hard timing-drift timing-corrcoef libporc.a

porc-san.o: src/porc.cpp
	$(CXX) $(CXXFLAGS) -c $^ -o $@

stats-san.o: src/stats.cpp
	$(CXX) $(CXXFLAGS) -c $^ -o $@

porc.o: src/porc.cpp
	$(CXX) $(CXXFLAGS_UNSANITARY) -c $^ -o $@

stats.o: src/stats.cpp
	$(CXX) $(CXXFLAGS_UNSANITARY) -c $^ -o $@

libporc-san.a: porc-san.o stats-san.o
	ar rcs $@ $^

libporc.a: porc.o stats.o
	ar rcs $@ $^

simple: examples/simple.cpp examples/common.cpp libporc-san.a
	$(CXX) examples/simple.cpp $(EXAMPLE_FLAGS) -o $@

timing: examples/timing.cpp examples/common.cpp libporc-san.a
	$(CXX) examples/timing.cpp $(EXAMPLE_FLAGS) -o $@

timing-hard: examples/timing-hard.cpp examples/common.cpp libporc.a
	$(CXX) examples/timing-hard.cpp $(EXAMPLE_FLAGS_UNSANITARY) -o $@

timing-drift: examples/timing-drift.cpp examples/common.cpp libporc-san.a
	$(CXX) examples/timing-drift.cpp $(EXAMPLE_FLAGS) -o $@

timing-corrcoef: examples/timing-corrcoef.cpp examples/common.cpp libporc-san.a
	$(CXX) examples/timing-corrcoef.cpp $(EXAMPLE_FLAGS) -o $@

unreliable: examples/unreliable.cpp examples/common.cpp libporc-san.a
	$(CXX) examples/unreliable.cpp $(EXAMPLE_FLAGS) -o $@

clean:
	rm -f simple timing timing-hard timing-drift timing-corrcoef unreliable \
          libporc.a libporc-san.a *.o
