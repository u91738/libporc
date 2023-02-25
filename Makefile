CXX=g++
CXXFLAGS= \
	-fsanitize=address \
	-fsanitize=leak \
	-fsanitize=undefined \
	-fsanitize=bounds-strict \
	-fstack-protector-all \
	-fPIC \
	-O2 -flto -g -Wall #-DUSLEEP_CHEAT #-Werror

all: example libporc.a

porc.o: porc.cpp
	$(CXX) $(CXXFLAGS) -c $^ -o $@

libporc.a: porc.o
	ar rcs $@ $^

example: example.cpp libporc.a
	$(CXX) $(CXXFLAGS)  example.cpp -L. -lcrypto -lporc -o $@

clean:
	rm -f example libporc.a porc.o
