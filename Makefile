CXX=g++
CXXFLAGS= \
	-fsanitize=address \
	-fsanitize=leak \
	-fsanitize=undefined \
	-fsanitize=bounds-strict \
	-fstack-protector-all \
	-O2 -flto -g -Wall #-DUSLEEP_CHEAT #-Werror

porc:
	$(CXX) $(CXXFLAGS) porc.cpp example.cpp -lcrypto -o $@

all: porc

clean:
	rm -f porc
