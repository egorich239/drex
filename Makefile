all: *.cc
	g++ -g -O0 -fno-inline -Werror -Wall -Wno-sign-compare --std=c++0x *.cc -o rev.dbg
	g++ -DNDEBUG -O2 -Werror -Wall -Wno-sign-compare --std=c++0x *.cc -o rev
