all: *.cc
	g++ -g -O0 -fno-inline -Wall -Wno-sign-compare --std=c++0x *.cc -o rev.dbg
	g++ -O2 -Wall -Wno-sign-compare --std=c++0x *.cc -o rev
