all:
	mkdir -p build
	cd build; cmake -DCMAKE_BUILD_TYPE="Debug" ..; make

test:
	mkdir -p build
	cd build; cmake -DCMAKE_BUILD_TYPE="Debug" ..; make test

clean:
	rm -rf build

.PHONY: all clean test
