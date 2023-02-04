fmt:
	clang-format -i include/*.h include/lwmqtt/*.h -style="{BasedOnStyle: Google, ColumnLimit: 120, SortIncludes: false}"
	clang-format -i src/*.c src/*.h -style="{BasedOnStyle: Google, ColumnLimit: 120, SortIncludes: false}"
	clang-format -i src/os/*.c -style="{BasedOnStyle: Google, ColumnLimit: 120, SortIncludes: false}"
	clang-format -i examples/*.c -style="{BasedOnStyle: Google, ColumnLimit: 120, SortIncludes: false}"
	clang-format -i tests/*.cpp -style="{BasedOnStyle: Google, ColumnLimit: 120, SortIncludes: false}"

gtest:
	git clone --branc release-1.8.1 --depth 1 https://github.com/google/googletest.git gtest
