fmt:
	clang-format -i include/*.h include/lwmqtt/*.h -style="{BasedOnStyle: Google, ColumnLimit: 120, SortIncludes: false}"
	clang-format -i src/*.c src/*.h -style="{BasedOnStyle: Google, ColumnLimit: 120, SortIncludes: false}"
	clang-format -i examples/*.c -style="{BasedOnStyle: Google, ColumnLimit: 120, SortIncludes: false}"
	clang-format -i tests/*.cpp -style="{BasedOnStyle: Google, ColumnLimit: 120, SortIncludes: false}"
