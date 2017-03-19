fmt:
	clang-format -i src/* -style="{BasedOnStyle: Google, ColumnLimit: 120}"
	clang-format -i example/* -style="{BasedOnStyle: Google, ColumnLimit: 120}"
	clang-format -i tests/* -style="{BasedOnStyle: Google, ColumnLimit: 120}"
