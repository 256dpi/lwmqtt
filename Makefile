fmt:
	clang-format -i *.c *.h -style="{BasedOnStyle: Google, ColumnLimit: 120}"
	clang-format -i packet/* -style="{BasedOnStyle: Google, ColumnLimit: 120}"
