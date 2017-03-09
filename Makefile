fmt:
	clang-format -i MQTTClient.c MQTTClient.h -style="{BasedOnStyle: Google, ColumnLimit: 120}"
	clang-format -i packet/* -style="{BasedOnStyle: Google, ColumnLimit: 120}"
