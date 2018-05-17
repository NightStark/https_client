all:https
https:http.c
	gcc http.c -levent -lssl -lcrypto -lpthread -Wall -ggdb -o https
