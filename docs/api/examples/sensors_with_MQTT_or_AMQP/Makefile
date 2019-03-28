CC=gcc
LDFLAGS=-lprelude

all: sensor1 sensor2

sensor1: sensor1.c
	${CC} sensor1.c ${LDFLAGS} -o sensor1

sensor2: sensor2.c
	${CC} sensor2.c ${LDFLAGS} -o sensor2

clean:
	rm sensor1;
	rm sensor2;
