.POSIX:

BIN = highlight

.PHONY: format

XCFLAGS = \
	$(CFLAGS) $(CPPFLAGS) -O3 -std=c11 \
	-fstack-protector-strong --param=ssp-buffer-size=4 \
	-Wall -Wextra -Wpedantic -Wshadow -Wwrite-strings \
	-Werror=int-conversion \
	-Werror=implicit-function-declaration \
	-Werror=incompatible-pointer-types

XLDLIBS = $(LDLIBS) -lpcre

OBJ = highlight.o

all: $(BIN)

.c.o:
	$(CC) $(XCFLAGS) -c $< -o $@

$(BIN): $(OBJ)
	$(CC) $(XCFLAGS) -o $@ $(OBJ) $(XLDLIBS) $(LDFLAGS)

format:
	clang-format -i ./*.c

clean:
	rm -f $(OBJ) $(BIN)
