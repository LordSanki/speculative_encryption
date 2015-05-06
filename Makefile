CFLAGS= -I. -g
LIBS=
LFLGAS=

src= aes_core.c cbc128.c cbc.c main.c

obj= $(src:%.c=%.o)

all: $(obj)
	@gcc -o bin $(obj) $(LFLAGS) $(LIBS)
	@rm -f *.o
	@echo "done..............."

%.o: %.c
	@gcc -c $(CFLAGS) $< -o $@

clean:
	@rm -f bin *.o
