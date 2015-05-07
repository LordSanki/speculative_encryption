CFLAGS= -I. -Wno-write-strings
LIBS=
LFLGAS=

src= simple_aes8.cpp

obj= $(src:%.cpp=%.o)

all: $(obj)
	@g++ -o bin $(obj) $(LFLAGS) $(LIBS)
	@rm -f *.o
	@echo "done..............."

%.o: %.cpp
	@g++ -c $(CFLAGS) $< -o $@

clean:
	@rm -f bin *.o
