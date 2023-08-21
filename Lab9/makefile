all : task0 

task0: myELF.o
	gcc -m32 -g -o task0 myELF.o
        
myELF.o: myELF.c
	gcc -m32 -g -c -o myELF.o myELF.c


.PHONY: clean

clean:
	rm task0 myELF.o 
