
# -- Compilers --
CC  = gcc
CXX = g++

# -- Output files --
OUT ?= missing.h preprocessed.h functions.py

# -- Directories --
SRC ?= .
INCLUDES = -I.
LDFLAGS = -L.

# -- Flags --
ifdef DEBUG
	CFLAGS		+= -ggdb -O0 -DDEBUG=1
	LDFLAGS		+= -ggdb -O0 -DDEBUG=1
endif
CFLAGS 		+= $(INCLUDES)

# -- Input Files --
C_FILES   = $(wildcard $(SRC)/*.c)
CPP_FILES = $(wildcard $(SRC)/*.cpp) $(wildcard $(SRC)/*.cc)
OBJ_FILES = $(patsubst %.c, %.o, $(C_FILES)) $(patsubst %.cpp, %.o, $(CPP_FILES)) $(patsubst %.cc, %.o, $(CPP_FILES))

# -- Dependencies --
DEPFILE = .depfile

all: $(OUT)

missing.h:
	bash missing.sh > "$@"

release:
	$(MAKE) -C docker

# Output file
# =========================================================
preprocessed.h: $(OBJ_FILES) missing.h
	@echo Collecting $@ from [ $^ ]
	cat $^ > $@

functions.py: preprocessed.h script.py
	python script.py $<

# Compile source files
# These rules are rewritten into the dependencies file
# =========================================================
.c.o:
	@echo Compiling $@ from [ $< ]
	$(CC) $(CFLAGS) -E -P -c $< > $@

.cc.o:
	@echo Compiling $@ from [ $< ]
	$(CXX) $(CFLAGS) -E -P -c $< > $@

.cpp.o:
	@echo Compiling $@ from [ $< ]
	$(CXX) $(CFLAGS) -E -P -c $< > $@

# Generate dependencies.
# =========================================================
$(DEPFILE):
	rm -f $(DEPFILE)
	$(CC)  -E -MM $(CFLAGS) $(INCLUDES) $(CPP_FILES) $(C_FILES) -MF $(DEPFILE)

clean:
	rm -f $(OUT) $(SRC)/*.o $(DEPFILE)

# Generated dependency file.  Note the dependencies on
# $(DEPFILE)
# =========================================================
NODEPS:=clean tags svn
ifeq (0, $(words $(findstring $(MAKECMDGOALS), $(NODEPS))))
	-include $(DEPFILE)
endif

.SUFFIXES: .c .cpp
.PHONY: all clean install
