# functions

Python repository containing parsed standard C library function and argument information.
See `Example usage` section to see if it may help you.

## How do I use it?

I already built it for you, just look at [functions.py](functions.py).

If you want to build `functions.py` yourself, just clone the repo and fire `make clean all`.

Things will probably blow up, which is why I included a `Dockerfile`.
You can build `functions.py` with a simple `make release`.

Note that it will build a docker image `functions` on your machine using the [Dockerfile](docker/Dockerfile) present in repo that is based on [pwntools/pwntools](https://hub.docker.com/r/pwntools/pwntools) docker image.

## Example usage

```
>>> from functions import functions
>>> print functions['memcpy']
Function(type='void', derefcnt=1, name='memcpy', args=[Argument(type='void', derefcnt=1, name='dest'), Argument(type='void', derefcnt=1, name='src'), Argument(type='size_t', derefcnt=0, name='n')])
>>> print functions['memcpy'].args
[Argument(type='void', derefcnt=1, name='dest'), Argument(type='void', derefcnt=1, name='src'), Argument(type='size_t', derefcnt=0, name='n')]
>>> print functions['memcpy'].args[0]
Argument(type='void', derefcnt=1, name='dest')
>>> print functions['memcpy'].type
void
>>> print functions['memcpy'].derefcnt
1
```

## Notes aka how it works

We keep a list of includes in [source.c](source.c). This file is then passed to GCC's preprocessor (`gcc -E` flag) so we get a `source.o` file that contains the content of all included headers (it is not really an object file).

We also keep a list of missing functions in `missing.txt`. Those functions are not present in the listed headers. We fetch their declarations from `man` pages using `missing.sh` and create `missing.h` header.

Later, we concatenate both files: `source.o` and `missing.h` into `preprocesed.h` file.

Finally, we just pass everything (`preprocessed.h` file) to [PyCParser](https://github.com/eliben/pycparser) and extract all functions and arguments, as well as their types.

Some syscalls are not in any standard C headers, so these have been added to `missing.txt`.  The signatures are manually (pun!) extracted from the man pages.
