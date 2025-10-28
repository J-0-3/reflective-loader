# Reflective Loader

This project is a reflective PE loader capable of taking the raw bytes of a
PE binary from memory and loading it so that it can be used like a normal
DLL / executable. 

It can load binaries either into its own address space (local) or into
another process's address space (remote). The remote loading is done by
re-implementing all of the loader steps with ReadProcessMemory and
WriteProcessMemory. 

# Usage

The project by default compiles a demo executable which will take the path to a
dll, a function name, and an optional pid to inject into, and then read the dll
from disk, reflectively load it into itself or the specified process, and
execute the given function (using CreateRemoteThread if a remote process was
specified). 

This, clearly, is not much use, but serves as a blueprint for how to use the
loader. You can copy the basic structure of how `main.c` performs its loading
and code execution in order to do more useful things with the loader in your
own code.

I may at some point turn this into a statically linkable library which would be
somewhat easier to include in other projects, but right now you will have to
include the source directly in your project code, or adapt this repo directly.

# Building

The project is designed to be built on linux with mingw-w64 and cmake. That
being said, its only dependency is the windows API so it would definitely be
possible to adapt the build scripts to work on windows with cmake or msbuild.

## Steps

- Install mingw-w64 and cmake, how you do this depends on your linux distro.
- Clone the repo if you have not already done so, and cd into it.
- Run the following command: `mkdir build && cd build && cmake .. && cmake --build .`
- The loader demo binary is now at `loader.exe`

# Disclaimer

Reflective loading is a technique commonly used by malware, I have written this
POC exclusively for educational and legitimate research purposes. Please do not
use it to write malicious software or in any other unauthorised or illegal way!
Always be aware of and follow your local relevant laws and regulations. This
repo does not aim to bypass security products, or act in a stealthy manner, and
is solely an example of how reflective loading could be implemented for
research and educational purposes.
