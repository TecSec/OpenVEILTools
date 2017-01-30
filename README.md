# OpenVEILTools

OpenVEILTools are a set of build tools used by OpenVEIL.  These tools used to be in OpenVEIL and were split out to make it easier to cross-compile OpenVEIL.

VEIL is the productization of a revolutionary Key Management system called Constructive Key Management.  This key management system has been vetted and published in the following standards:
* ANSI X9.69
* ANSI X9.73-2010



## Installation

We use an out of source build process.  The project/make files and output
can be found in the build folder that is created by the bootstrap.

### Requirements
- VEIL Cryptographic Library 7.1.0 or later (Contact TecSec, Inc.)
- Windows
  - CMake 3.3+
  - Visual Studio 2013 or Visual Studio 2015 or mingw-w64.
- Linux
  - CMake 3.3+
  - GCC 4.8.2+
  - Ninja
- OSX
  - CLang
  - CMake 3.3+
  - XCode or Ninja
	
### Windows
	
1. Clone the repository
2. Go to the directory of the repository in a command prompt
3. `cd make\windows`
4. Run the following command to bootstrap x86 and x64(Debug and Release)
  - If Visual Studio 2015:
    - `bootstrap_VS2015.cmd`
  - If Visual Studio 2013:
    - `bootstrap_VS2013.cmd`
5. `cd ..\..\Build`
6. Run the following command to build x86 and x64(Debug and Release)
  - If Visual Studio 2015:
    - `buildall-vc14.cmd`
  - If Visual Studio 2013:
    - `buildall-vc12.cmd`

If you are going to use mingw then copy the files in make\windows\mingw_support to a folder in your path.  Then modify the files so that they reference the path to the required mingw folder.  The files are currently configured as if you had installed the mingw system in the folder c:\mingw-w64.  To bootstrap a mingw environment use the following:

`cd make\windows`

`bootstrap_mingw 4.8.2w x64`

This will use the file UseGcc4.8.2w.cmd to configure the path and then create the makefiles needed to build the samples.  In this command the 4.8.2 is the version of GCC.  The 'w' represents 'win32' threads.  Replace this with a 'p' if you are using pthreads.  The x64 is the processor type.  This could be replaced with x86 for 32 bit.

### Linux

Under Linux we support gcc but you may be able to use any compiler that cmake supports.  Note however that you must use a C++11 compiler.  The lowest version that we have tested is GCC 4.8.2.

## Usage

TODO: Write usage instructions

## Documentation

Documentation is not available yet.  Sorry.

## Contributing

To become a contributor to this project please look at the document called
**Contribution Agreement.pdf**

## License

See **LICENSE.md**
