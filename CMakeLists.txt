#	Copyright (c) 2017, TecSec, Inc.
#
#	Redistribution and use in source and binary forms, with or without
#	modification, are permitted provided that the following conditions are met:
#	
#		* Redistributions of source code must retain the above copyright
#		  notice, this list of conditions and the following disclaimer.
#		* Redistributions in binary form must reproduce the above copyright
#		  notice, this list of conditions and the following disclaimer in the
#		  documentation and/or other materials provided with the distribution.
#		* Neither the name of TecSec nor the names of the contributors may be
#		  used to endorse or promote products derived from this software 
#		  without specific prior written permission.
#		 
#	ALTERNATIVELY, provided that this notice is retained in full, this product
#	may be distributed under the terms of the GNU General Public License (GPL),
#	in which case the provisions of the GPL apply INSTEAD OF those given above.
#		 
#	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
#	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Written by Roger Butler

IF(WIN32)
	cmake_minimum_required(VERSION 3.2)
	set_property(GLOBAL PROPERTY USE_FOLDERS On)
ELSE()
    cmake_minimum_required(VERSION 3.2)
ENDIF()

LIST(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmakemodules)
if(POLICY CMP0005)
    cmake_policy(SET CMP0005 NEW)
endif()
if(POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)
endif()
if(POLICY CMP0058)
    cmake_policy(SET CMP0058 NEW)
endif()

set(TS_VS_CONFIG ${CMAKE_BUILD_TYPE})
set (CMAKE_CONFIGURATION_TYPES ${CMAKE_BUILD_TYPE})
set (CMAKE_CONFIGURATION_TYPES "${CMAKE_CONFIGURATION_TYPES}" CACHE STRING "Reset the configurations" FORCE )
mark_as_advanced(CMAKE_CONFIGURATION_TYPES)

set(CMAKE_OSX_DEPLOYMENT_TARGET 10.11)
set(CMAKE_OSX_ARCHITECTURES "Universal")

set(DEBUG_CYBERVEIL OFF)

set(SuperProject ON)
set(TS_SUPPRESS_TOOLSET ON)

#
# Set up the project name and look for the compiler configuration
#
# set(TS_MODULE_BIN OpenVEIL)
set(TS_MODULE_INCLUDE OpenVEILTools)
project(OpenVEILTools LANGUAGES C CXX)

#
# Include the TecSec macros and variables.  Look for the OpaqueVEIL, OpenVEIL and VEILCrypto
#
include(tecsec_configure_env)
include(tecsec_ConfigureCyberVEIL)
set(SDK_FOLDER ${CRYPTO_INSTALL_BASE_DIR})
if(APPLE)
	set(TS_INSTALL_PREFIX /usr/local)
else()
	set(TS_INSTALL_PREFIX ${CRYPTO_INSTALL_PREFIX})
endif()

include(tecsec_packages)
IF(MSVC)
	# include(compiler_tecsec_msvc.noWarnings)
ENDIF(MSVC)
set(NO_PCH OFF)
if(MINGW)
    set(NO_PCH ON)
endif(MINGW)
include(precompiled.header)
include (tecsec_installdirs)

# Reconfigure for static RTE
if(MSVC)
	set(CMAKE_C_FLAGS_DEBUG         "${CMAKE_C_FLAGS_DEBUGSTATIC}")
	set(CMAKE_C_FLAGS_RELEASE       "${CMAKE_C_FLAGS_RELEASESTATIC}")
	set(CMAKE_CXX_FLAGS_DEBUG       "${CMAKE_CXX_FLAGS_DEBUGSTATIC}")
	set(CMAKE_CXX_FLAGS_RELEASE     "${CMAKE_CXX_FLAGS_RELEASESTATIC}")
endif(MSVC)

ImportTarget(CyberVEIL)

#
# Configure some of the Linux SO parameters
#
if(APPLE)
    SET(CMAKE_SKIP_BUILD_RPATH FALSE)
    SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
    SET(CMAKE_INSTALL_RPATH "$ORIGIN;${SHLIB_DIR};~/local")
    SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
elseif(UNIX)
    SET(CMAKE_SKIP_BUILD_RPATH FALSE)
    SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
    SET(CMAKE_INSTALL_RPATH "$ORIGIN;${SHLIB_DIR};~/local")
    SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)
endif(APPLE)


#####################################################################
## Start Options
#####################################################################

## SET VERSION HERE
set(VEILTOOLS_MAJOR_VERSION 7)
set(VEILTOOLS_MINOR_VERSION 0)
set(VEILTOOLS_REVISION_VERSION 67)
set(VEILTOOLS_BUILD_VERSION 0)
set(OSX_FRAMEWORK_VERSION A)

#####################################################################
## End Options
#####################################################################
set(VEIL_COPYRIGHT "Copyright (C) 2018 TecSec, Inc.  All Rights Reserved Worldwide.")

set(VEILTOOLS_VERSION "${VEILTOOLS_MAJOR_VERSION}.${VEILTOOLS_MINOR_VERSION}.${VEILTOOLS_REVISION_VERSION}")
set(VEILTOOLS_VERSION_COMMA "${VEILTOOLS_MAJOR_VERSION},${VEILTOOLS_MINOR_VERSION},${VEILTOOLS_REVISION_VERSION}")
set(VEILTOOLS_SO_VERSION "${VEILTOOLS_MAJOR_VERSION}")

set(VEILCORE_VERSION ${VEILTOOLS_VERSION})
set(VEILCORE_VERSION_COMMA ${VEILTOOLS_VERSION_COMMA})

set(ENABLE_NASM OFF)
ENABLE_LANGUAGE(ASM_NASM)
if(CMAKE_ASM_NASM_COMPILER_WORKS)
	set(ENABLE_NASM ON)
endif(CMAKE_ASM_NASM_COMPILER_WORKS)

# set(ENABLE_MASM OFF)
# ENABLE_LANGUAGE(ASM_MASM)
# if(CMAKE_ASM_MASM_COMPILER_WORKS)
# 	set(ENABLE_MASM ON)
# endif(CMAKE_ASM_MASM_COMPILER_WORKS)

IF(WIN32)
    set(GTEST_ROOT c:/GoogleTest/${TS_TOOLSET}_${TS_X_PLATFORM})
ENDIF(WIN32)

find_package(GTest)

if(GTEST_FOUND)
	# enable_testing()
endif()

include(summary)

#
# Place the output into these folders
#
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PUBLIC_BINARY_TOP_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PUBLIC_BINARY_TOP_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PUBLIC_BINARY_TOP_DIR}/bin")
set(CMAKE_PDB_OUTPUT_DIRECTORY "${PUBLIC_BINARY_TOP_DIR}/pdb")
set(OSX_FRAMEWORK_FOLDER "/Library/Frameworks")
set(OSX_SDK_DIR "{PUBLIC_BINARY_TOP_DIR}/sdk")

set(EXTRA_FILE_OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
if (MSVC_IDE)
	set(EXTRA_FILE_OUTPUT ${EXTRA_FILE_OUTPUT}/${CMAKE_BUILD_TYPE})
endif(MSVC_IDE)

# look for system header files needed

FOREACH(KEYWORD "__inline__" "__inline" "inline")
  IF(NOT DEFINED C_INLINE)
    TRY_COMPILE(C_HAS_${KEYWORD} "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems/test_inline.c" COMPILE_DEFINITIONS "-Dinline=${KEYWORD}")
    IF(C_HAS_${KEYWORD})
      MESSAGE(STATUS "Inline found as ${KEYWORD}")
      SET(C_INLINE TRUE)
      SET(TS_INLINE ${KEYWORD})
    ENDIF()
  ENDIF()
ENDFOREACH(KEYWORD)
IF(NOT DEFINED C_INLINE)
  MESSAGE(STATUS "Inline not found")
  SET(TS_INLINE "")
ENDIF()

find_package(PCSC)

if (PCSC_FOUND AND NOT APPLE)
	get_property(_tmp TARGET pcsc PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
	if(NOT ("${_tmp}" STREQUAL ""))
		include_directories(${_tmp})
		set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES} ${_tmp})
	endif(NOT ("${_tmp}" STREQUAL ""))
	get_property(_tmp TARGET pcsc PROPERTY DLOPEN_SONAME)
	set(PCSC_SO_NAME, ${_tmp})
	message(STATUS 	"set(PCSC_SO_NAME, ${_tmp})")
endif()

if(CMAKE_COMPILER_IS_GNUCC)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wdeclaration-after-statement -Wstrict-prototypes")
endif()

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(PROJECT_POSTFIX _d)
else()
    set(PROJECT_POSTFIX )
endif()

set(HAVE_SMARTCARD 0)
if(WIN32)
    set(HAVE_SMARTCARD 1)
elseif(TARGET pcsc)
    set(HAVE_SMARTCARD 1)
elseif(APPLE)
    set(HAVE_SMARTCARD 1)
endif(WIN32)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems/compilerconfig.h.in ${CMAKE_CURRENT_BINARY_DIR}/core/compilerconfig.h)
# CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems/compilerconfig_c.h.in ${CMAKE_CURRENT_BINARY_DIR}/core/compilerconfig_c.h)

include_directories(
	${CMAKE_CURRENT_BINARY_DIR} 
	${CMAKE_CURRENT_SOURCE_DIR}/include 
	${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems
	)

IF(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/bzip2")
	include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/bzip2)
ENDIF(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/bzip2")
if(NOT ANDROID)
	IF(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/zlib")
		include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/zlib)
		include_directories(${CMAKE_CURRENT_BINARY_DIR}/ThirdParty/zlib)
	ENDIF(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/zlib")
ELSE()
	set(CMAKE_INSTALL_DO_STRIP ON)
ENDIF()

add_subdirectory(core)
add_subdirectory(xml2Asn1CodeGen)
# add_subdirectory(tsschemagen)
IF(WIN32)
    add_subdirectory(Com2H)
ENDIF(WIN32)

summary()
add_uninstall()

# DumpAllVariables()
