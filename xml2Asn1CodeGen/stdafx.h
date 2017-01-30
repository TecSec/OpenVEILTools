//	Copyright (c) 2017, TecSec, Inc.
//
//	Redistribution and use in source and binary forms, with or without
//	modification, are permitted provided that the following conditions are met:
//	
//		* Redistributions of source code must retain the above copyright
//		  notice, this list of conditions and the following disclaimer.
//		* Redistributions in binary form must reproduce the above copyright
//		  notice, this list of conditions and the following disclaimer in the
//		  documentation and/or other materials provided with the distribution.
//		* Neither the name of TecSec nor the names of the contributors may be
//		  used to endorse or promote products derived from this software 
//		  without specific prior written permission.
//		 
//	ALTERNATIVELY, provided that this notice is retained in full, this product
//	may be distributed under the terms of the GNU General Public License (GPL),
//	in which case the provisions of the GPL apply INSTEAD OF those given above.
//		 
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
//	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Written by Roger Butler

// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#ifdef _WIN32
#include "targetver.h"
#endif

#include "core/compilerconfig.h"
#include "core.h"

#include "Nodes/ProcessableNode.h"

extern tsStringBase gOutputPath;
extern tsStringBase gInputPath;
extern tsStringBase gExportPath;


////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that will reverse the byte order of a 2 byte entity regardless of the byte order of the machine</summary>
///
/// <remarks>This macro is a code block and therefore cannot be used like a function.</remarks>
///
/// <param name="x">2 bytes to process.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define SWAP_SHORT(x) { BYTE * y=(BYTE *)&x; BYTE temp=*y; *y= *(y+1); *(y+1) = temp; }
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that will reverse the byte order of a 4 byte entity regardless of the byte order of the machine</summary>
///
/// <remarks>This macro is a code block and therefore cannot be used like a function.</remarks>
///
/// <param name="x">4 bytes to process.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define SWAP_LONG(x) { BYTE * y=(BYTE *)&x; BYTE temp=*y; *y= *(y+3); *(y+3) = temp; temp = *(y+1); *(y+1) = *(y+2); *(y+2) = temp; }



#ifdef _WIN32
/// <summary>A macro that defines cross platform path separator character.</summary>
#define XP_PATH_SEP_CHAR '\\'
/// <summary>A macro that defines cross platform path separator string.</summary>
#define XP_PATH_SEP_STR "\\"
/// <summary>A macro that defines cross platform pathlist separator.</summary>
#define XP_PATHLIST_SEPARATOR ';'
#else
#define XP_PATH_SEP_CHAR '/'
#define XP_PATH_SEP_STR "/"
#define XP_PATHLIST_SEPARATOR ':'
#endif

extern bool isBasicEleType(const tsStringBase& eleType);
extern bool isSequence(const tsStringBase& eleType);
extern bool getNeedsChoiceField(const tsStringBase& eleType);
extern bool getNeedsSetElementType(const tsStringBase& eleType);
extern bool getUseNumberHandling(const tsStringBase& eleType);
extern bool getCanEncode(const tsStringBase& eleType);
extern bool hasSubMetafields(const tsStringBase& eleType);
extern const char* getMetadataType(const tsStringBase& eleType);
extern const char* getToOptionalJsonLine(const tsStringBase& eleType);
extern const char* getToJsonLine(const tsStringBase& eleType);
extern const char* getFromJsonLine(const tsStringBase& eleType);
extern const char* getFromJsonLineForArray(const tsStringBase& eleType);
extern const char* getClassInitializer(const tsStringBase& eleType);
extern const char* getElementTag(const tsStringBase& eleType);
extern const char* getCppType(const tsStringBase& eleType);
extern const char* getInitializer(const tsStringBase& eleType);
extern const char* getListIteratorType(const tsStringBase& eleType);
