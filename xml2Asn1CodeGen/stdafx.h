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
extern int gUseConst;
extern int gAsC;


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
