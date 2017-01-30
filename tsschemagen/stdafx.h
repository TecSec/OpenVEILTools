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

#pragma once

#ifdef _WIN32
#include "targetver.h"
#endif

#include "core/compilerconfig.h"

#ifdef _WIN32
#include <Windows.h>
#else
typedef unsigned char BYTE;
#endif

#include "core.h"

#include "Nodes/Schema.h"
#include "Nodes/ColumnContainer.h"
#include "Nodes/TableColumn.h"
#include "Nodes/Index.h"
#include "Nodes/DataRow.h"
#include "Nodes/CppInclude.h"
#include "Nodes/Table.h"
#include "Nodes/DatabaseView.h"
#include "Nodes/View.h"
#include "Nodes/Relation.h"

extern tsStringBase gOutputPath;
extern tsStringBase gPrefix;
extern tsStringBase gBuildType;

#include "SQLHelper.h"
#include "SQLServerHelper.h"
#include "SqliteHelper.h"
#include "CppHelper.h"
#include "OracleHelper.h"
#include "MySQLHelper.h"



