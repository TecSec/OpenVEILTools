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

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR} 
    )

set(CppSources 
    schemagen.cpp
    stdafx.cpp
	SQLHelper.cpp
	SQLServerHelper.cpp
	SqliteHelper.cpp
	CppHelper.cpp
	CHelper.cpp
	OracleHelper.cpp
	MySQLHelper.cpp
	
	Nodes/Schema.cpp
	Nodes/ColumnContainer.cpp
	Nodes/Index.cpp
	Nodes/TableColumn.cpp
	Nodes/DataRow.cpp
	Nodes/CppInclude.cpp
	Nodes/Table.cpp
	Nodes/View.cpp
	Nodes/DatabaseView.cpp
	Nodes/Relation.cpp
    )

IF(WIN32)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/schemagen.rc.in ${CMAKE_CURRENT_BINARY_DIR}/schemagen.rc)
    set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/schemagen.rc PROPERTIES COMPILE_DEFINITIONS RC_COMPILED)
    set(CppSources ${CppSources} ${CMAKE_CURRENT_BINARY_DIR}/schemagen.rc schemagen.rc.in)
ENDIF(WIN32)

# CopyImportTargetBinariesToBuildFolder(VEILCore ${EXTRA_FILE_OUTPUT})

add_executable(tsschemagen 
	targetver.h 
	stdafx.h 
	SQLHelper.h
	SQLServerHelper.h
	SqliteHelper.h
	CppHelper.h
	CHelper.h
	OracleHelper.h
	MySQLHelper.h

    # ${soFilesToCopy}

	${CppSources} 
	Nodes/Schema.h
	Nodes/ColumnContainer.h
	Nodes/Index.h
	Nodes/TableColumn.h
	Nodes/DataRow.h
	Nodes/CppInclude.h
	Nodes/Table.h
	Nodes/View.h
	Nodes/DatabaseView.h
	Nodes/Relation.h
	)
SOURCE_GROUP("Nodes" FILES
	Nodes/Schema.cpp
	Nodes/Schema.h
	Nodes/ColumnContainer.cpp
	Nodes/ColumnContainer.h
	Nodes/Index.cpp
	Nodes/Index.h
	Nodes/TableColumn.cpp
	Nodes/TableColumn.h
	Nodes/DataRow.cpp
	Nodes/DataRow.h
	Nodes/CppInclude.cpp
	Nodes/CppInclude.h
	Nodes/Table.cpp
	Nodes/Table.h
	Nodes/View.cpp
	Nodes/View.h
	Nodes/DatabaseView.cpp
	Nodes/DatabaseView.h
	Nodes/Relation.cpp
	Nodes/Relation.h
	)
add_precompiled_header(tsschemagen stdafx.h FORCEINCLUDE SOURCE_CXX stdafx.cpp)
set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/schemagen.rc PROPERTIES COMPILE_DEFINITIONS RC_COMPILED)
# add_dependencies(schemagen toolsBase)
# SetCxxExeTargetProperties_sdk(schemagen)
set_target_properties(tsschemagen PROPERTIES FOLDER "BuildTools")
TARGET_LINK_LIBRARIES(tsschemagen 
	ToolsCore
)

# install(TARGETS tsschemagen ARCHIVE DESTINATION ${LIB_DIR} LIBRARY DESTINATION ${SHLIB_DIR} RUNTIME DESTINATION ${BIN_DIR})
