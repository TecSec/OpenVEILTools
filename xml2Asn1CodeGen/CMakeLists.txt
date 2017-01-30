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
    xml2Asn1CodeGen.cpp
    stdafx.cpp
	
	Nodes/Asn1DatasetNode.cpp
    Nodes/Asn1Export.cpp
	Nodes/DescriptionNode.cpp
	Nodes/Namespace.cpp
	Nodes/ProcessableNode.cpp
	Nodes/SequenceNode.cpp
	Nodes/SequenceOfNode.cpp
	Nodes/SetNode.cpp
	Nodes/VersionNode.cpp
	Nodes/PartNode.cpp
	Nodes/FunctionNode.cpp
	Nodes/BasicFieldNode.cpp
	Nodes/ChoiceNode.cpp
	Nodes/SequenceFieldNode.cpp
	Nodes/SequenceOfFieldNode.cpp
	Nodes/Element.cpp
	Nodes/TaggedElement.cpp
	Nodes/EnumNode.cpp
	Nodes/NamedInt.cpp
	Nodes/BitstringNode.cpp
	Nodes/AliasNode.cpp
	Nodes/OIDNode.cpp
	Nodes/ChoiceFieldNode.cpp
    Nodes/ImportNode.cpp
    )
	
IF(WIN32)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/xml2Asn1CodeGen.rc.in ${CMAKE_CURRENT_BINARY_DIR}/xml2Asn1CodeGen.rc)
    set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/xml2Asn1CodeGen.rc PROPERTIES COMPILE_DEFINITIONS RC_COMPILED)
    set(CppSources ${CppSources} ${CMAKE_CURRENT_BINARY_DIR}/xml2Asn1CodeGen.rc xml2Asn1CodeGen.rc.in)
ENDIF(WIN32)

add_executable(xml2Asn1CodeGen 
	targetver.h 
	stdafx.h 

	Nodes/Asn1DatasetNode.h
	Nodes/Asn1Export.h
	Nodes/DescriptionNode.h
	Nodes/FileNode.h
	Nodes/Namespace.h
	Nodes/ProcessableNode.h
	Nodes/IncludeNode.h
	Nodes/OIDNode.h
	Nodes/AliasNode.h
	Nodes/EnumNode.h
	Nodes/NamedInt.h
	Nodes/BitstringNode.h
	Nodes/SequenceNode.h
	Nodes/SequenceOfNode.h
	Nodes/SetNode.h
	Nodes/VersionNode.h
	Nodes/PartNode.h
	Nodes/FunctionNode.h
	Nodes/BasicFieldNode.h
	Nodes/ChoiceNode.h
	Nodes/SequenceFieldNode.h
	Nodes/SequenceOfFieldNode.h
	Nodes/Element.h
	Nodes/ElementModifier.h
	Nodes/TaggedElement.h
	Nodes/ElementContainer.h
	Nodes/ChoiceFieldNode.h
    Nodes/ImportNode.h

	${CppSources} 
	${PUBLIC_SOURCE_TOP_DIR}/SolutionItems/xml2asn1codegen.xsd
	)
SOURCE_GROUP("Nodes" FILES
	Nodes/Asn1DatasetNode.h
	Nodes/Asn1DatasetNode.cpp
	Nodes/Asn1Export.h
	Nodes/Asn1Export.cpp
	Nodes/DescriptionNode.h
	Nodes/DescriptionNode.cpp
	Nodes/FileNode.h
	Nodes/Namespace.h
	Nodes/Namespace.cpp
	Nodes/ProcessableNode.h
	Nodes/ProcessableNode.cpp
	Nodes/IncludeNode.h
	Nodes/OIDNode.h
	Nodes/OIDNode.cpp
	Nodes/AliasNode.h
	Nodes/AliasNode.cpp
	Nodes/EnumNode.h
	Nodes/EnumNode.cpp
	Nodes/NamedInt.h
	Nodes/NamedInt.cpp
	Nodes/BitstringNode.h
	Nodes/BitstringNode.cpp
	Nodes/ImportNode.h
	Nodes/ImportNode.cpp
    Nodes/SequenceNode.h
	Nodes/SequenceOfNode.h
	Nodes/SetNode.h
	Nodes/SequenceNode.cpp
	Nodes/SequenceOfNode.cpp
	Nodes/SetNode.cpp
	Nodes/VersionNode.h
	Nodes/VersionNode.cpp
	Nodes/PartNode.h
	Nodes/PartNode.cpp
	Nodes/FunctionNode.h
	Nodes/FunctionNode.cpp
	Nodes/BasicFieldNode.h
	Nodes/BasicFieldNode.cpp
	Nodes/ChoiceNode.h
	Nodes/ChoiceNode.cpp
	Nodes/SequenceFieldNode.h
	Nodes/SequenceFieldNode.cpp
	Nodes/SequenceOfFieldNode.h
	Nodes/SequenceOfFieldNode.cpp
	Nodes/Element.h
	Nodes/Element.cpp
	Nodes/ElementModifier.h
	Nodes/TaggedElement.h
	Nodes/TaggedElement.cpp
	Nodes/ElementContainer.h
	Nodes/ChoiceFieldNode.h
	Nodes/ChoiceFieldNode.cpp
	)

add_precompiled_header(xml2Asn1CodeGen stdafx.h FORCEINCLUDE SOURCE_CXX stdafx.cpp)
target_compile_definitions(xml2Asn1CodeGen PRIVATE $<$<NOT:$<COMPILE_FEATURES:cxx_constexpr>>:USE_CONST>)
set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/xml2Asn1CodeGen.rc PROPERTIES COMPILE_DEFINITIONS RC_COMPILED)
# add_dependencies(xml2Asn1CodeGen toolsBase)
# SetCxxExeTargetProperties_sdk(xml2Asn1CodeGen)

set_target_properties(xml2Asn1CodeGen PROPERTIES FOLDER "BuildTools")
TARGET_LINK_LIBRARIES(xml2Asn1CodeGen 
    ToolsCore
)

install(TARGETS xml2Asn1CodeGen ARCHIVE DESTINATION ${LIB_DIR} LIBRARY DESTINATION ${SHLIB_DIR} RUNTIME DESTINATION ${BIN_DIR})
