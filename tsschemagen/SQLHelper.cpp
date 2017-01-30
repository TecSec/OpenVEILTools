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

#include "stdafx.h"
#include "SQLHelper.h"
#include "Nodes/Schema.h"

SQLHelper::SQLHelper()
{
}

SQLHelper::~SQLHelper()
{

}

//public XmlDocument SchemaData
//{
//    get { return m_schemaData; }
//}

std::shared_ptr<::Schema> SQLHelper::Schema() const
{
	return m_schema;
}

tsStringBase SQLHelper::StringToSQL(const tsStringBase& _input)
{
	tsStringBase input(_input);

	if (input == "[[NULL]]")
		return "NULL";

	input.Replace(StringEnd(), StringEnd() + StringEnd());
	return StringStart() + input + StringEnd();
}
void SQLHelper::LoadSchemaInfo(const tsStringBase& schemaFile)
{
	std::shared_ptr<tsXmlNode> doc = tsXmlNode::Create();
	tsStringBase contents;
	tsStringBase Results;

	if (!xp_ReadAllText(schemaFile, contents))
	{
		printf("Unable to open file %s\n", schemaFile.c_str());
		return;
	}
	doc->AddTsIDs(false);
	if (!doc->Parse(contents, Results, false, false))
	{
		printf("The contents of the file %s could not be processed.\n", schemaFile.c_str());
		return;
	}

	m_schema = ::Schema::Create(doc);
}
//System.Type SQLHelper::ResolveType(string typeName)
//{
//	switch (typeName)
//	{
//	case "System.String":
//	case "System.Char[]":
//		return typeof(System.String);
//	case "System.Guid":
//		return typeof(System.Guid);
//	case "System.Boolean":
//		return typeof(System.Boolean);
//	case "System.Int32":
//		return typeof(System.Int32);
//	case "System.Int16":
//		return typeof(System.Int16);
//	case "System.DateTime":
//		return typeof(System.DateTime);
//	case "System.Double":
//		return typeof(System.Double);
//	default:
//		return null;
//	}
//}
