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

#ifndef __CPPHELPER_H__
#define __CPPHELPER_H__

#pragma once

#include "stdafx.h"

class CppHelper : public SQLHelper
{
public:
	CppHelper(bool returnHeader, bool returnSource) : _returnHeader(returnHeader), _returnSource(returnSource)
	{
	}
	virtual ~CppHelper()
	{
	}
	tsStringBase DataEncryptorClass() const
	{
		return gPrefix + "DataEncryptor";
	}
	virtual tsStringBase ResolveTypeToDatabase(const tsStringBase& _typeName, int length)
	{
		tsStringBase typeName(_typeName);

		if (typeName == "System.String" || typeName == "System.Char[]")
			return tsStringBase().append("varchar(").append((int32_t)length).append(")");
		if (typeName == "System.Guid")
			return "char(36)";
		if (typeName == "System.Boolean")
			return "tinyint(1)";
		if (typeName == "System.Int32" || typeName == "System.Int16")
			return "int";
		if (typeName == "System.DateTime")
			return "datetime";
		if (typeName == "System.Double")
			return "decimal(18, 2)";
		return "varchar(1)";
	}
	virtual tsStringBase BuildSchema(const tsStringBase& schemaFile)
	{
		tsStringBase header;
		tsStringBase source;
		tsStringBase name;
		tsStringBase classname;

		LoadSchemaInfo(schemaFile);

		header << "//\r\n";
		header << "// This file is the property of TecSec, Inc. (c)2017 TecSec, Inc.\r\n";
		header << "// All rights are reserved to TecSec.\r\n";
		header << "//\r\n";
		header << "// The information in this file may be protected by one or more of the following\r\n";
		header << "// U.S. patents, as well as pending U.S. patent applications and foreign patents:\r\n";
		header << "// 5,369,702 5,369,707 5,375,169 5,410,599 5,432,851 5,680,452 5,717,755 5,787,173 \r\n";
		header << "// 5,898,781 6,075,865 6,266,417 6,490,680 6,542,608 6,549,623 6,606,386 6,608,901 \r\n";
		header << "// 6,684,330 6,694,433 6,754,820 6,845,453 7,016,495 7,079,653 7,089,417 7,095,852 \r\n";
		header << "// 7,111,173 7,131,009 7,178,030 7,212,632 7,490,240 7,539,855 7,738,660 7,817,800 \r\n";
		header << "// 7,974,410 8,077,870\r\n";
		header << "//\r\n";
		header << "\r\n";
		header << "// GENERATED CODE - DO NOT MODIFY\r\n";
		header << "\r\n";
		header << "#ifndef __" + Schema()->SymbolName() + "__\r\n";
		header << "#define __" + Schema()->SymbolName() + "__\r\n";

		source << "//\r\n";
		source << "// This file is the property of TecSec, Inc. (c)2017 TecSec, Inc.\r\n";
		source << "// All rights are reserved to TecSec.\r\n";
		source << "//\r\n";
		source << "// The information in this file may be protected by one or more of the following\r\n";
		source << "// U.S. patents, as well as pending U.S. patent applications and foreign patents:\r\n";
		source << "// 5,369,702 5,369,707 5,375,169 5,410,599 5,432,851 5,680,452 5,717,755 5,787,173 \r\n";
		source << "// 5,898,781 6,075,865 6,266,417 6,490,680 6,542,608 6,549,623 6,606,386 6,608,901 \r\n";
		source << "// 6,684,330 6,694,433 6,754,820 6,845,453 7,016,495 7,079,653 7,089,417 7,095,852 \r\n";
		source << "// 7,111,173 7,131,009 7,178,030 7,212,632 7,490,240 7,539,855 7,738,660 7,817,800 \r\n";
		source << "// 7,974,410 8,077,870\r\n";
		source << "//\r\n";
		source << "\r\n";
		source << "// GENERATED CODE - DO NOT MODIFY\r\n";
		source << "\r\n";

		source << "#include \"stdafx.h\"\r\n\r\nusing namespace tscrypto;\r\n\r\n";
		header << "#pragma once\r\n\r\n";

		std::vector<std::shared_ptr<CppInclude> > includeList = Schema()->CppIncludes();

		std::for_each(includeList.begin(), includeList.end(), [this, &header](std::shared_ptr<CppInclude> ci) {
			header << "#include \"" + ci->Name() + "\"\r\n";
		});

		tsStringBase myPrefix(gPrefix);
		if (myPrefix.size() > 0)
			myPrefix << "_";

		header << "#define " << myPrefix << "SCHEMA_MAJOR " << Schema()->Major() << "\r\n";
		header << "#define " << myPrefix << "SCHEMA_MINOR " << Schema()->Minor() << "\r\n";
		header << "#define " << myPrefix << "SCHEMA_SUBMINOR " << Schema()->Subminor() << "\r\n";
		header << "\r\n";

		std::vector<std::shared_ptr<Table> > tableList = Schema()->AllTables();

		if (tableList.size() < 1)
			throw std::runtime_error("Unable to locate schema information for the database tables");

		std::vector<std::shared_ptr<ColumnContainer> > containerList = Schema()->AllContainers();

		std::for_each(containerList.begin(), containerList.end(), [this, &name, &classname, &header](std::shared_ptr<ColumnContainer> cntr) {
			name = cntr->Name();
			classname = name + "Data";

			header << "class " + classname + ";\r\n";
		});
		header << "\r\n";

		std::for_each(containerList.begin(), containerList.end(), [this, &name, &classname, &header, &source](std::shared_ptr<ColumnContainer> cntr) {
			name = cntr->Name();
			classname = name + "Data";

			AddConstructors(header, source, cntr, name, classname);
			AddJSONConverters(header, source, cntr, name, classname);
			AddClearFunctions(header, source, cntr, name, classname);
			AddSelectSqlFunction(header, source, cntr, name, classname);
			AddCountSqlFunction(header, source, cntr, name, classname);
			if (!cntr->ReadOnly())
			{
				AddBuildSaveSqlFunction(header, source, cntr, name, classname);
				AddBuildUpdateSqlFunction(header, source, cntr, name, classname);
			}

			std::vector<std::shared_ptr<Index> > indexList = cntr->Indexes();

			std::for_each(indexList.begin(), indexList.end(), [this, &name, &classname, &header, &source, &cntr](std::shared_ptr<Index> idx) {
				if (idx->SearchableName().size() > 0)
				{
					AddBuildSqlFunction(header, source, cntr, idx, name, classname);
					AddBuildCountSqlFunction(header, source, cntr, idx, name, classname);
					if (!cntr->ReadOnly())
					{
						AddBuildDeleteSqlFunction(header, source, cntr, idx, name, classname);
					}
				}
			});

			header << "\r\n";
			AddInflateFunction(header, source, cntr, name, classname);
			header << "\r\n";

			std::for_each(indexList.begin(), indexList.end(), [this, &name, &classname, &header, &source, &cntr](std::shared_ptr<Index> idx) {
				if (idx->SearchableName().size() > 0)
				{
					AddLoadFunction(header, source, cntr, idx, name, classname);
					AddSearchFunction(header, source, cntr, idx, name, classname);
					AddCountFunction(header, source, cntr, idx, name, classname);
					AddCountSearchFunction(header, source, cntr, idx, name, classname);
					if (!cntr->ReadOnly())
					{
						AddDeleteFunction(header, source, cntr, idx, name, classname);
					}
				}
			});
			AddLoadAllFunction(header, source, cntr, name, classname);
			AddSearchAllFunction(header, source, cntr, name, classname);
			AddCountAllFunction(header, source, cntr, name, classname);
			AddCountSearchAllFunction(header, source, cntr, name, classname);
			header << "\r\n";
			if (!cntr->ReadOnly())
			{
				AddSaveFunction(header, source, cntr, name, classname);
				AddUpdateFunction(header, source, cntr, name, classname);
				header << "\r\n";
				AddModifiedFunction(header, source, cntr, name, classname);
				AddPrimaryKeyModifiedFunction(header, source, cntr, name, classname);
			}
			AddAccessors(header, source, cntr, name, classname);
			header << "\r\n";

			std::vector<std::shared_ptr<Relation> > relList = Schema()->FindRelationsWithDestinationTable(name);

			std::for_each(relList.begin(), relList.end(), [this, &name, &classname, &header, &source, &cntr](std::shared_ptr<Relation> rel) {
				if (rel->ManyToOneName().size() > 0)
				{
					AddManyToOneFunction(header, source, cntr, rel, name, classname);
				}
				else if (rel->OneToOneDestName().size() > 0)
				{
					AddOneToOneDestFunction(header, source, cntr, rel, name, classname);
				}
			});

			relList = Schema()->FindRelationsWithSourceTable(name);

			std::for_each(relList.begin(), relList.end(), [this, &name, &classname, &header, &source, &cntr](std::shared_ptr<Relation> rel) {
				if (rel->OneToManyName().size() > 0 && rel->LoaderForMany().size() > 0)
				{
					AddOneToManyFunction(header, source, cntr, rel, name, classname);
				}
				else if (rel->OneToOneSourceName().size() > 0 && rel->LoaderForDest().size() > 0)
				{
					AddOneToOneSourceFunction(header, source, cntr, rel, name, classname);
				}
			});

			AddVariables(header, source, cntr, name, classname);
			header << "};\r\n\r\n";
		});
		header << "#endif // __" + Schema()->SymbolName() + "__\r\n";

		if (!_returnHeader)
		{
			return source;
		}
		else if (!_returnSource)
		{
			return header;
		}

		return header << "<<<<NEXT FILE>>>>" << source;
	}

protected:
	virtual tsStringBase FieldStart() const
	{
		return "`";
	}
	virtual tsStringBase FieldEnd() const
	{
		return "`";
	}
	virtual tsStringBase TableStart() const
	{
		return "`";
	}
	virtual tsStringBase TableEnd() const
	{
		return "`";
	}
	virtual tsStringBase StatementTerminator() const
	{
		return ";";
	}
	virtual int getColumnSize(std::shared_ptr<tsXmlNode> node)
	{
		return 0;
	}

private:
	bool _returnHeader;
	bool _returnSource;

	void AddConstructors(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		header << "/////////////////////////////////////////////////////////////\r\n// " + classname + "\r\n/////////////////////////////////////////////////////////////\r\n";
		header << "class " + Schema()->ExportSymbol() + " " + classname + " {\r\npublic:\r\n    " + classname + "();\r\n    ~" + classname + "();\r\n";
		header << "    " + classname + "(const " + classname + " &obj);\r\n";
		header << "    " + classname + "(const std::shared_ptr<ITSRecord> &obj);\r\n";

		source << "/////////////////////////////////////////////////////////////\r\n// " + classname + "\r\n/////////////////////////////////////////////////////////////\r\n";
		source << classname + "::" + classname + "()\r\n{\r\n    current.clear();\r\n";
		if (cntr->Persist() && !cntr->ReadOnly())
			source << "    original.clear();\r\n";
		source << "}\r\n" + classname + "::~" + classname + "()\r\n{\r\n    current.clear();\r\n";
		if (cntr->Persist() && !cntr->ReadOnly())
			source << "    original.clear();\r\n";
		source << "}\r\n\r\n";
		source << classname + "::" + classname + "(const " + classname + " &obj)\r\n{\r\n    *this = obj;\r\n}\r\n\r\n";


		header << "    " + classname + " &operator=(const " + classname + " &obj);\r\n";
		source << classname + " &" + classname + "::operator=(const " + classname + " &obj)\r\n{\r\n    if (this != &obj)\r\n    {\r\n";
		source << "        current = obj.current;\r\n";
		if (cntr->Persist() && !cntr->ReadOnly())
			source << "        original = obj.original;\r\n";
		source << "    }\r\n    return *this;\r\n}\r\n\r\n";

		source << classname + "::" + classname + "(const std::shared_ptr<ITSRecord> &obj)\r\n{\r\n    DSErrorList errorList;\r\n    Inflate(obj, errorList);\r\n}\r\n\r\n";
	}
	void AddDataHolderConstructors(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		tsStringBase RightPart;
		tsStringBase type;

		header << "        dataHolder();\r\n";
		header << "        ~dataHolder();\r\n";
		header << "        dataHolder(const dataHolder &obj);\r\n";
		header << "        dataHolder &operator=(const dataHolder &obj);\r\n";
		header << "        bool operator==(const dataHolder &obj) const;\r\n";
		header << "        bool operator!=(const dataHolder &obj) const;\r\n";
		header << "        void clear();\r\n\r\n";

		source << classname + "::dataHolder::dataHolder()\r\n{\r\n    clear();\r\n}\r\n" + classname + "::dataHolder::~dataHolder()\r\n{\r\n    clear();\r\n}\r\n\r\n";
		source << classname + "::dataHolder::dataHolder(const " + classname + "::dataHolder &obj)\r\n{\r\n    *this = obj;\r\n}\r\n\r\n";


		source << classname + "::dataHolder &" + classname + "::dataHolder::operator=(const " + classname + "::dataHolder &obj)\r\n{\r\n    if (this != &obj)\r\n    {\r\n";

		std::vector<std::shared_ptr<TableColumn> > colList = cntr->Columns();

		std::for_each(colList.begin(), colList.end(), [this, &source](std::shared_ptr<TableColumn> col) {
			source << "        _" + col->AliasFieldname() + " = obj._" + col->AliasFieldname() + ";\r\n";
			if (col->Nullable())
			{
				source << "        _has_" + col->AliasFieldname() + " = obj._has_" + col->AliasFieldname() + ";\r\n";
			}
		});
		source << "    }\r\n    return *this;\r\n}\r\n\r\n";


		source << "bool " + classname + "::dataHolder::operator==(const " + classname + "::dataHolder &obj) const\r\n{\r\n";
		std::for_each(colList.begin(), colList.end(), [this, &source](std::shared_ptr<TableColumn> col) {
			tsStringBase fieldName = col->AliasFieldname();

			if (col->Nullable())
			{
				source << "    if (_has_" + fieldName + " != obj._has_" + fieldName + ")\r\n        return false;\r\n";
				source << "    if (_has_" + fieldName + " && _" + fieldName + " != obj._" + fieldName + ")\r\n        return false;\r\n";
			}
			else
				source << "    if (_" + fieldName + " != obj._" + fieldName + ")\r\n        return false;\r\n";
		});

		source << "    return true;\r\n}\r\n\r\n";


		source << "bool " + classname + "::dataHolder::operator!=(const " + classname + "::dataHolder &obj) const\r\n{\r\n    return !(*this == obj);\r\n}\r\n\r\n";


		source << "void " + classname + "::dataHolder::clear()\r\n{\r\n";

		std::for_each(colList.begin(), colList.end(), [this, &source, &type, &RightPart](std::shared_ptr<TableColumn> col) {

			type = col->FieldType();
			RightPart = "";

			if (type == "System.String" || type == "System.Char[]")
				RightPart = ".clear();";
			else if (type == "System.Guid")
				RightPart = " = GUID_NULL;";
			else if (type == "System.Boolean")
				RightPart = " = false;";
			else if (type == "System.Int32" || type == "System.Int16")
				RightPart = " = 0;";
			else if (type == "System.DateTime")
				RightPart = ".clear();";
			else if (type == "System.Double")
				RightPart = " = 0;";
			else
				RightPart = ".clear();";

			source << "    _" + col->AliasFieldname() + RightPart + "\r\n";
			if (col->Nullable())
			{
				source << "    _has_" + col->AliasFieldname() + " = false;\r\n";
			}
		});

		source << "}\r\n\r\n";
	}
	void AddClearFunctions(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		if (cntr->Persist())
		{
			header << "\r\n    void clear();\r\n";
			source << "void " + classname + "::clear()\r\n{\r\n    current.clear();\r\n}\r\n";
			if (!cntr->ReadOnly())
			{
				header << "    void clearOriginal();\r\n";
				source << "void " + classname + "::clearOriginal()\r\n{\r\n    original.clear();\r\n}\r\n\r\n";
				header << "    void setOriginalToCurrent();\r\n";
				source << "void " + classname + "::setOriginalToCurrent()\r\n{\r\n    original = current;\r\n}\r\n\r\n";
				header << "    void reset();\r\n";
				source << "void " + classname + "::reset()\r\n{\r\n    current = original;\r\n}\r\n\r\n";
				header << "    void resetToOriginal();\r\n";
				source << "void " + classname + "::resetToOriginal()\r\n{\r\n    current = original;\r\n}\r\n\r\n";
			}
			header << "\r\n";
		}
	}
	void AddJSONConverters(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> tbl, const tsStringBase& name, const tsStringBase& classname)
	{
		if (tbl->JSONName().size() == 0)
			return;

		header << "\r\n    static const char *JSONName();\r\n";
		source << "const char* " + classname + "::JSONName()\r\n{\r\n    return \"" + tbl->JSONName() + "\";\r\n}\r\n";

		header << "\r\n    tscrypto::JSONObject toJSON(std::shared_ptr<tsmod::IServiceLocator> loc);\r\n";
		source << "tscrypto::JSONObject " + classname + "::toJSON(std::shared_ptr<tsmod::IServiceLocator> loc)\r\n{\r\n";
		source << "    tscrypto::JSONObject obj;\r\n";
		source << "\r\n";

		std::vector<std::shared_ptr<TableColumn> > colList = tbl->Columns();

		std::for_each(colList.begin(), colList.end(), [this, &source](std::shared_ptr<TableColumn> col) {
			if (col->JSONName().size() > 0)
			{
				if ((col->EncryptedObject().size() > 0 && col->JSONUseDecrypted()) || col->UnencryptedObject().size() > 0)
				{
					if (col->JSONMergeType() == jmt_Combine)
					{
						if (col->Nullable())
						{
							source << "    if (current._has_" + col->AliasFieldname() + ")\r\n    ";
						}
						source << "    {\r\n        tscrypto::JSONObject tmpObj;\r\n";
						source << "        get_" + col->AliasFieldname() + "Object(loc).toJSON(tmpObj);\r\n";
						source << "        obj.expand(tmpObj);\r\n";
						source << "    }\r\n";
					}
					else if (col->JSONMergeType() == jmt_Overwrite)
					{
						if (col->Nullable())
						{
							source << "    if (current._has_" + col->AliasFieldname() + ")\r\n    ";
						}
						source << "    {\r\n        tscrypto::JSONObject tmpObj;\r\n";
						source << "        get_" + col->AliasFieldname() + "Object(loc).toJSON(tmpObj);\r\n";
						source << "        tmpObj.expand(obj);\r\n";
						source << "        obj = tmpObj;\r\n";
						source << "    }\r\n";
					}
					else
					{
						if (col->Nullable())
						{
							source << "    if (current._has_" + col->AliasFieldname() + ")\r\n    ";
							source << "    {\r\n";
							source << "        obj.add(\"" + col->JSONName() + "\", get_" + col->AliasFieldname() + "Object(loc).toJSON());\r\n";
							source << "    }\r\n";
						}
						else
						{
							source << "   obj.add(\"" + col->JSONName() + "\", get_" + col->AliasFieldname() + "Object(loc).toJSON());\r\n";
						}
					}
				}
				else
				{
					tsStringBase fieldType(col->FieldType());

					if (fieldType == "System.String" || fieldType == "System.Char[]")
						source << "    obj.add(\"" + col->JSONName() + "\", current._" + col->AliasFieldname() + ");\r\n";
					else if (fieldType == "System.DateTime")
						source << "    obj.add(\"" + col->JSONName() + "\", ZuluToDateTime(current._" + col->AliasFieldname() + ".ToZuluTime()));\r\n";
					else if (fieldType == "System.Guid" || fieldType == "System.Double")
						source << "    obj.add(\"" + col->JSONName() + "\", ToString()(current._" + col->AliasFieldname() + "));\r\n";
					else if (fieldType == "System.Boolean")
						source << "    obj.add(\"" + col->JSONName() + "\", current._" + col->AliasFieldname() + ");\r\n";
					else if (fieldType == "System.Int32" || fieldType == "System.Int16")
						source << "    obj.add(\"" + col->JSONName() + "\", (int64_t)current._" + col->AliasFieldname() + ");\r\n";
					else
						source << "    obj.add(\"" + col->JSONName() + "\", current._" + col->AliasFieldname() + ");\r\n";
				}
			}
		});

		source << "    return obj;\r\n";
		source << "}\r\n";

		if (tbl->Persist())
		{
			header << "    bool fromJSON(std::shared_ptr<tsmod::IServiceLocator> loc, const tscrypto::tsCryptoStringBase& json);\r\n";
			source << "bool " + classname + "::fromJSON(std::shared_ptr<tsmod::IServiceLocator> loc, const tscrypto::tsCryptoStringBase& json)\r\n{\r\n";
			source << "    tscrypto::JSONObject obj;\r\n";
			source << "\r\n";
			source << "    if (!obj.FromJSON(json))\r\n";
			source << "        return false;\r\n";
			source << "\r\n";
			source << "    return fromJSON(loc, obj);\r\n";
			source << "}\r\n";

			header << "    bool fromJSON(std::shared_ptr<tsmod::IServiceLocator> loc, const tscrypto::JSONObject& obj);\r\n";
			source << "bool " + classname + "::fromJSON(std::shared_ptr<tsmod::IServiceLocator> loc, const tscrypto::JSONObject& obj)\r\n{\r\n";
			source << "    clear();\r\n";

			std::vector<std::shared_ptr<TableColumn> > colList1 = tbl->Columns();

			std::for_each(colList1.begin(), colList1.end(), [this, &source](std::shared_ptr<TableColumn> col) {
				tsStringBase prefix = "";

				if (col->JSONName().size() > 0)
				{
					if ((col->EncryptedObject().size() > 0 && col->JSONUseDecrypted()) || col->UnencryptedObject().size() > 0)
					{
						if (col->JSONMergeType() == jmt_Combine || col->JSONMergeType() == jmt_Overwrite)
						{
							source << "    {\r\n";
							source << "        " + col->EncryptedObject() + " o;\r\n";
							source << "\r\n";
							source << "        o = get_" + col->AliasFieldname() + "Object(loc);\r\n";
							source << "        if (!o.fromJSON(obj))\r\n";
							source << "            return false;\r\n";
							source << "        if (!set_" + col->AliasFieldname() + "Object(loc, o))\r\n";
							source << "            return false;\r\n";
							source << "    }\r\n";
						}
						else
						{
							if (col->Nullable())
							{

								source << "    if (obj.hasField(\"" + col->JSONName() + "\"))\r\n";
							}
							source << "    {\r\n";
							source << "        Asn1::EB::AttributeData o;\r\n";
							source << "\r\n";
							source << "        o = get_" + col->AliasFieldname() + "Object(loc);\r\n";
							source << "        if (!o.fromJSON(obj.AsObject(\"" + col->JSONName() + "\")))\r\n";
							source << "            return false;\r\n";
							source << "        if (!set_" + col->AliasFieldname() + "Object(loc, o))\r\n";
							source << "            return false;\r\n";
							source << "    }\r\n";
						}
					}
					else
					{
						if (col->Nullable())
						{
							source << "    if (obj.hasField(\"" + col->JSONName() + "\"))\r\n";
							source << "    {\r\n";
							source << "        current._has_" + col->AliasFieldname() + " = true;\r\n";
							prefix = "    ";
						}

						tsStringBase fieldType(col->FieldType());

						if (fieldType == "System.String" || fieldType == "System.Char[]")
							source << prefix + "    current._" + col->AliasFieldname() + " = obj.AsString(\"" + col->JSONName() + "\");\r\n";
						else if (fieldType == "System.Guid")
							source << prefix + "    current._" + col->AliasFieldname() + " = ToGuid()(obj.AsString(\"" + col->JSONName() + "\"));\r\n";
						else if (fieldType == "System.DateTime")
							source << prefix + "    current._" + col->AliasFieldname() + " = ToTsDate()(obj.AsString(\"" + col->JSONName() + "\"));\r\n";
						else if (fieldType == "System.Double")
							source << prefix + "    current._" + col->AliasFieldname() + " = atod(obj.AsString(\"" + col->JSONName() + "\").c_str());\r\n";
						else if (fieldType == "System.Boolean")
							source << prefix + "    current._" + col->AliasFieldname() + " = obj.AsBool(\"" + col->JSONName() + "\", false);\r\n";
						else if (fieldType == "System.Int32")
							source << prefix + "    current._" + col->AliasFieldname() + " = (int)obj.AsNumber(\"" + col->JSONName() + "\", 0);\r\n";
						else if (fieldType == "System.Int16")
							source << prefix + "    current._" + col->AliasFieldname() + " = (short)obj.AsNumber(\"" + col->JSONName() + "\", 0);\r\n";
						else
							source << prefix + "    current._" + col->AliasFieldname() + " = obj.AsString(\"" + col->JSONName() + "\");\r\n";
						if (col->Nullable())
						{
							source << "    }\r\n";
							prefix = "";
						}
					}
				}
			});
			source << "    return true;\r\n";
			source << "}\r\n";
		}
		header << "\r\n";
	}
	void AddLoadFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, const tsStringBase& name, const tsStringBase& classname)
	{
		tsStringBase ConstPart;
		tsStringBase TypePart;
		tsStringBase RightPart;
		tsStringBase Parameters;
		tsStringBase ParametersForCall;
		tsStringBase Sql;
		tsStringBase ReplaceParams;
		std::shared_ptr<Table> tbl = std::dynamic_pointer_cast<Table>(cntr);
		std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

		std::for_each(colList.begin(), colList.end(), [this, &Parameters, &ConstPart, &TypePart, &RightPart, &ParametersForCall](std::shared_ptr<TableColumn> c) {
			c->GetColumnNodeParameters(ConstPart, TypePart, RightPart);
			if (Parameters.size() > 0)
				Parameters << ", ";
			Parameters << ConstPart + TypePart + RightPart + " " + c->Name();
			if (ParametersForCall.size() > 0)
				ParametersForCall << ", ";
			ParametersForCall << c->Name();
		});

		if (idx->LoadReturnsSingle())
		{
			if (Parameters.size() > 0)
				Parameters << ", ";
			Parameters << "DSErrorList &errorList";

			header << "    bool " + idx->SearchableName() + "(TSDatabase *db, " + Parameters + ");\r\n";
			source << "bool " + classname + "::" + idx->SearchableName() + "(TSDatabase *db, " + Parameters + ")\r\n{\r\n";
			source << "    tscrypto::tsCryptoString sql = build" + idx->SearchableName() + "Sql(db, " + ParametersForCall + ");\r\n";
			source << "\r\n";

			source << "    SmartRecordset RecordSet(NULL);\r\n";
			source << "    size_t rowCount;\r\n";
			if (!!tbl)
			{
				if (tbl->GroupBy().size() > 0)
					source << "    sql += \" GROUP BY " + tbl->GroupBy() + "\";\r\n";
			}
			source << "    if (!db->ReadData(sql.c_str(), 0, 0, RecordSet, errorList) || RecordSet == NULL)\r\n";
			source << "    {\r\n";
			source << "        AddXMLError(errorList, \"" + classname + "\", \"Load\", IDS_E_CANT_RETRIEVE, \"" + name + "\");\r\n";
			source << "        return false;\r\n";
			source << "    }\r\n";
			source << "    if (RecordSet->IsRowcount())\r\n";
			source << "    {\r\n";
			source << "        return false;\r\n";
			source << "    }\r\n";
			source << "\r\n";
			source << "    rowCount = RecordSet->RecordCount();\r\n";
			source << "    if (rowCount != 1)\r\n";
			source << "    {\r\n";
			source << "        AddXMLError(errorList, \"" + classname + "\", \"Load\", IDS_E_CANT_RETRIEVE, \"" + name + "\");\r\n";
			source << "        return false;\r\n";
			source << "    }\r\n";
			source << "\r\n";

			source << "    return Inflate(RecordSet->row(0), errorList);\r\n";
			source << "}\r\n\r\n";
		}
		else
		{
			if (Parameters.size() > 0)
				Parameters << ", ";
			Parameters << "std::vector<" + classname + "> &list";

			if (Parameters.size() > 0)
				Parameters << ", ";
			Parameters << "DSErrorList &errorList";

			header << "    static bool " + idx->SearchableName() + "(TSDatabase *db, " + Parameters + ", int pageSize = 0, int pageNumber = 0, const tscrypto::tsCryptoStringBase& sort = \"\");\r\n";
			source << "bool " + classname + "::" + idx->SearchableName() + "(TSDatabase *db, " + Parameters + ", int pageSize, int pageNumber, const tscrypto::tsCryptoStringBase& sort)\r\n{\r\n";

			source << "    tscrypto::tsCryptoString sql = build" + idx->SearchableName() + "Sql(db, " + ParametersForCall + ");\r\n";
			source << "\r\n";
			source << "    SmartRecordset RecordSet(NULL);\r\n";
			source << "    size_t rowCount;\r\n";
			source << "    if (sort.size() > 0)\r\n    {\r\n        sql << \" ORDER BY \" << sort;\r\n    }\r\n";
			if (!!tbl)
			{
				if (tbl->GroupBy().size() > 0)
					source << "    sql += \" GROUP BY " + tbl->GroupBy() + "\";\r\n";
			}
			source << "    if (!db->ReadData(sql.c_str(), pageSize, pageNumber, RecordSet, errorList) || RecordSet == NULL)\r\n";
			source << "    {\r\n";
			source << "        AddXMLError(errorList, \"" + classname + "\", \"Load\", IDS_E_CANT_RETRIEVE, \"" + name + "\");\r\n";
			source << "        return false;\r\n";
			source << "    }\r\n";
			source << "    if (RecordSet->IsRowcount())\r\n";
			source << "    {\r\n";
			source << "        return true;\r\n";
			source << "    }\r\n";
			source << "\r\n";
			source << "    rowCount = RecordSet->RecordCount();\r\n";
			source << "\r\n";
			source << "    for (size_t i = 0; i < rowCount; i++)\r\n";
			source << "    {\r\n";
			source << "        list.push_back(" + classname + "(RecordSet->row(i)));\r\n";
			source << "    }\r\n";
			source << "\r\n";

			source << "    return true;\r\n";
			source << "}\r\n\r\n";
		}
	}
	void AddSearchFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, const tsStringBase& name, const tsStringBase& classname)
	{
		tsStringBase ConstPart;
		tsStringBase TypePart;
		tsStringBase RightPart;
		tsStringBase Parameters;
		tsStringBase ParametersForCall;
		tsStringBase Sql;
		tsStringBase ReplaceParams;
		std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);
		std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

		std::for_each(colList.begin(), colList.end(), [this, &Parameters, &ConstPart, &TypePart, &RightPart, &ParametersForCall](std::shared_ptr<TableColumn> c) {
			c->GetColumnNodeParameters(ConstPart, TypePart, RightPart);
			Parameters << ", ";
			Parameters << ConstPart + TypePart + RightPart + " " + c->Name();
			if (ParametersForCall.size() > 0)
				ParametersForCall << ", ";
			ParametersForCall << c->Name();
		});

		if (idx->LoadReturnsSingle())
		{
			header << "    bool Search" + idx->SearchableName().substring(4, 9999) + "(TSDatabase *db" + Parameters + ", const tscrypto::tsCryptoStringBase& searchString, DSErrorList &errorList);\r\n";
			source << "bool " + classname + "::Search" + idx->SearchableName().substring(4, 9999) + "(TSDatabase *db" + Parameters + ", const tscrypto::tsCryptoStringBase& searchString, DSErrorList &errorList)\r\n{\r\n";
			source << "    tscrypto::tsCryptoString sql = build" + idx->SearchableName() + "Sql(db, " + ParametersForCall + ");\r\n";
			source << "\r\n";

			source << "    SmartRecordset RecordSet(NULL);\r\n";
			source << "    size_t rowCount;\r\n";
			if (Parameters.size() > 0)
				source << "    sql << \" AND \" << searchString;\r\n";
			else
				source << "    sql << \" WHERE \" << searchString;\r\n";
			if (!!table)
			{
				if (table->GroupBy().size() > 0)
					source << "    sql += \" GROUP BY " + table->GroupBy() + "\";\r\n";
			}
			source << "    if (!db->ReadData(sql.c_str(), 0, 0, RecordSet, errorList) || RecordSet == NULL)\r\n";
			source << "    {\r\n";
			source << "        AddXMLError(errorList, \"" + classname + "\", \"Load\", IDS_E_CANT_RETRIEVE, \"" + name + "\");\r\n";
			source << "        return false;\r\n";
			source << "    }\r\n";
			source << "    if (RecordSet->IsRowcount())\r\n";
			source << "    {\r\n";
			source << "        return false;\r\n";
			source << "    }\r\n";
			source << "\r\n";
			source << "    rowCount = RecordSet->RecordCount();\r\n";
			source << "    if (rowCount != 1)\r\n";
			source << "    {\r\n";
			source << "        AddXMLError(errorList, \"" + classname + "\", \"Load\", IDS_E_CANT_RETRIEVE, \"" + name + "\");\r\n";
			source << "        return false;\r\n";
			source << "    }\r\n";
			source << "\r\n";

			source << "    return Inflate(RecordSet->row(0), errorList);\r\n";
			source << "}\r\n\r\n";
		}
		else
		{
			header << "    static bool Search" + idx->SearchableName().substring(4, 9999) + "(TSDatabase *db" + Parameters + ", const tscrypto::tsCryptoStringBase& searchString, std::vector<" + classname + "> &list, DSErrorList &errorList, int pageSize = 0, int pageNumber = 0, const tscrypto::tsCryptoStringBase& sort = \"\");\r\n";
			source << "bool " + classname + "::Search" + idx->SearchableName().substring(4, 9999) + "(TSDatabase *db" + Parameters + ", const tscrypto::tsCryptoStringBase& searchString, std::vector<" + classname + "> &list, DSErrorList &errorList, int pageSize, int pageNumber, const tscrypto::tsCryptoStringBase& sort)\r\n{\r\n";

			source << "    tscrypto::tsCryptoString sql = build" + idx->SearchableName() + "Sql(db, " + ParametersForCall + ");\r\n";
			source << "\r\n";
			source << "    SmartRecordset RecordSet(NULL);\r\n";
			source << "    size_t rowCount;\r\n";
			if (Parameters.size() > 0)
				source << "    sql << \" AND \" << searchString;\r\n";
			else
				source << "    sql << \" WHERE \" << searchString;\r\n";
			source << "    if (sort.size() > 0)\r\n    {\r\n        sql << \" ORDER BY \" << sort;\r\n    }\r\n";
			if (!!table)
			{
				if (table->GroupBy().size() > 0)
					source << "    sql += \" GROUP BY " + table->GroupBy() + "\";\r\n";
			}
			source << "    if (!db->ReadData(sql.c_str(), pageSize, pageNumber, RecordSet, errorList) || RecordSet == NULL)\r\n";
			source << "    {\r\n";
			source << "        AddXMLError(errorList, \"" + classname + "\", \"Load\", IDS_E_CANT_RETRIEVE, \"" + name + "\");\r\n";
			source << "        return false;\r\n";
			source << "    }\r\n";
			source << "    if (RecordSet->IsRowcount())\r\n";
			source << "    {\r\n";
			source << "        return true;\r\n";
			source << "    }\r\n";
			source << "\r\n";
			source << "    rowCount = RecordSet->RecordCount();\r\n";
			source << "\r\n";
			source << "    for (size_t i = 0; i < rowCount; i++)\r\n";
			source << "    {\r\n";
			source << "        list.push_back(" + classname + "(RecordSet->row(i)));\r\n";
			source << "    }\r\n";
			source << "\r\n";

			source << "    return true;\r\n";
			source << "}\r\n\r\n";
		}
	}
	void AddCountSearchFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, const tsStringBase& name, const tsStringBase& classname)
	{
		if (!idx->LoadReturnsSingle())
		{
			tsStringBase ConstPart;
			tsStringBase TypePart;
			tsStringBase RightPart;
			tsStringBase Parameters;
			tsStringBase ParametersForCall;
			tsStringBase Sql;
			tsStringBase ReplaceParams;
			std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);
			std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

			std::for_each(colList.begin(), colList.end(), [this, &Parameters, &ConstPart, &TypePart, &RightPart, &ParametersForCall](std::shared_ptr<TableColumn> c) {
				c->GetColumnNodeParameters(ConstPart, TypePart, RightPart);
				if (Parameters.size() > 0)
					Parameters << ", ";
				Parameters << ConstPart + TypePart + RightPart + " " + c->Name();
				if (ParametersForCall.size() > 0)
					ParametersForCall << ", ";
				ParametersForCall << c->Name();
			});

			header << "    static bool CountSearch" + idx->SearchableName().substring(4, 9999) + "(TSDatabase *db, " + Parameters + ", const tscrypto::tsCryptoStringBase& searchString, int32_t &count, DSErrorList &errorList);\r\n";
			source << "bool " + classname + "::CountSearch" + idx->SearchableName().substring(4, 9999) + "(TSDatabase *db, " + Parameters + ", const tscrypto::tsCryptoStringBase& searchString, int32_t &count, DSErrorList &errorList)\r\n{\r\n";

			source << "    tscrypto::tsCryptoString sql = buildCount" + idx->SearchableName().substring(4, 9999) + "Sql(db, " + ParametersForCall + ");\r\n";
			source << "\r\n";
			if (Parameters.size() > 0)
				source << "    sql << \" AND \" << searchString;\r\n";
			else
				source << "    sql << \" WHERE \" << searchString;\r\n";
			if (!!table)
			{
				if (table->GroupBy().size() > 0)
					source << "    sql += \" GROUP BY " + table->GroupBy() + "\";\r\n";
			}
			source << "    if (!db->SqlGetLong(sql, count, errorList))\r\n";
			source << "    {\r\n";
			source << "        AddXMLError(errorList, \"" + classname + "\", \"Load\", IDS_E_CANT_RETRIEVE, \"" + classname + "\");\r\n";
			source << "        return false;\r\n";
			source << "    }\r\n";
			source << "    return true;\r\n";
			source << "}\r\n\r\n";
		}
	}
	void AddCountFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, const tsStringBase& name, const tsStringBase& classname)
	{
		if (!idx->LoadReturnsSingle())
		{
			tsStringBase ConstPart;
			tsStringBase TypePart;
			tsStringBase RightPart;
			tsStringBase Parameters;
			tsStringBase ParametersForCall;
			tsStringBase Sql;
			tsStringBase ReplaceParams;
			std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);
			std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

			std::for_each(colList.begin(), colList.end(), [this, &Parameters, &ConstPart, &TypePart, &RightPart, &ParametersForCall](std::shared_ptr<TableColumn> c) {
				c->GetColumnNodeParameters(ConstPart, TypePart, RightPart);
				if (Parameters.size() > 0)
					Parameters << ", ";
				Parameters << ConstPart + TypePart + RightPart + " " + c->Name();
				if (ParametersForCall.size() > 0)
					ParametersForCall << ", ";
				ParametersForCall << c->Name();
			});

			header << "    static bool Count" + idx->SearchableName().substring(4, 9999) + "(TSDatabase *db, " + Parameters + ", int32_t &count, DSErrorList &errorList);\r\n";
			source << "bool " + classname + "::Count" + idx->SearchableName().substring(4, 9999) + "(TSDatabase *db, " + Parameters + ", int32_t &count, DSErrorList &errorList)\r\n{\r\n";

			source << "    tscrypto::tsCryptoString sql = buildCount" + idx->SearchableName().substring(4, 9999) + "Sql(db, " + ParametersForCall + ");\r\n";
			source << "\r\n";
			if (!!table)
			{
				if (table->GroupBy().size() > 0)
					source << "    sql += \" GROUP BY " + table->GroupBy() + "\";\r\n";
			}
			source << "    if (!db->SqlGetLong(sql, count, errorList))\r\n";
			source << "    {\r\n";
			source << "        AddXMLError(errorList, \"" + classname + "\", \"Load\", IDS_E_CANT_RETRIEVE, \"" + classname + "\");\r\n";
			source << "        return false;\r\n";
			source << "    }\r\n";
			source << "    return true;\r\n";
			source << "}\r\n\r\n";
		}
	}
	void AddLoadAllFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);

		header << "    static bool LoadAll(TSDatabase *db, std::vector<" + classname + "> &list, DSErrorList &errorList, int pageSize = 0, int pageNumber = 0, const tscrypto::tsCryptoStringBase& sort = \"\");\r\n";
		source << "bool " + classname + "::LoadAll(TSDatabase *db, std::vector<" + classname + "> &list, DSErrorList &errorList, int pageSize, int pageNumber, const tscrypto::tsCryptoStringBase& sort)\r\n{\r\n";

		source << "    tscrypto::tsCryptoString sql = selectSql(db);\r\n";
		source << "\r\n";
		source << "    SmartRecordset RecordSet(NULL);\r\n";
		source << "    size_t rowCount;\r\n";
		source << "    if (sort.size() > 0)\r\n    {\r\n        sql << \" ORDER BY \" << sort;\r\n    }\r\n";
		if (!!table)
		{
			if (table->GroupBy().size() > 0)
				source << "    sql += \" GROUP BY " + table->GroupBy() + "\";\r\n";
		}
		source << "    if (!db->ReadData(sql.c_str(), pageSize, pageNumber, RecordSet, errorList) || RecordSet == NULL)\r\n";
		source << "    {\r\n";
		source << "        AddXMLError(errorList, \"" + classname + "\", \"Load\", IDS_E_CANT_RETRIEVE, \"" + name + "\");\r\n";
		source << "        return false;\r\n";
		source << "    }\r\n";
		source << "    if (RecordSet->IsRowcount())\r\n";
		source << "    {\r\n";
		source << "        return true;\r\n";
		source << "    }\r\n";
		source << "\r\n";
		source << "    rowCount = RecordSet->RecordCount();\r\n";
		source << "\r\n";
		source << "    for (size_t i = 0; i < rowCount; i++)\r\n";
		source << "    {\r\n";
		source << "        list.push_back(" + classname + "(RecordSet->row(i)));\r\n";
		source << "    }\r\n";
		source << "\r\n";

		source << "    return true;\r\n";
		source << "}\r\n\r\n";
	}
	void AddSearchAllFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);

		header << "    static bool SearchAll(TSDatabase *db, const tscrypto::tsCryptoStringBase& searchString, std::vector<" + classname + "> &list, DSErrorList &errorList, int pageSize = 0, int pageNumber = 0, const tscrypto::tsCryptoStringBase& sort = \"\");\r\n";
		source << "bool " + classname + "::SearchAll(TSDatabase *db, const tscrypto::tsCryptoStringBase& searchString, std::vector<" + classname + "> &list, DSErrorList &errorList, int pageSize, int pageNumber, const tscrypto::tsCryptoStringBase& sort)\r\n{\r\n";

		source << "    tscrypto::tsCryptoString sql = selectSql(db);\r\n";
		source << "\r\n";
		source << "    SmartRecordset RecordSet(NULL);\r\n";
		source << "    size_t rowCount;\r\n";
		source << "    sql << \" WHERE \" << searchString;\r\n";
		source << "    if (sort.size() > 0)\r\n    {\r\n        sql << \" ORDER BY \" << sort;\r\n    }\r\n";
		if (!!table)
		{
			if (table->GroupBy().size() > 0)
				source << "    sql += \" GROUP BY " + table->GroupBy() + "\";\r\n";
		}
		source << "    if (!db->ReadData(sql.c_str(), pageSize, pageNumber, RecordSet, errorList) || RecordSet == NULL)\r\n";
		source << "    {\r\n";
		source << "        AddXMLError(errorList, \"" + classname + "\", \"Load\", IDS_E_CANT_RETRIEVE, \"" + name + "\");\r\n";
		source << "        return false;\r\n";
		source << "    }\r\n";
		source << "    if (RecordSet->IsRowcount())\r\n";
		source << "    {\r\n";
		source << "        return true;\r\n";
		source << "    }\r\n";
		source << "\r\n";
		source << "    rowCount = RecordSet->RecordCount();\r\n";
		source << "\r\n";
		source << "    for (size_t i = 0; i < rowCount; i++)\r\n";
		source << "    {\r\n";
		source << "        list.push_back(" + classname + "(RecordSet->row(i)));\r\n";
		source << "    }\r\n";
		source << "\r\n";

		source << "    return true;\r\n";
		source << "}\r\n\r\n";
	}
	void AddCountSearchAllFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);

		header << "    static bool CountSearchAll(TSDatabase *db, const tscrypto::tsCryptoStringBase& searchString, int32_t &count, DSErrorList &errorList);\r\n";
		source << "bool " + classname + "::CountSearchAll(TSDatabase *db, const tscrypto::tsCryptoStringBase& searchString, int32_t &count, DSErrorList &errorList)\r\n{\r\n";

		source << "    tscrypto::tsCryptoString sql = countSql(db);\r\n";
		source << "\r\n";
		source << "    SmartRecordset RecordSet(NULL);\r\n";
		source << "\r\n";
		source << "    sql << \" WHERE \" << searchString;\r\n";
		if (!!table)
		{
			if (table->GroupBy().size() > 0)
				source << "    sql += \" GROUP BY " + table->GroupBy() + "\";\r\n";
		}
		source << "    if (!db->SqlGetLong(sql, count, errorList))\r\n";
		source << "    {\r\n";
		source << "        AddXMLError(errorList, \"" + classname + "\", \"Load\", IDS_E_CANT_RETRIEVE, \"" + classname + "\");\r\n";
		source << "        return false;\r\n";
		source << "    }\r\n";
		source << "\r\n";

		source << "    return true;\r\n";
		source << "}\r\n\r\n";
	}
	void AddCountAllFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);

		header << "    static bool CountAll(TSDatabase *db, int32_t &count, DSErrorList &errorList);\r\n";
		source << "bool " + classname + "::CountAll(TSDatabase *db, int32_t &count, DSErrorList &errorList)\r\n{\r\n";

		source << "    tscrypto::tsCryptoString sql = countSql(db);\r\n";
		source << "\r\n";
		if (!!table)
		{
			if (table->GroupBy().size() > 0)
				source << "    sql += \" GROUP BY " + table->GroupBy() + "\";\r\n";
		}
		source << "    if (!db->SqlGetLong(sql, count, errorList))\r\n";
		source << "    {\r\n";
		source << "        AddXMLError(errorList, \"" + classname + "\", \"Load\", IDS_E_CANT_RETRIEVE, \"" + name + "\");\r\n";
		source << "        return false;\r\n";
		source << "    }\r\n";
		source << "    return true;\r\n";
		source << "}\r\n\r\n";
	}
	void AddBuildSqlFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, const tsStringBase& name, const tsStringBase& classname)
	{
		tsStringBase ConstPart;
		tsStringBase TypePart;
		tsStringBase RightPart;
		tsStringBase Parameters;
		tsStringBase ParametersForCall;
		tsStringBase Sql;
		tsStringBase ReplaceParams;
		int parameterNumber = 0;
		std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);
		std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

		std::for_each(colList.begin(), colList.end(), [this, &Parameters, &ConstPart, &TypePart, &RightPart, &ParametersForCall](std::shared_ptr<TableColumn> c) {
			c->GetColumnNodeParameters(ConstPart, TypePart, RightPart);
			if (Parameters.size() > 0)
				Parameters << ", ";
			Parameters << ConstPart + TypePart + RightPart + " " + c->AliasFieldname();
			if (ParametersForCall.size() > 0)
				ParametersForCall << ", ";
			ParametersForCall << c->AliasFieldname();
		});

		header << "    static tscrypto::tsCryptoString build" + idx->SearchableName() + "Sql(TSDatabase* db, " + Parameters + ");\r\n";
		source << "tscrypto::tsCryptoString " + classname + "::build" + idx->SearchableName() + "Sql(TSDatabase* db, " + Parameters + ")\r\n{\r\n";
		colList = cntr->Columns();
		std::for_each(colList.begin(), colList.end(), [this, &cntr, &Sql, &Parameters, &ConstPart, &TypePart, &RightPart, &ParametersForCall](std::shared_ptr<TableColumn> c) {
			if (c->Formula().size() > 0)
			{
				if (Sql.size() > 0)
				{
					Sql << "        << \", \"";
				}
				else
					Sql << "       ";
				Sql << " << \"";
				Sql << c->Formula();
				Sql << " as ";
				Sql << c->AliasFieldname();
				Sql << "\"\r\n";
			}
			else
			{
				if (Sql.size() > 0)
				{
					Sql << "        << \", \" << db->CreateSelectField(\"";
				}
				else
					Sql << "        << db->CreateSelectField(\"";

				if (c->Table().size() > 0)
					Sql << c->Table() + ".";
				else
					Sql << cntr->Name() + ".";
				Sql << c->Name();
				Sql << "\", " + c->GetTSFieldType() + ")";
				if (c->Alias().size() > 0)
					Sql << " << \" as " + c->Alias() + "\"";
				else
					Sql << " << \" as " + c->Name() + "\"";

			}
			Sql << "\r\n";
		});

		Sql << "        << \" FROM " << cntr->From();
		if (!!table)
		{
			if (table->ForeignJoins().size() > 0)
				Sql << " " + table->ForeignJoins();
		}
		Sql << " WHERE \"\r\n";

		colList = idx->Columns();
		std::for_each(colList.begin(), colList.end(), [this, &cntr, &Sql, &Parameters, &ConstPart, &TypePart, &RightPart, &ParametersForCall, &parameterNumber, &ReplaceParams](std::shared_ptr<TableColumn> c) {
			c->GetColumnNodeParameters(ConstPart, TypePart, RightPart);
			if (parameterNumber > 0)
				Sql << "        << \" AND \"";
			else
				Sql << "        ";
			Sql << " << db->CreateSelectField(\"" << (c->Table().size() > 0 ? c->Table() : cntr->Name()) << "." << c->AliasFieldname() << "\", " 
				<< c->GetTSFieldType() + ") << \" = \" << db->ConvertDataValue(\"{" << parameterNumber << "}\", " << c->GetTSFieldType() << ")\r\n";

			ReplaceParams << "    sql.Replace(tscrypto::tsCryptoString(\"{" << parameterNumber << "}\"), ";
			ReplaceParams << "db->ConvertDataValue(ToSql(" + c->AliasFieldname() + "), " + c->GetTSFieldType() + "));\r\n";

			parameterNumber++;
		});

		if (idx->SearchClause().size() > 0)
		{
			if (parameterNumber > 0)
				Sql << "        << \" AND \"";
			else
				Sql << "        ";
			Sql << " << \"" + idx->SearchClause() + "\"\r\n";
		}
		//Sql << "    );\r\n";

		source << "    tscrypto::tsCryptoString sql;\r\n    sql << \"SELECT \"\r\n";
		source << Sql;
		source << ";\r\n";
		source << ReplaceParams;
		source << "\r\n";
		source << "    return sql;\r\n";
		source << "}\r\n\r\n";
	}
	void AddBuildCountSqlFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, const tsStringBase& name, const tsStringBase& classname)
	{
		tsStringBase ConstPart;
		tsStringBase TypePart;
		tsStringBase RightPart;
		tsStringBase Parameters;
		tsStringBase ParametersForCall;
		tsStringBase Sql;
		tsStringBase ReplaceParams;
		int parameterNumber = 0;
		std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);
		std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

		std::for_each(colList.begin(), colList.end(), [this, &Parameters, &ConstPart, &TypePart, &RightPart, &ParametersForCall](std::shared_ptr<TableColumn> c) {
			c->GetColumnNodeParameters(ConstPart, TypePart, RightPart);
			Parameters << ", ";
			Parameters << ConstPart + TypePart + RightPart + " " + c->AliasFieldname();
			ParametersForCall << ", ";
			ParametersForCall << c->AliasFieldname();
		});

		header << "    static tscrypto::tsCryptoString buildCount" + idx->SearchableName().substring(4, 9999) + "Sql(TSDatabase* db" + Parameters + ");\r\n";
		source << "tscrypto::tsCryptoString " + classname + "::buildCount" + idx->SearchableName().substring(4, 9999) + "Sql(TSDatabase* db" + Parameters + ")\r\n{\r\n";
		Sql << "COUNT(*) FROM " + cntr->From();
		if (!!table)
		{
			if (table->ForeignJoins().size() > 0)
				Sql << " " + table->ForeignJoins();
		}
		Sql << " WHERE \"\r\n";

		std::for_each(colList.begin(), colList.end(), [this, &Parameters, &ConstPart, &TypePart, &RightPart, &ParametersForCall, &parameterNumber, &Sql, &ReplaceParams, &cntr](std::shared_ptr<TableColumn> c) {
			c->GetColumnNodeParameters(ConstPart, TypePart, RightPart);
			if (parameterNumber > 0)
				Sql << "        << \" AND \" << ";
			else
				Sql << "        << ";
			Sql << "db->CreateSelectField(\"" << (c->Table().size() > 0 ? c->Table() : cntr->Name()) + "." << c->AliasFieldname() << "\", " << c->GetTSFieldType() << ") << \" = \" << db->ConvertDataValue(\"{" << parameterNumber << "}\", " << c->GetTSFieldType() << ")\r\n";

			ReplaceParams << "    sql.Replace(tscrypto::tsCryptoString(\"{" << parameterNumber << "}\"), ";
			ReplaceParams << "ToSql(" + c->AliasFieldname() + "));\r\n";

			parameterNumber++;
		});

		if (idx->SearchClause().size() > 0)
		{
			if (parameterNumber > 0)
				Sql << "    << \" AND \" << \"";
			Sql << idx->SearchClause();
			Sql << "\"\r\n";
		}
		//Sql << "    );\r\n";

		source << "    tscrypto::tsCryptoString sql;\r\n    sql << \"SELECT ";
		source << Sql;
		source << ";\r\n";
		source << ReplaceParams;
		source << "\r\n";
		source << "    return sql;\r\n";
		source << "}\r\n\r\n";
	}
	void AddSelectSqlFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		tsStringBase Sql;
		std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);

		header << "    static tscrypto::tsCryptoString selectSql(TSDatabase* db);\r\n";
		source << "tscrypto::tsCryptoString " + classname + "::selectSql(TSDatabase* db)\r\n{\r\n";

		source << "    tscrypto::tsCryptoString tmp;\r\n    tmp << \"SELECT \"\r\n";

		std::vector<std::shared_ptr<TableColumn> > colList = cntr->Columns();

		std::for_each(colList.begin(), colList.end(), [this, &Sql, &cntr](std::shared_ptr<TableColumn> c) {
			if (c->Formula().size() > 0)
			{
				if (Sql.size() > 0)
				{
					Sql << "        << \", \"";
				}
				else
					Sql << "       ";
				Sql << " << \"";
				Sql << c->Formula();
				Sql << " as ";
				Sql << c->AliasFieldname();
				Sql << "\"\r\n";
			}
			else
			{
				if (Sql.size() > 0)
				{
					Sql << "        << \", \" << db->CreateSelectField(\"";
				}
				else
					Sql << "        << db->CreateSelectField(\"";
				if (c->Table().size() > 0)
					Sql << c->Table() + ".";
				else
					Sql << cntr->Name() + ".";
				Sql << c->Name();
				Sql << "\", " + c->GetTSFieldType() + ")";
				if (c->Alias().size() > 0)
					Sql << " << \" as " + c->Alias() + "\"";
				else
					Sql << " << \" as " + c->Name() + "\"";

				Sql << "\r\n";
			}
		});

		source << Sql;
		source << "        << \" FROM " + cntr->From();
		if (!!table)
		{
			if (table->ForeignJoins().size() > 0)
				source << " " + table->ForeignJoins();
		}
		source << "\";\r\n    return tmp;\r\n}\r\n\r\n";
	}
	void AddCountSqlFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		tsStringBase Sql;
		std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);

		header << "    static tscrypto::tsCryptoString countSql(TSDatabase* db);\r\n";
		source << "tscrypto::tsCryptoString " + classname + "::countSql(TSDatabase* db)\r\n{\r\n";

		source << "    	UNREFERENCED_PARAMETER(db);\r\n";
		source << "    return \"SELECT COUNT(*)";
		source << " FROM " + cntr->From();
		if (!!table)
		{
			if (table->ForeignJoins().size() > 0)
				source << " " + table->ForeignJoins();
		}
		source << "\";\r\n}\r\n\r\n";
	}
	void AddBuildSaveSqlFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		if (cntr->Persist())
		{
			tsStringBase Sql;
			tsStringBase nonNullableNames;
			tsStringBase nonNullableValues;
			tsStringBase nullableNames;
			tsStringBase nullableValues;
			tsStringBase codeBlock;
			tsStringBase nullableCodeBlock;
			int NNparamNumber = 0;
			bool hasNullable = false;

			header << "    tscrypto::tsCryptoString buildSaveSql(TSDatabase* db);\r\n";
			source << "tscrypto::tsCryptoString " + classname + "::buildSaveSql(TSDatabase* db)\r\n{\r\n";
			source << "    tscrypto::tsCryptoString sql;\r\n    sql << \"INSERT INTO dbo." + name + " (";

			//
			// Compute the nullable and non-nullable fields here
			//
			std::vector<std::shared_ptr<TableColumn> > colList = cntr->Columns();

			std::for_each(colList.begin(), colList.end(), [this, &codeBlock, &Sql, &cntr, &hasNullable, &nullableNames, &nullableCodeBlock, &nonNullableNames, &nonNullableValues, &NNparamNumber](std::shared_ptr<TableColumn> c) {
				if (c->Table().size() == 0)
				{
					tsStringBase childName = c->Name();

					if (c->Nullable())
					{
						hasNullable = true;
						if (nullableNames.size() > 0)
						{
							nullableNames << ", ";
							nullableCodeBlock << "    values += \", \";\r\n";
						}
						nullableNames << childName;

						nullableCodeBlock << "    if (exists_" + childName + "())\r\n    {\r\n";
						nullableCodeBlock << "        values += db->ConvertDataValue(ToSql(get_" + childName + "()), " + c->GetTSFieldType() + ");\r\n";
						nullableCodeBlock << "    }\r\n";
						nullableCodeBlock << "    else\r\n";
						nullableCodeBlock << "    {\r\n";
						nullableCodeBlock << "        values += \"NULL\";\r\n";
						nullableCodeBlock << "    }\r\n";

						//source << "    _has_" + childName + " = RecordSet->row(0)->Value(\"" + childName + "\").size() > 0;\r\n");
					}
					else
					{
						if (nonNullableNames.size() > 0)
						{
							nonNullableNames << ", ";
							nonNullableValues << ", ";
						}
						nonNullableNames << "dbo." + childName;
						nonNullableValues << "{nn" << NNparamNumber << "}";
						codeBlock << "    sql.Replace(tscrypto::tsCryptoString(\"{nn" << NNparamNumber << "}\"), db->ConvertDataValue(ToSql(get_" << childName << "()), " << c->GetTSFieldType() << "));\r\n";
						NNparamNumber++;
					}
				}
			});

			if (hasNullable)
			{
				if (nonNullableNames.size() > 0)
				{
					nonNullableNames << ", ";
					nonNullableValues << ", ";
				}
				nonNullableNames << nullableNames;
				nonNullableValues << "{nullable}";
			}
			source << nonNullableNames;
			source << ") VALUES (";
			source << nonNullableValues;
			source << ");\";\r\n";
			if (hasNullable)
			{
				source << "    tscrypto::tsCryptoString values;\r\n\r\n";
			}
			source << codeBlock;
			source << nullableCodeBlock;
			if (hasNullable)
			{
				source << "    sql.Replace(tscrypto::tsCryptoString(\"{nullable}\"), values);\r\n";
			}

			source << "    return sql;\r\n}\r\n\r\n";
		}
	}
	void AddBuildUpdateSqlFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		if (cntr->Persist() && !cntr->ReadOnly())
		{
			tsStringBase Sql;
			std::vector<tsStringBase> primaryKeys;
			tsStringBase whereSource;
			std::vector<std::shared_ptr<Index> > idxList = cntr->Indexes();

			std::for_each(idxList.begin(), idxList.end(), [this, &primaryKeys](std::shared_ptr<Index> idx) {
				if (idx->IndexType() == "primary")
				{
					std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

					std::for_each(colList.begin(), colList.end(), [this, &primaryKeys](std::shared_ptr<TableColumn> c) {
						primaryKeys.push_back(c->Name());
					});
				}
			});

			header << "    tscrypto::tsCryptoString buildUpdateSql(TSDatabase* db) const;\r\n";
			source << "tscrypto::tsCryptoString " + classname + "::buildUpdateSql(TSDatabase* db) const\r\n{\r\n";
			source << "    tscrypto::tsCryptoString setFields;\r\n";
			source << "    tscrypto::tsCryptoString sql;\r\n    sql << \"UPDATE dbo." + name + " SET \";\r\n";

			//
			// Compute the nullable and non-nullable fields here
			//
			std::vector<std::shared_ptr<TableColumn> > colList = cntr->Columns();

			std::for_each(colList.begin(), colList.end(), [this, &source, &whereSource, &primaryKeys](std::shared_ptr<TableColumn> c) {
				if (c->Table().size() == 0)
				{
					tsStringBase childName = c->Name();

					if (c->Nullable())
					{
						source << "    if (current._has_" + childName + " != original._has_" + childName + " || (current._has_" + childName + " && current._" + childName + " != original._" + childName + "))\r\n    {\r\n";
						source << "        if (setFields.size() > 0)\r\n            setFields += \", \";\r\n";
						source << "        setFields += \"" + childName + " = \" + db->ConvertDataValue(ToSql(current._has_" + childName + ", current._" + childName + "), " + c->GetTSFieldType() + ");\r\n";
						source << "    }\r\n";
						if (std::find_if(primaryKeys.begin(), primaryKeys.end(), [childName](tsStringBase& s) { return s == childName; }) != primaryKeys.end())
						{
							if (whereSource.size() > 0)
								whereSource << "    sql += \" AND \";\r\n";
							whereSource << "    sql += db->CreateSelectField(\"" + childName + "\", " + c->GetTSFieldType() + ") + \" = \";\r\n";
							whereSource << "    sql += db->ConvertDataValue(ToSql(original._has_" + childName + ", original._" + childName + "), " + c->GetTSFieldType() + ");\r\n";
						}
					}
					else
					{
						source << "    if (current._" + childName + " != original._" + childName + ")\r\n    {\r\n";
						source << "        if (setFields.size() > 0)\r\n            setFields += \", \";\r\n";
						source << "        setFields += \"" + childName + " = \" + db->ConvertDataValue(ToSql(current._" + childName + "), " + c->GetTSFieldType() + ");\r\n";
						source << "    }\r\n";
						if (std::find_if(primaryKeys.begin(), primaryKeys.end(), [childName](tsStringBase& s) { return s == childName; }) != primaryKeys.end())
						{
							if (whereSource.size() > 0)
								whereSource << "    sql += \" AND \";\r\n";
							whereSource << "    sql += db->CreateSelectField(\"" + childName + "\", " + c->GetTSFieldType() + ") + \" = \";\r\n";
							whereSource << "    sql += db->ConvertDataValue(ToSql(original._" + childName + "), " + c->GetTSFieldType() + ");\r\n";
						}
					}
				}
			});

			source << "    if (setFields.size() == 0)\r\n    {\r\n        return \"\";\r\n    }\r\n";
			source << "    sql += setFields;\r\n";
			source << "    sql += \" WHERE \";\r\n";
			source << whereSource;

			source << "    return sql;\r\n";
			source << "\r\n}\r\n\r\n";
		}
	}
	void AddBuildDeleteSqlFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, const tsStringBase& name, const tsStringBase& classname)
	{
		if (cntr->Persist() && idx->Deletable() && !cntr->ReadOnly())
		{
			std::vector<tsStringBase> primaryKeys;
			tsStringBase whereSource;
			tsStringBase Parameters;
			tsStringBase ParametersForCall;
			tsStringBase ConstPart;
			tsStringBase TypePart;
			tsStringBase RightPart;
			std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

			if (!idx->LoadReturnsSingle())
			{

				std::for_each(colList.begin(), colList.end(), [this, &ConstPart, &TypePart, &RightPart, &Parameters, &ParametersForCall](std::shared_ptr<TableColumn> c) {
					c->GetColumnNodeParameters(ConstPart, TypePart, RightPart);
					Parameters << ", ";
					Parameters << ConstPart + TypePart + RightPart + " " + c->Name();
					ParametersForCall << ", ";
					ParametersForCall << c->Name();
				});
			}


			std::for_each(colList.begin(), colList.end(), [this, &primaryKeys](std::shared_ptr<TableColumn> c) {
				primaryKeys.push_back(c->Name());
			});

			header << "    " << (idx->LoadReturnsSingle() ? "" : "static ") << "tscrypto::tsCryptoString buildDelete" << idx->SearchableName().substring(4, 9999) << "Sql(TSDatabase* db" << Parameters << ") " << (idx->LoadReturnsSingle() ? "const" : "") << ";\r\n";
			source << "tscrypto::tsCryptoString " << classname << "::buildDelete" << idx->SearchableName().substring(4, 9999) << "Sql(TSDatabase* db" << Parameters << ") " << (idx->LoadReturnsSingle() ? "const" : "") << "\r\n{\r\n";
			source << "    tscrypto::tsCryptoString sql;\r\n    sql << \"DELETE FROM dbo." + name + " WHERE \";\r\n";
			source << "\r\n";

			//
			// Compute the nullable and non-nullable fields here
			//
			if (idx->LoadReturnsSingle())
			{
				std::for_each(colList.begin(), colList.end(), [this, &primaryKeys, &whereSource](std::shared_ptr<TableColumn> c) {
					tsStringBase childName = c->Name();

					if (c->Nullable())
					{
						if (whereSource.size() > 0)
							whereSource << "    sql += \" AND \";\r\n";
						whereSource << "    sql += db->CreateSelectField(\"" + childName + "\", " + c->GetTSFieldType() + ") + \" = \";\r\n";
						whereSource << "    sql += db->ConvertDataValue(ToSql(original._has_" + childName + ", original._" + childName + "), " + c->GetTSFieldType() + ");\r\n";
					}
					else
					{
						if (whereSource.size() > 0)
							whereSource << "    sql += \" AND \";\r\n";
						whereSource << "    sql += db->CreateSelectField(\"" + childName + "\", " + c->GetTSFieldType() + ") + \" = \";\r\n";
						whereSource << "    sql += db->ConvertDataValue(ToSql(original._" + childName + "), " + c->GetTSFieldType() + ");\r\n";
					}
				});
			}
			else
			{
				std::for_each(colList.begin(), colList.end(), [this, &primaryKeys, &whereSource](std::shared_ptr<TableColumn> c) {
					tsStringBase childName = c->Name();

					if (whereSource.size() > 0)
						whereSource << "    sql += \" AND \";\r\n";
					whereSource << "    sql += db->CreateSelectField(\"" + childName + "\", " + c->GetTSFieldType() + ") + \" = \";\r\n";
					whereSource << "    sql += db->ConvertDataValue(ToSql(" + childName + "), " + c->GetTSFieldType() + ");\r\n";
				});
			}
			if (idx->DeleteSearchClause().size() > 0)
			{
				if (whereSource.size() > 0)
					whereSource << "    sql += \" AND \";\r\n";
				whereSource << "    sql += \"" + idx->DeleteSearchClause() + "\";\r\n";
			}

			source << whereSource;

			source << "    return sql;\r\n}\r\n\r\n";
		}
	}
	void AddInflateFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		tsStringBase type;
		tsStringBase Sql;
		tsStringBase ReplaceParams;
		std::vector<std::shared_ptr<TableColumn> > colList = cntr->Columns();


		header << "    bool Inflate(const std::shared_ptr<ITSRecord> &record, DSErrorList &errorList);\r\n";
		source << "bool " + classname + "::Inflate(const std::shared_ptr<ITSRecord> &record, DSErrorList &errorList)\r\n{\r\n";
		source << "    UNREFERENCED_PARAMETER(errorList);\r\n";

		std::for_each(colList.begin(), colList.end(), [this, &type, &source](std::shared_ptr<TableColumn> c) {
			tsStringBase childName = c->AliasFieldname();
			type = c->FieldType();

			if (type == "System.String" || type == "System.Char[]")
				source << "    current._" + childName + " = record->Value(\"" + childName + "\");\r\n";
			else if (type == "System.Guid")
				source << "    TSStringToGuid(record->Value(\"" + childName + "\"), current._" + childName + ");\r\n";
			else if (type == "System.Boolean")
				source << "    current._" + childName + " = TsStrToInt(record->Value(\"" + childName + "\")) != 0;\r\n";
			else if (type == "System.Int32" || type == "System.Int16")
				source << "    current._" + childName + " = TsStrToInt(record->Value(\"" + childName + "\"));\r\n";
			else if (type == "System.DateTime")
				source << "    current._" + childName + " = tscrypto::tsCryptoDate(record->Value(\"" + childName + "\"), tscrypto::tsCryptoDate::ISO8601);\r\n";
			else if (type == "System.Double")
				source << "    current._" + childName + " = TsStrToDouble(record->Value(\"" + childName + "\"));\r\n";
			else
			{
				source << "    current._" + childName + " = record->Value(\"" + childName + "\");\r\n";
			}
			if (c->Nullable())
			{
				source << "    current._has_" + childName + " = (!record->IsNull(\"" + childName + "\"));\r\n";
			}
		});

		if (cntr->Persist() && !cntr->ReadOnly())
			source << "    original = current;\r\n";
		source << "    return true;\r\n}\r\n\r\n";
	}
	void AddSaveFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		if (cntr->Persist() && !cntr->ReadOnly())
		{
			header << "    bool Save(TSDatabase *db, DSErrorList &errorList);\r\n";
			source << "bool " + classname + "::Save(TSDatabase *db, DSErrorList &errorList)\r\n{\r\n";
			source << "    tscrypto::tsCryptoString sql(buildSaveSql(db));\r\n\r\n";

			source << "    if (!db->RunUpdateSql(sql, IDS_E_CANT_SAVE, \"" + name + "\", true, errorList))\r\n";
			source << "        return false;\r\n";

			source << "    original = current;\r\n    return true;\r\n}\r\n\r\n";
		}
	}
	void AddUpdateFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		if (cntr->Persist() && !cntr->ReadOnly())
		{

			header << "    bool Update(TSDatabase *db, DSErrorList &errorList);\r\n";
			source << "bool " + classname + "::Update(TSDatabase *db, DSErrorList &errorList)\r\n{\r\n";
			source << "    tscrypto::tsCryptoString sql(buildUpdateSql(db));\r\n";
			source << "\r\n";

			source << "    if (sql.size() == 0)\r\n        return true;\r\n\r\n";
			source << "    if (!db->RunUpdateSql(sql, IDS_E_CANT_SAVE, \"" + name + "\", true, errorList))\r\n";
			source << "        return false;\r\n";

			source << "    original = current;\r\n    return true;\r\n}\r\n\r\n";
		}
	}
	void AddDeleteFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, const tsStringBase& name, const tsStringBase& classname)
	{
		if (cntr->Persist() && idx->Deletable() && !cntr->ReadOnly())
		{
			tsStringBase Parameters;
			tsStringBase ParametersForCall;
			tsStringBase ConstPart;
			tsStringBase TypePart;
			tsStringBase RightPart;
			std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

			if (!idx->LoadReturnsSingle())
			{
				std::for_each(colList.begin(), colList.end(), [this, &ConstPart, &TypePart, &RightPart, &Parameters, &ParametersForCall](std::shared_ptr<TableColumn> c) {
					c->GetColumnNodeParameters(ConstPart, TypePart, RightPart);
					Parameters << ", ";
					Parameters << ConstPart + TypePart + RightPart + " " + c->Name();
					ParametersForCall << ", ";
					ParametersForCall << c->Name();
				});
			}

			header << "    " << (idx->LoadReturnsSingle() ? "" : "static ") << "bool Delete" << idx->SearchableName().substring(4, 9999) << "(TSDatabase *db" << Parameters << ", DSErrorList &errorList);\r\n";
			source << "bool " << classname + "::Delete" << idx->SearchableName().substring(4, 9999) + "(TSDatabase *db" << Parameters << ", DSErrorList &errorList)\r\n{\r\n";
			source << "    tscrypto::tsCryptoString sql(buildDelete" << idx->SearchableName().substring(4, 9999) + "Sql(db" << ParametersForCall << "));\r\n";
			source << "\r\n";

			if (idx->LoadReturnsSingle())
				source << "    if (!db->RunUpdateSql(sql, IDS_E_CANT_DELETE, \"" + name + "\", true, errorList))\r\n";
			else
				source << "    if (!db->RunUpdateSql(sql, IDS_E_CANT_DELETE, \"" + name + "\", false, errorList))\r\n";
			source << "        return false;\r\n";

			if (idx->LoadReturnsSingle())
				source << "    original.clear();\r\n    current.clear();\r\n";
			source << "    return true;\r\n}\r\n\r\n";
		}
	}
	void AddModifiedFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		if (cntr->Persist() && !cntr->ReadOnly())
		{
			std::vector<std::shared_ptr<TableColumn> > colList = cntr->Columns();

			header << "    bool Modified() const;\r\n";
			source << "bool " + classname + "::Modified() const\r\n{\r\n";

			//
			// Compute the nullable and non-nullable fields here
			//
			std::for_each(colList.begin(), colList.end(), [this, &source](std::shared_ptr<TableColumn> c) {
				if (c->Table().size() == 0)
				{
					tsStringBase childName = c->Name();

					if (c->Nullable())
					{
						source << "    if (current._has_" << childName << " != original._has_" << childName << " || (current._has_" << childName << " && current._" << childName << " != original._" << childName << "))\r\n    {\r\n";
						source << "        return true;\r\n";
						source << "    }\r\n";
					}
					else
					{
						source << "    if (current._" + childName + " != original._" + childName + ")\r\n    {\r\n";
						source << "        return true;\r\n";
						source << "    }\r\n";
					}
				}
			});
			source << "    return false;\r\n}\r\n\r\n";
		}
	}
	void AddPrimaryKeyModifiedFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		if (cntr->Persist() && !cntr->ReadOnly())
		{
			std::vector<tsStringBase> primaryKeys;
			std::vector<std::shared_ptr<Index> > idxList = cntr->Indexes();

			std::for_each(idxList.begin(), idxList.end(), [this, &primaryKeys](std::shared_ptr<Index> idx) {
				if (idx->IndexType() == "primary")
				{
					std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

					std::for_each(colList.begin(), colList.end(), [this, &primaryKeys](std::shared_ptr<TableColumn> c) {
						primaryKeys.push_back(c->Name());
					});
				}
			});

			header << "    bool PrimaryKeyModified() const;\r\n";
			source << "bool " + classname + "::PrimaryKeyModified() const\r\n{\r\n";

			//
			// Compute the nullable and non-nullable fields here
			//
			std::vector<std::shared_ptr<TableColumn> > colList = cntr->Columns();

			std::for_each(colList.begin(), colList.end(), [this, &primaryKeys, &source](std::shared_ptr<TableColumn> c) {
				tsStringBase childName = c->Name();

				if (std::find_if(primaryKeys.begin(), primaryKeys.end(), [childName](tsStringBase& s) { return s == childName; }) != primaryKeys.end())
				{
					if (c->Nullable())
					{
						source << "    if (current._has_" + childName + " != original._has_" + childName + " || (current._has_" + childName + " && current._" + childName + " != original._" + childName + "))\r\n    {\r\n";
						source << "        return true;\r\n";
						source << "    }\r\n";
					}
					else
					{
						source << "    if (current._" + childName + " != original._" + childName + ")\r\n    {\r\n";
						source << "        return true;\r\n";
						source << "    }\r\n";
					}
				}
			});

			source << "    return false;\r\n}\r\n\r\n";
		}
	}
	void AddAccessors(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		tsStringBase ConstPart;
		tsStringBase TypePart;
		tsStringBase RightPart;

		//// First do the generic access functions (by name)
		//header << "\r\n    tscrypto::tsCryptoString get(const tscrypto::tsCryptoString& fieldName) const;\r\n");
		//header << "    bool exists(const tscrypto::tsCryptoString& fieldName) const;\r\n");
		//header << "    static int maximumLength(const tscrypto::tsCryptoString& fieldName);\r\n");
		//if (cntr->Persist())
		//{
		//    header << "    tscrypto::tsCryptoString getOriginal(const tscrypto::tsCryptoString& fieldName) const;\r\n");
		//    header << "    bool originalExists(const tscrypto::tsCryptoString& fieldName) const;\r\n");
		//    header << "    void set(const tscrypto::tsCryptoString& fieldName, const tscrypto::tsCryptoString& value);\r\n");
		//    header << "    void setexists(const tscrypto::tsCryptoString& fieldName, bool setTo);\r\n");
		//}

		// Add them to the source file

		//source << "tscrypto::tsCryptoString " + classname + "::get(const tscrypto::tsCryptoString& fieldName) const\r\n{\r\n}\r\n");
		//source << "bool " + classname + "::exists(const tscrypto::tsCryptoString& fieldName) const\r\n{\r\n}\r\n");
		//source << "int " + classname + "::maximumLength(const tscrypto::tsCryptoString& fieldName)\r\n{\r\n}\r\n");
		//if (cntr->Persist())
		//{
		//    source << "tscrypto::tsCryptoString " + classname + "::getOriginal(const tscrypto::tsCryptoString& fieldName) const\r\n{\r\n}\r\n");
		//    source << "bool " + classname + "::originalExists(const tscrypto::tsCryptoString& fieldName) const\r\n{\r\n}\r\n");
		//    source << "void " + classname + "::set(const tscrypto::tsCryptoString& fieldName, const tscrypto::tsCryptoString& value)\r\n{\r\n}\r\n");
		//    source << "void " + classname + "::setexists(const tscrypto::tsCryptoString& fieldName, bool setTo)\r\n{\r\n}\r\n");
		//}


		// Then do the normal access functions
		std::vector<std::shared_ptr<TableColumn> > colList = cntr->Columns();

		std::for_each(colList.begin(), colList.end(), [this, &ConstPart, &TypePart, &RightPart, &source, &header, &cntr, &classname](std::shared_ptr<TableColumn> c) {
			c->GetColumnNodeParameters(ConstPart, TypePart, RightPart);
			tsStringBase columnName = c->AliasFieldname();

			header << "\r\n    " + ConstPart + TypePart + RightPart + " get_" + columnName + "() const;\r\n";
			if (cntr->Persist() && c->Table().size() == 0 && !cntr->ReadOnly())
			{
				header << "    " + ConstPart + TypePart + RightPart + " getOriginal_" + columnName + "() const;\r\n";
			}
			if (c->Nullable())
			{
				header << "    bool exists_" + columnName + "() const;\r\n";
				if (cntr->Persist() && !cntr->ReadOnly())
				{
					header << "    bool originalExists_" + columnName + "() const;\r\n";
				}
			}
			header << "    static int maximumLength_" + columnName + "();\r\n";
			if (cntr->Persist() && c->Table().size() == 0 && !cntr->ReadOnly())
			{
				header << "    void set_" + columnName + "(" + ConstPart + TypePart + RightPart + " obj);\r\n";
				if (c->Nullable())
				{
					header << "    void setexists_" + columnName + "(bool setTo);\r\n";
				}
			}
			if (c->EncryptedObject().size() > 0 || c->EncryptionOIDCode().size() > 0)
			{
				tsStringBase encObjName = c->EncryptedObject();
				tsStringBase oidGenerator = c->EncryptionOIDCode();
				if (encObjName.size() > 0 && oidGenerator.size() > 0)
				{
					header << "    // Encrypts or decrypts the specified object.  The decrypted object is not cached.\r\n";
					header << "    " + encObjName + " get_" + columnName + "Object(std::shared_ptr<tsmod::IServiceLocator> loc) const;\r\n";
					if (cntr->Persist() && c->Table().size() == 0 && !cntr->ReadOnly())
					{
						header << "    bool set_" + columnName + "Object(std::shared_ptr<tsmod::IServiceLocator> loc, " + encObjName + "& object);\r\n";
					}

					source << encObjName + " " + classname + "::get_" + columnName + "Object(std::shared_ptr<tsmod::IServiceLocator> loc) const\r\n";
					source << "{\r\n";
					source << "    " + encObjName + " tmp;\r\n";
					source << "    tscrypto::tsCryptoData tmpData;\r\n";
					source << "    std::shared_ptr<DataProtector> dp = loc->get_instance<DataProtector>(\"/DataProtector\");\r\n";
					source << "\r\n";
					source << "    if (!dp || !dp->UnprotectData(" + oidGenerator + ", tscrypto::tsCryptoData(), get_" + columnName + "().Base64ToData(), tmpData) ||\r\n";
					source << "        !tmp.Decode(tmpData))\r\n";
					source << "    {\r\n";
					source << "        tmp.clear();\r\n";
					source << "    }\r\n";
					source << "    else if (tmp.NeedsUpdating())\r\n";
					source << "    {\r\n";
					source << "        if (!tmp.DoUpdate())\r\n";
					source << "            tmp.clear();\r\n";
					source << "    }\r\n";
					source << "    return tmp;\r\n";
					source << "}\r\n\r\n";
					if (cntr->Persist() && c->Table().size() == 0 && !cntr->ReadOnly())
					{
						source << "bool " + classname + "::set_" + columnName + "Object(std::shared_ptr<tsmod::IServiceLocator> loc, " + encObjName + "& object)\r\n";
						source << "{\r\n";
						source << "    tscrypto::tsCryptoData tmpData, tmp2;\r\n";
						source << "\r\n";
						source << "    std::shared_ptr<DataProtector> dp = loc->get_instance<DataProtector>(\"/DataProtector\");\r\n";
						source << "\r\n";
						source << "    if (!object.Encode(tmp2) || !dp || !dp->ProtectData(" + oidGenerator + ", tscrypto::tsCryptoData(), tmp2, tmpData))\r\n";
						source << "    {\r\n";
						source << "        return false;\r\n";
						source << "    }\r\n";
						source << "    set_" + columnName + "(tmpData.ToBase64());\r\n";
						source << "    return true;\r\n";
						source << "}\r\n\r\n";
					}
				}
				else if (encObjName.size() > 0)
				{
					header << "    // Encodes or Decodes the specified object.  The decoded object is not cached.\r\n";
					header << "    " + encObjName + " get_" + columnName + "Object() const;\r\n";
					if (cntr->Persist() && c->Table().size() == 0 && !cntr->ReadOnly())
					{
						header << "    bool set_" + columnName + "Object(" + encObjName + "& object);\r\n";
					}

					source << encObjName + " " + classname + "::get_" + columnName + "Object() const\r\n";
					source << "{\r\n";
					source << "    " + encObjName + " tmp;\r\n";
					source << "\r\n";
					source << "    if (!tmp.Decode(get_" + columnName + "().Base64ToData()))\r\n";
					source << "    {\r\n";
					source << "        tmp.clear();\r\n";
					source << "    }\r\n";
					source << "    else if (tmp.NeedsUpdating())\r\n";
					source << "    {\r\n";
					source << "        if (!tmp.DoUpdate())\r\n";
					source << "            tmp.clear();\r\n";
					source << "    }\r\n";
					source << "    return tmp;\r\n";
					source << "}\r\n\r\n";
					if (cntr->Persist() && c->Table().size() == 0 && !cntr->ReadOnly())
					{
						source << "bool " + classname + "::set_" + columnName + "Object(" + encObjName + "& object)\r\n";
						source << "{\r\n";
						source << "    tscrypto::tsCryptoData tmpData;\r\n";
						source << "\r\n";
						source << "    if (!object.Encode(tmpData))\r\n";
						source << "    {\r\n";
						source << "        return false;\r\n";
						source << "    }\r\n";
						source << "    set_" + columnName + "(tmpData.ToBase64());\r\n";
						source << "    return true;\r\n";
						source << "}\r\n\r\n";
					}
				}
				else if (oidGenerator.size() > 0)
				{
					header << "    // Encrypts or Decrypts the specified object to a byte string.  The decrypted object is not cached.\r\n";
					header << "    tscrypto::tsCryptoData get_" + columnName + "Object(std::shared_ptr<tsmod::IServiceLocator> loc) const;\r\n";
					if (cntr->Persist() && c->Table().size() == 0 && !cntr->ReadOnly())
					{
						header << "    bool set_" + columnName + "Object(std::shared_ptr<tsmod::IServiceLocator> loc, const tscrypto::tsCryptoData& object);\r\n";
					}

					source << "tscrypto::tsCryptoData " + classname + "::get_" + columnName + "Object(std::shared_ptr<tsmod::IServiceLocator> loc) const\r\n";
					source << "{\r\n";
					source << "    tscrypto::tsCryptoData tmpData;\r\n";
					source << "    std::shared_ptr<DataProtector> dp = loc->get_instance<DataProtector>(\"/DataProtector\");\r\n";
					source << "\r\n";
					source << "    if (!dp || !dp->UnprotectData(" + oidGenerator + ", tscrypto::tsCryptoData(), get_" + columnName + "().Base64ToData(), tmpData))\r\n";
					source << "    {\r\n";
					source << "        tmpData.clear();\r\n";
					source << "    }\r\n";
					source << "    return tmpData;\r\n";
					source << "}\r\n\r\n";
					if (cntr->Persist() && c->Table().size() == 0 && !cntr->ReadOnly())
					{
						source << "bool " + classname + "::set_" + columnName + "Object(std::shared_ptr<tsmod::IServiceLocator> loc, const tscrypto::tsCryptoData& data)\r\n";
						source << "{\r\n";
						source << "    tscrypto::tsCryptoData tmpData;\r\n";
						source << "\r\n";
						source << "    std::shared_ptr<DataProtector> dp = loc->get_instance<DataProtector>(\"/DataProtector\");\r\n";
						source << "\r\n";
						source << "    if (!dp || !dp->ProtectData(" + oidGenerator + ", tscrypto::tsCryptoData(), data, tmpData))\r\n";
						source << "    {\r\n";
						source << "        return false;\r\n";
						source << "    }\r\n";
						source << "    set_" + columnName + "(tmpData.ToBase64());\r\n";
						source << "    return true;\r\n";
						source << "}\r\n\r\n";
					}
				}
				else
					header << "    // Got encrypted data here but need the name of the object\r\n";
			}

			if (c->UnencryptedObject().size() > 0)
			{
				tsStringBase encObjName = c->UnencryptedObject();
				if (encObjName.size() > 0)
				{
					header << "    // Encodes or decodes the specified object.  The decoded object is not cached.\r\n";
					header << "    " + encObjName + " get_" + columnName + "Object() const;\r\n";
					if (cntr->Persist() && c->Table().size() == 0 && !cntr->ReadOnly())
					{
						header << "    bool set_" + columnName + "Object(" + encObjName + "& object);\r\n";
					}

					source << encObjName + " " + classname + "::get_" + columnName + "Object() const\r\n";
					source << "{\r\n";
					source << "    " + encObjName + " tmp;\r\n\r\n";
					source << "    if (!tmp.Decode(get_" + columnName + "().Base64ToData()))\r\n";
					source << "        tmp.clear();\r\n";
					source << "    else if (tmp.NeedsUpdating())\r\n";
					source << "    {\r\n";
					source << "        if (!tmp.DoUpdate())\r\n";
					source << "            tmp.clear();\r\n";
					source << "    }\r\n";
					source << "    return tmp;\r\n";
					source << "}\r\n\r\n";
					if (cntr->Persist() && c->Table().size() == 0 && !cntr->ReadOnly())
					{
						source << "bool " + classname + "::set_" + columnName + "Object(" + encObjName + "& object)\r\n";
						source << "{\r\n";
						source << "    tscrypto::tsCryptoData tmp;\r\n\r\n";
						source << "    if (!object.Encode(tmp))\r\n";
						source << "        return false;\r\n";
						source << "    set_" + columnName + "(tmp.ToBase64());\r\n";
						source << "    return true;\r\n";
						source << "}\r\n\r\n";
					}
				}
				else
					header << "    // Got encoded data here but need the name of the object\r\n";
			}


			source << ConstPart + TypePart + RightPart + " " + classname + "::get_" + columnName + "() const\r\n{\r\n    return current._" + columnName + ";\r\n}\r\n\r\n";
			if (cntr->Persist() && c->Table().size() == 0 && !cntr->ReadOnly())
			{
				source << ConstPart + TypePart + RightPart + " " + classname + "::getOriginal_" + columnName + "() const\r\n{\r\n    return original._" + columnName + ";\r\n}\r\n\r\n";
			}
			source << "int " + classname + "::maximumLength_" + columnName + "()\r\n{\r\n    return " << c->FieldLength() << ";\r\n}\r\n\r\n";
			if (c->Nullable())
			{
				source << "bool " + classname + "::exists_" + columnName + "() const\r\n{\r\n    return current._has_" + columnName + ";\r\n}\r\n\r\n";
				if (cntr->Persist() && c->Table().size() == 0 && !cntr->ReadOnly())
				{
					source << "bool " + classname + "::originalExists_" + columnName + "() const\r\n{\r\n    return original._has_" + columnName + ";\r\n}\r\n\r\n";
					source << "void " + classname + "::set_" + columnName + "(" + ConstPart + TypePart + RightPart + " obj)\r\n{\r\n    setexists_" + columnName + "(true);\r\n    current._" + columnName + " = obj;\r\n}\r\n\r\n";
				}
			}
			else
			{
				if (cntr->Persist() && c->Table().size() == 0 && !cntr->ReadOnly())
				{
					source << "void " + classname + "::set_" + columnName + "(" + ConstPart + TypePart + RightPart + " obj)\r\n{\r\n    current._" + columnName + " = obj;\r\n}\r\n\r\n";
				}
			}
			if (cntr->Persist() && c->Table().size() == 0 && !cntr->ReadOnly())
			{
				if (c->Nullable())
				{
					source << "void " + classname + "::setexists_" + columnName + "(bool setTo)\r\n{\r\n    current._has_" + columnName + " = setTo;\r\n}\r\n\r\n";
				}
			}
		});
	}
	void AddVariables(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
	{
		tsStringBase TypePart;
		tsStringBase ConstPart;
		tsStringBase RightPart;
		std::vector<tsStringBase> primaryKeys;
		std::vector<std::shared_ptr<Index> > idxList = cntr->Indexes();

		std::for_each(idxList.begin(), idxList.end(), [this, &primaryKeys](std::shared_ptr<Index> idx) {
			if (idx->IndexType() == "primary")
			{
				std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

				std::for_each(colList.begin(), colList.end(), [this, &primaryKeys](std::shared_ptr<TableColumn> c) {
					primaryKeys.push_back(c->AliasFieldname());
				});
			}
		});

		header << "\r\nprotected:\r\n    class " + Schema()->ExportSymbol() + " dataHolder {\r\n    public:\r\n";
		AddDataHolderConstructors(header, source, cntr, name, classname);

		std::vector<std::shared_ptr<TableColumn> > colList = cntr->Columns();

		std::for_each(colList.begin(), colList.end(), [this, &ConstPart, &TypePart, &RightPart, &primaryKeys, &header](std::shared_ptr<TableColumn> c) {
			c->GetColumnNodeParameters(ConstPart, TypePart, RightPart);

			header << "        " + TypePart + " _" + c->AliasFieldname() + ";";
			if (std::find_if(primaryKeys.begin(), primaryKeys.end(), [c](tsStringBase& s) { return s == c->AliasFieldname(); }) != primaryKeys.end())
				header << "  // Primary key\r\n";
			else
				header << "\r\n";
			if (c->Nullable())
			{
				header << "        bool _has_" + c->AliasFieldname() + ";\r\n";
			}
		});

		header << "    };\r\n    dataHolder current;\r\n";
		if (cntr->Persist() && !cntr->ReadOnly())
		{
			header << "    dataHolder original;\r\n";
		}
	}
	void AddManyToOneFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Relation> rel, const tsStringBase& name, const tsStringBase& classname)
	{
		tsStringBase Parameters;
		std::vector<std::shared_ptr<TableColumn> > colList = rel->DestinationColumns();

		std::for_each(colList.begin(), colList.end(), [this, &header, &Parameters](std::shared_ptr<TableColumn> c) {
			if (Parameters.size() > 0)
				Parameters << ", ";
			Parameters << "get_" + c->Name() + "()";
		});

		header << "    bool " + rel->ManyToOneName() << "(TSDatabase *db, " << rel->Source()->Name() << "Data &data, DSErrorList &errorList);\r\n";
		source << "bool " + classname + "::" + rel->ManyToOneName() + "(TSDatabase *db, " + rel->Source()->Name() + "Data &data, DSErrorList &errorList)\r\n{\r\n";
		source << "    return data." << rel->LoaderForOne() << "(db, " << Parameters << ", errorList);\r\n";
		source << "}\r\n\r\n";
	}
	void AddOneToOneDestFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Relation> rel, const tsStringBase& name, const tsStringBase& classname)
	{
		tsStringBase Parameters;
		std::vector<std::shared_ptr<TableColumn> > colList = rel->DestinationColumns();

		std::for_each(colList.begin(), colList.end(), [this, &header, &Parameters](std::shared_ptr<TableColumn> c) {
			if (Parameters.size() > 0)
				Parameters << ", ";
			Parameters << "get_" + c->Name() + "()";
		});

		header << "    std::shared_ptr<" + rel->Source()->Name() + "Data> " + rel->OneToOneDestName() << "(TSDatabase *db, DSErrorList &errorList);\r\n";
		source << "std::shared_ptr<" + rel->Source()->Name() + "Data> " + classname + "::" + rel->OneToOneDestName() + "(TSDatabase *db, DSErrorList &errorList)\r\n{\r\n";
		source << "    std::shared_ptr<" + rel->Source()->Name() + "Data> data = std::make_shared<" + rel->Source()->Name() + "Data>();\r\n";
		source << "\r\n";
		source << "    if (!data->Load(db, " << Parameters << ", errorList))\r\n";
		source << "        return nullptr;\r\n";
		source << "    return data;\r\n";
		source << "}\r\n\r\n";
	}
	void AddOneToManyFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Relation> rel, const tsStringBase& name, const tsStringBase& classname)
	{
		tsStringBase Parameters;
		std::vector<std::shared_ptr<TableColumn> > colList = rel->SourceColumns();

		std::for_each(colList.begin(), colList.end(), [this, &header, &Parameters](std::shared_ptr<TableColumn> c) {
			if (Parameters.size() > 0)
				Parameters << ", ";
			Parameters << "get_" + c->Name() + "()";
		});

		header << "    bool " + rel->OneToManyName() + "(TSDatabase *db, std::vector<" + rel->Destination()->Name() + "Data> &list, DSErrorList &errorList);\r\n";
		source << "bool " + classname + "::" + rel->OneToManyName() + "(TSDatabase *db, std::vector<" + rel->Destination()->Name() + "Data> &list, DSErrorList &errorList)\r\n{\r\n";
		source << "    return " + rel->Destination()->Name() + "Data::" + rel->LoaderForMany() + "(db, " << Parameters << ", list, errorList);\r\n";
		source << "}\r\n\r\n";
	}
	void AddOneToOneSourceFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Relation> rel, const tsStringBase& name, const tsStringBase& classname)
	{
		tsStringBase Parameters;
		std::vector<std::shared_ptr<TableColumn> > colList = rel->SourceColumns();

		std::for_each(colList.begin(), colList.end(), [this, &header, &Parameters](std::shared_ptr<TableColumn> c) {
			if (Parameters.size() > 0)
				Parameters << ", ";
			Parameters << "get_" + c->Name() + "()";
		});

		header << "    std::shared_ptr<" + rel->Destination()->Name() + "Data> " + rel->OneToOneSourceName() + "(TSDatabase *db, DSErrorList &errorList);\r\n";
		source << "std::shared_ptr<" + rel->Destination()->Name() + "Data> " + classname + "::" + rel->OneToOneSourceName() + "(TSDatabase *db, DSErrorList &errorList)\r\n{\r\n";
		source << "    std::shared_ptr<" + rel->Destination()->Name() + "Data> data = std::make_shared<" + rel->Destination()->Name() + "Data>();\r\n";
		source << "\r\n";
		source << "    if (!data->" << rel->LoaderForDest() << "(db, " << Parameters << ", errorList))\r\n";
		source << "        return nullptr;\r\n";
		source << "    return data;\r\n";
		source << "}\r\n\r\n";
	}
};

#endif // __CPPHELPER_H__
