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

#ifndef __CHELPER_H__
#define __CHELPER_H__

#pragma once

#include "stdafx.h"

class CHelper : public SQLHelper
{
public:
    CHelper(bool returnHeader, bool returnSource) : _returnHeader(returnHeader), _returnSource(returnSource)
    {
    }
    virtual ~CHelper()
    {
    }
    tsStringBase DataEncryptorClass() const
    {
        return gPrefix + "DataEncryptor";
    }
    virtual tsStringBase ResolveTypeToDatabase(const tsStringBase& _typeName, int length) override
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
    virtual tsStringBase BuildSchema(const tsStringBase& schemaFile, SchemaPartType schemaPart) override
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

        source << "#include \"utilities_interface.h\"\r\n";
        source << "#include \"buffers_interface.h\"\r\n";
        source << "#include \"database_interface.h\"\r\n";
        source << "#include \"" + gPrefix + "_Data.h\"\r\n\r\n";

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

            header << "struct tag" + classname + ";\r\n";
        });
        header << "\r\n";

        std::for_each(containerList.begin(), containerList.end(), [this, &name, &classname, &header, &source](std::shared_ptr<ColumnContainer> cntr) {
            name = cntr->Name();
            classname = name + "Data";

            header << "struct tag" + classname + "\r\n{\r\n";
            AddVariables(header, source, cntr, name, classname);
            header << "};\r\ntypedef struct tag" << classname << " " << classname << ";\r\n";

            header << "// SQL generation functions\r\n";
            AddSelectSqlFunction(header, source, cntr, name, classname);
            AddCountSqlFunction(header, source, cntr, name, classname);
            if (!cntr->ReadOnly())
            {
                int idxNumber = 0;
                AddBuildSaveSqlFunction(header, source, cntr, name, classname);
                AddBuildUpdateSqlFunction(header, source, cntr, name, classname);
                std::vector<std::shared_ptr<Index> > indexList = cntr->Indexes();

                std::for_each(indexList.begin(), indexList.end(), [this, &name, &classname, &header, &source, &cntr, &idxNumber](std::shared_ptr<Index> idx) {
                    if (idx->SearchableName().size() > 0)
                    {
                        AddBuildSqlFunction(header, source, cntr, idx, idxNumber, name, classname);
                        AddBuildCountSqlFunction(header, source, cntr, idx, idxNumber, name, classname);
                        if (!cntr->ReadOnly())
                        {
                            AddBuildDeleteSqlFunction(header, source, cntr, idx, idxNumber, name, classname);
                        }
                        idxNumber++;
                    }
                });
            }

            header << "// Query functions\r\n";
            AddSearchAllFunction(header, source, cntr, name, classname);
            AddClearFunctions(header, source, cntr, name, classname);
            AddLoadAllFunction(header, source, cntr, name, classname);
            AddCountAllFunction(header, source, cntr, name, classname);
            AddCountSearchAllFunction(header, source, cntr, name, classname);
            if (!cntr->ReadOnly())
            {
                int idxNumber = 0;
                AddInflateFunction(header, source, cntr, name, classname);
                AddSaveFunction(header, source, cntr, name, classname);
                AddUpdateFunction(header, source, cntr, name, classname);

                std::vector<std::shared_ptr<Index> > indexList = cntr->Indexes();

                std::for_each(indexList.begin(), indexList.end(), [this, &name, &classname, &header, &source, &cntr, &idxNumber](std::shared_ptr<Index> idx) {
                    if (idx->SearchableName().size() > 0)
                    {
                        AddLoadFunction(header, source, cntr, idx, idxNumber, name, classname);
                        AddSearchFunction(header, source, cntr, idx, idxNumber, name, classname);
                        AddCountFunction(header, source, cntr, idx, idxNumber, name, classname);
                        AddCountSearchFunction(header, source, cntr, idx, idxNumber, name, classname);
                        if (!cntr->ReadOnly())
                        {
                            AddDeleteFunction(header, source, cntr, idx, idxNumber, name, classname);
                        }


                        idxNumber++;
                    }
                });
            }
            header << "\r\n";

        });

        std::for_each(containerList.begin(), containerList.end(), [this, &name, &classname, &header, &source](std::shared_ptr<ColumnContainer> cntr) {
            name = cntr->Name();
            classname = name + "Data";


            //	AddConstructors(header, source, cntr, name, classname);
            //	AddJSONConverters(header, source, cntr, name, classname);
            //
            //	AddAppendInsertFunction(header, source, cntr, name, classname);
            //	header << "\r\n";
            //	if (!cntr->ReadOnly())
            //	{
            //		AddModifiedFunction(header, source, cntr, name, classname);
            //		AddPrimaryKeyModifiedFunction(header, source, cntr, name, classname);
            //	}
            //	AddAccessors(header, source, cntr, name, classname);
            //	header << "\r\n";
            //
            //	std::vector<std::shared_ptr<Relation> > relList = Schema()->FindRelationsWithDestinationTable(name);
            //
            //	std::for_each(relList.begin(), relList.end(), [this, &name, &classname, &header, &source, &cntr](std::shared_ptr<Relation> rel) {
            //		if (rel->ManyToOneName().size() > 0)
            //		{
            //			AddManyToOneFunction(header, source, cntr, rel, name, classname);
            //		}
            //		else if (rel->OneToOneDestName().size() > 0)
            //		{
            //			AddOneToOneDestFunction(header, source, cntr, rel, name, classname);
            //		}
            //	});
            //
            //	relList = Schema()->FindRelationsWithSourceTable(name);
            //
            //	std::for_each(relList.begin(), relList.end(), [this, &name, &classname, &header, &source, &cntr](std::shared_ptr<Relation> rel) {
            //		if (rel->OneToManyName().size() > 0 && rel->LoaderForMany().size() > 0)
            //		{
            //			AddOneToManyFunction(header, source, cntr, rel, name, classname);
            //		}
            //		else if (rel->OneToOneSourceName().size() > 0 && rel->LoaderForDest().size() > 0)
            //		{
            //			AddOneToOneSourceFunction(header, source, cntr, rel, name, classname);
            //		}
            //	});
            //
            //	AddBulkDataSupport(header, source, cntr, name, classname);
            //
            //	header << "};\r\n\r\n";
        });

        // Now create the schema exporter
        AddSchemaExporter(header, source);

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

        //		AddDataHolderConstructors(header, source, cntr, name, classname);

        std::vector<std::shared_ptr<TableColumn> > colList = cntr->Columns();

        header << "    void* _userField_nonFree;\r\n";
        header << "    void* _userField_free;\r\n";


        source << "#define g" << classname << "Count " << colList.size() << "\r\n";
        source << "static const PODDefinition g" << classname << "Defs[g" << classname << "Count] =\r\n";
        source << "{\r\n";
        std::for_each(colList.begin(), colList.end(), [this, &ConstPart, &TypePart, &RightPart, &primaryKeys, &header, &source, &classname](std::shared_ptr<TableColumn> c) {
            uint32_t arraySize = 0;

            c->Get_C_ColumnNodeParameters(ConstPart, TypePart, RightPart, arraySize);

            header << "    " + TypePart + " " + c->AliasFieldname();
            if (arraySize > 0)
            {
                header << "[" << arraySize + 1 << "]";
            }
            header << ";";
            source << "    { \"" << c->AliasFieldname() << "\", \"" << c->FullName() << "\", ";
            if (std::find_if(primaryKeys.begin(), primaryKeys.end(), [c](tsStringBase& s) { return s == c->AliasFieldname(); }) != primaryKeys.end())
            {
                header << "  // Primary key\r\n";
                source << "ts_true, ";
            }
            else
            {
                header << "\r\n";
                source << "ts_false, ";
            }
            source << "offsetof(" << classname << ", " << c->AliasFieldname() << "), ";
            if (c->Nullable())
            {
                header << "    ts_bool _has_" + c->AliasFieldname() + ";\r\n";
                source << "offsetof(" << classname << ", _has_" << c->AliasFieldname() << "), ";
            }
            else
            {
                source << "-1, ";
            }
            source << "sizeof(((" << classname << "*)0)->" + c->AliasFieldname() + ")" << ", " << c->Get_C_TSFieldType() << ", (convertToSqlFn)" << c->Get_C_ToSqlName() << ", (fieldPopulationFn)" << c->Get_C_FromSqlName() << " },\r\n";
        });
        source << "};\r\n";

        std::vector<std::shared_ptr<Index> > indexList = cntr->Indexes();

        std::for_each(indexList.begin(), indexList.end(), [this, &name, &classname, &header, &source, &cntr](std::shared_ptr<Index> idx) {
            if (idx->SearchableName().size() > 0)
            {
                AddIndexVariables(header, source, cntr, idx, name, classname);
            }
        });

        source << "static const PODIndexDefinition* g" << classname << "IndexList[] =\r\n";
        source << "{\r\n";
        std::for_each(indexList.begin(), indexList.end(), [this, &name, &classname, &header, &source, &cntr](std::shared_ptr<Index> idx) {
            if (idx->SearchableName().size() > 0)
            {
                tsStringBase idxNamePart;

                if (idx->IndexType() == "primary")
                {
                    idxNamePart = "_PK";
                }
                else
                {
                    idxNamePart = idx->SearchableName();
                    if (idxNamePart.substr(0, 4) == "Load")
                        idxNamePart.erase(0, 4);
                }
                source << "    &g" << classname << "Idx_" << idxNamePart << ",\r\n";
            }
        });
        source << "};\r\n";

        source << "static const PODStructDefinition g" << classname << "StructDef =\r\n";
        source << "{\r\n";
        source << "    \"" << classname << "\", \"" << classname.substr(0, classname.size() - 4) << "\", sizeof(" << classname << "), g" << classname << "Count, g" << classname << "Defs, " << idxList.size() << ", g" << classname << "IndexList\r\n";
        source << "};\r\n";
    }
    void AddIndexVariables(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, const tsStringBase& name, const tsStringBase& classname)
    {
        tsStringBase idxNamePart;

        if (idx->IndexType() == "primary")
        {
            idxNamePart = "_PK";
        }
        else
        {
            idxNamePart = idx->SearchableName();
            if (idxNamePart.substr(0, 4) == "Load")
                idxNamePart.erase(0, 4);
        }
        std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();
        std::vector<std::shared_ptr<TableColumn> > masterColList = cntr->Columns();

        source << "static const int g" << classname << "IdxList_" << idxNamePart << "[] = {\r\n";
        std::for_each(colList.begin(), colList.end(), [this, &header, &source, &classname, &masterColList](std::shared_ptr<TableColumn> c) {

            for (uint32_t i = 0; i < (uint32_t)masterColList.size(); i++)
            {
                if (c->AliasFieldname() == masterColList[i]->AliasFieldname())
                {
                    source << "    " << i << ",\r\n";
                    break;
                }
            }
        });
        source << "};\r\n";

        source << "static const PODIndexDefinition g" << classname << "Idx_" << idxNamePart << " =\r\n";
        source << "{\r\n";
        source << "    \"" << idxNamePart << "\", " << ((idxNamePart == "_PK") ? "ts_true" : "ts_false") << ", " << colList.size() << ", g" << classname << "IdxList_" << idxNamePart << "\r\n";
        source << "};\r\n";

    }
    void AddSelectSqlFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
        header << "ts_bool buildSelectSql_" + classname + "(DATABASE_CONNECTION db, BYTE_BUFF* outData);\r\n";
        source << "ts_bool buildSelectSql_" + classname + "(DATABASE_CONNECTION db, BYTE_BUFF* outData)\r\n{\r\n";

        source << "    return buildSelectStatement(db, &g" << classname << "StructDef, outData);\r\n";
        source << "}\r\n\r\n";
    }
    void AddBuildSaveSqlFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
        if (cntr->Persist() && !cntr->ReadOnly())
        {
            header << "ts_bool buildSaveSql_" + classname + "(DATABASE_CONNECTION db, " + classname + "* data, BYTE_BUFF* outData);\r\n";
            source << "ts_bool buildSaveSql_" + classname + "(DATABASE_CONNECTION db, " + classname + "* data, BYTE_BUFF* outData)\r\n{\r\n";

            source << "    return buildInsertSql(db, &g" << classname << "StructDef, (uint8_t*)data, outData);\r\n";

            source << "}\r\n\r\n";
        }
    }
    void AddBuildUpdateSqlFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
        if (cntr->Persist() && !cntr->ReadOnly())
        {
            header << "ts_bool buildUpdateSql_" + classname + "(DATABASE_CONNECTION db, " + classname + "* data, BYTE_BUFF* outData);\r\n";
            source << "ts_bool buildUpdateSql_" + classname + "(DATABASE_CONNECTION db, " + classname + "* data, BYTE_BUFF* outData)\r\n{\r\n";

            source << "    return buildUpdateSql(db, &g" << classname << "StructDef, (uint8_t*)data, outData);\r\n";

            source << "}\r\n\r\n";
        }
    }
    void AddInflateFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
        header << "ts_bool populate_" + classname + "(DATABASE_CONNECTION db, DATABASE_RECORDSET record, " + classname + "* data);\r\n";
        source << "ts_bool populate_" + classname + "(DATABASE_CONNECTION db, DATABASE_RECORDSET record, " + classname + "* data)\r\n{\r\n";

        source << "    PTR_BUFF row = NULL;\r\n";
        source << "\r\n";
        source << "    if (db == NULL || record == NULL || data == NULL)\r\n";
        source << "        return ts_false;\r\n";
        source << "\r\n";
        source << "    row = getCurrentDatabaseRecordsetRow(record);\r\n";
        source << "    return populateFields(db, row, &g" + classname + "StructDef, (uint8_t*)data);\r\n";
        source << "}\r\n";
    }
    void AddBuildDeleteSqlFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, int idxNumber, const tsStringBase& name, const tsStringBase& classname)
    {
        if (cntr->Persist() && idx->Deletable() && !cntr->ReadOnly())
        {
            tsStringBase idxNamePart;

            if (idx->IndexType() == "primary")
            {
                header << "ts_bool buildDeleteSql_" << classname << "(DATABASE_CONNECTION db, " << classname << "* data, BYTE_BUFF* outData);\r\n";
                source << "ts_bool buildDeleteSql_" << classname << "(DATABASE_CONNECTION db, " << classname << "* data, BYTE_BUFF* outData)\r\n{\r\n";
                source << "    return buildDeleteSql(db, &g" << classname << "StructDef, " << idxNumber << ", (uint8_t*)data, outData);\r\n";
                source << "}\r\n\r\n";
            }
            else
            {
                std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();
                bool first = true;
                std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);
                tsStringBase ConstPart;
                tsStringBase TypePart;
                tsStringBase RightPart;
                tsStringBase Parameters;
                tsStringBase ParametersForCall;
                int parameterNumber = 0;
                uint32_t arraySize;

                std::for_each(colList.begin(), colList.end(), [this, &Parameters, &ConstPart, &TypePart, &RightPart, &arraySize, &ParametersForCall](std::shared_ptr<TableColumn> c) {
                    c->Get_C_ColumnNodeParameters(ConstPart, TypePart, RightPart, arraySize);
                    Parameters << ", ";
                    Parameters << ConstPart + TypePart + RightPart + " " + c->AliasFieldname();
                    ParametersForCall << ", ";
                    ParametersForCall << c->AliasFieldname();
                });

                idxNamePart = idx->SearchableName();
                if (idxNamePart.substr(0, 4) == "Load")
                    idxNamePart.erase(0, 4);

                header << "ts_bool buildDeleteSql_" << classname << "_" << idxNamePart << "(DATABASE_CONNECTION db" << Parameters << ", BYTE_BUFF* outData);\r\n";
                source << "ts_bool buildDeleteSql_" << classname << "_" << idxNamePart << "(DATABASE_CONNECTION db" << Parameters << ", BYTE_BUFF* outData)\r\n{\r\n";

                source << "    BYTE_BUFF tmp = NULL;\r\n";
                source << "    ts_bool retVal = ts_true;\r\n";
                source << "\r\n";
                source << "    if (outData == NULL || db == NULL || outData == NULL || !createBuffer(&tmp, 200))\r\n";
                source << "        return ts_false;\r\n";
                source << "    if (*outData == NULL)\r\n";
                source << "    {\r\n";
                source << "        if (!createBuffer(outData, 200))\r\n";
                source << "        {\r\n";
                source << "            freeBuffer(&tmp);\r\n";
                source << "            return ts_false;\r\n";
                source << "        }\r\n";
                source << "    }\r\n";
                source << "    else\r\n";
                source << "        emptyBuffer(outData);\r\n";
                source << "\r\n";
                source << "    retVal = appendStringToBuffer(outData, \"DELETE FROM " << name << " WHERE \") && retVal;\r\n";

                for (auto& c : colList)
                {
                    tsStringBase tmp;

                    if (!first)
                        tmp << " AND ";
                    first = false;
                    tmp << c->AliasFieldname() << " = ";

                    source << "    retVal = appendStringToBuffer(outData, \"" << tmp << "\") && retVal;\r\n";
                    source << "    retVal = appendStringToBuffer(outData, (const char*)getBufferDataPtr(" << c->Get_C_ToSqlName() << "(" << c->AliasFieldname() << ", NULL, &tmp))) && retVal;\r\n";
                }

                source << "    freeBuffer(&tmp);\r\n";
                source << "    return retVal;\r\n";
                source << "}\r\n\r\n";
            }
        }
    }
    void AddDeleteFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, uint32_t idxNumber, const tsStringBase& name, const tsStringBase& classname)
    {
        if (cntr->Persist() && idx->Deletable() && !cntr->ReadOnly())
        {
            tsStringBase Parameters;
            tsStringBase ParametersForCall;
            tsStringBase ConstPart;
            tsStringBase TypePart;
            tsStringBase RightPart;
            uint32_t arraySize;
            std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

            if (idx->IndexType() == "primary")
            {
                header << "ts_bool delete_" << classname << "(DATABASE_CONNECTION db, " << classname << "* data, ERRORLIST* errorList);\r\n";
                source << "ts_bool delete_" << classname << "(DATABASE_CONNECTION db, " << classname << "* data, ERRORLIST* errorList)\r\n{\r\n";

                source << "    BYTE_BUFF sql = NULL;\r\n";
                source << "\r\n";
                source << "    if (!buildDeleteSql_" << classname << "(db, data, &sql) ||\r\n";
                source << "        !RunUpdateSql(db, (const char*)getBufferDataPtr(&sql), \"Cannot retrieve '" << classname << "'\", ts_true, errorList))\r\n";
                source << "    {\r\n";
                source << "        freeBuffer(&sql);\r\n";
                source << "        return ts_false;\r\n";
                source << "    }\r\n";
                source << "\r\n";
                source << "    freeBuffer(&sql);\r\n";
                source << "    clearStructure(&g" << classname << "StructDef, (uint8_t*)data);\r\n";
                source << "    return ts_true;\r\n";
                source << "}\r\n\r\n";
            }
            else 
            {
                std::for_each(colList.begin(), colList.end(), [this, &ConstPart, &TypePart, &RightPart, &Parameters, &ParametersForCall, &arraySize](std::shared_ptr<TableColumn> c) {
                    c->Get_C_ColumnNodeParameters(ConstPart, TypePart, RightPart, arraySize);
                    Parameters << ", ";
                    Parameters << ConstPart + TypePart + RightPart + " " + c->Name();
                    ParametersForCall << ", ";
                    ParametersForCall << c->Name();
                });

                header << "ts_bool delete_" << classname << "_" << idx->SearchableName().substring(4, 9999) << "(DATABASE_CONNECTION db" << Parameters << ", ERRORLIST* errorList);\r\n";
                source << "ts_bool delete_" << classname << "_" << idx->SearchableName().substring(4, 9999) + "(DATABASE_CONNECTION db" << Parameters << ", ERRORLIST* errorList)\r\n{\r\n";

                source << "    BYTE_BUFF sql = NULL;\r\n";
                source << "\r\n";
                source << "    if (!buildDeleteSql_" << classname << "_" << idx->SearchableName().substring(4, 9999) + "(db" << ParametersForCall << ", &sql) ||\r\n";
                source << "        !RunUpdateSql(db, (const char*)getBufferDataPtr(&sql), \"Cannot retrieve '" << classname << "'\", ts_false, errorList))\r\n";
                source << "    {\r\n";
                source << "        freeBuffer(&sql);\r\n";
                source << "        return ts_false;\r\n";
                source << "    }\r\n";
                source << "\r\n";
                source << "    freeBuffer(&sql);\r\n";
                source << "    return ts_true;\r\n";
                source << "}\r\n\r\n";
            }

        }
    }
    void AddCountSqlFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
        tsStringBase Sql;
        std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);

        header << "ts_bool buildCountAllSql_" + classname + "(DATABASE_CONNECTION db, BYTE_BUFF* outData);\r\n";
        source << "ts_bool buildCountAllSql_" + classname + "(DATABASE_CONNECTION db, BYTE_BUFF* outData)\r\n{\r\n";

        source << "    if (!appendStringToBuffer(outData, \"SELECT COUNT(*) FROM " << cntr->From() << "\"))\r\n";
        source << "        return ts_false;\r\n";
        if (!!table)
        {
            if (table->ForeignJoins().size() > 0)
                source << "    return appendStringToBuffer(outData, \"" << table->ForeignJoins() << "\");\r\n";
            else
                source << "    return ts_true;\r\n";
        }
        else
            source << "    return ts_true;\r\n";
        source << "}\r\n\r\n";
    }
    void AddLoadAllFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
        std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);

        header << "ts_bool loadAll_" + classname + "(DATABASE_CONNECTION db, PTR_BUFF* list, int pageSize, int pageNumber, const char* sort, ERRORLIST* errorList);\r\n";
        source << "ts_bool loadAll_" + classname + "(DATABASE_CONNECTION db, PTR_BUFF* list, int pageSize, int pageNumber, const char* sort, ERRORLIST* errorList)\r\n{\r\n";
        source << "    BYTE_BUFF sql = NULL;\r\n";
        source << "    DATABASE_RECORDSET RecordSet = NULL;\r\n";
        source << "\r\n";
        source << "    if (db == NULL || list == NULL || errorList == NULL)\r\n";
        source << "        return ts_false;\r\n";
        source << "\r\n";
        source << "    if (!buildSelectSql_" + classname + "(db, &sql))\r\n";
        source << "    {\r\n";
        source << "        freeBuffer(&sql);\r\n";
        source << "        return ts_false;\r\n";
        source << "    }\r\n";
        source << "    if (sort != NULL && sort[0] != 0)\r\n";
        source << "    {\r\n";
        source << "        if (!appendStringToBuffer(&sql, \" ORDER BY \") || !appendStringToBuffer(&sql, sort))\r\n";
        source << "        {\r\n";
        source << "            freeBuffer(&sql);\r\n";
        source << "            return ts_false;\r\n";
        source << "        }\r\n";
        source << "    }\r\n";
        if (!!table)
        {
            if (table->GroupBy().size() > 0)
            {
                source << "        if (!appendStringToBuffer(&sql, \" GROUP BY \") || !appendStringToBuffer(&sql, \"" << table->GroupBy() << "\"))\r\n";
                source << "        {\r\n";
                source << "            freeBuffer(&sql);\r\n";
                source << "            return ts_false;\r\n";
                source << "        }\r\n";
            }
        }
        source << "\r\n";
        source << "    if (!readDatabaseData(db, (const char*)getBufferDataPtr(&sql), pageSize, pageNumber, &RecordSet, errorList))\r\n";
        source << "    {\r\n";
        source << "        freeBuffer(&sql);\r\n";
        source << "        freeDatabaseRecordset(&RecordSet);\r\n";
        source << "        errorlistAddError(errorList, \"Cannot retrieve 'ServerVersionInformation'\");\r\n";
        source << "        return ts_false;\r\n";
        source << "    }\r\n";
        source << "    freeBuffer(&sql);\r\n";
        source << "\r\n";
        source << "    if (!readNextDatabaseRecordset(RecordSet) || !populateStructureListFromRecordSet(db, RecordSet, &g" << classname << "StructDef, list))\r\n";
        source << "    {\r\n";
        source << "        freeDatabaseRecordset(&RecordSet);\r\n";
        source << "        return ts_true;\r\n";
        source << "    }\r\n";
        source << "    freeDatabaseRecordset(&RecordSet);\r\n";
        source << "    return ts_true;\r\n";
        source << "}\r\n\r\n";
    }
    void AddBuildSqlFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, uint32_t idxNumber, const tsStringBase& name, const tsStringBase& classname)
    {
        tsStringBase ConstPart;
        tsStringBase TypePart;
        tsStringBase RightPart;
        tsStringBase Parameters;
        tsStringBase ParametersForCall;
        int parameterNumber = 0;
        uint32_t arraySize;
        std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);
        std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

        std::for_each(colList.begin(), colList.end(), [this, &Parameters, &ConstPart, &TypePart, &RightPart, &arraySize, &ParametersForCall](std::shared_ptr<TableColumn> c) {
            c->Get_C_ColumnNodeParameters(ConstPart, TypePart, RightPart, arraySize);
            Parameters << ", ";
            Parameters << ConstPart + TypePart + RightPart + " " + c->AliasFieldname();
            if (ParametersForCall.size() > 0)
                ParametersForCall << ", ";
            ParametersForCall << c->AliasFieldname();
        });

        header << "ts_bool build" + idx->SearchableName() + "Sql_" << classname << "(DATABASE_CONNECTION db" + Parameters + ", BYTE_BUFF* outData);\r\n";
        source << "ts_bool build" + idx->SearchableName() + "Sql_" << classname << "(DATABASE_CONNECTION db" + Parameters + ", BYTE_BUFF* outData)\r\n{\r\n";

        source << "    BYTE_BUFF tmp = NULL;\r\n";
        source << "\r\n";
        source << "    if (!buildSelectSql_" + classname + "(db, outData))\r\n";
        source << "        return ts_false;\r\n";
        if (!!table)
        {
            if (table->ForeignJoins().size() > 0)
            {
                source << "    if (!appendStringToBuffer(outData, \" \") || !appendStringToBuffer(outData, \"" << table->ForeignJoins() << "\")\r\n";
            }
        }
        source << "    if (!appendStringToBuffer(outData, \" WHERE \")\r\n";

        colList = idx->Columns();
        std::for_each(colList.begin(), colList.end(), [this, &source, &cntr, &Parameters, &ConstPart, &TypePart, &RightPart, &ParametersForCall, &parameterNumber](std::shared_ptr<TableColumn> c) {
            c->GetColumnNodeParameters(ConstPart, TypePart, RightPart);
            if (parameterNumber > 0)
                source << "        || !appendStringToBuffer(outData, \" AND \")\r\n";

            source << "        || !appendStringToBuffer(outData, \"" << c->AliasFieldname() << "\")\r\n";
            source << "        || !appendStringToBuffer(outData, \" = \")\r\n";
            source << "        || !appendStringToBuffer(outData, (const char*)getBufferDataPtr(" << c->Get_C_ToSqlName() << "(" << c->AliasFieldname() << ", NULL, &tmp)))\r\n";

            parameterNumber++;
        });

        if (idx->SearchClause().size() > 0)
        {
            if (parameterNumber > 0)
                source << "        || !appendStringToBuffer(outData, \" AND \")\r\n";
            source << "        || !appendStringToBuffer(outData, \"" + idx->SearchClause() + "\")\r\n";
        }

        source << "    )\r\n";
        source << "    {\r\n";
        source << "        freeBuffer(&tmp);\r\n";
        source << "        return ts_false;\r\n";
        source << "    }\r\n";
        source << "\r\n";
        source << "    freeBuffer(&tmp);\r\n";
        source << "    return ts_true;\r\n";
        source << "}\r\n\r\n";
    }
    void AddLoadFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, uint32_t idxNumber, const tsStringBase& name, const tsStringBase& classname)
    {
        std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);
        tsStringBase ConstPart;
        tsStringBase TypePart;
        tsStringBase RightPart;
        tsStringBase Parameters;
        tsStringBase ParametersForCall;
        int parameterNumber = 0;
        uint32_t arraySize;
        std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

        std::for_each(colList.begin(), colList.end(), [this, &Parameters, &ConstPart, &TypePart, &RightPart, &arraySize, &ParametersForCall](std::shared_ptr<TableColumn> c) {
            c->Get_C_ColumnNodeParameters(ConstPart, TypePart, RightPart, arraySize);
            Parameters << ", ";
            Parameters << ConstPart + TypePart + RightPart + " " + c->AliasFieldname();
            ParametersForCall << ", ";
            ParametersForCall << c->AliasFieldname();
        });


        if (idx->LoadReturnsSingle())
        {
            header << "ts_bool load_" << classname << "_" << idx->SearchableName().substr(4, 9999) << "(DATABASE_CONNECTION db" + Parameters + ", " << classname << "* data, ERRORLIST* errorList);\r\n";
            source << "ts_bool load_" << classname << "_" << idx->SearchableName().substr(4, 9999) << "(DATABASE_CONNECTION db" + Parameters + ", " << classname << "* data, ERRORLIST* errorList)\r\n{\r\n";
            source << "    BYTE_BUFF sql = NULL;\r\n";
            source << "    DATABASE_RECORDSET RecordSet = NULL;\r\n";
            source << "\r\n";
            source << "    if (db == NULL || data == NULL || errorList == NULL)\r\n";
            source << "        return ts_false;\r\n";
            source << "\r\n";
            source << "    if (!build" + idx->SearchableName() + "Sql_" << classname << "(db" << ParametersForCall << ", &sql))\r\n";
            source << "    {\r\n";
            source << "        freeBuffer(&sql);\r\n";
            source << "        return ts_false;\r\n";
            source << "    }\r\n";
            if (!!table)
            {
                if (table->GroupBy().size() > 0)
                {
                    source << "        if (!appendStringToBuffer(&sql, \" GROUP BY \") || !appendStringToBuffer(&sql, \"" << table->GroupBy() << "\"))\r\n";
                    source << "        {\r\n";
                    source << "            freeBuffer(&sql);\r\n";
                    source << "            return ts_false;\r\n";
                    source << "        }\r\n";
                }
            }
            source << "\r\n";
            source << "    if (!readDatabaseData(db, (const char*)getBufferDataPtr(&sql), 0, 0, &RecordSet, errorList))\r\n";
            source << "    {\r\n";
            source << "        freeBuffer(&sql);\r\n";
            source << "        freeDatabaseRecordset(&RecordSet);\r\n";
            source << "        errorlistAddError(errorList, \"Cannot retrieve '" << classname << "'\");\r\n";
            source << "        return ts_false;\r\n";
            source << "    }\r\n";
            source << "    freeBuffer(&sql);\r\n";
            source << "\r\n";
            source << "    if (!readNextDatabaseRecordset(RecordSet))\r\n";
            source << "    {\r\n";
            source << "        freeDatabaseRecordset(&RecordSet);\r\n";
            source << "        return ts_true;\r\n";
            source << "    }\r\n";

            source << "    if (getNextDatabaseRecordsetRow(RecordSet))\r\n";
            source << "    {\r\n";
            source << "        if (!populateFields(db, getCurrentDatabaseRecordsetRow(RecordSet), &g" << classname << "StructDef, (uint8_t*)data))\r\n";
            source << "        {\r\n";
            source << "            freeDatabaseRecordset(&RecordSet);\r\n";
            source << "            return ts_false;\r\n";
            source << "        }\r\n";
            source << "    }\r\n";
            source << "    else\r\n";
            source << "    {\r\n";
            source << "        freeDatabaseRecordset(&RecordSet);\r\n";
            source << "        return ts_false;\r\n";
            source << "    }\r\n";


            source << "    freeDatabaseRecordset(&RecordSet);\r\n";
            source << "    return ts_true;\r\n";
            source << "}\r\n\r\n";
        }
        else
        {
            header << "ts_bool load_" << classname << "_" << idx->SearchableName().substr(4, 9999) << "(DATABASE_CONNECTION db, const char* Name, uint32_t pageSize, uint32_t pageNumber, const char* sort, PTR_BUFF* list, ERRORLIST* errorList);\r\n";
            source << "ts_bool load_" << classname << "_" << idx->SearchableName().substr(4, 9999) << "(DATABASE_CONNECTION db, const char* Name, uint32_t pageSize, uint32_t pageNumber, const char* sort, PTR_BUFF* list, ERRORLIST* errorList)\r\n{\r\n";


            source << "    BYTE_BUFF sql = NULL;\r\n";
            source << "    DATABASE_RECORDSET RecordSet = NULL;\r\n";
            source << "\r\n";
            source << "    if (db == NULL || list == NULL || errorList == NULL)\r\n";
            source << "        return ts_false;\r\n";
            source << "\r\n";
            source << "    if (!buildSelectSql_" << classname << "(db, &sql))\r\n";
            source << "    {\r\n";
            source << "        freeBuffer(&sql);\r\n";
            source << "        return ts_false;\r\n";
            source << "    }\r\n";
            source << "    if (sort != NULL && sort[0] != 0)\r\n";
            source << "    {\r\n";
            source << "        if (!appendStringToBuffer(&sql, \" ORDER BY \") || !appendStringToBuffer(&sql, sort))\r\n";
            source << "        {\r\n";
            source << "            freeBuffer(&sql);\r\n";
            source << "            return ts_false;\r\n";
            source << "        }\r\n";
            source << "    }\r\n";
            if (!!table)
            {
                if (table->GroupBy().size() > 0)
                {
                    source << "        if (!appendStringToBuffer(&sql, \" GROUP BY \") || !appendStringToBuffer(&sql, \"" << table->GroupBy() << "\"))\r\n";
                    source << "        {\r\n";
                    source << "            freeBuffer(&sql);\r\n";
                    source << "            return ts_false;\r\n";
                    source << "        }\r\n";
                }
            }
            source << "\r\n";
            source << "    if (!readDatabaseData(db, (const char*)getBufferDataPtr(&sql), pageSize, pageNumber, &RecordSet, errorList))\r\n";
            source << "    {\r\n";
            source << "        freeBuffer(&sql);\r\n";
            source << "        freeDatabaseRecordset(&RecordSet);\r\n";
            source << "        errorlistAddError(errorList, \"Cannot retrieve '" << classname << "'\");\r\n";
            source << "        return ts_false;\r\n";
            source << "    }\r\n";
            source << "    freeBuffer(&sql);\r\n";
            source << "\r\n";
            source << "    if (!readNextDatabaseRecordset(RecordSet) || !populateStructureListFromRecordSet(db, RecordSet, &g" << classname << "StructDef, list))\r\n";
            source << "    {\r\n";
            source << "        freeDatabaseRecordset(&RecordSet);\r\n";
            source << "        return ts_true;\r\n";
            source << "    }\r\n";
            source << "    freeDatabaseRecordset(&RecordSet);\r\n";
            source << "    return ts_true;\r\n";
            source << "}\r\n\r\n";
        }
    }
    void AddBuildCountSqlFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, uint32_t idxNumber, const tsStringBase& name, const tsStringBase& classname)
    {
        tsStringBase ConstPart;
        tsStringBase TypePart;
        tsStringBase RightPart;
        tsStringBase Parameters;
        tsStringBase ParametersForCall;
        tsStringBase Sql;
        tsStringBase ReplaceParams;
        uint32_t arraySize;
        int parameterNumber = 0;
        std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);
        std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

        std::for_each(colList.begin(), colList.end(), [this, &Parameters, &ConstPart, &TypePart, &RightPart, &ParametersForCall, &arraySize](std::shared_ptr<TableColumn> c) {
            c->Get_C_ColumnNodeParameters(ConstPart, TypePart, RightPart, arraySize);
            Parameters << ", ";
            Parameters << ConstPart + TypePart + RightPart + " " + c->AliasFieldname();
            ParametersForCall << ", ";
            ParametersForCall << c->AliasFieldname();
        });

        header << "ts_bool buildCount" + idx->SearchableName().substring(4, 9999) + "Sql_" << classname << "(DATABASE_CONNECTION db" + Parameters + ", BYTE_BUFF* outData);\r\n";
        source << "ts_bool buildCount" + idx->SearchableName().substring(4, 9999) + "Sql_" << classname << "(DATABASE_CONNECTION db" + Parameters + ", BYTE_BUFF* outData)\r\n{\r\n";


        source << "    BYTE_BUFF tmp = NULL;\r\n";
        source << "    if (outData == NULL || db == NULL)\r\n";
        source << "        return ts_false;\r\n";
        source << "\r\n";
        source << "    if (!appendStringToBuffer(outData, \"SELECT COUNT(*) FROM " << cntr->From() << "\")\r\n";

        if (!!table)
        {
            if (table->ForeignJoins().size() > 0)
                source << "        || !appendStringToBuffer(outData, \"" << table->ForeignJoins() << "\")\r\n";
        }

        source << "        || !appendStringToBuffer(outData, \" WHERE \")\r\n";

        std::for_each(colList.begin(), colList.end(), [this, &Parameters, &ConstPart, &TypePart, &RightPart, &ParametersForCall, &parameterNumber, &Sql, &ReplaceParams, &cntr, &source](std::shared_ptr<TableColumn> c) {
            c->GetColumnNodeParameters(ConstPart, TypePart, RightPart);
            if (parameterNumber > 0)
                source << "        || !appendStringToBuffer(outData, \" AND \")\r\n";

            source << "        || !appendStringToBuffer(outData, \"" << c->AliasFieldname() << "\")\r\n";
            source << "        || !appendStringToBuffer(outData, \" = \")\r\n";
            source << "        || !appendStringToBuffer(outData, (const char*)getBufferDataPtr(" << c->Get_C_ToSqlName() << "(" << c->AliasFieldname() << ", NULL, &tmp)))\r\n";

            parameterNumber++;
        });

        if (idx->SearchClause().size() > 0)
        {
            if (parameterNumber > 0)
                source << "        || !appendStringToBuffer(outData, \" AND \")\r\n";
            source << "        || !appendStringToBuffer(outData, \"" << idx->SearchClause() << "\")\r\n";
        }

        source << "        )\r\n";
        source << "    {\r\n";
        source << "        freeBuffer(&tmp);\r\n";
        source << "        return ts_false;\r\n";
        source << "    }\r\n";
        source << "    freeBuffer(&tmp);\r\n";
        source << "    return ts_true;\r\n";

        source << "}\r\n\r\n";
    }
    void AddClearFunctions(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
        if (cntr->Persist())
        {
            header << "void clear_" << classname << "(" << classname << "* data);\r\n";
            source << "void clear_" << classname << "(" << classname << "* data)\r\n{\r\n" <<
                "    if (data != NULL)\r\n" <<
                "        clearStructure(&g" << classname << "StructDef, (uint8_t*)data);\r\n" <<
                "}\r\n";
            //if (!cntr->ReadOnly())
            //{
            //    header << "    void clearOriginal();\r\n";
            //    source << "void " + classname + "::clearOriginal()\r\n{\r\n    original.clear();\r\n}\r\n\r\n";
            //    header << "    void setOriginalToCurrent();\r\n";
            //    source << "void " + classname + "::setOriginalToCurrent()\r\n{\r\n    original = current;\r\n}\r\n\r\n";
            //    header << "    void reset();\r\n";
            //    source << "void " + classname + "::reset()\r\n{\r\n    current = original;\r\n}\r\n\r\n";
            //    header << "    void resetToOriginal();\r\n";
            //    source << "void " + classname + "::resetToOriginal()\r\n{\r\n    current = original;\r\n}\r\n\r\n";
            //}
        }
    }
    void AddSearchFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, uint32_t idxNumber, const tsStringBase& name, const tsStringBase& classname)
    {
        std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);
        tsStringBase ConstPart;
        tsStringBase TypePart;
        tsStringBase RightPart;
        tsStringBase Parameters;
        tsStringBase ParametersForCall;
        int parameterNumber = 0;
        uint32_t arraySize;
        std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

        std::for_each(colList.begin(), colList.end(), [this, &Parameters, &ConstPart, &TypePart, &RightPart, &arraySize, &ParametersForCall](std::shared_ptr<TableColumn> c) {
            c->Get_C_ColumnNodeParameters(ConstPart, TypePart, RightPart, arraySize);
            Parameters << ", ";
            Parameters << ConstPart + TypePart + RightPart + " " + c->AliasFieldname();
            ParametersForCall << ", ";
            ParametersForCall << c->AliasFieldname();
        });


        if (!idx->LoadReturnsSingle())
        {
            header << "ts_bool search_" << classname << "_" << idx->SearchableName().substr(4, 9999) << "(DATABASE_CONNECTION db, const char* Name, const char* searchString, uint32_t pageSize, uint32_t pageNumber, const char* sort, PTR_BUFF* list, ERRORLIST* errorList);\r\n";
            source << "ts_bool search_" << classname << "_" << idx->SearchableName().substr(4, 9999) << "(DATABASE_CONNECTION db, const char* Name, const char* searchString, uint32_t pageSize, uint32_t pageNumber, const char* sort, PTR_BUFF* list, ERRORLIST* errorList)\r\n{\r\n";


            source << "    BYTE_BUFF sql = NULL;\r\n";
            source << "    DATABASE_RECORDSET RecordSet = NULL;\r\n";
            source << "\r\n";
            source << "    if (db == NULL || list == NULL || errorList == NULL || searchString == NULL)\r\n";
            source << "        return ts_false;\r\n";
            source << "\r\n";
            source << "    if (!buildSelectSql_" << classname << "(db, &sql) ||\r\n";
            source << "        !appendStringToBuffer(&sql, \" AND \") ||\r\n";
            source << "        !appendStringToBuffer(&sql, searchString))\r\n";
            source << "    {\r\n";
            source << "        freeBuffer(&sql);\r\n";
            source << "        return ts_false;\r\n";
            source << "    }\r\n";
            source << "    if (sort != NULL && sort[0] != 0)\r\n";
            source << "    {\r\n";
            source << "        if (!appendStringToBuffer(&sql, \" ORDER BY \") || !appendStringToBuffer(&sql, sort))\r\n";
            source << "        {\r\n";
            source << "            freeBuffer(&sql);\r\n";
            source << "            return ts_false;\r\n";
            source << "        }\r\n";
            source << "    }\r\n";
            if (!!table)
            {
                if (table->GroupBy().size() > 0)
                {
                    source << "        if (!appendStringToBuffer(&sql, \" GROUP BY \") || !appendStringToBuffer(&sql, \"" << table->GroupBy() << "\"))\r\n";
                    source << "        {\r\n";
                    source << "            freeBuffer(&sql);\r\n";
                    source << "            return ts_false;\r\n";
                    source << "        }\r\n";
                }
            }
            source << "\r\n";
            source << "    if (!readDatabaseData(db, (const char*)getBufferDataPtr(&sql), pageSize, pageNumber, &RecordSet, errorList))\r\n";
            source << "    {\r\n";
            source << "        freeBuffer(&sql);\r\n";
            source << "        freeDatabaseRecordset(&RecordSet);\r\n";
            source << "        errorlistAddError(errorList, \"Cannot retrieve '" << classname << "'\");\r\n";
            source << "        return ts_false;\r\n";
            source << "    }\r\n";
            source << "    freeBuffer(&sql);\r\n";
            source << "\r\n";
            source << "    if (!readNextDatabaseRecordset(RecordSet) || !populateStructureListFromRecordSet(db, RecordSet, &g" << classname << "StructDef, list))\r\n";
            source << "    {\r\n";
            source << "        freeDatabaseRecordset(&RecordSet);\r\n";
            source << "        return ts_true;\r\n";
            source << "    }\r\n";
            source << "    freeDatabaseRecordset(&RecordSet);\r\n";
            source << "    return ts_true;\r\n";
            source << "}\r\n\r\n";
        }
    }
    void AddCountFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, uint32_t idxNumber, const tsStringBase& name, const tsStringBase& classname)
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
            uint32_t arraySize;
            std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);
            std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

            std::for_each(colList.begin(), colList.end(), [this, &Parameters, &ConstPart, &TypePart, &RightPart, &ParametersForCall, &arraySize](std::shared_ptr<TableColumn> c) {
                c->Get_C_ColumnNodeParameters(ConstPart, TypePart, RightPart, arraySize);
                Parameters << ", ";
                Parameters << ConstPart + TypePart + RightPart + " " + c->Name();
                ParametersForCall << ", ";
                ParametersForCall << c->Name();
            });

            header << "ts_bool count_" << classname << "_" + idx->SearchableName().substring(4, 9999) + "(DATABASE_CONNECTION db" + Parameters + ", int32_t *count, ERRORLIST* errorList);\r\n";
            source << "ts_bool count_" << classname << "_" + idx->SearchableName().substring(4, 9999) + "(DATABASE_CONNECTION db" + Parameters + ", int32_t *count, ERRORLIST* errorList)\r\n{\r\n";

            source << "    BYTE_BUFF sql = NULL;\r\n";
            source << "\r\n";
            source << "    if (db == NULL || count == NULL || errorList == NULL)\r\n";
            source << "        return ts_false;\r\n";
            source << "\r\n";
            source << "    if (!buildCount" << idx->SearchableName().substring(4, 9999) << "Sql_" << classname << "(db" << ParametersForCall << ", &sql))\r\n";
            source << "    {\r\n";
            source << "        freeBuffer(&sql);\r\n";
            source << "        return ts_false;\r\n";
            source << "    }\r\n";
            if (!!table)
            {
                if (table->GroupBy().size() > 0)
                {
                    source << "    if (!appendStringToBuffer(&sql, \" GROUP BY \") ||\r\n";
                    source << "        !appendStringToBuffer(&sql, \"" << table->GroupBy() << "\"))\r\n";
                    source << "    {\r\n";
                    source << "        freeBuffer(&sql);\r\n";
                    source << "        return ts_false;\r\n";
                    source << "    }\r\n";
                }
            }
            source << "\r\n";
            source << "    if (!SqlGetLong(db, (const char*)getBufferDataPtr(&sql), count, errorList))\r\n";
            source << "    {\r\n";
            source << "        freeBuffer(&sql);\r\n";
            source << "        errorlistAddError(errorList, \"Cannot retrieve '" << classname << "'\");\r\n";
            source << "        return ts_false;\r\n";
            source << "    }\r\n";
            source << "    freeBuffer(&sql);\r\n";
            source << "    return ts_true;\r\n";
            source << "}\r\n\r\n";
        }
    }
    void AddCountSearchFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Index> idx, uint32_t idxNumber, const tsStringBase& name, const tsStringBase& classname)
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
            uint32_t arraySize;
            std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);
            std::vector<std::shared_ptr<TableColumn> > colList = idx->Columns();

            std::for_each(colList.begin(), colList.end(), [this, &Parameters, &ConstPart, &TypePart, &RightPart, &ParametersForCall, &arraySize](std::shared_ptr<TableColumn> c) {
                c->Get_C_ColumnNodeParameters(ConstPart, TypePart, RightPart, arraySize);
                Parameters << ", ";
                Parameters << ConstPart + TypePart + RightPart + " " + c->Name();
                ParametersForCall << ", ";
                ParametersForCall << c->Name();
            });

            header << "ts_bool countSearch_" << classname << "_" + idx->SearchableName().substring(4, 9999) + "(DATABASE_CONNECTION db" + Parameters + ", const char* searchString, int32_t *count, ERRORLIST* errorList);\r\n";
            source << "ts_bool countSearch_" << classname << "_" + idx->SearchableName().substring(4, 9999) + "(DATABASE_CONNECTION db" + Parameters + ", const char* searchString, int32_t *count, ERRORLIST* errorList)\r\n{\r\n";

            source << "    BYTE_BUFF sql = NULL;\r\n";
            source << "\r\n";
            source << "    if (db == NULL || count == NULL || errorList == NULL || searchString == NULL)\r\n";
            source << "        return ts_false;\r\n";
            source << "\r\n";
            source << "    if (!buildCount" << idx->SearchableName().substring(4, 9999) << "Sql_" << classname << "(db" << ParametersForCall << ", &sql) ||\r\n";
            source << "        !appendStringToBuffer(&sql, \" AND \") ||\r\n";
            source << "        !appendStringToBuffer(&sql, searchString))\r\n";
            source << "    {\r\n";
            source << "        freeBuffer(&sql);\r\n";
            source << "        return ts_false;\r\n";
            source << "    }\r\n";
            if (!!table)
            {
                if (table->GroupBy().size() > 0)
                {
                    source << "    if (!appendStringToBuffer(&sql, \" GROUP BY \") ||\r\n";
                    source << "        !appendStringToBuffer(&sql, \"" << table->GroupBy() << "\"))\r\n";
                    source << "    {\r\n";
                    source << "        freeBuffer(&sql);\r\n";
                    source << "        return ts_false;\r\n";
                    source << "    }\r\n";
                }
            }
            source << "\r\n";
            source << "    if (!SqlGetLong(db, (const char*)getBufferDataPtr(&sql), count, errorList))\r\n";
            source << "    {\r\n";
            source << "        freeBuffer(&sql);\r\n";
            source << "        errorlistAddError(errorList, \"Cannot retrieve '" << classname << "'\");\r\n";
            source << "        return ts_false;\r\n";
            source << "    }\r\n";
            source << "    freeBuffer(&sql);\r\n";
            source << "    return ts_true;\r\n";
            source << "}\r\n\r\n";
        }
    }
    void AddSearchAllFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
        std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);

        header << "ts_bool searchAll_" + classname + "(DATABASE_CONNECTION db, const char* searchString, PTR_BUFF* list, int pageSize, int pageNumber, const char* sort, ERRORLIST* errorList);\r\n";
        source << "ts_bool searchAll_" + classname + "(DATABASE_CONNECTION db, const char* searchString, PTR_BUFF* list, int pageSize, int pageNumber, const char* sort, ERRORLIST* errorList)\r\n{\r\n";
        source << "    BYTE_BUFF sql = NULL;\r\n";
        source << "    DATABASE_RECORDSET RecordSet = NULL;\r\n";
        source << "\r\n";
        source << "    if (db == NULL || list == NULL || errorList == NULL || searchString == NULL)\r\n";
        source << "        return ts_false;\r\n";
        source << "\r\n";
        source << "    if (!buildSelectSql_" + classname + "(db, &sql) ||\r\n";
        source << "        !appendStringToBuffer(&sql, \" AND \") ||\r\n";
        source << "        !appendStringToBuffer(&sql, searchString))\r\n";
        source << "    {\r\n";
        source << "        freeBuffer(&sql);\r\n";
        source << "        return ts_false;\r\n";
        source << "    }\r\n";
        source << "    if (sort != NULL && sort[0] != 0)\r\n";
        source << "    {\r\n";
        source << "        if (!appendStringToBuffer(&sql, \" ORDER BY \") || !appendStringToBuffer(&sql, sort))\r\n";
        source << "        {\r\n";
        source << "            freeBuffer(&sql);\r\n";
        source << "            return ts_false;\r\n";
        source << "        }\r\n";
        source << "    }\r\n";
        if (!!table)
        {
            if (table->GroupBy().size() > 0)
            {
                source << "        if (!appendStringToBuffer(&sql, \" GROUP BY \") || !appendStringToBuffer(&sql, \"" << table->GroupBy() << "\"))\r\n";
                source << "        {\r\n";
                source << "            freeBuffer(&sql);\r\n";
                source << "            return ts_false;\r\n";
                source << "        }\r\n";
            }
        }
        source << "\r\n";
        source << "    if (!readDatabaseData(db, (const char*)getBufferDataPtr(&sql), pageSize, pageNumber, &RecordSet, errorList))\r\n";
        source << "    {\r\n";
        source << "        freeBuffer(&sql);\r\n";
        source << "        freeDatabaseRecordset(&RecordSet);\r\n";
        source << "        errorlistAddError(errorList, \"Cannot retrieve 'ServerVersionInformation'\");\r\n";
        source << "        return ts_false;\r\n";
        source << "    }\r\n";
        source << "    freeBuffer(&sql);\r\n";
        source << "\r\n";
        source << "    if (!readNextDatabaseRecordset(RecordSet) || !populateStructureListFromRecordSet(db, RecordSet, &g" << classname << "StructDef, list))\r\n";
        source << "    {\r\n";
        source << "        freeDatabaseRecordset(&RecordSet);\r\n";
        source << "        return ts_true;\r\n";
        source << "    }\r\n";
        source << "    freeDatabaseRecordset(&RecordSet);\r\n";
        source << "    return ts_true;\r\n";
        source << "}\r\n\r\n";
    }
    void AddCountAllFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
        std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);

        header << "ts_bool countAll_" << classname << "(DATABASE_CONNECTION db, int32_t *count, ERRORLIST* errorList);\r\n";
        source << "ts_bool countAll_" << classname << "(DATABASE_CONNECTION db, int32_t *count, ERRORLIST* errorList)\r\n{\r\n";

        source << "    BYTE_BUFF sql = NULL;\r\n";
        source << "\r\n";
        source << "    if (db == NULL || count == NULL || errorList == NULL)\r\n";
        source << "        return ts_false;\r\n";
        source << "\r\n";
        source << "    if (!buildCountAllSql_" << classname << "(db, &sql))\r\n";
        source << "    {\r\n";
        source << "        freeBuffer(&sql);\r\n";
        source << "        return ts_false;\r\n";
        source << "    }\r\n";
        if (!!table)
        {
            if (table->GroupBy().size() > 0)
            {
                source << "    if (!appendStringToBuffer(&sql, \" GROUP BY \") ||\r\n";
                source << "        !appendStringToBuffer(&sql, \"" << table->GroupBy() << "\"))\r\n";
                source << "    {\r\n";
                source << "        freeBuffer(&sql);\r\n";
                source << "        return ts_false;\r\n";
                source << "    }\r\n";
            }
        }
        source << "\r\n";
        source << "    if (!SqlGetLong(db, (const char*)getBufferDataPtr(&sql), count, errorList))\r\n";
        source << "    {\r\n";
        source << "        freeBuffer(&sql);\r\n";
        source << "        errorlistAddError(errorList, \"Cannot retrieve '" << classname << "'\");\r\n";
        source << "        return ts_false;\r\n";
        source << "    }\r\n";
        source << "    freeBuffer(&sql);\r\n";
        source << "    return ts_true;\r\n";
        source << "}\r\n\r\n";
    }
    void AddCountSearchAllFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
        std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);

        header << "ts_bool countSearchAll_" << classname << "(DATABASE_CONNECTION db, const char* searchString, int32_t *count, ERRORLIST* errorList);\r\n";
        source << "ts_bool countSearchAll_" << classname << "(DATABASE_CONNECTION db, const char* searchString, int32_t *count, ERRORLIST* errorList)\r\n{\r\n";

        source << "    BYTE_BUFF sql = NULL;\r\n";
        source << "\r\n";
        source << "    if (db == NULL || count == NULL || errorList == NULL || searchString == NULL)\r\n";
        source << "        return ts_false;\r\n";
        source << "\r\n";
        source << "    if (!buildCountAllSql_" << classname << "(db, &sql) ||\r\n";
        source << "        !appendStringToBuffer(&sql, \" WHERE \") ||\r\n";
        source << "        !appendStringToBuffer(&sql, searchString))\r\n";
        source << "    {\r\n";
        source << "        freeBuffer(&sql);\r\n";
        source << "        return ts_false;\r\n";
        source << "    }\r\n";
        if (!!table)
        {
            if (table->GroupBy().size() > 0)
            {
                source << "    if (!appendStringToBuffer(&sql, \" GROUP BY \") ||\r\n";
                source << "        !appendStringToBuffer(&sql, \"" << table->GroupBy() << "\"))\r\n";
                source << "    {\r\n";
                source << "        freeBuffer(&sql);\r\n";
                source << "        return ts_false;\r\n";
                source << "    }\r\n";
            }
        }
        source << "\r\n";
        source << "    if (!SqlGetLong(db, (const char*)getBufferDataPtr(&sql), count, errorList))\r\n";
        source << "    {\r\n";
        source << "        freeBuffer(&sql);\r\n";
        source << "        errorlistAddError(errorList, \"Cannot retrieve '" << classname << "'\");\r\n";
        source << "        return ts_false;\r\n";
        source << "    }\r\n";
        source << "    freeBuffer(&sql);\r\n";
        source << "    return ts_true;\r\n";
        source << "}\r\n\r\n";
    }
    void AddSaveFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
        if (cntr->Persist() && !cntr->ReadOnly())
        {
            header << "ts_bool save_" + classname + "(DATABASE_CONNECTION db, " + classname + "* data, ERRORLIST* errorList);\r\n";
            source << "ts_bool save_" + classname + "(DATABASE_CONNECTION db, " + classname + "* data, ERRORLIST* errorList)\r\n{\r\n";
            source << "    BYTE_BUFF sql = NULL;\r\n";
            source << "\r\n";
            source << "    if (db == NULL || data == NULL || errorList == NULL || !buildSaveSql_" + classname + "(db, data, &sql))\r\n";
            source << "        return ts_false;\r\n";
            source << "\r\n";
            source << "    if (!RunUpdateSql(db, (const char*)getBufferDataPtr(&sql), \"Unable to save '" + classname + "'\", ts_true, errorList))\r\n";
            source << "    {\r\n";
            source << "        freeBuffer(&sql);\r\n";
            source << "        return ts_false;\r\n";
            source << "    }\r\n";
            source << "    freeBuffer(&sql);\r\n";
            source << "    return ts_true;\r\n";
            source << "}\r\n\r\n";
        }
    }
    void AddUpdateFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
        if (cntr->Persist() && !cntr->ReadOnly())
        {
            header << "ts_bool update_" + classname + "(DATABASE_CONNECTION db, " + classname + "* data, ERRORLIST* errorList);\r\n";
            source << "ts_bool update_" + classname + "(DATABASE_CONNECTION db, " + classname + "* data, ERRORLIST* errorList)\r\n{\r\n";
            source << "    BYTE_BUFF sql = NULL;\r\n";
            source << "\r\n";
            source << "    if (db == NULL || data == NULL || errorList == NULL || !buildUpdateSql_" + classname + "(db, data, &sql))\r\n";
            source << "        return ts_false;\r\n";
            source << "\r\n";
            source << "    if (!RunUpdateSql(db, (const char*)getBufferDataPtr(&sql), \"Unable to update '" + classname + "'\", ts_true, errorList))\r\n";
            source << "    {\r\n";
            source << "        freeBuffer(&sql);\r\n";
            source << "        return ts_false;\r\n";
            source << "    }\r\n";
            source << "    freeBuffer(&sql);\r\n";
            source << "    return ts_true;\r\n";
            source << "}\r\n\r\n";
        }
    }












    virtual tsStringBase FieldStart() const override
    {
        return "`";
    }
    virtual tsStringBase FieldEnd() const override
    {
        return "`";
    }
    virtual tsStringBase TableStart() const override
    {
        return "`";
    }
    virtual tsStringBase TableEnd() const override
    {
        return "`";
    }
    virtual tsStringBase StatementTerminator() const override
    {
        return ";";
    }
    int getColumnSize(std::shared_ptr<tsXmlNode> node)
    {
        return 0;
    }

private:
    bool _returnHeader;
    bool _returnSource;

    void AddConstructors(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
#if 0
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
#endif // 0
    }
    void AddDataHolderConstructors(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
#if 0
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
#endif
    }
    void AddJSONConverters(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> tbl, const tsStringBase& name, const tsStringBase& classname)
    {
#if 0
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
#endif
    }
    void AddAppendInsertFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
#if 0
        std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);

        if (!table || !table->Persist())
            return;

        tsStringBase primaryKeys;

        for (const std::shared_ptr<Index>& idx : cntr->Indexes())
        {
            if (idx->IndexType() == "primary")
            {
                for (const std::shared_ptr<TableColumn>& c : idx->Columns())
                {
                    if (!primaryKeys.empty())
                        primaryKeys << ",";
                    primaryKeys << c->Name();
                }
            }
        }

        header << "    static bool AppendInsertScripts(TSDatabase* sourceData, TSDatabase* destFormatter, uint32_t pageSize, tscrypto::IStringWriter* appender, DSErrorList &errorList);\r\n";
        source << "bool " + classname + "::AppendInsertScripts(TSDatabase* sourceData, TSDatabase* destFormatter, uint32_t pageSize, tscrypto::IStringWriter* appender, DSErrorList &errorList)\r\n{\r\n";
        source << "    std::vector<" << classname << "> list;\r\n";
        source << "    int32_t count, itemCount = 0;\r\n";
        source << "    \r\n";
        source << "    if (sourceData == nullptr || destFormatter == nullptr || appender == nullptr)\r\n";
        source << "    {\r\n";
        source << "        errorList.Add(DSError(\"" << classname << "\", \"AppendInsertScripts\", IDS_E_GENERAL_ERROR, \"Invalid parameters\"));\r\n";
        source << "        return false;\r\n";
        source << "    }\r\n";
        source << "    if (!CountAll(sourceData, count, errorList))\r\n";
        source << "    {\r\n";
        source << "        return false;\r\n";
        source << "    }\r\n";
        source << "    if (count == 0)\r\n";
        source << "        return true;\r\n";
        source << "    if (pageSize == 0 && count > 100)\r\n";
        source << "        pageSize = 100;\r\n";
        source << "    while (itemCount < count)\r\n";
        source << "    {\r\n";
        source << "        bool first = true;\r\n";
        source << "    \r\n";
        source << "        if (!LoadAll(sourceData, list, errorList, pageSize, itemCount / pageSize, \"" << primaryKeys << "\"))\r\n";
        source << "            return false;\r\n";
        source << "        if (list.size() == 0)\r\n";
        source << "            return true;\r\n";
        source << "        if (!appender->WriteString(destFormatter->fixUpSQL(list[0].buildInsertPrefixSql(destFormatter), errorList)))\r\n";
        source << "        {\r\n";
        source << "            errorList.Add(DSError(\"" << classname << "\", \"AppendInsertScripts\", IDS_E_GENERAL_ERROR, \"Unable to save the data\"));\r\n";
        source << "            return false;\r\n";
        source << "        }\r\n";
        source << "        for (" << classname << "& data : list)\r\n";
        source << "        {\r\n";
        source << "            if (first)\r\n";
        source << "            {\r\n";
        source << "                if (!appender->WriteString(\"\\r\\n    \"))\r\n";
        source << "                {\r\n";
        source << "                    errorList.Add(DSError(\"" << classname << "\", \"AppendInsertScripts\", IDS_E_GENERAL_ERROR, \"Unable to save the data\"));\r\n";
        source << "                    return false;\r\n";
        source << "                }\r\n";
        source << "                first = false;\r\n";
        source << "            }\r\n";
        source << "            else\r\n";
        source << "            {\r\n";
        source << "                if (!appender->WriteString(\",\\r\\n    \"))\r\n";
        source << "                {\r\n";
        source << "                    errorList.Add(DSError(\"" << classname << "\", \"AppendInsertScripts\", IDS_E_GENERAL_ERROR, \"Unable to save the data\"));\r\n";
        source << "                    return false;\r\n";
        source << "                }\r\n";
        source << "            }\r\n";
        source << "            if (!appender->WriteString(data.buildValuesSql(destFormatter)))\r\n";
        source << "            {\r\n";
        source << "                errorList.Add(DSError(\"" << classname << "\", \"AppendInsertScripts\", IDS_E_GENERAL_ERROR, \"Unable to save the data\"));\r\n";
        source << "                return false;\r\n";
        source << "            }\r\n";
        source << "        }\r\n";
        source << "        appender->WriteString(\";\\r\\n\");\r\n";
        source << "        itemCount += (int)list.size();\r\n";
        source << "    }\r\n";
        source << "    return true;\r\n";
        source << "}\r\n\r\n";
#endif
    }
    void AddModifiedFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
#if 0
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
#endif
    }
    void AddPrimaryKeyModifiedFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
#if 0
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
#endif
    }
    void AddAccessors(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
#if 0
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
#endif
    }
    void AddManyToOneFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Relation> rel, const tsStringBase& name, const tsStringBase& classname)
    {
#if 0
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
#endif
    }
    void AddOneToOneDestFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Relation> rel, const tsStringBase& name, const tsStringBase& classname)
    {
#if 0
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
#endif
    }
    void AddOneToManyFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Relation> rel, const tsStringBase& name, const tsStringBase& classname)
    {
#if 0
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
#endif
    }
    void AddOneToOneSourceFunction(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, std::shared_ptr<Relation> rel, const tsStringBase& name, const tsStringBase& classname)
    {
#if 0
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
#endif
    }
    void AddBulkDataSupport(tsStringBase& header, tsStringBase& source, std::shared_ptr<ColumnContainer> cntr, const tsStringBase& name, const tsStringBase& classname)
    {
#if 0
        std::shared_ptr<Table> table = std::dynamic_pointer_cast<Table>(cntr);

        if (!!table && table->Persist())
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


            header << "    tscrypto::tsCryptoString buildInsertPrefixSql(TSDatabase* db);\r\n";
            source << "tscrypto::tsCryptoString " + classname + "::buildInsertPrefixSql(TSDatabase* db)\r\n{\r\n";
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
            source << ") VALUES ";
            source << "\";\r\n    return sql;\r\n}\r\n";

            header << "    tscrypto::tsCryptoString buildValuesSql(TSDatabase* db);\r\n";
            source << "tscrypto::tsCryptoString " + classname + "::buildValuesSql(TSDatabase* db)\r\n{\r\n";
            source << "    tscrypto::tsCryptoString sql;\r\n    sql << \"(";

            source << nonNullableValues << ")\";\r\n";
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
#endif
    }
    void AddSchemaExporter(tsStringBase& header, tsStringBase& source)
    {
#if 0
        std::vector<std::shared_ptr<Table> > tableList = Schema()->AllTables();
        tsStringBase tmp;

        if (Schema()->LoaderName().empty())
            return;

        header << "class " << Schema()->ExportSymbol() << " Export" << gPrefix << "Data {\r\n";
        header << "public:\r\n";
        header << "    Export" << gPrefix << "Data() = delete;\r\n";
        header << "    ~Export" << gPrefix << "Data() = delete;\r\n";
        header << "    Export" << gPrefix << "Data(const Export" << gPrefix << "Data &obj) = delete;\r\n";
        header << "    Export" << gPrefix << "Data &operator=(const Export" << gPrefix << "Data &obj) = delete;\r\n";
        header << "\r\n";
        header << "    static bool appendDropTables(std::shared_ptr<tsmod::IServiceLocator> locator, TSDatabase* sourceData, TSDatabase* destFormatter, tscrypto::IStringWriter* appender, DSErrorList &errorList);\r\n";
        header << "    static bool appendCreateTables(std::shared_ptr<tsmod::IServiceLocator> locator, TSDatabase* sourceData, TSDatabase* destFormatter, tscrypto::IStringWriter* appender, DSErrorList &errorList);\r\n";
        header << "    static bool appendData(std::shared_ptr<tsmod::IServiceLocator> locator, TSDatabase* sourceData, TSDatabase* destFormatter, tscrypto::IStringWriter* appender, DSErrorList &errorList);\r\n";
        header << "    static bool appendCreateKeys(std::shared_ptr<tsmod::IServiceLocator> locator, TSDatabase* sourceData, TSDatabase* destFormatter, tscrypto::IStringWriter* appender, DSErrorList &errorList);\r\n";
        header << "    static bool LoadScript(std::shared_ptr<tsmod::IServiceLocator> locator, const tscrypto::tsCryptoString& _scriptName, tscrypto::tsCryptoString &sql, TS_SchemaPartType part, DSErrorList &errorList);\r\n";
        header << "};\r\n";


        source << "bool Export" << gPrefix << "Data::appendDropTables(std::shared_ptr<tsmod::IServiceLocator> locator, TSDatabase* sourceData, TSDatabase* destFormatter, tscrypto::IStringWriter* appender, DSErrorList &errorList)\r\n";
        source << "{\r\n";
        source << "    tscrypto::tsCryptoString sql;\r\n";
        source << "    tscrypto::tsCryptoString dbType;\r\n";
        source << "    tscrypto::tsCryptoString szSchema;\r\n";
        source << "\r\n";
        source << "    dbType = destFormatter->DBType();\r\n";
        source << "    szSchema = \"" << gPrefix << "\" + dbType + \".sql\";\r\n";
        source << "    szSchema.ToLower();\r\n";
        source << "\r\n";
        source << "    if (!LoadScript(locator, szSchema, sql, ts_DropPart, errorList))\r\n";
        source << "        return false;\r\n";
        source << "    return appender->WriteString(sql);\r\n";
        source << "}\r\n";
        source << "bool Export" << gPrefix << "Data::appendCreateTables(std::shared_ptr<tsmod::IServiceLocator> locator, TSDatabase* sourceData, TSDatabase* destFormatter, tscrypto::IStringWriter* appender, DSErrorList &errorList)\r\n";
        source << "{\r\n";
        source << "    tscrypto::tsCryptoString sql;\r\n";
        source << "    tscrypto::tsCryptoString dbType;\r\n";
        source << "    tscrypto::tsCryptoString szSchema;\r\n";
        source << "\r\n";
        source << "    dbType = destFormatter->DBType();\r\n";
        source << "    szSchema = \"" << gPrefix << "\" + dbType + \".sql\";\r\n";
        source << "    szSchema.ToLower();\r\n";
        source << "\r\n";
        source << "    if (!LoadScript(locator, szSchema, sql, ts_CreateTablePart, errorList))\r\n";
        source << "        return false;\r\n";
        source << "    return appender->WriteString(sql);\r\n";
        source << "}\r\n";
        source << "bool Export" << gPrefix << "Data::appendData(std::shared_ptr<tsmod::IServiceLocator> locator, TSDatabase* sourceData, TSDatabase* destFormatter, tscrypto::IStringWriter* appender, DSErrorList &errorList)\r\n";
        source << "{\r\n";
        source << "    if (!appender->WriteString(destFormatter->startTransactionSql()))\r\n";
        source << "    {\r\n";
        source << "        errorList.Add(DSError(\"Export" << gPrefix << "Data\", \"appendData\", IDS_E_GENERAL_ERROR, \"Unable to write the export script.\"));\r\n";
        source << "        return false;\r\n";
        source << "    }\r\n";

        for (std::shared_ptr<Table> tbl : tableList)
        {
            if (tbl->Persist())
            {
                if (!tmp.empty())
                {
                    tmp << " ||\r\n        ";
                }
                else
                    tmp << "    if (";
                tmp << "!" << tbl->Name() << "Data::AppendInsertScripts(sourceData, destFormatter, 100, appender, errorList)";
            }
        }
        tmp << ")\r\n    {\r\n        return false;\r\n    }\r\n";
        source << tmp;
        source << "    if (!appender->WriteString(destFormatter->commitTransactionSql()))\r\n";
        source << "    {\r\n";
        source << "        errorList.Add(DSError(\"Export" << gPrefix << "Data\", \"appendData\", IDS_E_GENERAL_ERROR, \"Unable to write the export script.\"));\r\n";
        source << "        return false;\r\n";
        source << "    }\r\n";
        source << "    return true;\r\n";

        source << "}\r\n";
        source << "bool Export" << gPrefix << "Data::appendCreateKeys(std::shared_ptr<tsmod::IServiceLocator> locator, TSDatabase* sourceData, TSDatabase* destFormatter, tscrypto::IStringWriter* appender, DSErrorList &errorList)\r\n";
        source << "{\r\n";
        source << "    tscrypto::tsCryptoString sql;\r\n";
        source << "    tscrypto::tsCryptoString dbType;\r\n";
        source << "    tscrypto::tsCryptoString szSchema;\r\n";
        source << "\r\n";
        source << "    dbType = destFormatter->DBType();\r\n";
        source << "    szSchema = \"" << gPrefix << "\" + dbType + \".sql\";\r\n";
        source << "    szSchema.ToLower();\r\n";
        source << "\r\n";
        source << "    if (!LoadScript(locator, szSchema, sql, ts_AddKeysPart, errorList))\r\n";
        source << "        return false;\r\n";
        source << "    return appender->WriteString(sql);\r\n";
        source << "}\r\n";
        source << "bool Export" << gPrefix << "Data::LoadScript(std::shared_ptr<tsmod::IServiceLocator> locator, const tscrypto::tsCryptoString& _scriptName, tscrypto::tsCryptoString &sql, TS_SchemaPartType part, DSErrorList &errorList)\r\n";
        source << "{\r\n";
        source << "    tscrypto::tsCryptoString tmp;\r\n";
        source << "    tscrypto::tsCryptoString scriptName(_scriptName);\r\n";
        source << "\r\n";
        source << "    switch (part)\r\n";
        source << "    {\r\n";
        source << "    case ts_AllParts:\r\n";
        source << "        break;\r\n";
        source << "    case ts_DropPart:\r\n";
        source << "        scriptName.Replace(\".sql\", \"_dr.sql\");\r\n";
        source << "        break;\r\n";
        source << "    case ts_CreateTablePart:\r\n";
        source << "        scriptName.Replace(\".sql\", \"_ct.sql\");\r\n";
        source << "        break;\r\n";
        source << "    case ts_AddKeysPart:\r\n";
        source << "        scriptName.Replace(\".sql\", \"_ak.sql\");\r\n";
        source << "        break;\r\n";
        source << "    case ts_AddDataPart:\r\n";
        source << "        scriptName.Replace(\".sql\", \"_ad.sql\");\r\n";
        source << "        break;\r\n";
        source << "    }\r\n";
        source << "\r\n";
        source << "    tmp = \"we were unable to load the script called '\";\r\n";
        source << "    tmp += scriptName;\r\n";
        source << "    tmp += \"'\";\r\n";
        source << "\r\n";
        source << "    std::shared_ptr<tsmod::IResourceLoader> loader = locator->try_get_instance<tsmod::IResourceLoader>(\"" << Schema()->LoaderName() << "\");\r\n";
        source << "    if (!loader || !loader->IsValid())\r\n";
        source << "    {\r\n";
        source << "        errorList.Add(DSError(\"Export" << gPrefix << "Data\", \"LoadScript\", IDS_E_CANT_UPGRADE, tmp.c_str()));\r\n";
        source << "        return false;\r\n";
        source << "    }\r\n";
        source << "    sql = loader->LoadResource(scriptName.c_str()).ToUtf8String();\r\n";
        source << "    if (sql.size() == 0)\r\n";
        source << "    {\r\n";
        source << "        errorList.Add(DSError(\"Export" << gPrefix << "Data\", \"LoadScript\", IDS_E_CANT_UPGRADE, tmp.c_str()));\r\n";
        source << "        return false;\r\n";
        source << "    }\r\n";
        source << "    return true;\r\n";
        source << "}\r\n";
#endif
            }
};

#endif // __CHELPER_H__
