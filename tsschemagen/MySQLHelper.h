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

#ifndef __MYSQLHELPER_H__
#define __MYSQLHELPER_H__

#pragma once

class MySqlHelper : public SQLHelper
{
public:
	MySqlHelper()
	{
	}
	virtual ~MySqlHelper()
	{
	}
	virtual tsStringBase ResolveTypeToDatabase(const tsStringBase& typeName, int length) override
	{
		tsStringBase tmp;

		if (typeName == "System.String" || typeName == "System.Char[]")
			tmp << "varchar(" << length << ")";
		else if (typeName == "System.Guid")
			return "char(36)";
		else if (typeName == "System.Boolean")
			return "tinyint(1)";
		else if (typeName == "System.Int32" || typeName == "System.Int16")
			return "int";
		else if (typeName == "System.DateTime")
			return "datetime";
		else if (typeName == "System.Double")
			return "decimal(18, 2)";
		else
			return "varchar(1)";
		return tmp;
	}
	virtual tsStringBase BuildSchema(const tsStringBase& schemaFile, SchemaPartType schemaPart) override
	{
		tsStringBase sql = "";
		tsStringBase name;
		int length;
		tsStringBase type;
		tsStringBase primaryKey;
		tsStringBase sourceList;
		tsStringBase destList;
		tsStringBase uid = "[[UID]]";
		tsStringBase pwd = "[[PWD]]";
		std::vector<std::shared_ptr<Table> > tableList;

		LoadSchemaInfo(schemaFile);

		tableList = Schema()->PersistedTables();
		if (tableList.size() < 1)
			throw std::runtime_error("Unable to locate schema information for the database tables");

        sql += "-- Generated file\n";

		if (schemaPart == AllParts || schemaPart == DropPart)
		{
			sql += "CREATE DATABASE IF NOT EXISTS [[DATABASE]];\r\n";
			sql += "USE [[DATABASE]];\r\n\r\n";

			std::for_each(tableList.begin(), tableList.end(), [this, &sql, &name](std::shared_ptr<Table> t_node) {
			name = t_node->Name();
			sql += "DROP TABLE IF EXISTS `" + name + "`;\r\n";
		});
		sql += "\r\n\r\n";
		}

		if (schemaPart == AllParts || schemaPart == CreateTablePart)
		{
			if (schemaPart == CreateTablePart)
			{
				sql += "CREATE DATABASE IF NOT EXISTS [[DATABASE]];\r\n";
				sql += "USE [[DATABASE]];\r\n\r\n";
			}
			std::for_each(tableList.begin(), tableList.end(), [this, &sql, &name, &type, &length, &primaryKey](std::shared_ptr<Table> t_node) {
			int colCount = 0;

			name = t_node->Name();
			sql += "CREATE TABLE `" + name + "` (\r\n";
			colCount = 0;
			
			std::vector<std::shared_ptr<TableColumn> > colList = t_node->Columns();

				std::for_each(colList.begin(), colList.end(), [this, &sql, &name, &colCount, &type, &length](std::shared_ptr<TableColumn> node) {
				if (node->Table().size() == 0)
				{
					if (colCount > 0)
						sql += "  , ";
					else
						sql += "    ";
					sql += "`" + node->Name() + "` ";
					type = node->FieldType();
					length = node->FieldLength();
					sql += ResolveTypeToDatabase(type, length);
					if (!node->Nullable())
						sql += " NOT";
					sql += " NULL\r\n";
					colCount++;
				}
			});

			primaryKey = "";
			std::vector<std::shared_ptr<Index> > idxList = t_node->PrimaryKeys();

				std::for_each(idxList.begin(), idxList.end(), [this, &sql, &name, &primaryKey](std::shared_ptr<Index> p_node) {
				if (primaryKey.size() > 0)
					primaryKey += ", ";
				primaryKey += "`" + p_node->Name() + "` ";
			});

			if (primaryKey.size() > 0)
			{
				if (colCount > 0)
				{
					sql += "  , PRIMARY KEY (" + primaryKey + ")\r\n";
				}
			}

			idxList = t_node->NonPrimaryKeys();

				std::for_each(idxList.begin(), idxList.end(), [this, &sql, &name, &primaryKey, &colCount](std::shared_ptr<Index> i_node) {
				if (i_node->IndexType().ToLower() == "temporary")
					return;
				name = i_node->Name();

				primaryKey = "";

				std::vector<std::shared_ptr<TableColumn> > colList = i_node->Columns();

					std::for_each(colList.begin(), colList.end(), [this, &sql, &name, &primaryKey](std::shared_ptr<TableColumn> f_node) {
					if (primaryKey.size() > 0)
						primaryKey += ", ";
					primaryKey += "`" + f_node->Name() + "` ";
				});
				if (primaryKey.size() > 0)
				{
					if (colCount > 0)
					{
						sql += "  , INDEX (" + primaryKey + ")\r\n";
					}
				}
			});

			sql += ") TYPE=InnoDB;\r\n\r\n";
		});
		}

		//
		// Now it is time to create the relationships
		//
		std::vector<std::shared_ptr<Relation> > idxList = Schema()->PersistedRelations();

		if (schemaPart == AllParts || schemaPart == AddKeysPart)
		{
			std::for_each(idxList.begin(), idxList.end(), [this, &sql, &sourceList, &destList](std::shared_ptr<Relation> r_node) {
			sourceList = "";
			destList = "";

			const std::vector<std::shared_ptr<TableColumn> > SourceCols = r_node->SourceColumns();
			const std::vector<std::shared_ptr<TableColumn> > DestCols = r_node->DestinationColumns();

			for (int i = 0; i < (int)SourceCols.size(); i++)
			{
				if (sourceList.size() > 0)
				{
					sourceList += ", ";
					destList += ", ";
				}
				sourceList += "`" + SourceCols[i]->Name() + "`";
				destList += "`" + DestCols[i]->Name() + "`";
			}
			if (sourceList.size() > 0)
			{
				sql += "ALTER TABLE `" + r_node->Destination()->Name() + "` ADD FOREIGN KEY\r\n";
				sql += "  FK_" + r_node->Destination()->Name() + "_" + r_node->Source()->Name() + "\r\n";
				sql += "  ( " + destList + ")\r\n";
				sql += "  REFERENCES `" + r_node->Source()->Name() + "`\r\n";
				sql += "  ( " + sourceList + ")\r\n";
				sql += "  ON DELETE RESTRICT ON UPDATE RESTRICT;\r\n\r\n";
			}
		});
		}
		//
		// Now it is time to load data into the tables
		//
		std::vector<std::shared_ptr<DataRow> > rowList = Schema()->AllDataRows();

		if (schemaPart == AllParts || schemaPart == AddDataPart)
		{
			std::for_each(rowList.begin(), rowList.end(), [&sql, this, &sourceList, &destList](std::shared_ptr<DataRow> r_node) {
			sourceList = "";
			destList = "";
			sql += "INSERT INTO " + TableStart() + r_node->Table()->Name() + TableEnd() + "(";

			const tsAttributeMap& map = r_node->Values();
				map.foreach([&sourceList, &destList, this](const char* name, const char* value) {
				if (sourceList.size() > 0)
				{
					sourceList += ", ";
					destList += ", ";
				}
					sourceList += FieldStart() + name + FieldEnd();
					destList += StringToSQL(value);
			});

			sql += sourceList + ") VALUES (" + destList + ");\r\n";
			//					sql += "<<<<BREAK>>>>\r\n";
		});
		}

		if (schemaPart == AllParts || schemaPart == AddKeysPart)
		{
		sql += "GRANT ALL PRIVILEGES ON [[DATABASE]].* TO " + uid + "@localhost IDENTIFIED BY '" + pwd + "';\r\n";
		sql += "GRANT ALL PRIVILEGES ON [[DATABASE]].* TO " + uid + "@'%' IDENTIFIED BY '" + pwd + "';\r\n";
		}
		return sql;
	}

protected:
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
		if (node->Attributes().item("Type") == "System.Guid")
			return 36;
		else
			return node->Attributes().itemAsNumber("Length", 0);
	}
};

#endif // __MYSQLHELPER_H__
