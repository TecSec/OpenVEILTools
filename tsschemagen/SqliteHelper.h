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

#ifndef __SQLITEHELPER_H__
#define __SQLITEHELPER_H__

#pragma once

//#define TRIGGERS_FOR_FOREIGN_KEYS

class SqliteHelper : public SQLHelper
{
public:
	SqliteHelper()
	{
	}
	virtual ~SqliteHelper()
	{
	}
	virtual tsStringBase ResolveTypeToDatabase(const tsStringBase& _typeName, int length) override
	{
		tsStringBase typeName(_typeName);

		typeName.ToLower();
		if (typeName == "system.datetime")
			return "DATE";
		if (typeName == "system.string" || typeName == "system.guid")
			return "TEXT collate nocase";
		if (typeName == "system.boolean")
			return "BOOLEAN";
		if (typeName == "system.int32" || typeName == "system.long")
			return "INTEGER";
		if (typeName == "system.int64")
			return "INT8";
		if (typeName == "system.double")
			return "REAL";
		if (typeName == "autoincrement")
			return "INTEGER";
		return "TEXT collate nocase";
	}

	virtual tsStringBase BuildSchema(const tsStringBase& schemaFile, SchemaPartType schemaPart) override
	{
		tsStringBase sql = "";
		tsStringBase name;
		tsStringBase sourceList;
		tsStringBase destList;
		//tsStringBase deleteDestList;
		std::vector<std::shared_ptr<Table> > tableList;

		LoadSchemaInfo(schemaFile);

		tableList = Schema()->PersistedTables();

		if (tableList.size() < 1)
			throw std::runtime_error("Unable to locate schema information for the database tables");

        sql += "-- Generated file\n";

        if (schemaPart == AllParts || schemaPart == CreateTablePart)
        {
            sql += "PRAGMA foreign_keys = true;\r\n";
        }
		sql += "BEGIN;\r\n";

		if (schemaPart == AllParts || schemaPart == DropPart)
		{
		std::for_each(tableList.begin(), tableList.end(), [&sql, this](std::shared_ptr<Table> t_node) {
			tsStringBase name = t_node->Name();
			sql += "DROP TABLE IF EXISTS " + name + ";\r\n";
		});

		sql += "\r\n";
		}

		std::for_each(tableList.begin(), tableList.end(), [&sql, this, schemaPart](std::shared_ptr<Table> t_node) {
			if (schemaPart == AllParts || schemaPart == CreateTablePart)
			BuildSQLiteCreateTable(sql, t_node);
			if (schemaPart == AllParts || schemaPart == AddKeysPart)
			BuildSQLiteCreateTableIndices(sql, t_node);
			if (schemaPart == AllParts || schemaPart == CreateTablePart || schemaPart == AddKeysPart)
			sql += "\r\n";
		});
		//
		// Now it is time to create the relationships
		//
#if TRIGGERS_FOR_FOREIGN_KEYS
		foreach(Relation r_node in Schema.PersistedRelations)
		{
			sourceList = "";
			destList = "";
			deleteDestList = "";
			string firstDest = "";
			string firstSrc = "";
			string relationName;
			if (string.IsNullOrEmpty(r_node.Name))
			{
				relationName = "FK_" + r_node.Destination.Name + "_" + r_node.Source.Name;
			}
			else
			{
				relationName = r_node.Name;
			}

			if (r_node.SourceColumns.Count == 1 && r_node.DestinationColumns[0].Nullable)
			{
				sql += "CREATE TRIGGER " + relationName + "Insert BEFORE INSERT ON " + r_node.Destination.Name + " FOR EACH ROW BEGIN\r\n";
				sql += "    SELECT RAISE(ROLLBACK, 'insert on table \"" + r_node.Destination.Name + "\" violates foreign key constraint \"" + relationName + "\"')\r\n";
				sql += "    WHERE  NEW." + r_node.DestinationColumns[0].Name + " IS NOT NULL AND ((SELECT " + r_node.SourceColumns[0].Name + " FROM " + r_node.Source.Name +
					" WHERE " + r_node.SourceColumns[0].Name + " = NEW." + r_node.DestinationColumns[0].Name + " ) IS NULL);\r\n";
				sql += "END;\r\n";

				sql += "CREATE TRIGGER " + relationName + "Update BEFORE UPDATE ON " + r_node.Destination.Name + " FOR EACH ROW BEGIN\r\n";
				sql += "    SELECT RAISE(ROLLBACK, 'update on table \"" + r_node.Destination.Name + "\" violates foreign key constraint \"" + relationName + "\"')\r\n";
				sql += "    WHERE  NEW." + r_node.DestinationColumns[0].Name + " IS NOT NULL AND ((SELECT " + r_node.SourceColumns[0].Name + " FROM " + r_node.Source.Name +
					" WHERE " + r_node.SourceColumns[0].Name + " = NEW." + r_node.DestinationColumns[0].Name + " ) IS NULL);\r\n";
				sql += "END;\r\n";

				sql += "CREATE TRIGGER " + relationName + "Delete BEFORE DELETE ON " + r_node.Source.Name + " FOR EACH ROW BEGIN\r\n";
				sql += "    SELECT RAISE(ROLLBACK, 'delete on table \"" + r_node.Source.Name + "\" violates foreign key constraint \"" + relationName + "\"')\r\n";
				sql += "    WHERE  " + r_node.DestinationColumns[0].Name + " IS NOT NULL AND ((SELECT " + r_node.DestinationColumns[0].Name + " FROM " + r_node.Destination.Name +
					" WHERE " + r_node.DestinationColumns[0].Name + " = OLD." + r_node.SourceColumns[0].Name + " ) IS NULL);\r\n";
				sql += "END;\r\n";

			}
			else
			{
				for (int i = 0; i < r_node.SourceColumns.Count; i++)
				{
					if (sourceList.Length > 0)
					{
						sourceList += " AND ";
						destList += " AND ";
						deleteDestList += " AND ";
					}
					else
					{
						firstDest = r_node.DestinationColumns[i].Name;
						firstSrc = r_node.SourceColumns[i].Name;
					}
					if (r_node.DestinationColumns[i].Nullable)
					{
						sourceList += r_node.SourceColumns[i].Name + " = NEW." + r_node.DestinationColumns[i].Name;
					}
					else
					{
						sourceList += r_node.SourceColumns[i].Name + " = NEW." + r_node.DestinationColumns[i].Name;
					}
					destList += r_node.DestinationColumns[i].Name + " = NEW." + r_node.SourceColumns[i].Name;
					deleteDestList += r_node.DestinationColumns[i].Name + " = OLD." + r_node.SourceColumns[i].Name;
				}
				if (sourceList.Length > 0)
				{
					sql += "CREATE TRIGGER " + relationName + "Insert BEFORE INSERT ON " + r_node.Destination.Name + " FOR EACH ROW BEGIN\r\n";
					sql += "    SELECT RAISE(ROLLBACK, 'insert on table \"" + r_node.Destination.Name + "\" violates foreign key constraint \"" + relationName + "\"')\r\n";
					sql += "    WHERE  (SELECT " + firstSrc + " FROM " + r_node.Source.Name + " WHERE " + sourceList + ") IS NULL;\r\n";
					sql += "END;\r\n";

					sql += "CREATE TRIGGER " + relationName + "Update BEFORE UPDATE ON " + r_node.Destination.Name + " FOR EACH ROW BEGIN\r\n";
					sql += "    SELECT RAISE(ROLLBACK, 'update on table \"" + r_node.Destination.Name + "\" violates foreign key constraint \"" + relationName + "\"')\r\n";
					sql += "    WHERE  (SELECT " + firstSrc + " FROM " + r_node.Source.Name + " WHERE " + sourceList + ") IS NULL;\r\n";
					sql += "END;\r\n";

					sql += "CREATE TRIGGER " + relationName + "Delete BEFORE DELETE ON " + r_node.Source.Name + " FOR EACH ROW BEGIN\r\n";
					sql += "    SELECT RAISE(ROLLBACK, 'delete on table \"" + r_node.Source.Name + "\" violates foreign key constraint \"" + relationName + "\"')\r\n";
					sql += "    WHERE  (SELECT " + firstDest + " FROM " + r_node.Destination.Name + " WHERE " + deleteDestList + ") IS NULL;\r\n";
					sql += "END;\r\n";
				}
			}
		}
#endif
		if (schemaPart == AllParts || schemaPart == CreateTablePart)
		{
		//
		// Now it is time to create the views
		//
		std::vector<std::shared_ptr<View> > viewList = Schema()->PersistedViews();;

		std::for_each(viewList.begin(), viewList.end(), [&sql, this](std::shared_ptr<View> v_node) {
			std::vector<std::shared_ptr<DatabaseView> > dbViewList = v_node->DatabaseViews();

			std::for_each(dbViewList.begin(), dbViewList.end(), [&sql, this](std::shared_ptr<DatabaseView> vc_node) {
				if (vc_node->dbName().ToLower() == "sqliteview")
				{
					sql += vc_node->Code();
					//
					// Insert a command separator to support limitations in ADO
					//
						//sql += "\r\n<<<<BREAK>>>>\r\n\r\n";
						sql += "\r\n";
				}
			});
		});
		}
		if (schemaPart == AllParts || schemaPart == AddDataPart)
		{
		//
		// Now it is time to load data into the tables
		//
		std::vector<std::shared_ptr<DataRow> > rowList = Schema()->AllDataRows();

		std::for_each(rowList.begin(), rowList.end(), [&sql, this, &sourceList, &destList](std::shared_ptr<DataRow> r_node) {
			sourceList = "";
			destList = "";
			sql += "INSERT INTO " + r_node->Table()->Name() + " (";
			const tsAttributeMap& map = r_node->Values();
				map.foreach([&sourceList, &destList, this](const char* name, const char* value) {
				if (sourceList.size() > 0)
				{
					sourceList += ", ";
					destList += ", ";
				}
					sourceList += name;
					destList += StringToSQL(value);
			});
			sql += sourceList + ") VALUES (" + destList + ");\r\n";
		});
		}
		sql += "COMMIT;\r\n";
		return sql;
	}

protected:
	virtual tsStringBase FieldStart() const override
	{
		return "";
	}
	virtual tsStringBase FieldEnd() const override
	{
		return "";
	}
	virtual tsStringBase TableStart() const override
	{
		return "";
	}
	virtual tsStringBase TableEnd() const override
	{
		return "";
	}
	virtual tsStringBase StatementTerminator() const override
	{
		return ";";
	}
	int getColumnSize(std::shared_ptr<tsXmlNode> node)
	{
		return node->Attributes().itemAsNumber("Length", 0);
	}


private:
	tsStringBase BuildForeignKeyName(std::shared_ptr<Relation> r_node)
	{
		tsStringBase name = "";
		try
		{
			name = r_node->Name();
		}
		catch (...)
		{
			name = "";
		}
		if (name.size() > 0)
			return name;
		return "FK_" + r_node->Destination()->Name() + "_" + r_node->Source()->Name();
	}

	void BuildSQLiteCreateTable(tsStringBase& sql, std::shared_ptr<Table> t_node)
	{
		int colCount = 0;
		tsStringBase name;
		int length;
		tsStringBase type;
		tsStringBase primaryKey;

		name = t_node->Name();
		sql += "CREATE TABLE " + name + " (\r\n";
		colCount = 0;

		std::vector<std::shared_ptr<TableColumn> > cols = t_node->Columns();

		std::for_each(cols.begin(), cols.end(), [&colCount, &sql, &type, &length, this](std::shared_ptr<TableColumn> node) {
			if (node->Table().size() == 0)
			{
				if (colCount > 0)
					sql += "  , ";
				else
					sql += "    ";
				sql += node->Name() + " ";
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

		std::for_each(idxList.begin(), idxList.end(), [&sql, this, &primaryKey](std::shared_ptr<Index> p_node) {
			std::vector<std::shared_ptr<TableColumn> > cols = p_node->Columns();

			std::for_each(cols.begin(), cols.end(), [&primaryKey, &sql, this](std::shared_ptr<TableColumn> f_node) {
				if (primaryKey.size() > 0)
					primaryKey += ", ";
				primaryKey += f_node->Name();
			});
		});
		if (primaryKey.size() > 0)
		{
			if (colCount > 0)
			{
				sql += "  , PRIMARY KEY (" + primaryKey + ")\r\n";
			}
		}

		//
		// Now it is time to create the relationships
		//
		std::vector<std::shared_ptr<Relation> > relationList = Schema()->PersistedRelations();

		std::for_each(relationList.begin(), relationList.end(), [&sql, this, &name](std::shared_ptr<Relation> r_node) {
			tsStringBase sourceList = "";
			tsStringBase destList = "";
			if (r_node->Destination()->Name() == name)
			{
				const std::vector<std::shared_ptr<TableColumn> > SourceCols = r_node->SourceColumns();
				const std::vector<std::shared_ptr<TableColumn> > DestCols = r_node->DestinationColumns();

				for (int i = 0; i < (int)SourceCols.size(); i++)
				{
					if (sourceList.size() > 0)
					{
						sourceList += ",\r\n    ";
						destList += ",\r\n    ";
					}
					sourceList += FieldStart() + SourceCols[i]->Name() + FieldEnd();
					destList += FieldStart() + DestCols[i]->Name() + FieldEnd();
				}
				if (sourceList.size() > 0)
				{
					sql += "    , FOREIGN KEY (" + TableStart() + destList + TableEnd() + ") REFERENCES " + TableStart() + r_node->Source()->Name() + TableEnd() + "(" + sourceList + ")";
				}
			}
		});


		sql += ");\r\n";
	}
	void BuildSQLiteCreateTableIndices(tsStringBase& sql, std::shared_ptr<Table> t_node)
	{
		tsStringBase tablename;
		tsStringBase name;
		tsStringBase columns;
		tsStringBase unique;

		tablename = t_node->Name();
		std::vector<std::shared_ptr<Index> > idxList = t_node->NonPrimaryKeys();

		std::for_each(idxList.begin(), idxList.end(), [&sql, this, &name, &unique, &columns, &tablename](std::shared_ptr<Index> i_node) {
			if (i_node->IndexType().ToLower() == "temporary")
				return;
			name = i_node->Name();
			if (i_node->UniqueKey())
				unique = "UNIQUE ";
			else
				unique = "";

			columns = "";
			std::vector<std::shared_ptr<TableColumn> > cols = i_node->Columns();

			std::for_each(cols.begin(), cols.end(), [&sql, this, &columns](std::shared_ptr<TableColumn> f_node) {
				if (columns.size() > 0)
					columns += ", ";
				columns += f_node->Name();
			});
			if (columns.size() > 0)
			{
				sql += "CREATE " + unique + "INDEX IF NOT EXISTS " + name + " ON " + tablename + " (" + columns + ");\r\n";
			}
		});
	}
};

#endif // __SQLITEHELPER_H__
