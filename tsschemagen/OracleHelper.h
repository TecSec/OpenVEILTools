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

#ifndef __ORACLEHELPER_H__
#define __ORACLEHELPER_H__

#pragma once

class OracleHelper : public SQLHelper
{
public:
	OracleHelper()
	{
	}
	virtual ~OracleHelper()
	{
	}
	virtual tsStringBase ResolveTypeToDatabase(const tsStringBase& typeName, int length) override
	{
		tsStringBase tmp;

		if (typeName == "System.String")
			tmp << "varchar (" << length << ")";
		else if (typeName == "System.Char[]")
			tmp << "char (" << length << ")";
		else if (typeName == "System.Guid")
			return "char (38)";
		else if (typeName == "System.Boolean")
			return "number (1,0)";
		else if (typeName == "System.Int32")
			return "integer";
		else if (typeName == "System.Int16")
			return "smallint";
		else if (typeName == "System.DateTime")
			return "date";
		else if (typeName == "System.Double")
			return "number (18, 2)";
		else
			return "varchar (1)";
		return tmp;
	}
	virtual tsStringBase BuildSchema(const tsStringBase& schemaFile, SchemaPartType schemaPart) override
	{
		tsStringBase sql = "";
		tsStringBase name;
		int length;
		tsStringBase type;
		tsStringBase primaryKey;
		std::vector<std::shared_ptr<Relation> > nodeList;
		std::vector<std::shared_ptr<View> > viewList;
		std::vector<std::shared_ptr<Table> > tableList;
		tsStringBase sourceList;
		tsStringBase destList;

		LoadSchemaInfo(schemaFile);
		//
		// First retrieve the list of relationships from the schema file
		//
		nodeList = Schema()->PersistedRelations();
		tableList = Schema()->PersistedTables();
		viewList = Schema()->PersistedViews();

        sql += "-- Generated file\n";

		if (schemaPart == AllParts || schemaPart == DropPart)
		{
		if (nodeList.size() > 1)
		{
			//
			// And remove the foreign keys from the current database
			//
				std::for_each(nodeList.begin(), nodeList.end(), [this, &sql](std::shared_ptr<Relation> r_node) {
				tsStringBase test = BuildForeignKeyName(r_node);
				sql += "DECLARE\r\n";
				sql += "c_constraint_name varchar2(50) := upper('" + BuildForeignKeyName(r_node) + "');\r\n";
				sql += "cursor c1 is\r\n";
				sql += "select constraint_name\r\n";
				sql += "from user_constraints\r\n";
				sql += "where constraint_name = c_constraint_name;\r\n";
				sql += "BEGIN\r\n";
				sql += "open c1;\r\n";
				sql += "fetch c1 into c_constraint_name;\r\n";
				sql += "if c1%FOUND\r\n";
				sql += "then execute immediate 'ALTER TABLE " + r_node->Destination()->Name() + " DROP CONSTRAINT " + BuildForeignKeyName(r_node) + "';\r\n";
				sql += "end if;\r\n";
				sql += "close c1;\r\n";
				sql += "END;\r\n";
				sql += "<<<<BREAK>>>>\r\n";
			});
		}
		//
		// Now retrieve the view list
		//

		if (viewList.size() >= 1)			// jea: changed > to >= 
		{
			//
			// And remove the views from the current database
			//
				std::for_each(viewList.begin(), viewList.end(), [this, &sql, &name](std::shared_ptr<View> v_node) {
				name = v_node->Name();

				sql += "DECLARE\r\n";
				sql += "c_view_name varchar2(50) := upper('" + name + "');\r\n";
				sql += "cursor c1 is\r\n";
				sql += "select view_name\r\n";
				sql += "from user_views\r\n";
				sql += "where view_name = c_view_name;\r\n";
				sql += "BEGIN\r\n";
				sql += "open c1;\r\n";
				sql += "fetch c1 into c_view_name;\r\n";
				sql += "if c1%FOUND\r\n";
				sql += "then execute immediate 'DROP VIEW " + name + "';\r\n";
				sql += "end if;\r\n";
				sql += "close c1;\r\n";
				sql += "END;\r\n";
				sql += "<<<<BREAK>>>>\r\n";
			});
		}
		//
		// Now retrieve the table list
		//
		if (tableList.size() < 1)
			throw std::runtime_error("Unable to locate schema information for the database tables");
		//
		// First remove the triggers
		//
		/*
		foreach (XmlNode t_node in nodeList)
		{
		XmlNodeList trigRelList;

		name = t_node.Attributes["Name"].Value.ToString();
		try
		{
		trigRelList = SchemaData.DocumentElement.SelectNodes("Relations/Relation[@SrcTbl='" + name + "']");
		}
		catch (Exception &exc)
		{
		trigRelList = null;
		}

		if ( trigRelList != null && trigRelList.Count > 0 )
		{
		sql += "DECLARE\r\n";
		sql += "c_trigger_name varchar2(50) := upper('" + name + "');\r\n";
		sql += "cursor c1 is\r\n";
		sql += "select trigger_name\r\n";
		sql += "from user_triggers\r\n";
		sql += "where trigger_name = c_trigger_name;\r\n";
		sql += "BEGIN\r\n";
		sql += "open c1;\r\n";
		sql += "fetch c1 into c_trigger_name;\r\n";
		sql += "if c1%FOUND\r\n";
		sql += "then execute immediate 'DROP TRIGGER " + name + "';\r\n";
		sql += "end if;\r\n";
		sql += "close c1;\r\n";
		sql += "END;\r\n";
		sql += "/\r\n\r\n";
		}
		}
		*/
		//
		// And then remove the tables from the current database
		//
			std::for_each(tableList.begin(), tableList.end(), [this, &sql, &name](std::shared_ptr<Table> t_node) {
			name = t_node->Name();

			sql += "DECLARE\r\n";
			sql += "c_table_name varchar2(50) := upper('" + name + "');\r\n";
			sql += "cursor c1 is\r\n";
			sql += "select table_name\r\n";
			sql += "from user_tables\r\n";
			sql += "where table_name = c_table_name;\r\n";
			sql += "BEGIN\r\n";
			sql += "open c1;\r\n";
			sql += "fetch c1 into c_table_name;\r\n";
			sql += "if c1%FOUND\r\n";
			sql += "then execute immediate 'DROP TABLE " + name + "';\r\n";
			sql += "end if;\r\n";
			sql += "close c1;\r\n";
			sql += "END;\r\n";
			sql += "<<<<BREAK>>>>\r\n";

		});
		}

		if (schemaPart == AllParts || schemaPart == CreateTablePart)
		{
		//
		// Now create the tables
		//
			std::for_each(tableList.begin(), tableList.end(), [this, &sql, &name, &type, &length](std::shared_ptr<Table> t_node) {
			int colCount = 0;

			name = t_node->Name();
			sql += "CREATE TABLE " + TableStart() + name + TableEnd() + " (";
			colCount = 0;

			std::vector<std::shared_ptr<TableColumn> > colList = t_node->Columns();

				std::for_each(colList.begin(), colList.end(), [this, &sql, &name, &colCount, &type, &length](std::shared_ptr<TableColumn> node) {
				if (node->Table().size() == 0)
				{
					if (colCount == 0)
						sql += "\r\n  ";
					else
						sql += " ,\r\n  ";
					sql += FieldStart() + node->Name() + FieldEnd() + " ";
					type = node->FieldType();
					length = node->FieldLength();
					sql += ResolveTypeToDatabase(type, length);
					if (!node->Nullable())
						sql += " NOT";
					sql += " NULL";
					colCount++;
				}
			});
			sql += "\r\n)\r\n";
			sql += "<<<<BREAK>>>>\r\n";

		});
			//
			// Now it is time to create the views
			//
			std::for_each(viewList.begin(), viewList.end(), [this, &sql, &name](std::shared_ptr<View> v_node) {
				std::vector<std::shared_ptr<DatabaseView> > dbViewList = v_node->DatabaseViews();

				std::for_each(dbViewList.begin(), dbViewList.end(), [&sql, this](std::shared_ptr<DatabaseView> vc_node) {
					if (vc_node->dbName().ToLower() == "oracleview")
					{
						sql += vc_node->Code();
						//
						// Insert a command separator to support limitations in ADO
						//
						sql += "\r\n<<<<BREAK>>>>\r\n";
					}
				});
			});
		}

		if (schemaPart == AllParts || schemaPart == AddKeysPart)
		{
		//
		// Now create the primary keys
		//$$$
			std::for_each(tableList.begin(), tableList.end(), [this, &sql, &name, &primaryKey](std::shared_ptr<Table> t_node) {
			tsStringBase indexName;

			name = t_node->Name();

			primaryKey = "";
			std::vector<std::shared_ptr<Index> > idxList = t_node->PrimaryKeys();

				std::for_each(idxList.begin(), idxList.end(), [this, &sql, &name, &primaryKey, &indexName, &t_node](std::shared_ptr<Index> p_node) {
				indexName = p_node->Name();

				primaryKey = "";
				std::vector<std::shared_ptr<TableColumn> > colList = p_node->Columns();

					std::for_each(colList.begin(), colList.end(), [this, &sql, &name, &primaryKey](std::shared_ptr<TableColumn> f_node) {
					if (primaryKey.size() > 0)
						primaryKey += ",\r\n    ";
					else
						primaryKey += "    ";
					primaryKey += FieldStart() + f_node->Name() + FieldEnd();
				});

				if (primaryKey.size() > 0)
				{
					if (name.size() > 30)
						name = t_node->ShortName();

					tsStringBase tmpName = name;

					if (indexName.size() > 0)
					{
						if (indexName.size() > 30)
							indexName = p_node->ShortName();

						tmpName = indexName;
					}

					sql += "ALTER TABLE " + TableStart() + name + TableEnd() + " ADD\r\n";
					sql += "  CONSTRAINT " + FieldStart() + tmpName + FieldEnd() + " PRIMARY KEY\r\n";
					sql += "  (\r\n";

					sql += primaryKey + "\r\n)\r\n";
					sql += "<<<<BREAK>>>>\r\n";
				}
			});
		});

		//
		// Now create the tables
		//
			std::for_each(tableList.begin(), tableList.end(), [this, &sql, &name](std::shared_ptr<Table> t_node) {
			tsStringBase defValue;

			name = t_node->Name();
			std::vector<std::shared_ptr<TableColumn> > colList = t_node->Columns();

				std::for_each(colList.begin(), colList.end(), [this, &sql, &name, &defValue, &t_node](std::shared_ptr<TableColumn> node) {
				try
				{
					defValue = node->DefaultGenerator();
				}
				catch (...)
				{
					defValue = "";
				}
				if (defValue.size() > 0)
				{
					if (name.size() > 30)
						name = t_node->ShortName();

					tsStringBase nodeName = node->Name();

					sql += "ALTER TABLE " + TableStart() + name + TableEnd() + " ALTER \r\n";
					sql += "	COLUMN " + FieldStart() + node->Name() + FieldEnd() + " SET DEFAULT " + defValue + "\r\n";
					//							sql += "	COLUMN " + FieldStart + node.Attributes["Name"].Value.ToString() + FieldEnd + FieldStart + "DF_" + name + "_" + nodeName + FieldEnd + " SET DEFAULT (newid())" + "\r\n";
					sql += "<<<<BREAK>>>>\r\n";
				}
			});
		});
		//
		// Now create the tables
		//
			std::for_each(tableList.begin(), tableList.end(), [this, &sql, &name, &primaryKey](std::shared_ptr<Table> t_node) {
			tsStringBase indexName;

			name = t_node->Name();
			std::vector<std::shared_ptr<Index> > idxList = t_node->NonPrimaryKeys();

				std::for_each(idxList.begin(), idxList.end(), [this, &sql, &name, &indexName, &t_node, &primaryKey](std::shared_ptr<Index> i_node) {
				if (i_node->IndexType().ToLower() == "temporary")
					return;
				//$$$
				indexName = i_node->Name();

				primaryKey = "";
				std::vector<std::shared_ptr<TableColumn> > colList = i_node->Columns();

					std::for_each(colList.begin(), colList.end(), [this, &sql, &name, &primaryKey](std::shared_ptr<TableColumn> f_node) {
					if (f_node->Name().ToLower() == "indexfield")
					{
						if (primaryKey.size() > 0)
							primaryKey += ", ";
						primaryKey += FieldStart() + f_node->Name() + FieldEnd();
					}
				});
				if (primaryKey.size() > 0)
				{
					sql += "CREATE";
					if (i_node->UniqueKey())
						sql += "  UNIQUE";
					sql += "  INDEX " + FieldStart() + indexName + FieldEnd() + " ON " + TableStart() + name + TableEnd() + "(" + primaryKey + ")\r\n";
					sql += "<<<<BREAK>>>>\r\n";
				}
			});
		});


		//
		// Now it is time to create the relationships
		//
			std::for_each(nodeList.begin(), nodeList.end(), [this, &sql, &sourceList, &destList](std::shared_ptr<Relation> r_node) {
			sourceList = "";
			destList = "";

			const std::vector<std::shared_ptr<TableColumn> > SourceCols = r_node->SourceColumns();
			const std::vector<std::shared_ptr<TableColumn> > DestCols = r_node->DestinationColumns();

			for (int i = 0; i < (int)SourceCols.size(); i++)
			{
				if (sourceList.size() > 0)
				{
					sourceList += ",\r\n    ";
					destList += ",\r\n    ";
				}
				else
				{
					sourceList += "    ";
					destList += "    ";
				}
				sourceList += FieldStart() + SourceCols[i]->Name() + FieldEnd();
				destList += FieldStart() + DestCols[i]->Name() + FieldEnd();
			}
			if (sourceList.size() > 0)
			{
				sql += "ALTER TABLE " + TableStart() + r_node->Destination()->Name() + TableEnd() + " ADD\r\n";
				sql += "  CONSTRAINT " + FieldStart() + BuildForeignKeyName(r_node) + FieldEnd() + " FOREIGN KEY\r\n";
				sql += "  (\r\n" + destList + "\r\n  ) ";
				sql += "REFERENCES " + TableStart() + r_node->Source()->Name() + TableEnd() + " (\r\n";
				sql += sourceList + "\r\n  )\r\n";
				sql += "<<<<BREAK>>>>\r\n";
			}
		});
				}

		//
		// Now it is time to create the update and delete triggers
		//
		/*
		nodeList = SchemaData.DocumentElement.SelectNodes("Tables/Table[@Type='Persist']");

		foreach (XmlNode t_node in nodeList)
		{
		string trigger = BuildUpdateTriggerForTable(t_node.Attributes["Name"].Value.ToString());

		if ( trigger.Length > 0 )
		{
		sql += trigger;
		//
		// Insert a command separator to support limitations in ADO
		//
		sql += "\r\n<<<<BREAK>>>>\r\n\r\n";  + BuildDeleteTriggerForTable(t_node.Attributes["Name"].Value.ToString());
		sql += "\r\n<<<<BREAK>>>>\r\n\r\n";
		}
		}
		*/
		//
		// Now it is time to load data into the tables
		//
		if (schemaPart == AllParts || schemaPart == AddDataPart)
		{
		sql += "BEGIN\r\n";

		std::vector<std::shared_ptr<DataRow> > rowList = Schema()->AllDataRows();

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

		sql += "END;\r\n";
		}
		////
		////            sql += "GRANT ALL PRIVILEGES ON [[DATABASE]].* TO " + uid + "@localhost IDENTIFIED BY '" + pwd + "';\r\n";
		////            sql += "GRANT ALL PRIVILEGES ON [[DATABASE]].* TO " + uid + "@'%' IDENTIFIED BY '" + pwd + "';\r\n";
		////
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
	tsStringBase BuildUpdateTriggerForTable(const tsStringBase& TableName)
	{
		tsStringBase trigger = "";
		std::vector<std::shared_ptr<Relation> > nodeList;

		//
		// First retrieve the list of relationships from the schema file
		//
		nodeList = Schema()->FindRelationsWithSourceTable(TableName);
		if (nodeList.size() == 0)
		{
			return "";
		}
		trigger += "/****** Object:  Trigger " + TableName + "update ******/\r\n";
		trigger += "\r\n";
		trigger += "Create Trigger " + TableName + "update on " + TableName + "\r\n";
		trigger += "for update\r\n";
		trigger += "as\r\n";
		trigger += "/* Visio Enterprise generated trigger code. */\r\n";
		trigger += "BEGIN\r\n";
		trigger += "  declare\r\n";
		trigger += "  @rowsAffected int,\r\n";
		trigger += "  @nullRows int,\r\n";
		trigger += "  @validRows int,\r\n";
		trigger += "  @errorNumber int,\r\n";
		trigger += "  @errorMsg varchar(255)\r\n";
		trigger += "\r\n";
		trigger += "  select @rowsAffected = @@rowcount\r\n";
		trigger += "\r\n";
		trigger += "/* trigger for ON UPDATE to PARENT NO ACTION (RESTRICT) */\r\n";

		std::for_each(nodeList.begin(), nodeList.end(), [&trigger, this, &TableName](std::shared_ptr<Relation> r_node) {
			std::vector<tsStringBase> srcFields;
			std::vector<tsStringBase> dstFields;
			tsStringBase updateList = "";

			if (!r_node->Persist() && !r_node->ForceInTrigger())
				return;

			const std::vector<std::shared_ptr<TableColumn> > SourceCols = r_node->SourceColumns();
			const std::vector<std::shared_ptr<TableColumn> > DestCols = r_node->DestinationColumns();

			for (int i = 0; i < (int)SourceCols.size(); i++)
			{
				srcFields.push_back(SourceCols[i]->Name());
				dstFields.push_back(DestCols[i]->Name());
				if (updateList.size() > 0)
					updateList += " OR ";
				updateList += "update(" + srcFields[i] + ")";
			}

			trigger += "\r\n";
			trigger += "if\r\n";
			trigger += updateList + "\r\n";
			trigger += "  begin\r\n";
			trigger += "    if exists(\r\n";
			trigger += "      select * from deleted, " + r_node->Destination()->Name() + "\r\n";
			trigger += "      where ";
			for (int i = 0; i < (int)SourceCols.size(); i++)
			{
				if (i > 0)
					trigger += " AND ";
				trigger += r_node->Destination()->Name() + "." + dstFields[i];
				trigger += " = deleted." + srcFields[i];
			}
			trigger += ")\r\n";
			trigger += "    begin\r\n";
			trigger += "      select @errorNumber = 30002,\r\n";
			trigger += "             @errorMsg = 'Cannot modify values ";
			for (int i = 0; i < (int)SourceCols.size(); i++)
			{
				if (i > 0)
					trigger += " or ";
				trigger += srcFields[i];
			}
			trigger += " in " + TableName + " because there are dependent values in " + r_node->Destination()->Name() + "'\r\n";
			trigger += "      goto errorHandler\r\n";
			trigger += "    end\r\n";
			trigger += "  end\r\n";
		});

		trigger += "\r\n";
		trigger += "  return\r\n";
		trigger += "errorHandler:\r\n";
		trigger += "  raiserror @errorNumber @errorMsg\r\n";
		trigger += "  rollback transaction\r\n";
		trigger += "END\r\n";
		return trigger;
	}

	tsStringBase BuildDeleteTriggerForTable(const tsStringBase& TableName)
	{
		tsStringBase trigger = "";
		std::vector<std::shared_ptr<Relation> > nodeList;
		tsStringBase destTable;

		//
		// First retrieve the list of relationships from the schema file
		//
		nodeList = Schema()->FindRelationsWithSourceTable(TableName);
		if (nodeList.size() == 0)
		{
			return "";
		}
		trigger += "/****** Object:  Trigger " + TableName + "delete ******/\r\n";
		trigger += "\r\n";
		trigger += "Create Trigger " + TableName + "delete on " + TableName + "\r\n";
		trigger += "for delete\r\n";
		trigger += "as\r\n";
		trigger += "/* Visio Enterprise generated trigger code. */\r\n";
		trigger += "BEGIN\r\n";
		trigger += "  declare\r\n";
		trigger += "  @errorNumber int,\r\n";
		trigger += "  @errorMsg varchar(255)\r\n";
		trigger += "\r\n";

		std::for_each(nodeList.begin(), nodeList.end(), [&trigger, this, &TableName, &destTable](std::shared_ptr<Relation> r_node) {
			std::vector<tsStringBase> srcFields;
			std::vector<tsStringBase> dstFields;
			tsStringBase updateList = "";

			if (!r_node->Persist() && !r_node->ForceInTrigger())
				return;

			destTable = r_node->Destination()->Name();

			const std::vector<std::shared_ptr<TableColumn> > SourceCols = r_node->SourceColumns();
			const std::vector<std::shared_ptr<TableColumn> > DestCols = r_node->DestinationColumns();

			for (int i = 0; i < (int)SourceCols.size(); i++)
			{
				srcFields.push_back(SourceCols[i]->Name());
				dstFields.push_back(DestCols[i]->Name());
				if (updateList.size() > 0)
					updateList += " OR ";
				updateList += "update(" + srcFields[i] + ")";
			}

			trigger += "\r\n";
			trigger += "/* trigger for ON DELETE to PARENT NO ACTION (RESTRICT) */\r\n";
			trigger += "\r\n";
			trigger += "  if exists(\r\n";
			trigger += "     select * from deleted, " + destTable + "     where ";

			for (int i = 0; i < (int)SourceCols.size(); i++)
			{
				if (i > 0)
					trigger += " AND ";
				trigger += r_node->Destination()->Name() + "." + dstFields[i];
				trigger += " = deleted." + srcFields[i];
			}

			trigger += ")\r\n";
			trigger += "    begin\r\n";
			trigger += "      select @errorNumber = 30004,\r\n";
			trigger += "             @errorMsg = 'Cannot delete from ";
			trigger += TableName + " because there are dependent values in " + r_node->Destination()->Name() + "'\r\n";
			trigger += "    goto errorHandler\r\n";
			trigger += "  end\r\n";
		});

		trigger += "\r\n";
		trigger += "  return\r\n";
		trigger += "errorHandler:\r\n";
		trigger += "  raiserror @errorNumber @errorMsg\r\n";
		trigger += "  rollback transaction\r\n";
		trigger += "END\r\n";
		return trigger;
	}

	tsStringBase BuildForeignKeyName(std::shared_ptr<Relation> r_node)
	{
		tsStringBase name = "";
		try
		{
			name = r_node->Name();
			if (name.size() > 30)
			{
				name = r_node->ShortName();
			}
		}
		catch (...)
		{
			name = "";
		}
		if (name.size() > 0)
			return name;
		return "FK_" + r_node->Destination()->Name() + "_" + r_node->Source()->Name();
	}

};

#endif // __ORACLEHELPER_H__
