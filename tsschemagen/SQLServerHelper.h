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

#ifndef __SQLSERVERHELPER_H__
#define __SQLSERVERHELPER_H__

#pragma once

class SqlServerHelper : public SQLHelper
{
public:
	SqlServerHelper() : m_state(0)
	{
	}
	virtual ~SqlServerHelper()
	{
	}

	virtual tsStringBase ResolveTypeToDatabase(const tsStringBase& typeName, int length) override
	{
		if (typeName == "System.String")
		{
			if (length > 8000)
				return "[varchar] (max)";
			tsStringBase tmp;
			tmp << length;
			return "[varchar] (" + tmp + ")";
		}
		else if (typeName == "System.Char[]")
		{
			tsStringBase tmp;
			tmp << length;
			return "[char] (" + tmp + ")";
		}
		else if (typeName == "System.Guid")
		{
			return "[uniqueidentifier]";
		}
		else if (typeName == "System.Boolean")
		{
			return "[bit]";
		}
		else if (typeName == "System.Int32")
		{
			return "[int]";
		}
		else if (typeName == "System.Int16")
		{
			return "[smallint]";
		}
		else if (typeName == "System.DateTime")
		{
			return "[datetime]";
		}
		else if (typeName == "System.Double")
		{
			return "[decimal] (18, 2)";
		}
		else
		{
			return "[varchar] (1)";
		}
	}
	virtual tsStringBase BuildSchema(const tsStringBase& schemaFile, SchemaPartType schemaPart) override
	{
		tsStringBase sql;
		std::vector<std::shared_ptr<Relation> > nodeList;
		std::vector<std::shared_ptr<View> > viewList;
		std::vector<std::shared_ptr<Table> > tableList;

		sql.resize(100000);
		sql.resize(0);

		m_state = 0;
		LoadSchemaInfo(schemaFile);
		nodeList = Schema()->PersistedRelations();
		viewList = Schema()->PersistedViews();
		tableList = Schema()->PersistedTables();

		if (schemaPart == AllParts || schemaPart == DropPart)
		{
		//
		// First retrieve the list of relationships from the schema file
		//
		if (nodeList.size() > 0)
		{
			//
			// And remove the foreign keys from the current database
			//
			std::for_each(nodeList.begin(), nodeList.end(), [this, &sql](std::shared_ptr<Relation> r_node) {
				sql << "if exists (select * from dbo.sysobjects where id = object_id(N'" + TableStart() + BuildForeignKeyName(r_node) + TableEnd() + "') and OBJECTPROPERTY(id, N'IsForeignKey') = 1)\r\n";
				sql << "ALTER TABLE " + TableStart() + r_node->Destination()->Name() + TableEnd() + " DROP CONSTRAINT " + BuildForeignKeyName(r_node) + "\r\n";
				sql << StatementTerminator() + "\r\n\r\n";
			});
		}
		//
		// Now retrieve the view list
		//
		//
		// And remove the views from the current database
		//
		std::for_each(viewList.begin(), viewList.end(), [&sql, this](std::shared_ptr<View> v_node) {
			tsStringBase name = v_node->Name();
			sql << "if exists (select * from dbo.sysobjects where id = object_id(N'" + TableStart() + name + TableEnd() + "') and OBJECTPROPERTY(id, N'IsView') = 1)\r\n";
			sql << "drop view " + TableStart() + name + TableEnd() + "\r\n";
			sql << StatementTerminator() + "\r\n\r\n";
		});
		//
		// Now retrieve the table list
		//
		if (tableList.size() < 1)
			throw std::runtime_error("Unable to locate schema information for the database tables");
		//
		// First remove the triggers
		//
		std::for_each(tableList.begin(), tableList.end(), [&sql, this](std::shared_ptr<Table> t_node) {
			std::vector<std::shared_ptr<Relation> > trigRelList;

			tsStringBase name = t_node->Name();
			try
			{
				trigRelList = Schema()->FindRelationsWithSourceTable(name);
			}
			catch (std::exception /*exc*/)
			{
				trigRelList.clear();
			}
			if (trigRelList.size() > 0)
			{
				sql << "if exists (select * from dbo.sysobjects where id = object_id(N'" + TableStart() + name + "update" + TableEnd() + "') and OBJECTPROPERTY(id, N'IsTrigger') = 1)\r\n";
				sql << "drop trigger " + TableStart() + name + "update" + TableEnd() + "\r\n";
				sql << StatementTerminator() + "\r\n\r\n";

				sql << "if exists (select * from dbo.sysobjects where id = object_id(N'" + TableStart() + name + "delete" + TableEnd() + "') and OBJECTPROPERTY(id, N'IsTrigger') = 1)\r\n";
				sql << "drop trigger " + TableStart() + name + "delete" + TableEnd() + "\r\n";
				sql << StatementTerminator() + "\r\n\r\n";
			}
		});
		//
		// And then remove the tables from the current database
		//
		std::for_each(tableList.begin(), tableList.end(), [&sql, this](std::shared_ptr<Table> t_node) {
			tsStringBase name = t_node->Name();
			sql << "if exists (select * from dbo.sysobjects where id = object_id(N'" + TableStart() + name + TableEnd() + "') and OBJECTPROPERTY(id, N'IsUserTable') = 1)\r\n";
			sql << "drop table " + TableStart() + name + TableEnd() + "\r\n";
			sql << StatementTerminator() + "\r\n\r\n";
		});

		//
		// Insert a command separator to support limitations in ADO
		//
			if (schemaPart == AllParts)
		sql << "\r\n<<<<BREAK>>>>\r\n\r\n";
		}
		//
		// Now create the tables
		//
		if (schemaPart == AllParts || schemaPart == CreateTablePart)
		{
		std::for_each(tableList.begin(), tableList.end(), [&sql, this](std::shared_ptr<Table> t_node) {
			int colCount = 0;
			tsStringBase defValue;

			tsStringBase name = t_node->Name();
			sql << "CREATE TABLE " + TableStart() + name + TableEnd() + " (";
			colCount = 0;

			std::vector<std::shared_ptr<TableColumn> > colList = t_node->Columns();
			std::for_each(colList.begin(), colList.end(), [&sql, this, &colCount, &defValue](std::shared_ptr<TableColumn> node) {
				if (node->Table().size() == 0)
				{
					if (colCount == 0)
						sql << "\r\n  ";
					else
						sql << " ,\r\n  ";
					sql << FieldStart() + node->Name() + FieldEnd() + " ";
					tsStringBase type = node->FieldType();
					int length = node->FieldLength();
					sql << ResolveTypeToDatabase(type, length);
					try
					{
						defValue = node->Default();
					}
					catch (...)
					{
						defValue = "";
					}
					if (defValue.size() > 0)
						sql << " " + defValue;
					if (!node->Nullable())
						sql << " NOT";
					sql << " NULL";
					colCount++;
				}
			});
			sql << "\r\n) ON [PRIMARY]\r\n" + StatementTerminator() + "\r\n\r\n";
		});
		//
		// Insert a command separator to support limitations in ADO
		//
		sql << "\r\n<<<<BREAK>>>>\r\n\r\n";
			//
			// Now it is time to create the views
			//
			std::for_each(viewList.begin(), viewList.end(), [&sql, this](std::shared_ptr<View> v_node) {
				std::vector<std::shared_ptr<DatabaseView> > dbViewList = v_node->DatabaseViews();

				std::for_each(dbViewList.begin(), dbViewList.end(), [&sql, this](std::shared_ptr<DatabaseView> vc_node) {
					if (vc_node->dbName().ToLower() == "sqlserverview")
					{
						sql << vc_node->Code();
						//
						// Insert a command separator to support limitations in ADO
						//
						sql << "\r\n<<<<BREAK>>>>\r\n\r\n";
					}
				});
			});
			if (schemaPart == AllParts)
				sql << "\r\n<<<<BREAK>>>>\r\n\r\n";
		}

		if (schemaPart == AllParts || schemaPart == AddKeysPart)
		{
		//
		// Now create the primary keys
		//$$$
		std::for_each(tableList.begin(), tableList.end(), [&sql, this](std::shared_ptr<Table> t_node) {
			tsStringBase indexName;

			tsStringBase name = t_node->Name();

			tsStringBase primaryKey = "";
			std::vector<std::shared_ptr<Index> > idxList = t_node->PrimaryKeys();

			std::for_each(idxList.begin(), idxList.end(), [&sql, this, &name](std::shared_ptr<Index> p_node) {
				tsStringBase indexName = p_node->Name();

				tsStringBase primaryKey = "";
				std::vector<std::shared_ptr<TableColumn> > colList = p_node->Columns();
				std::for_each(colList.begin(), colList.end(), [&sql, this, &primaryKey](std::shared_ptr<TableColumn> f_node) {
					if (primaryKey.size() > 0)
						primaryKey += ",\r\n    ";
					else
						primaryKey += "    ";
					primaryKey += FieldStart() + f_node->Name() + FieldEnd();
				});
				if (primaryKey.size() > 0)
				{
					tsStringBase tmpName = "PK_" + name;

					if (indexName.size() > 0)
						tmpName = indexName;

					sql << "ALTER TABLE " + TableStart() + name + TableEnd() + " WITH NOCHECK ADD\r\n";
					sql << "  CONSTRAINT " + FieldStart() + tmpName + FieldEnd() + " PRIMARY KEY  CLUSTERED\r\n";
					sql << "  (\r\n";

					sql << primaryKey + "\r\n  ) ON [PRIMARY]\r\n" + StatementTerminator() + "\r\n\r\n";
				}
			});
		});

		//
		// Now create the tables
		//
		std::for_each(tableList.begin(), tableList.end(), [&sql, this](std::shared_ptr<Table> t_node) {
			tsStringBase defValue;

			tsStringBase name = t_node->Name();
			std::vector<std::shared_ptr<TableColumn> > colList = t_node->Columns();
			std::for_each(colList.begin(), colList.end(), [&sql, this, &defValue, &name](std::shared_ptr<TableColumn> node) {
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
					sql << "ALTER TABLE " + TableStart() + name + TableEnd() + " WITH NOCHECK ADD \r\n";
					sql << "	CONSTRAINT " + FieldStart() + "DF_" + name + "_" + node->Name() + FieldEnd() + " DEFAULT (newid()) FOR " + FieldStart() + node->Name() + FieldEnd() + "\r\n";
					sql << StatementTerminator() + "\r\n\r\n";
				}
			});
		});
		//
		// Insert a command separator to support limitations in ADO
		//
		sql << "\r\n<<<<BREAK>>>>\r\n\r\n";

		//
		// Now create the tables
		//
		std::for_each(tableList.begin(), tableList.end(), [&sql, this](std::shared_ptr<Table> t_node) {
			tsStringBase name = t_node->Name();
			std::vector<std::shared_ptr<Index> > idxList = t_node->NonPrimaryKeys();

			std::for_each(idxList.begin(), idxList.end(), [&sql, this, &name](std::shared_ptr<Index> i_node) {
				if (i_node->IndexType().ToLower() == "temporary")
					return;

				//$$$
				tsStringBase indexName = i_node->Name();

				tsStringBase primaryKey = "";
				std::vector<std::shared_ptr<TableColumn> > colList = i_node->Columns();
				std::for_each(colList.begin(), colList.end(), [&sql, this, &primaryKey](std::shared_ptr<TableColumn> f_node) {
					if (primaryKey.size() > 0)
						primaryKey += ", ";
					primaryKey += FieldStart() + f_node->Name() + FieldEnd();
				});
				if (primaryKey.size() > 0)
				{
					sql << "CREATE";
					if (i_node->UniqueKey())
						sql << "  UNIQUE";
					sql << "  INDEX " + FieldStart() + indexName + FieldEnd() + " ON " + TableStart() + name + TableEnd() + "(" + primaryKey + ") ON [PRIMARY]\r\n";
					sql << StatementTerminator() + "\r\n\r\n";
				}
			});
		});
		//
		// Insert a command separator to support limitations in ADO
		//
		sql << "\r\n<<<<BREAK>>>>\r\n\r\n";

		//
		// Now it is time to create the relationships
		//
		std::for_each(nodeList.begin(), nodeList.end(), [this, &sql](std::shared_ptr<Relation> r_node) {
			tsStringBase sourceList = "";
			tsStringBase destList = "";

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
				sql << "ALTER TABLE " + TableStart() + r_node->Destination()->Name() + TableEnd() + " ADD\r\n";
				sql << "  CONSTRAINT " + FieldStart() + BuildForeignKeyName(r_node) + FieldEnd() + " FOREIGN KEY\r\n";
				sql << "  (\r\n" + destList + "\r\n  ) ";
				sql << "REFERENCES " + TableStart() + r_node->Source()->Name() + TableEnd() + " (\r\n";
				sql << sourceList + "\r\n  )\r\n";
				sql << StatementTerminator() + "\r\n\r\n";
			}
		});
		//
		// Insert a command separator to support limitations in ADO
		//
		sql << "\r\n<<<<BREAK>>>>\r\n\r\n";
		sql << "SET QUOTED_IDENTIFIER ON;\r\n";
		sql << "SET ANSI_NULLS ON;\r\n";
		//
		// Insert a command separator to support limitations in ADO
		//
		sql << "\r\n<<<<BREAK>>>>\r\n\r\n";

		//
		// Now it is time to create the update and delete triggers
		//
		std::for_each(tableList.begin(), tableList.end(), [&sql, this](std::shared_ptr<Table> t_node) {
			tsStringBase trigger = BuildUpdateTriggerForTable(t_node->Name());

			if (trigger.size() > 0)
			{
				sql << trigger;
				//
				// Insert a command separator to support limitations in ADO
				//
				sql << "\r\n<<<<BREAK>>>>\r\n\r\n" + BuildDeleteTriggerForTable(t_node->Name());
				sql << "\r\n<<<<BREAK>>>>\r\n\r\n";
			}
		});
		}

		//
		// Now it is time to load data into the tables
		//
		if (schemaPart == AllParts || schemaPart == AddDataPart)
		{
		std::vector<std::shared_ptr<DataRow> > rowList = Schema()->AllDataRows();

		std::for_each(rowList.begin(), rowList.end(), [&sql, this](std::shared_ptr<DataRow> r_node) {
			tsStringBase sourceList = "";
			tsStringBase destList = "";
			sql << "INSERT INTO " + TableStart() + r_node->Table()->Name() + TableEnd() + "(";

			const tsAttributeMap& map = r_node->Values();
			map.foreach([&sourceList, &destList, this](const __tsAttributeMapItem& item) {
				if (sourceList.size() > 0)
				{
					sourceList += ", ";
					destList += ", ";
				}
				sourceList += FieldStart() + item.m_name + FieldEnd();
				destList += StringToSQL(item.m_value);
			});
			sql << sourceList + ") VALUES (" + destList + ")\r\n" + StatementTerminator() + "\r\n";
		});
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
		return "[";
	}
	virtual tsStringBase FieldEnd() const override
	{
		return "]";
	}
	virtual tsStringBase TableStart() const override
	{
		return "[dbo].[";
	}
	virtual tsStringBase TableEnd() const override
	{
		return "]";
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
	int m_state;

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
		trigger += "/****** Object:  Trigger dbo." + TableName + "update ******/\r\n";
		trigger += "\r\n";
		trigger += "Create Trigger " + TableName + "update on dbo.[" + TableName + "]\r\n";
		trigger += "for update\r\n";
		trigger += "as\r\n";
		trigger += "/* Visio Enterprise generated trigger code. */\r\n";
		trigger += "BEGIN\r\n";
		trigger += "  declare\r\n";
		trigger += "  @rowsAffected int,\r\n";
		trigger += "  @nullRows int,\r\n";
		trigger += "  @validRows int,\r\n";
		trigger += "  @errorMsg varchar(255)\r\n";
		trigger += "\r\n";
		trigger += "  select @rowsAffected = @@rowcount\r\n";
		trigger += "\r\n";
		trigger += "/* trigger for ON UPDATE to PARENT NO ACTION (RESTRICT) */\r\n";

		std::for_each(nodeList.begin(), nodeList.end(), [&trigger, &TableName](std::shared_ptr<Relation> r_node) {
			if (!r_node->Persist() && !r_node->ForceInTrigger())
				return;

			std::vector<tsStringBase> srcFields;
			std::vector<tsStringBase> dstFields;
			tsStringBase updateList = "";

			const std::vector<std::shared_ptr<TableColumn> > SourceCols = r_node->SourceColumns();
			const std::vector<std::shared_ptr<TableColumn> > DestCols = r_node->DestinationColumns();

			for (int i = 0; i < (int)SourceCols.size(); i++)
			{
				srcFields.push_back(SourceCols[i]->Name());
				dstFields.push_back(DestCols[i]->Name());
				if (updateList.size() > 0)
					updateList += " OR ";
				updateList += "update([" + srcFields[i] + "])";
			}

			trigger += "\r\n";
			trigger += "if\r\n";
			trigger += updateList + "\r\n";
			trigger += "  begin\r\n";
			trigger += "    if exists(\r\n";
			trigger += "      select * from deleted, [" + r_node->Destination()->Name() + "]\r\n";
			trigger += "      where ";
			for (int i = 0; i < (int)srcFields.size(); i++)
			{
				if (i > 0)
					trigger += " AND ";
				trigger += "[" + r_node->Destination()->Name() + "].[" + dstFields[i] + "]";
				trigger += " = deleted.[" + srcFields[i] + "]";
			}
			trigger += ")\r\n";
			trigger += "    begin\r\n";
			trigger += "      select @errorMsg = 'Cannot modify values ";
			for (int i = 0; i < (int)srcFields.size(); i++)
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
		trigger << "  raiserror (@errorMsg, 1, " << ((m_state++ % 127) + 1) << ")\r\n";
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
		trigger += "/****** Object:  Trigger dbo." + TableName + "delete ******/\r\n";
		trigger += "\r\n";
		trigger += "Create Trigger " + TableName + "delete on dbo.[" + TableName + "]\r\n";
		trigger += "for delete\r\n";
		trigger += "as\r\n";
		trigger += "/* Visio Enterprise generated trigger code. */\r\n";
		trigger += "BEGIN\r\n";
		trigger += "  declare\r\n";
		trigger += "  @errorMsg varchar(255)\r\n";
		trigger += "\r\n";

		std::for_each(nodeList.begin(), nodeList.end(), [&trigger, &TableName, &destTable](std::shared_ptr<Relation> r_node) {
			if (!r_node->Persist() && !r_node->ForceInTrigger())
				return;

			std::vector<tsStringBase> srcFields;
			std::vector<tsStringBase> dstFields;
			tsStringBase updateList = "";

			destTable = r_node->Destination()->Name();

			const std::vector<std::shared_ptr<TableColumn> > SourceCols = r_node->SourceColumns();
			const std::vector<std::shared_ptr<TableColumn> > DestCols = r_node->DestinationColumns();

			for (int i = 0; i < (int)SourceCols.size(); i++)
			{
				srcFields.push_back(SourceCols[i]->Name());
				dstFields.push_back(DestCols[i]->Name());
				if (updateList.size() > 0)
					updateList += " OR ";
				updateList += "update([" + srcFields[i] + "])";
			}

			trigger += "\r\n";
			trigger += "/* trigger for ON DELETE to PARENT NO ACTION (RESTRICT) */\r\n";
			trigger += "\r\n";
			trigger += "  if exists(\r\n";
			trigger += "     select * from deleted, [" + destTable + "]     where ";

			for (int i = 0; i < (int)srcFields.size(); i++)
			{
				if (i > 0)
					trigger += " AND ";
				trigger += "[" + destTable + "].[" + dstFields[i] + "]";
				trigger += " = deleted.[" + srcFields[i] + "]";
			}

			trigger += ")\r\n";
			trigger += "    begin\r\n";
			trigger += "      select @errorMsg = 'Cannot delete from ";
			trigger += TableName + " because there are dependent values in " + destTable + "'\r\n";
			trigger += "    goto errorHandler\r\n";
			trigger += "  end\r\n";
		});

		trigger += "\r\n";
		trigger += "  return\r\n";
		trigger += "errorHandler:\r\n";
		trigger << "  raiserror (@errorMsg, 1, " << ((m_state++ % 127) + 1) << ")\r\n";
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

#endif // __SQLSERVERHELPER_H__
