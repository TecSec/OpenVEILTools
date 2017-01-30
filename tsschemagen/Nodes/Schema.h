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


#ifndef __SCHEMA_H__
#define __SCHEMA_H__

#pragma once

class CppInclude;
class ColumnContainer;
class Table;
class View;
class Relation;
class DataRow;

class Schema : public IObject
{
public:
	static std::shared_ptr<Schema> Create(std::shared_ptr<tsXmlNode> doc) { return IObject::Create<Schema>(doc); }

	Schema(std::shared_ptr<tsXmlNode> doc);
	virtual ~Schema() {}

	int Major() const { return _Major; }
	int Minor() const { return _Minor; }
	int Subminor() const { return _Subminor; }
	tsStringBase SymbolName() const { return _SymbolName; }
	tsStringBase ExportSymbol() const { return _ExportSymbol; }
	const std::vector<std::shared_ptr<CppInclude> > CppIncludes() const { return _CppIncludes; }
	const std::vector<std::shared_ptr<ColumnContainer> > AllContainers() const { return _AllContainers; }
	const std::vector<std::shared_ptr<ColumnContainer> > PersistedContainers() const { return _PersistedContainers; }
	const std::vector<std::shared_ptr<ColumnContainer> > TemporaryContainers() const { return _TemporaryContainers; }
	const std::vector<std::shared_ptr<Table> > AllTables() const { return _AllTables; }
	const std::vector<std::shared_ptr<Table> > PersistedTables() const { return _PersistedTables; }
	const std::vector<std::shared_ptr<Table> > TemporaryTables() const { return _TemporaryTables; }
	const std::vector<std::shared_ptr<View> > AllViews() const { return _AllViews; }
	const std::vector<std::shared_ptr<View> > PersistedViews() const { return _PersistedViews; }
	const std::vector<std::shared_ptr<View> > TemporaryViews() const { return _TemporaryViews; }
	const std::vector<std::shared_ptr<Relation> > AllRelations() const { return _AllRelations; }
	const std::vector<std::shared_ptr<Relation> > PersistedRelations() const { return _PersistedRelations; }
	const std::vector<std::shared_ptr<Relation> > TemporaryRelations() const { return _TemporaryRelations; }
	const std::vector<std::shared_ptr<DataRow> > AllDataRows() const { return _AllDataRows; }


	std::shared_ptr<Table> FindTable(const tsStringBase& name);
	const std::vector<std::shared_ptr<Relation> > FindRelationsWithSourceTable(const tsStringBase& tablename);
	const std::vector<std::shared_ptr<Relation> > FindRelationsWithDestinationTable(const tsStringBase& tablename);

	virtual void OnConstructionFinished();

private:
	int _Major;
	int _Minor;
	int _Subminor;
	tsStringBase _SymbolName;
	tsStringBase _ExportSymbol;
	std::vector<std::shared_ptr<CppInclude> > _CppIncludes;
	std::vector<std::shared_ptr<ColumnContainer> > _AllContainers;
	std::vector<std::shared_ptr<ColumnContainer> > _PersistedContainers;
	std::vector<std::shared_ptr<ColumnContainer> > _TemporaryContainers;
	std::vector<std::shared_ptr<Table> > _AllTables;
	std::vector<std::shared_ptr<Table> > _PersistedTables;
	std::vector<std::shared_ptr<Table> > _TemporaryTables;
	std::vector<std::shared_ptr<View> > _AllViews;
	std::vector<std::shared_ptr<View> > _PersistedViews;
	std::vector<std::shared_ptr<View> > _TemporaryViews;
	std::vector<std::shared_ptr<Relation> > _AllRelations;
	std::vector<std::shared_ptr<Relation> > _PersistedRelations;
	std::vector<std::shared_ptr<Relation> > _TemporaryRelations;
	std::vector<std::shared_ptr<DataRow> > _AllDataRows;

	std::shared_ptr<tsXmlNode> _doc;

	void Major(int setTo) { _Major = setTo; }
	void Minor(int setTo) { _Minor = setTo; }
	void Subminor(int setTo) { _Subminor = setTo; }
	void SymbolName(const tsStringBase& setTo) { _SymbolName = setTo; }
	void ExportSymbol(const tsStringBase& setTo) { _ExportSymbol = setTo; }
	void CppIncludes(std::vector<std::shared_ptr<CppInclude> > setTo) { _CppIncludes = setTo; }
	void AllContainers(std::vector<std::shared_ptr<ColumnContainer> > setTo) { _AllContainers = setTo; }
	void PersistedContainers(std::vector<std::shared_ptr<ColumnContainer> > setTo) { _PersistedContainers = setTo; }
	void TemporaryContainers(std::vector<std::shared_ptr<ColumnContainer> > setTo) { _TemporaryContainers = setTo; }
	void AllTables(std::vector<std::shared_ptr<Table> > setTo) { _AllTables = setTo; }
	void PersistedTables(std::vector<std::shared_ptr<Table> > setTo) { _PersistedTables = setTo; }
	void TemporaryTables(std::vector<std::shared_ptr<Table> > setTo) { _TemporaryTables = setTo; }
	void AllViews(std::vector<std::shared_ptr<View> > setTo) { _AllViews = setTo; }
	void PersistedViews(std::vector<std::shared_ptr<View> > setTo) { _PersistedViews = setTo; }
	void TemporaryViews(std::vector<std::shared_ptr<View> > setTo) { _TemporaryViews = setTo; }
	void AllRelations(std::vector<std::shared_ptr<Relation> > setTo) { _AllRelations = setTo; }
	void PersistedRelations(std::vector<std::shared_ptr<Relation> > setTo) { _PersistedRelations = setTo; }
	void TemporaryRelations(std::vector<std::shared_ptr<Relation> > setTo) { _TemporaryRelations = setTo; }
	void AllDataRows(std::vector<std::shared_ptr<DataRow> > setTo) { _AllDataRows = setTo; }
};

#endif // __SCHEMA_H__
