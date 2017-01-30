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

Schema::Schema(std::shared_ptr<tsXmlNode> doc)
{
	_doc = doc;
}
void Schema::OnConstructionFinished()
{
	tsXmlNodeList nodeList;
	std::vector<std::shared_ptr<CppInclude> > includes;
	std::vector<std::shared_ptr<Table> > tbls;
	std::vector<std::shared_ptr<Table> > persistedtbls;
	std::vector<std::shared_ptr<Table> > temporarytbls;
	std::vector<std::shared_ptr<View> > views;
	std::vector<std::shared_ptr<View> > persistedviews;
	std::vector<std::shared_ptr<View> > temporaryviews;
	std::vector<std::shared_ptr<Relation> > rels;
	std::vector<std::shared_ptr<Relation> > persistedrels;
	std::vector<std::shared_ptr<Relation> > temporaryrels;
	std::vector<std::shared_ptr<DataRow> > rows;
	std::shared_ptr<tsXmlNode> child;

	std::shared_ptr<tsXmlNode> doc(_doc);
	_doc.reset();

	Major(doc->Attributes().itemAsNumber("Major", 0));
	Minor(doc->Attributes().itemAsNumber("Minor", 0));
	Subminor(doc->Attributes().itemAsNumber("Subminor", 0));
	SymbolName(doc->Attributes().item("SymbolName"));
	ExportSymbol(doc->Attributes().item("ExportSymbol"));
	nodeList = doc->ChildrenByName("CppInclude");
	std::for_each(nodeList.begin(), nodeList.end(), [this, &includes](std::shared_ptr<tsXmlNode> child){
		includes.push_back(CppInclude::Create(std::dynamic_pointer_cast<Schema>(_me.lock()), child));
	});
	CppIncludes(includes);

	child = doc->ChildByName("Tables");
	if (!!child)
	{
		nodeList = child->ChildrenByName("Table");
		std::for_each(nodeList.begin(), nodeList.end(), [this, &persistedtbls, &tbls, &temporarytbls](std::shared_ptr<tsXmlNode> child){
			std::shared_ptr<Table> t = Table::Create(std::dynamic_pointer_cast<Schema>(_me.lock()), child);
			tbls.push_back(t);
			if (t->Persist())
				persistedtbls.push_back(t);
			else
				temporarytbls.push_back(t);
		});
	}
	AllTables(tbls);
	PersistedTables(persistedtbls);
	TemporaryTables(temporarytbls);

	child = doc->ChildByName("Views");
	if (!!child)
	{
		nodeList = child->ChildrenByName("View");
		std::for_each(nodeList.begin(), nodeList.end(), [this, &views, &persistedviews, &temporaryviews](std::shared_ptr<tsXmlNode> child){
			std::shared_ptr<View> v = View::Create(std::dynamic_pointer_cast<Schema>(_me.lock()), child);
			views.push_back(v);
			if (v->Persist())
				persistedviews.push_back(v);
			else
				temporaryviews.push_back(v);
		});
	}
	AllViews(views);
	PersistedViews(persistedviews);
	TemporaryViews(temporaryviews);

	std::vector < std::shared_ptr<ColumnContainer> > cntrs;
	std::vector < std::shared_ptr<ColumnContainer> > persistedcntrs;
	std::vector < std::shared_ptr<ColumnContainer> > temporarycntrs;

	std::for_each(tbls.begin(), tbls.end(), [&cntrs](std::shared_ptr<Table> tbl){
		cntrs.push_back(std::dynamic_pointer_cast<ColumnContainer>(tbl));
	});
	std::for_each(views.begin(), views.end(), [&cntrs](std::shared_ptr<View> view){
		cntrs.push_back(std::dynamic_pointer_cast<ColumnContainer>(view));
	});

	std::for_each(persistedtbls.begin(), persistedtbls.end(), [&persistedcntrs](std::shared_ptr<Table> tbl){
		persistedcntrs.push_back(std::dynamic_pointer_cast<ColumnContainer>(tbl));
	});
	std::for_each(persistedviews.begin(), persistedviews.end(), [&persistedcntrs](std::shared_ptr<View> view){
		persistedcntrs.push_back(std::dynamic_pointer_cast<ColumnContainer>(view));
	});

	std::for_each(temporarytbls.begin(), temporarytbls.end(), [&temporarycntrs](std::shared_ptr<Table> tbl){
		temporarycntrs.push_back(std::dynamic_pointer_cast<ColumnContainer>(tbl));
	});
	std::for_each(temporaryviews.begin(), temporaryviews.end(), [&temporarycntrs](std::shared_ptr<View> view){
		temporarycntrs.push_back(std::dynamic_pointer_cast<ColumnContainer>(view));
	});

	AllContainers(cntrs);
	PersistedContainers(persistedcntrs);
	TemporaryContainers(temporarycntrs);

	child = doc->ChildByName("Relations");
	if (!!child)
	{
		nodeList = child->ChildrenByName("Relation");
		std::for_each(nodeList.begin(), nodeList.end(), [this, &rels, &persistedrels, &temporaryrels](std::shared_ptr<tsXmlNode> child){
			std::shared_ptr<Relation> r = Relation::Create(std::dynamic_pointer_cast<Schema>(_me.lock()), child);
			rels.push_back(r);
			if (r->Persist())
				persistedrels.push_back(r);
			else
				temporaryrels.push_back(r);
		});
	}
	AllRelations(rels);
	PersistedRelations(persistedrels);
	TemporaryRelations(temporaryrels);


	child = doc->ChildByName("Rows");
	if (!!child)
	{
		nodeList = child->ChildrenByName("Row");
		std::for_each(nodeList.begin(), nodeList.end(), [&rows, this](std::shared_ptr<tsXmlNode> child){
			rows.push_back(DataRow::Create(std::dynamic_pointer_cast<Schema>(_me.lock()), child));
		});
	}
	AllDataRows(rows);
}

std::shared_ptr<Table> Schema::FindTable(const tsStringBase& name)
{
	auto it = std::find_if(_AllTables.begin(), _AllTables.end(), [&name](std::shared_ptr<Table> tbl)->bool { return tbl->Name() == name; });

	if (it == _AllTables.end())
		return nullptr;
	return *it;
}
const std::vector<std::shared_ptr<Relation> > Schema::FindRelationsWithSourceTable(const tsStringBase& tablename)
{
	std::vector<std::shared_ptr<Relation> > col;

	std::for_each(_AllRelations.begin(), _AllRelations.end(), [&col, &tablename](std::shared_ptr<Relation>& rel){
		if (rel->Source()->Name() == tablename)
			col.push_back(rel);
	});
	return col;
}
const std::vector<std::shared_ptr<Relation> > Schema::FindRelationsWithDestinationTable(const tsStringBase& tablename)
{
	std::vector<std::shared_ptr<Relation> > col;

	std::for_each(_AllRelations.begin(), _AllRelations.end(), [&col, &tablename](std::shared_ptr<Relation>& rel){
		if (rel->Destination()->Name() == tablename)
			col.push_back(rel);
	});
	return col;
}
