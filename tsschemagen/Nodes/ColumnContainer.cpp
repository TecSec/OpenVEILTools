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
ColumnContainer::ColumnContainer(std::shared_ptr<Schema> parent, std::shared_ptr<tsXmlNode> containerNode)
{
	Parent(parent);
	_containerNode = containerNode;
	ReadOnly(false);
}
void ColumnContainer::OnConstructionFinished()
{
	tsXmlNodeList nodeList;
	std::vector<std::shared_ptr<TableColumn> > cols;
	std::vector<std::shared_ptr<Index> > idxs;
	std::shared_ptr<tsXmlNode> containerNode(_containerNode);

	_containerNode.reset();

	Name(containerNode->Attributes().item("Name"));
	Persist(containerNode->Attributes().item("Type").ToLower() == "persist");
	JSONName(containerNode->Attributes().item("JSONName"));
	From(containerNode->Attributes().item("From"));
	if (From().size() == 0)
		From(Name());

	nodeList = containerNode->ChildrenByName("TableColumn");
	std::for_each(nodeList.begin(), nodeList.end(), [&cols, this](std::shared_ptr<tsXmlNode> child){
		cols.push_back(TableColumn::Create(std::dynamic_pointer_cast<ColumnContainer>(_me.lock()), child));
	});
	Columns(cols);

	nodeList = containerNode->ChildrenByName("Index");
	std::for_each(nodeList.begin(), nodeList.end(), [&idxs, this](std::shared_ptr<tsXmlNode> child){
		idxs.push_back(Index::Create(std::dynamic_pointer_cast<ColumnContainer>(_me.lock()), child));
	});
	Indexes(idxs);
	description(containerNode->Attributes().item("description"));
}

std::shared_ptr<TableColumn> ColumnContainer::FindColumn(const tsStringBase& name)
{
	std::vector<std::shared_ptr<TableColumn> > list = Columns();

	auto it = std::find_if(list.begin(), list.end(), [&name](std::shared_ptr<TableColumn> c) { return c->Name() == name; });

	if (it == list.end())
		return nullptr;
	return *it;
}
const std::vector<std::shared_ptr<Index> > ColumnContainer::PrimaryKeys()
{
	std::vector<std::shared_ptr<Index> > col;
	std::vector<std::shared_ptr<Index> > list = Indexes();

	std::for_each(list.begin(), list.end(), [&col](std::shared_ptr<Index> i){
		if (i->PrimaryKey())
			col.push_back(i);
	});
	return col;
}
const std::vector<std::shared_ptr<Index> > ColumnContainer::NonPrimaryKeys()
{
	std::vector<std::shared_ptr<Index> > col;
	std::vector<std::shared_ptr<Index> > list = Indexes();

	std::for_each(list.begin(), list.end(), [&col](std::shared_ptr<Index> i){
		if (!i->PrimaryKey())
			col.push_back(i);
	});
	return col;
}
