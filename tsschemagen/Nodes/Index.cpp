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

Index::Index(std::shared_ptr<ColumnContainer> parent, std::shared_ptr<tsXmlNode> indexNode)
{
	tsXmlNodeList nodeList;
	std::vector<std::shared_ptr<TableColumn> > cols;

	Parent(parent);
	Name(indexNode->Attributes().item("Name"));
	ShortName(indexNode->Attributes().item("ShortName"));
	SearchableName(indexNode->Attributes().item("SearchableName"));
	LoadReturnsSingle(indexNode->Attributes().itemAsBoolean("LoadReturnsSingle", false));
	Deletable(indexNode->Attributes().itemAsBoolean("Deletable", true));
	IndexType(indexNode->Attributes().item("Type").ToLower());
	SearchClause(indexNode->Attributes().item("SearchClause"));
	DeleteSearchClause(indexNode->Attributes().item("DeleteSearchClause"));
	description(indexNode->Attributes().item("description"));

	nodeList = indexNode->ChildrenByName("IndexField");
	std::for_each(nodeList.begin(), nodeList.end(), [this, &cols, &parent](std::shared_ptr<tsXmlNode>& child) {
		tsStringBase fieldName = child->Attributes().item("Name");

		std::shared_ptr<TableColumn> c = parent->FindColumn(fieldName);

		if (!c)
			throw std::runtime_error(("The column name " + fieldName + " is missing from " + parent->Name() + ".").c_str());
		cols.push_back(c);
	});
	Columns(cols);
}

