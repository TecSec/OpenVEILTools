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

Relation::Relation(std::shared_ptr<Schema> parent, std::shared_ptr<tsXmlNode> relationNode)
{
	std::vector<std::shared_ptr<TableColumn> > srcflds;
	std::vector<std::shared_ptr<TableColumn> > dstflds;

	Parent(parent);
	Name(relationNode->Attributes().item("KeyName"));
	ShortName(relationNode->Attributes().item("KeyShortName"));
	OneToManyName(relationNode->Attributes().item("OneToManyName"));
	ManyToOneName(relationNode->Attributes().item("ManyToOneName"));
	LoaderForMany(relationNode->Attributes().item("LoaderForMany"));
	LoaderForOne(relationNode->Attributes().item("LoaderForOne"));
	OneToOneSourceName(relationNode->Attributes().item("OneToOneSourceName"));
	OneToOneDestName(relationNode->Attributes().item("OneToOneDestName"));
	LoaderForDest(relationNode->Attributes().item("LoaderForDest"));
	Persist(relationNode->Attributes().item("Type").ToLower() == "persist");
	ForceInTrigger(relationNode->Attributes().itemAsBoolean("ForceInTrigger", false));

	if (LoaderForOne().size() == 0)
		LoaderForOne("Load");

	Source(parent->FindTable(relationNode->Attributes().item("SrcTbl")));
	Destination(parent->FindTable(relationNode->Attributes().item("DstTbl")));

	if (!!Source() && !!Destination())
	{
		tsXmlNodeList nodeList;

		nodeList = relationNode->ChildrenByName("RelationField");
		std::for_each(nodeList.begin(), nodeList.end(), [this, &srcflds, &dstflds](std::shared_ptr<tsXmlNode>& child){
			std::shared_ptr<TableColumn> src, dst;

			src = Source()->FindColumn(child->Attributes().item("SrcFld"));
			dst = Destination()->FindColumn(child->Attributes().item("DstFld"));
			if (!src || !dst)
				throw std::runtime_error("Relation field is missing.");
			srcflds.push_back(src);
			dstflds.push_back(dst);
		});
	}
	else
	{
		throw std::runtime_error("Relation source or destination table is missing.");
	}
	SourceColumns(srcflds);
	DestinationColumns(dstflds);
}