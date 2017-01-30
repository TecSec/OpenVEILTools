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


// tsXmlError.cpp: implementation of the CtsXmlError class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "ProcessableNode.h"
#include "SetNode.h"
#include "ChoiceNode.h"
#include "EnumNode.h"
#include "BitstringNode.h"
#include "SequenceOfNode.h"
#include "FileNode.h"
#include "Asn1Export.h"

std::shared_ptr<IDNode> ProcessableNode::SearchChildrenForOID(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType)
{
	std::shared_ptr<IDNode> id = std::dynamic_pointer_cast<IDNode>(nodeToSearch);

	if (!!id)
	{
		if (id->Name() == elementType)
			return id;
	}
	for (auto& child : nodeToSearch->Children())
	{
		id = SearchChildrenForOID(child, elementType);
		if (!!id)
			return id;
	}
	return nullptr;
}
std::shared_ptr<SequenceNode> ProcessableNode::SearchChildrenForSequence(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType)
{
	std::shared_ptr<SequenceNode> sn = std::dynamic_pointer_cast<SequenceNode>(nodeToSearch);

	if (!!sn)
	{
		if (elementType.find(':') != tsStringBase::npos)
		{
			if (sn->FullStructureName() == elementType)
				return sn;
		}
		else
		{
			if (sn->StructureName() == elementType)
				return sn;
		}
	}
	for (auto& child : nodeToSearch->Children())
	{
		sn = SearchChildrenForSequence(child, elementType);
		if (!!sn)
			return sn;
	}
	return nullptr;
}
std::shared_ptr<NamedInt> ProcessableNode::SearchChildrenForNamedInt(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType)
{
	std::shared_ptr<NamedInt> sn = std::dynamic_pointer_cast<NamedInt>(nodeToSearch);

	if (!!sn)
	{
		if (sn->Name() == elementType)
			return sn;
	}
	for (auto& child : nodeToSearch->Children())
	{
		sn = SearchChildrenForNamedInt(child, elementType);
		if (!!sn)
			return sn;
	}
	return nullptr;
}
std::shared_ptr<SequenceOfNode> ProcessableNode::SearchChildrenForSequenceOf(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType)
{
	std::shared_ptr<SequenceOfNode> sn = std::dynamic_pointer_cast<SequenceOfNode>(nodeToSearch);

	if (!!sn)
	{
		if (elementType.find(':') != tsStringBase::npos)
		{
			if (sn->FullStructureName() == elementType)
				return sn;
		}
		else
		{
			if (sn->StructureName() == elementType)
				return sn;
		}
	}
	for (auto& child : nodeToSearch->Children())
	{
		sn = SearchChildrenForSequenceOf(child, elementType);
		if (!!sn)
			return sn;
	}
	return nullptr;
}
std::shared_ptr<EnumNode> ProcessableNode::SearchChildrenForEnum(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType)
{
	std::shared_ptr<EnumNode> en = std::dynamic_pointer_cast<EnumNode>(nodeToSearch);

	if (!!en)
	{
		if (elementType.find(':') != tsStringBase::npos)
		{
			if (en->FullName() == elementType)
				return en;
		}
		else
		{
			if (en->Name() == elementType)
				return en;
		}
	}
	for (auto& child : nodeToSearch->Children())
	{
		en = SearchChildrenForEnum(child, elementType);
		if (!!en)
			return en;
	}
	return nullptr;
}
std::shared_ptr<BitstringNode> ProcessableNode::SearchChildrenForBitstring(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType)
{
	std::shared_ptr<BitstringNode> en = std::dynamic_pointer_cast<BitstringNode>(nodeToSearch);

	if (!!en)
	{
		if (elementType.find(':') != tsStringBase::npos)
		{
			if (en->FullName() == elementType)
				return en;
		}
		else
		{
			if (en->Name() == elementType)
				return en;
		}
	}
	for (auto& child : nodeToSearch->Children())
	{
		en = SearchChildrenForBitstring(child, elementType);
		if (!!en)
			return en;
	}
	return nullptr;
}
std::shared_ptr<SetNode> ProcessableNode::SearchChildrenForSet(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType)
{
	std::shared_ptr<SetNode> sn = std::dynamic_pointer_cast<SetNode>(nodeToSearch);

	if (!!sn)
	{
		if (elementType.find(':') != tsStringBase::npos)
		{
			if (sn->FullStructureName() == elementType)
				return sn;
		}
		else
		{
			if (sn->StructureName() == elementType)
				return sn;
		}
	}
	for (auto& child : nodeToSearch->Children())
	{
		sn = SearchChildrenForSet(child, elementType);
		if (!!sn)
			return sn;
	}
	return nullptr;
}
std::shared_ptr<ChoiceNode> ProcessableNode::SearchChildrenForChoice(std::shared_ptr<tsXmlNode> nodeToSearch, const tsStringBase& elementType)
{
	std::shared_ptr<ChoiceNode> cn = std::dynamic_pointer_cast<ChoiceNode>(nodeToSearch);

	if (!!cn)
	{
		if (elementType.find(':') != tsStringBase::npos)
		{
			if (cn->FullName() == elementType)
				return cn;
		}
		else
		{
			if (cn->Name() == elementType)
				return cn;
		}
	}
	for (auto& child : nodeToSearch->Children())
	{
		cn = SearchChildrenForChoice(child, elementType);
		if (!!cn)
			return cn;
	}
	return nullptr;
}

std::shared_ptr<IDNode> ProcessableNode::FindOID(const tsStringBase& elementType)
{
	std::shared_ptr<tsXmlNode> node = this->Parent().lock();
	std::shared_ptr<tsXmlNode> top;

	while (!!node)
	{
		top = node;
		node = node->Parent().lock();
	}
	if (!top)
		return nullptr;
	return SearchChildrenForOID(top, elementType);
}
std::shared_ptr<SequenceNode> ProcessableNode::FindSequence(const tsStringBase& elementType)
{
	std::shared_ptr<FileNode> fileNode = GetFileNode();

	if (!!fileNode)
	{
		for (auto& ele : fileNode->Elements())
		{
			std::shared_ptr<SequenceNode> sn = std::dynamic_pointer_cast<SequenceNode>(ele);

			if (!!sn)
			{
				if (elementType.find(':') != tsStringBase::npos)
				{
					if (sn->FullStructureName() == elementType)
						return sn;
				}
				else
				{
					if (sn->StructureName() == elementType)
						return sn;
				}
			}
		}
	}
	std::shared_ptr<tsXmlNode> node = this->Parent().lock();
	std::shared_ptr<tsXmlNode> top;

	while (!!node)
	{
		top = node;
		node = node->Parent().lock();
	}
	if (!top)
		return nullptr;
	return SearchChildrenForSequence(top, elementType);
}
std::shared_ptr<NamedInt> ProcessableNode::FindNamedInt(const tsStringBase& elementType)
{
	std::shared_ptr<FileNode> fileNode = GetFileNode();

	if (!!fileNode)
	{
		for (auto& ele : fileNode->Elements())
		{
			std::shared_ptr<NamedInt> sn = std::dynamic_pointer_cast<NamedInt>(ele);

			if (!!sn)
			{
				if (sn->Name() == elementType)
					return sn;
			}
		}
	}
	std::shared_ptr<tsXmlNode> node = this->Parent().lock();
	std::shared_ptr<tsXmlNode> top;

	while (!!node)
	{
		top = node;
		node = node->Parent().lock();
	}
	if (!top)
		return nullptr;
	return SearchChildrenForNamedInt(top, elementType);
}
std::shared_ptr<SequenceOfNode> ProcessableNode::FindSequenceOf(const tsStringBase& elementType)
{
	std::shared_ptr<FileNode> fileNode = GetFileNode();

	if (!!fileNode)
	{
		for (auto& ele : fileNode->Elements())
		{
			std::shared_ptr<SequenceOfNode> sn = std::dynamic_pointer_cast<SequenceOfNode>(ele);

			if (!!sn)
			{
				if (elementType.find(':') != tsStringBase::npos)
				{
					if (sn->FullStructureName() == elementType)
						return sn;
				}
				else
				{
					if (sn->StructureName() == elementType)
						return sn;
				}
			}
		}
	}
	std::shared_ptr<tsXmlNode> node = this->Parent().lock();
	std::shared_ptr<tsXmlNode> top;

	while (!!node)
	{
		top = node;
		node = node->Parent().lock();
	}
	if (!top)
		return nullptr;
	return SearchChildrenForSequenceOf(top, elementType);
}
std::shared_ptr<EnumNode> ProcessableNode::FindEnum(const tsStringBase& elementType)
{
	std::shared_ptr<FileNode> fileNode = GetFileNode();

	if (!!fileNode)
	{
		for (auto& ele : fileNode->Elements())
		{
			std::shared_ptr<EnumNode> sn = std::dynamic_pointer_cast<EnumNode>(ele);

			if (!!sn)
			{
				if (elementType.find(':') != tsStringBase::npos)
				{
					if (sn->FullName() == elementType)
						return sn;
				}
				else
				{
					if (sn->Name() == elementType)
						return sn;
				}
			}
		}
	}
	std::shared_ptr<tsXmlNode> node = this->Parent().lock();
	std::shared_ptr<tsXmlNode> top;

	while (!!node)
	{
		top = node;
		node = node->Parent().lock();
	}
	if (!top)
		return nullptr;
	return SearchChildrenForEnum(top, elementType);
}
std::shared_ptr<BitstringNode> ProcessableNode::FindBitstring(const tsStringBase& elementType)
{
	std::shared_ptr<FileNode> fileNode = GetFileNode();

	if (!!fileNode)
	{
		for (auto& ele : fileNode->Elements())
		{
			std::shared_ptr<BitstringNode> sn = std::dynamic_pointer_cast<BitstringNode>(ele);

			if (!!sn)
			{
				if (elementType.find(':') != tsStringBase::npos)
				{
					if (sn->FullName() == elementType)
						return sn;
				}
				else
				{
					if (sn->Name() == elementType)
						return sn;
				}
			}
		}
	}
	std::shared_ptr<tsXmlNode> node = this->Parent().lock();
	std::shared_ptr<tsXmlNode> top;

	while (!!node)
	{
		top = node;
		node = node->Parent().lock();
	}
	if (!top)
		return nullptr;
	return SearchChildrenForBitstring(top, elementType);
}
std::shared_ptr<SetNode> ProcessableNode::FindSet(const tsStringBase& elementType)
{
	std::shared_ptr<FileNode> fileNode = GetFileNode();

	if (!!fileNode)
	{
		for (auto& ele : fileNode->Elements())
		{
			std::shared_ptr<SetNode> sn = std::dynamic_pointer_cast<SetNode>(ele);

			if (!!sn)
			{
				if (elementType.find(':') != tsStringBase::npos)
				{
					if (sn->FullStructureName() == elementType)
						return sn;
				}
				else
				{
					if (sn->StructureName() == elementType)
						return sn;
				}
			}
		}
	}
	std::shared_ptr<tsXmlNode> node = this->Parent().lock();
	std::shared_ptr<tsXmlNode> top;

	while (!!node)
	{
		top = node;
		node = node->Parent().lock();
	}
	if (!top)
		return nullptr;
	return SearchChildrenForSet(top, elementType);
}
std::shared_ptr<ChoiceNode> ProcessableNode::FindChoice(const tsStringBase& elementType)
{
	std::shared_ptr<FileNode> fileNode = GetFileNode();

	if (!!fileNode)
	{
		for (auto& ele : fileNode->Elements())
		{
			std::shared_ptr<ChoiceNode> sn = std::dynamic_pointer_cast<ChoiceNode>(ele);

			if (!!sn && sn->StructureName() == elementType)
			{
				if (elementType.find(':') != tsStringBase::npos)
				{
					if (sn->FullStructureName() == elementType)
						return sn;
				}
				else
				{
					if (sn->StructureName() == elementType)
						return sn;
				}
			}
		}
	}
	std::shared_ptr<tsXmlNode> node = this->Parent().lock();
	std::shared_ptr<tsXmlNode> top;

	while (!!node)
	{
		top = node;
		node = node->Parent().lock();
	}
	if (!top)
		return nullptr;
	return SearchChildrenForChoice(top, elementType);
}
std::shared_ptr<FileNode> ProcessableNode::GetFileNode()
{
	std::shared_ptr<tsXmlNode> node = std::dynamic_pointer_cast<tsXmlNode>(_me.lock());

	while (!!node)
	{
		std::shared_ptr<FileNode> fl = std::dynamic_pointer_cast<FileNode>(node);
		std::shared_ptr<Asn1Export> exp = std::dynamic_pointer_cast<Asn1Export>(node);

		if (!!fl)
		{
			return fl;
		}
		if (!!exp)
			return exp->fileNode;
		node = node->Parent().lock();
	}
	return nullptr;
}

