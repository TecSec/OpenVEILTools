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



#ifndef __BITSTRINGNODE_H__
#define __BITSTRINGNODE_H__

#pragma once

#include "DescriptionNode.h"
#include "Element.h"

class BitstringItemNode : public ProcessableNode
{
public:
	BitstringItemNode() {}
	virtual ~BitstringItemNode() {}

	tsStringBase Value() const { return Attributes().item("Value"); }
	tsStringBase Description() const
	{
		const std::shared_ptr<tsXmlNode> node = ChildByName("Description");

		if (!node)
			return "";
		return node->NodeText();
	}
	virtual bool Process() {
		return true;
	}
	virtual bool Validate() {
		if (Validated())
			return true;
		Validated(true);
		if (!Attributes().hasItem("Name"))
		{
			AddError("xml2Asn1CodeGen", "", "BitstringItemNode is missing the Name attribute.\n");
			return false;
		}
		Name(Attributes().item("Name"));
		if (!Attributes().hasItem("Value"))
		{
			AddError("xml2Asn1CodeGen", "", "BitstringItemNode is missing the Value attribute.\n");
			return false;
		}
		int value = atoi(Attributes().item("Value").c_str());
		if (value < 0 || value > 8191)
		{
			AddError("xml2Asn1CodeGen", "", tsStringBase().append("BitstringItemNode value for item ").append(Attributes().item("Name")).append(" is invalid.  We only support values of 0 - 8191 at this time.  You specified ").append(value));
			return false;
		}
		for (size_t i = 0; i < Children().size(); i++)
		{
			std::shared_ptr<tsXmlNode> node = Children().at(i);
			std::shared_ptr<ProcessableNode> pNode = std::dynamic_pointer_cast<ProcessableNode>(node);
			if (!pNode)
				return false;
			if (!pNode->Validate())
				return false;
		}
		return true;
	}
protected:
	virtual std::shared_ptr<tsXmlNode> CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes)
	{
		std::shared_ptr<tsXmlNode> tmp;

		if (name == "Description")
		{
			tmp = IObject::Create<DescriptionNode>();
		}
		if (!!tmp)
		{
			tmp->Attributes() = Attributes;
			return tmp;
		}
		return nullptr;
	}

};

class BitstringNode : public Element
{
public:
	BitstringNode() { ElementType("bitstring"); }
	virtual ~BitstringNode() {}

	virtual bool Process() override {
		return true;
	}
	virtual bool Validate() override {
		if (Validated())
			return true;
		Validated(true);
		if (!Attributes().hasItem("Name"))
		{
			AddError("xml2Asn1CodeGen", "", "Bitstring is missing the Name attribute.\n");
			return false;
		}
		this->Name(Attributes().item("Name"));
		this->Export(Attributes().itemAsBoolean("Exported", false));
		Import(Attributes().itemAsBoolean("Imported", false));
		for (size_t i = 0; i < Children().size(); i++)
		{
			std::shared_ptr<tsXmlNode> node = Children().at(i);
			std::shared_ptr<ProcessableNode> pNode = std::dynamic_pointer_cast<ProcessableNode>(node);

			if (!pNode)
				return false;
			if (!pNode->Validate())
				return false;
		}
		return true;
	}
	virtual tsStringBase FullName() override;
	virtual bool WriteForwardReference(std::shared_ptr<FileNode> files) override;
	virtual bool WriteStructure(std::shared_ptr<FileNode> files) override;
	virtual bool usesSeparateClass() const override { return false; }
	virtual bool WriteExportElement(std::shared_ptr<FileNode> files) override { UNREFERENCED_PARAMETER(files); return true; }
protected:
	virtual std::shared_ptr<tsXmlNode> CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes) override
	{
		std::shared_ptr<tsXmlNode> tmp;

		if (name == "ID")
		{
			tmp = IObject::Create<BitstringItemNode>();
		}
		else if (name == "Description")
		{
			tmp = IObject::Create<DescriptionNode>();
		}
		if (!!tmp)
		{
			tmp->Attributes() = Attributes;
			return tmp;
		}
		AddError("xml2Asn1CodeGen", "CreateNode", "Unable to create node " + name, 2000);
		return nullptr;
	}

};

#endif // __BITSTRINGNODE_H__
