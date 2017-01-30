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


#ifndef __OIDNODE_H__
#define __OIDNODE_H__

#pragma once

class FileNode;
class Element;
class NamespaceNode;
class Namespace;

#include "DescriptionNode.h"

class IDNode : public ProcessableNode
{
public:
	IDNode(){}
	virtual ~IDNode(){}

	virtual bool Process() override {
		return true;
	}
	virtual bool Validate() override {
		if (Validated())
			return true;
		Validated(true);
		if (!Attributes().hasItem("Name"))
		{
			AddError("xml2Asn1CodeGen", "", "OID is missing the Name attribute.\n");
			return false;
		}
		Name(Attributes().item("Name"));
		if (!Attributes().hasItem("Value"))
		{
			AddError("xml2Asn1CodeGen", "", "OID is missing the Value attribute.\n");
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
	tsStringBase Value() const { return Attributes().item("Value"); }
	void Value(const tsStringBase& setTo) { Attributes().AddItem("Value", setTo); }
	bool Export() const { return Attributes().itemAsBoolean("Exported", false); }
	bool Import() const { return Attributes().itemAsBoolean("Imported", false); }
	tsStringBase Description() const
	{
		const std::shared_ptr<tsXmlNode> node = ChildByName("Description");

		if (!node)
			return "";
		return node->NodeText();
	}

	void WriteOID(std::shared_ptr<FileNode> files);

	virtual std::shared_ptr<Namespace> NameSpace();
	std::shared_ptr<NamespaceNode> ParentNamespace();

protected:
	virtual std::shared_ptr<tsXmlNode> CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes) override
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
		AddError("xml2Asn1CodeGen", "CreateNode", "Unable to create node " + name, 2000);
		return nullptr;
	}
	std::shared_ptr<Element> GetParentElement();

	std::shared_ptr<Namespace> _namespace;

private:
    using ProcessableNode::CreateNode;
};

#endif // __OIDNODE_H__
