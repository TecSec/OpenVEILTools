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
#include "Namespace.h"
#include "FileNode.h"
#include "BitstringNode.h"
#include "NamedInt.h"

void Namespace::Open(File* f)
{
	if (!!parent())
		parent()->Open(f);

	if (f->Language() == "C++")
	{
		f->WriteLine("namespace " + Name() + " {");
	}
	else
	{
		f->WriteLine("<Namespace Name=\"" + Name() + "\">");
	}
	f->indent();
}
void Namespace::Close(File* f)
{
	f->outdent();
	if (f->Language() == "C++")
	{
		f->WriteLine("}; // namespace " + Name());
	}
	else
	{
		f->WriteLine("</Namespace>");
	}
	if (!!parent())
		parent()->Close(f);
}

std::shared_ptr<tsXmlNode> NamespaceNode::CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes)
{
	std::shared_ptr<tsXmlNode> tmp;
	std::shared_ptr<FileNode> fn = GetFileNode();

	// TODO:  Synchronize with FileNode
	if (name == "Namespace")
	{
		tmp = IObject::Create<NamespaceNode>();
	}
	else  if (name == "Include")
	{
		tmp = IObject::Create<IncludeNode>();
		tmp->Attributes() = Attributes;
		fn->AddInclude(std::dynamic_pointer_cast<IncludeNode>(tmp));
	}
	else  if (name == "ID")
	{
		tmp = IObject::Create<IDNode>();
		fn->OIDs().push_back(std::dynamic_pointer_cast<IDNode>(tmp));
	}
	else  if (name == "Alias")
	{
		tmp = IObject::Create<AliasNode>();
		tmp->Attributes() = Attributes;
		if (!fn->AddElement(std::dynamic_pointer_cast<Element>(tmp)))
		{
			AddError("xml2Asn1CodeGen", "CreateNode", "This global alias name is already used:  " + Attributes.item("Name"), 2000);
			return nullptr;
		}
	}
	else  if (name == "Enum")
	{
		tmp = IObject::Create<EnumNode>();
		tmp->Attributes() = Attributes;
		if (!fn->AddElement(std::dynamic_pointer_cast<Element>(tmp)))
		{
			AddError("xml2Asn1CodeGen", "CreateNode", "This global enum name is already used:  " + Attributes.item("Name"), 2000);
			return nullptr;
		}
	}
	else  if (name == "Bitstring")
	{
		tmp = IObject::Create<BitstringNode>();
		tmp->Attributes() = Attributes;
		if (!fn->AddElement(std::dynamic_pointer_cast<Element>(tmp)))
		{
			AddError("xml2Asn1CodeGen", "CreateNode", "This global bitstring name is already used:  " + Attributes.item("Name"), 2000);
			return nullptr;
		}
	}
	else  if (name == "Sequence")
	{
		tmp = IObject::Create<SequenceNode>();
		tmp->Attributes() = Attributes;
		if (!fn->AddElement(std::dynamic_pointer_cast<Element>(tmp)))
		{
			AddError("xml2Asn1CodeGen", "CreateNode", "This global sequence name is already used:  " + Attributes.item("Name"), 2000);
			return nullptr;
		}
	}
	else  if (name == "SequenceOf")
	{
		tmp = IObject::Create<SequenceOfNode>();
		tmp->Attributes() = Attributes;
		if (!fn->AddElement(std::dynamic_pointer_cast<Element>(tmp)))
		{
			AddError("xml2Asn1CodeGen", "CreateNode", "This global sequenceof name is already used:  " + Attributes.item("Name"), 2000);
			return nullptr;
		}
	}
	else  if (name == "Choice")
	{
		tmp = IObject::Create<ChoiceNode>();
		tmp->Attributes() = Attributes;
		if (!fn->AddElement(std::dynamic_pointer_cast<Element>(tmp)))
		{
			AddError("xml2Asn1CodeGen", "CreateNode", "This global choice name is already used:  " + Attributes.item("Name"), 2000);
			return nullptr;
		}
	}
	else  if (name == "Set")
	{
		tmp = IObject::Create<SetNode>();
		tmp->Attributes() = Attributes;
		if (!fn->AddElement(std::dynamic_pointer_cast<Element>(tmp)))
		{
			AddError("xml2Asn1CodeGen", "CreateNode", "This global set name is already used:  " + Attributes.item("Name"), 2000);
			return nullptr;
		}
	}
	else  if (name == "NamedInt")
	{
		tmp = IObject::Create<NamedInt>();
		tmp->Attributes() = Attributes;
		if (!fn->AddElement(std::dynamic_pointer_cast<Element>(tmp)))
		{
			std::shared_ptr<tsXmlNode> root = fn->Parent().lock();

			while (!root->Parent().expired())
				root = root->Parent().lock();

			tsStringBase xml;

			root->BuildXML(xml, false);

			AddError("xml2Asn1CodeGen", "CreateNode", "This global NamedInt name is already used:  " + Attributes.item("Name"), 2000);
			return nullptr;
		}
	}
	if (!!tmp)
	{
		tmp->Attributes() = Attributes;
		return tmp;
	}
	AddError("xml2Asn1CodeGen", "CreateNode", "Unable to create node " + name, 2000);
	return nullptr;
}
