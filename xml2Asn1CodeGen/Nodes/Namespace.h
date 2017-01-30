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



#ifndef __NAMESPACE_H__
#define __NAMESPACE_H__

#pragma once

class File;
class IncodeNode;

#include "OIDNode.h"
#include "AliasNode.h"
#include "EnumNode.h"
#include "SetNode.h"

class Namespace
{
public:
	Namespace() : _parent(nullptr)
	{
		//Elements = new List<Element>();
	}
	std::shared_ptr<Namespace> parent() const { return _parent; }
	void parent(std::shared_ptr<Namespace> setTo) { _parent = setTo; }
	tsStringBase Name() const { return _name; }
	void Name(const tsStringBase& setTo) { _name = setTo; }

	virtual tsStringBase ToString()
	{
		return parent()->ToString() + Name() + "::";
	}
	//public List<Element> Elements{ get; set; }
	virtual void Open(File* f);
	virtual void Close(File* f);

protected:
	std::shared_ptr<Namespace> _parent;
	tsStringBase _name;
};

class RootNamespace : public Namespace
{
public:
	virtual tsStringBase ToString()
	{
		return "";
	}
	virtual void Open(File* f)
	{
		UNREFERENCED_PARAMETER(f);
	}
	virtual void Close(File* f)
	{
		UNREFERENCED_PARAMETER(f);
	}
};


class NamespaceNode : public Element
{
public:
	NamespaceNode(){}
	virtual ~NamespaceNode(){}

	virtual bool Process() override {
		return true;
	}
	virtual bool Validate() override {
		if (Validated())
			return true;
		Validated(true);
		if (!Attributes().hasItem("Name"))
		{
			AddError("xml2Asn1CodeGen", "", "Namespace is missing the Name attribute.\n");
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
	std::shared_ptr<Namespace> CreateNamespace()
	{
		if (!!_namespace)
			return _namespace;

		std::shared_ptr<Namespace> tmp = std::shared_ptr<Namespace>(new Namespace());
		std::shared_ptr<Namespace> last = tmp;

		tmp->Name(Attributes().item("Name"));

		std::shared_ptr<tsXmlNode> node = this->Parent().lock();

		while (!!node)
		{
			std::shared_ptr<NamespaceNode> nn = std::dynamic_pointer_cast<NamespaceNode>(node);

			if (!!nn)
			{
				last = nn->CreateNamespace();
				tmp->parent(last);
				_namespace = tmp;
				return _namespace;
			}
			node = node->Parent().lock();
		}

		std::shared_ptr<Namespace> root = std::shared_ptr<Namespace>((Namespace*)new RootNamespace());
		last->parent(root);
		_namespace = tmp;
		return _namespace;
	}
	virtual bool WriteForwardReference(std::shared_ptr<FileNode> files) override { UNREFERENCED_PARAMETER(files); return true; }
	virtual bool WriteStructure(std::shared_ptr<FileNode> files) override { UNREFERENCED_PARAMETER(files); return true; }
	virtual bool usesSeparateClass() const override { return false; }
	virtual bool WriteExportElement(std::shared_ptr<FileNode> files) override { UNREFERENCED_PARAMETER(files); return true; }
protected:
	virtual std::shared_ptr<tsXmlNode> CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes) override;

	std::shared_ptr<Namespace> _namespace;
};

#endif // __NAMESPACE_H__
