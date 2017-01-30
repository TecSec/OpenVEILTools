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



#ifndef __VERSIONNODE_H__
#define __VERSIONNODE_H__

#pragma once

#include "ElementContainer.h"
#include "Namespace.h"

class VersionNode : public ProcessableNode, public ElementContainer
{
public:
	VersionNode() : _hasOID(false), _hasVersion(false), _minVersion(0), _maxVersion(0)
	{
	}
	virtual ~VersionNode() {}

	virtual bool Validate() override;
	virtual bool Process() override;
	virtual tsStringBase NameForParent() { return StructureName(); }

	bool HasOID() const { return _hasOID; }
	void HasOID(bool setTo) { _hasOID = setTo; }
	bool HasVersion() const { return _hasVersion; }
	void HasVersion(bool setTo) { _hasVersion = setTo; }
	tsStringBase Description() const
	{
		const std::shared_ptr<tsXmlNode> node = ChildByName("Description");

		if (!node)
			return "";
		return node->NodeText();
	}
	tsStringBase OID() const { return _oid; }
	void OID(const tsStringBase& setTo) { _oid = setTo; }
	tsStringBase StructureName() const override { return _structureName; }
	void StructureName(const tsStringBase& setTo) override { _structureName = setTo; }

	int minVersion() const { return _minVersion; }
	void minVersion(int setTo) { _minVersion = setTo; }
	int maxVersion() const { return _maxVersion; }
	void maxVersion(int setTo) { _maxVersion = setTo; }

	std::shared_ptr<Namespace> NameSpace() override
	{
		if (!!_namespace)
			return _namespace;

		std::shared_ptr<tsXmlNode> node = std::dynamic_pointer_cast<tsXmlNode>(_me.lock());

		while (!!node)
		{
			std::shared_ptr<NamespaceNode> nn = std::dynamic_pointer_cast<NamespaceNode>(node);

			if (!!nn)
			{
				_namespace = nn->CreateNamespace();
				return _namespace;
			}
			node = node->Parent().lock();
		}
		return std::shared_ptr<Namespace>(new RootNamespace());
	}
	void WritePODVersionElementAccessors(std::shared_ptr<FileNode> files);
protected:
	bool _hasOID;
	bool _hasVersion;
	tsStringBase _oid;
	tsStringBase _structureName;
	int _minVersion;
	int _maxVersion;
	std::shared_ptr<Namespace> _namespace;


	virtual std::shared_ptr<tsXmlNode> CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes) override;
};

#endif // __VERSIONNODE_H__
