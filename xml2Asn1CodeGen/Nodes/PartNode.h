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


#ifndef __PARTNODE_H__
#define __PARTNODE_H__

#pragma once

#include "TaggedElement.h"
#include "ElementContainer.h"

class SequenceNode;
class FunctionNode;
class VersionNode;

class PartNode : public TaggedElement, public ElementContainer
{
public:
	PartNode() : _dontWrap(false), _export(false), _usedWithOptional(false), _usedWithArray(false), _hasOID(false), _hasVersion(false), _defaultVersion(0)
	{
		_parentType = "Asn1DataHolder";
		ElementType("SequencePart");
	}
	virtual ~PartNode() {}

	virtual bool Validate() override;
	virtual bool Process() override;

	virtual tsStringBase StructureName() const override { return Element::StructureName(); }
	virtual void StructureName(const tsStringBase& setTo) override { Element::StructureName(setTo); }
	virtual std::shared_ptr<Namespace> NameSpace() override { return Element::NameSpace(); }
	virtual tsStringBase NameForParent() override { return StructureName(); }


	std::vector<std::shared_ptr<FunctionNode>>& Functions() { return _functions; }
	std::vector<std::shared_ptr<VersionNode>>& Versions() { return _versions; }
	//tsVector<PartNode*>& Parts() { return _parts; }

	bool DontWrap() const { return _dontWrap; }
	void DontWrap(bool setTo) { _dontWrap = setTo; }
	bool Export() const { return _export; }
	void Export(bool setTo) { _export = setTo; }
	bool UsedWithOptional() const { return _usedWithOptional; }
	void UsedWithOptional(bool setTo) { _usedWithOptional = setTo; }
	bool UsedWithArray() const { return _usedWithArray; }
	void UsedWithArray(bool setTo) { _usedWithArray = setTo; }
	bool HasOID() const { return _hasOID; }
	void HasOID(bool setTo) { _hasOID = setTo; }
	bool HasVersion() const { return _hasVersion; }
	void HasVersion(bool setTo) { _hasVersion = setTo; }
	int DefaultVersion() const { return _defaultVersion; }
	void DefaultVersion(int setTo) { _defaultVersion = setTo; }
	tsStringBase ParentType() const { return _parentType; }
	void ParentType(const tsStringBase& setTo) { _parentType = setTo; }
	tsStringBase DefaultOID() const { return _defaultOID; }
	void DefaultOID(const tsStringBase& setTo) { _defaultOID = setTo; }

	virtual bool WritePODStructure(std::shared_ptr<FileNode> files) override;

	virtual bool WriteToJSON(std::shared_ptr<FileNode> files);
	virtual bool WriteFromJSON(std::shared_ptr<FileNode> files);

	virtual bool usesSeparateClass() const override { return true; } // TODO:  not sure on this one
	std::shared_ptr<Element> FindElement(std::shared_ptr<Element> ele);
	virtual bool WriteExportElement(std::shared_ptr<FileNode> files) override { UNREFERENCED_PARAMETER(files); return true; }
private:
    using TaggedElement::WriteToJSON;
    using TaggedElement::WriteFromJSON;
protected:
	std::vector<std::shared_ptr<FunctionNode>> _functions;
	std::vector<std::shared_ptr<VersionNode>> _versions;
	//tsVector<PartNode*> _parts;
	bool _dontWrap;
	bool _export;
	bool _usedWithOptional;
	bool _usedWithArray;
	bool _hasOID;
	bool _hasVersion;
	tsStringBase _parentType;
	tsStringBase _defaultOID;
	int _defaultVersion;

	virtual std::shared_ptr<tsXmlNode> CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes) override;
};

#endif // __PARTNODE_H__
