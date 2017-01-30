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


#ifndef __SEQUENCENODE_H__
#define __SEQUENCENODE_H__

#pragma once

#include "TaggedElement.h"
#include "ElementContainer.h"

class PartNode;
class VersionNode;
class FunctionNode;

class SequenceNode : public TaggedElement, public ElementContainer
{
public:
	SequenceNode() : _dontWrap(false), _usedWithOptional(false), _usedWithArray(false), _hasOID(false), _hasVersion(false), _isFinal(true), _defaultVersion(0)
	{
		_parentType = "Asn1DataHolder";
		ElementType("Sequence");
	}
	virtual ~SequenceNode() {}

	virtual bool Validate() override;
	virtual bool Process() override;

	virtual tsStringBase FullName() override;
	virtual tsStringBase FullStructureName() override;

	virtual tsStringBase StructureName() const override { return Element::StructureName(); }
	virtual void StructureName(const tsStringBase& setTo) override { Element::StructureName(setTo); }
	virtual std::shared_ptr<Namespace> NameSpace() override { return Element::NameSpace(); }
	virtual tsStringBase NameForParent() override { return StructureName(); }
	
	static std::shared_ptr<tsXmlNode> BuildField(std::shared_ptr<ElementContainer> container, const tsStringBase& name, const tsAttributeMap& Attributes, std::shared_ptr<FileNode> files);

	std::vector<std::shared_ptr<FunctionNode>>& Functions() { return _functions; }
	std::vector<std::shared_ptr<VersionNode>>& Versions() { return _versions; }
	std::vector<std::shared_ptr<PartNode>>& Parts() { return _parts; }

	bool DontWrap() const { return _dontWrap; }
	void DontWrap(bool setTo) { _dontWrap = setTo; }
	bool Final() const { return _isFinal; }
	void Final(bool setTo) { _isFinal = setTo; }
	bool UsedWithOptional() const { return _usedWithOptional; }
	void UsedWithOptional(bool setTo) { _usedWithOptional = setTo; }
	bool UsedWithArray() const { return _usedWithArray; }
	void UsedWithArray(bool setTo) { _usedWithArray = setTo; }
	bool InheritedHasOID() const { if (!!_inheritedFrom) return _inheritedFrom->HasOID(); return false; }
	bool HasOID() const { if (!_hasOID && !!_inheritedFrom) return _inheritedFrom->HasOID(); return _hasOID; }
	void HasOID(bool setTo) { _hasOID = setTo; }
	bool InheritedHasVersion() const { if (!!_inheritedFrom) return _inheritedFrom->HasVersion(); return false; }
	bool HasVersion() const { if (!_hasVersion && !!_inheritedFrom) return _inheritedFrom->HasVersion(); return _hasVersion; }
	void HasVersion(bool setTo) { _hasVersion = setTo; }
	int DefaultVersion() const { return _defaultVersion; }
	void DefaultVersion(int setTo) { _defaultVersion = setTo; }
	tsStringBase ParentType() const { return _parentType; }
	void ParentType(const tsStringBase& setTo) { _parentType = setTo; }
	tsStringBase DefaultOID() const { return _defaultOID; }
	void DefaultOID(const tsStringBase& setTo) { _defaultOID = setTo; }

	virtual bool WriteForwardReference(std::shared_ptr<FileNode> files) override;
	virtual bool WritePODStructure(std::shared_ptr<FileNode> files) override;
	virtual bool WriteStructure(std::shared_ptr<FileNode> files) override;
	virtual bool _WriteUserFunctions(File* file);
	std::shared_ptr<Element> FindElement(std::shared_ptr<Element> ele);
	bool WriteMetadataLine(std::shared_ptr<FileNode> files, int& versionEleCount);

	virtual bool usesSeparateClass() const override { return true; }
	virtual bool WriteExportElements(std::shared_ptr<FileNode> files);
	virtual bool WriteExportElement(std::shared_ptr<FileNode> files) override { UNREFERENCED_PARAMETER(files); return true; }
protected:
	std::vector<std::shared_ptr<FunctionNode>> _functions;
	std::vector<std::shared_ptr<VersionNode>> _versions;
	std::vector<std::shared_ptr<PartNode>> _parts;
	bool _dontWrap;
	bool _usedWithOptional;
	bool _usedWithArray;
	bool _hasOID;
	bool _hasVersion;
	bool _isFinal;
	tsStringBase _parentType;
	tsStringBase _defaultOID;
	int _defaultVersion;
	std::shared_ptr<SequenceNode> _inheritedFrom;

	virtual std::shared_ptr<tsXmlNode> CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes) override;
	tsStringBase buildInitializers(InitializerType type);
};

#endif // __SEQUENCENODE_H__
