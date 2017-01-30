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



#ifndef __SEQUENCEOFNODE_H__
#define __SEQUENCEOFNODE_H__

#pragma once

#include "TaggedElement.h"
#include "ElementContainer.h"

class FunctionNode;

class SequenceOfNode : public TaggedElement, public ElementContainer
{
public:
	SequenceOfNode() : _usedWithOptional(false), _usedWithArray(false), _isFinal(true)
	{
		_parentType = "Asn1DataHolder";
		ElementType("SequenceOf");
	}
	virtual ~SequenceOfNode() {}

	virtual bool Validate() override;
	virtual bool Process() override;
	virtual tsStringBase FullName() override;
	virtual tsStringBase FullStructureName() override;

	tsStringBase ElementName() const { return _elementName; }
	tsStringBase ArrayType() const { return _arrayType; }
	//tsCryptoString ArrayCreateType() const { return _arrayCreateType; }
	void ElementName(const tsStringBase& setTo) { _elementName = setTo; }
	virtual tsStringBase StructureName() const override { return Element::StructureName(); }
	virtual void StructureName(const tsStringBase& setTo) override { Element::StructureName(setTo); }
	virtual std::shared_ptr<Namespace> NameSpace() override { return Element::NameSpace(); }
	virtual tsStringBase NameForParent() override { return ElementName(); }
	
	std::vector<std::shared_ptr<FunctionNode>>& Functions() { return _functions; }

	//bool Final() const { return _isFinal; }
	//void Final(bool setTo) { _isFinal = setTo; }
	//bool UsedWithOptional() const { return _usedWithOptional; }
	//void UsedWithOptional(bool setTo) { _usedWithOptional = setTo; }
	//bool UsedWithArray() const { return _usedWithArray; }
	//void UsedWithArray(bool setTo) { _usedWithArray = setTo; }
	//tsCryptoString ParentType() const { return _parentType; }
	//void ParentType(const tsCryptoString& setTo) { _parentType = setTo; }

	virtual bool WriteForwardReference(std::shared_ptr<FileNode> files) override;
	virtual bool WritePODStructure(std::shared_ptr<FileNode> files) override;
	virtual bool WriteStructure(std::shared_ptr<FileNode> files) override;
	virtual bool _WriteUserFunctions(File* file);
	bool WriteMetadataLine(std::shared_ptr<FileNode> files, int& versionEleCount);

	virtual bool IsArray() override;
	virtual tsStringBase GetArrayStructureName() override;
	virtual tsStringBase GetArrayElementStructureName() override;
	virtual bool WritePODFieldDefinition(std::shared_ptr<FileNode> files) override;
	virtual bool WriteToJSON(File* file) override;
	virtual bool WriteFromJSON(File* file) override;
	virtual void BuildSequenceOfInitializer(tsStringBase& tmp);
	virtual tsStringBase BuildMoveLine(const tsStringBase& rightObject) override;
	virtual tsStringBase BuildClearForMove(const tsStringBase& rightObject) override;
	virtual tsStringBase BuildCopyLine(const tsStringBase& rightObject) override;
	virtual tsStringBase BuildCloneLine(const tsStringBase& rightObject) override;
	virtual tsStringBase BuildSequenceOfMetadataLine(const tsStringBase& structureName);
	virtual bool WriteSubMetadata(std::shared_ptr<FileNode> files, const tsStringBase& structureName, const tsStringBase& PODstructureName) override;
	virtual bool WriteAccessors(std::shared_ptr<FileNode> files, const tsStringBase& structureName) override;
	virtual bool WriteSequenceOfAccessors(std::shared_ptr<FileNode> files, const tsStringBase& structureName);

	virtual bool usesSeparateClass() const override { return true; }
	virtual bool WriteExportElement(std::shared_ptr<FileNode> files) override { UNREFERENCED_PARAMETER(files); return true; }
protected:
	virtual std::shared_ptr<tsXmlNode> CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes) override;

	std::vector<std::shared_ptr<FunctionNode>> _functions;
	bool _usedWithOptional;
	bool _usedWithArray;
	bool _isFinal;
	tsStringBase _parentType;
	tsStringBase _elementName;
	tsStringBase _arrayType;
	//tsStringBase _arrayCreateType;

	typedef enum { ForConstruct, ForCopy, ForMove } InitializerType;
	tsStringBase buildInitializers(InitializerType type);
};

#endif // __SEQUENCEOFNODE_H__
