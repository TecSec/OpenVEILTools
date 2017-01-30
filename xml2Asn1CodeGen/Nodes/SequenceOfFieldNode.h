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


#ifndef __SEQUENCEOFFIELDNODE_H__
#define __SEQUENCEOFFIELDNODE_H__

#pragma once

#include "TaggedElement.h"
#include "ElementContainer.h"
#include "SequenceOfNode.h"

class FileNode;

class SequenceOfFieldNode : public TaggedElement, public ElementContainer
{
public:
	SequenceOfFieldNode()
	{
		ElementType("SequenceOfField");
	}
	virtual ~SequenceOfFieldNode() {}

	virtual bool Validate() override;
	virtual bool Process() override;

	tsStringBase ElementName() const { return _elementName; }
	void ElementName(const tsStringBase& setTo) { _elementName = setTo; }
	virtual void StructureName(const tsStringBase& setTo) override { Element::StructureName(setTo); }
	virtual std::shared_ptr<Namespace> NameSpace() override { return Element::NameSpace(); }
	virtual tsStringBase NameForParent() override { return ElementName(); }

	virtual bool IsArray() override;
	virtual tsStringBase GetArrayStructureName() override;
	virtual tsStringBase GetArrayElementStructureName() override;
	virtual bool WritePODFieldDefinition(std::shared_ptr<FileNode> files) override;
	virtual bool WriteToJSON(File* file) override;
	virtual bool WriteFromJSON(File* file) override;
	virtual tsStringBase BuildMoveLine(const tsStringBase& rightObject) override;
	virtual tsStringBase BuildClearForMove(const tsStringBase& rightObject) override;
	virtual tsStringBase BuildCopyLine(const tsStringBase& rightObject) override;
	virtual tsStringBase BuildCloneLine(const tsStringBase& rightObject) override;
	virtual tsStringBase BuildMetadataLine(const tsStringBase& structureName, const tsStringBase& PODstructureName) override;
	virtual void BuildInitializer(InitializerType type, tsStringBase& tmp) override;

	virtual bool usesSeparateClass() const override { return true; }
	virtual bool WriteExportElement(std::shared_ptr<FileNode> files) override;

	virtual tsStringBase StructureName() const override { if (!!_element) return _element->StructureName(); return Element::StructureName(); }
	virtual tsStringBase FullStructureName() override {
		if (!!_element) 
			return _element->FullStructureName(); 
		return Element::FullStructureName();
	}

protected:
	virtual std::shared_ptr<tsXmlNode> CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes) override;

	std::shared_ptr<SequenceOfNode> _element;

	tsStringBase _elementName;
};

#endif // __SEQUENCEOFFIELDNODE_H__
