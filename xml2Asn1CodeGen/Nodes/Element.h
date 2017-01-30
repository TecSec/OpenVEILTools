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



#ifndef __ELEMENT_H__
#define __ELEMENT_H__

#pragma once

class FileNode;
class Namespace;
class ElementContainer;
class SequenceNode;
class NamespaceNode;

class Element : public ProcessableNode
{
public:
	Element();
	virtual ~Element();

	const std::vector<std::shared_ptr<Element>>& Dependencies() const { return _dependencies; }
	bool AddDependency(std::shared_ptr<Element> ele)
	{
		tsStringBase eleName = ele->Attributes().item("Name");
		for (auto& e : _dependencies)
		{
			if (e->Attributes().item("Name") == eleName)
			{
				return false;
			}
		}
		_dependencies.push_back(ele);
		return true;
	}
	bool StructureWritten() const { return _structureWritten; }
	void StructureWritten(bool setTo) { _structureWritten = setTo; }
	bool PODStructureWritten() const { return _PODstructureWritten; }
	void PODStructureWritten(bool setTo) { _PODstructureWritten = setTo; }
	bool FieldMetadataWritten() const { return _fieldMetadataWritten; }
	void FieldMetadataWritten(bool setTo) { _fieldMetadataWritten = setTo; }
	bool ForwardsWritten() const { return _forwardsWritten; }
	void ForwardsWritten(bool setTo) { _forwardsWritten = setTo; }
	bool ContainedInArray() const { return _containedInArray; }
	void ContainedInArray(bool setTo) { _containedInArray = setTo; }
	bool UseNumberHandling() const { return _useNumberHandling; }
	void UseNumberHandling(bool setTo) { _useNumberHandling = setTo; }
	tsStringBase Default() const { return _default; }
	void Default(const tsStringBase& setTo) { _default = setTo; }
	tsStringBase Initializer() const { return _initializer; }
	void Initializer(const tsStringBase& setTo) { _initializer = setTo; }
	tsStringBase ElementType() const { return _elementType; }
	void ElementType(const tsStringBase& setTo) { _elementType = setTo; }
	virtual tsStringBase StructureName() const { return _structureName; }
	virtual tsStringBase PODStructureName() const { return _PODstructureName; }
	virtual tsStringBase FullStructureName();
	virtual void StructureName(const tsStringBase& setTo) {
		_structureName = setTo; 

		tsStringBaseList list = tsStringBase(setTo).split(':');
		tsStringBase pod;

		for (size_t i = 0; i < list.size() - 1; i++)
		{
			if (!pod.empty())
			{
				pod << "::";
			}
			pod << list.at(i);
		}
		if (!pod.empty())
		{
			pod << "::";
		}
		pod << "_POD_" << list.back();
		_PODstructureName = pod;
	}
	tsStringBase CppType() const { return _cppType; }
	void CppType(const tsStringBase& setTo) { _cppType = setTo; }
	virtual tsStringBase JSONName() const { return _jsonName; }
	virtual void JSONName(const tsStringBase& setTo) { _jsonName = setTo; }
	virtual tsStringBase EncodedType() const { return _encodedType; }
	virtual void EncodedType(const tsStringBase& setTo) { _encodedType = setTo; }
	virtual tsStringBase EncodedAccessor() const { return _encodedAccessor; }
	virtual void EncodedAccessor(const tsStringBase& setTo) { _encodedAccessor = setTo; }
	virtual tsStringBase NameForParent()
	{
		return Name();
	}
	virtual tsStringBase CppTypeForArray() const { return _cppType; }
	//public Namespace NameSpace{ get; set; }
	virtual bool WriteForwardReference(std::shared_ptr<FileNode> files) { UNREFERENCED_PARAMETER(files); return true; }

	std::shared_ptr<Element> GetParentElement();
	virtual bool IsArray() { return false; }
	virtual bool IsOptional() { return _isOptional; }
	virtual void IsOptional(bool setTo) { _isOptional = setTo; }
	bool Export() const { return _export; }
	void Export(bool setTo) { _export = setTo; }
	bool Import() const { return _import; }
	void Import(bool setTo) { _import = setTo; }
	virtual tsStringBase GetArrayStructureName() { return ""; }
	virtual tsStringBase GetArrayElementStructureName() { return ""; }
	virtual bool WritePODStructure(std::shared_ptr<FileNode> files);
	virtual bool WriteStructure(std::shared_ptr<FileNode> files);
	//virtual bool WriteFieldDefinition(std::shared_ptr<FileNode> files) { UNREFERENCED_PARAMETER(files); return true; }
	virtual bool WritePODFieldDefinition(std::shared_ptr<FileNode> files) { UNREFERENCED_PARAMETER(files); return true; }
	virtual bool WriteAccessors(std::shared_ptr<FileNode> files, const tsStringBase& structureName);
	virtual bool WriteCopyLine(File* file);

	typedef enum { ForConstruct, ForCopy, ForMove } InitializerType;

	virtual void BuildInitializer(InitializerType type, tsStringBase& tmp) { UNREFERENCED_PARAMETER(type); UNREFERENCED_PARAMETER(tmp); }
	virtual tsStringBase BuildInequalityTest(const tsStringBase& rightObject);
	virtual tsStringBase BuildCloneLine(const tsStringBase& rightObject);
	virtual tsStringBase BuildCopyLine(const tsStringBase& rightObject);
	virtual tsStringBase BuildMoveLine(const tsStringBase& rightObject);
	virtual tsStringBase BuildClearForMove(const tsStringBase& rightObject);
	virtual tsStringBase BuildMetadataLine(const tsStringBase& structureName, const tsStringBase& PODstructureName);
	//virtual tsCryptoString GetOptionalElementType();
	//virtual tsCryptoString GetOptionalValueOffset();
	virtual tsStringBase GetTagOffset(const tsStringBase& structureName, const tsStringBase& PODstructureName);
	virtual tsStringBase GetTypeOffset(const tsStringBase& structureName, const tsStringBase& PODstructureName);
	virtual tsStringBase GetSubobjectValueOffset();
	//virtual tsCryptoString GetOptionalExistsOffset();
	virtual bool WriteUserFunctions(File* file) { UNREFERENCED_PARAMETER(file); return true; }
	virtual bool WriteToJSON(File* file);
	virtual bool WriteFromJSON(File* file) { UNREFERENCED_PARAMETER(file); return true; }
	virtual tsStringBase BuildTagString();
	virtual tsStringBase BuildTypeString();
	virtual bool WriteSubMetadata(std::shared_ptr<FileNode> files, const tsStringBase& structureName, const tsStringBase& PODstructureName) { UNREFERENCED_PARAMETER(files); UNREFERENCED_PARAMETER(structureName); UNREFERENCED_PARAMETER(PODstructureName); return true; }

	static std::vector<tsStringBase>& UserDefinedBasicTypes() { return _userDefinedBasicTypes; }
	static bool isBasicType(const tsStringBase& baseType);

	tsStringBase Description() const
	{
		const std::shared_ptr<tsXmlNode> node = ChildByName("Description");

		if (!node)
			return "";
		return node->NodeText();
	}
	virtual std::shared_ptr<Namespace> NameSpace();

	std::shared_ptr<SequenceNode> ParentSequence();
	std::shared_ptr<SequenceOfNode> ParentSequenceOf();
	std::shared_ptr<ChoiceNode> ParentChoice();
	std::shared_ptr<ElementContainer> ParentContainer();
	std::shared_ptr<Element> MatchingElement();
	std::shared_ptr<NamespaceNode> ParentNamespace();
	std::shared_ptr<FileNode> ParentFileNode();

	virtual bool usesSeparateClass() const = 0;
	tsStringBase BuildStructureName();

	virtual bool WriteExportElement(std::shared_ptr<FileNode> files) = 0;

protected:
	std::shared_ptr<SequenceNode> _parentSequence;
	std::shared_ptr<ElementContainer> _parentContainer;
	std::shared_ptr<Element> _matchingElement;
	static std::vector<tsStringBase> _userDefinedBasicTypes;
	std::vector<std::shared_ptr<Element>> _dependencies;
	bool _PODstructureWritten;
	bool _structureWritten;
	bool _fieldMetadataWritten;
	bool _forwardsWritten;
	bool _containedInArray;
	bool _useNumberHandling;
	bool _isOptional;
	bool _export;
	bool _import;
	tsStringBase _default;
	tsStringBase _initializer;
	tsStringBase _elementType;
	tsStringBase _structureName;
	tsStringBase _PODstructureName;
	tsStringBase _cppType;
	tsStringBase _jsonName;
	tsStringBase _encodedType;
	tsStringBase _encodedAccessor;
	std::shared_ptr<Namespace> _namespace;
};

#endif // __ELEMENT_H__
