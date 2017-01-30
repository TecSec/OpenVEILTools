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
#include "SetNode.h"
#include "DescriptionNode.h"
#include "VersionNode.h"
#include "PartNode.h"
#include "FunctionNode.h"
#include "BasicFieldNode.h"
#include "ChoiceNode.h"
#include "ChoiceFieldNode.h"
#include "SequenceFieldNode.h"
#include "FileNode.h"
#include "SequenceOfFieldNode.h"

bool SequenceNode::Validate()
{
	if (Validated())
		return true;
	Validated(true);
	if (!Attributes().hasItem("Name"))
	{
		AddError("xml2Asn1CodeGen", "", "Sequence is missing the Name attribute.\n");
		return false;
	}

	StructureName(Attributes().item("Name"));
	DontWrap(Attributes().itemAsBoolean("DontWrap", false));
	Export(Attributes().itemAsBoolean("Exported", false));
	Import(Attributes().itemAsBoolean("Imported", false));
	Final(Attributes().itemAsBoolean("Final", true));
	ParentType(Attributes().item("ParentType"));
	if (ParentType().size() == 0)
		ParentType("Asn1DataBaseClass");
	DefaultVersion(Attributes().itemAsNumber("DefaultVersion", 0));
	DefaultOID(Attributes().item("OID"));
	Type(Attributes().item("Type"));
	//if (Type().size() == 0)
	//	Type("Universal");
	Tag(Attributes().item("Tag"));
	//if (Tag().size() == 0)
	//	Tag(DefaultTag(std::dynamic_pointer_cast<tsXmlNode>(_me.lock())));
	JSONName(Attributes().item("JSONName"));

	// First process the main fields (not part or version
	for (size_t i = 0; i < Children().size(); i++)
	{
		std::shared_ptr<tsXmlNode> node = Children().at(i);
		std::shared_ptr<ProcessableNode> pNode = std::dynamic_pointer_cast<ProcessableNode>(node);
		std::shared_ptr<PartNode> pn = std::dynamic_pointer_cast<PartNode>(pNode);
		std::shared_ptr<VersionNode> vn = std::dynamic_pointer_cast<VersionNode>(pNode);

		if (!pNode)
			return false;
		if (!pn && !vn)
		{
			if (!pNode->Validate())
				return false;
		}
	}

	// Now process the part and version nodes
	for (size_t i = 0; i < Children().size(); i++)
	{
		std::shared_ptr<tsXmlNode> node = Children().at(i);
		std::shared_ptr<ProcessableNode> pNode = std::dynamic_pointer_cast<ProcessableNode>(node);
		std::shared_ptr<PartNode> pn = std::dynamic_pointer_cast<PartNode>(pNode);
		std::shared_ptr<VersionNode> vn = std::dynamic_pointer_cast<VersionNode>(pNode);

		if (!pNode)
			return false;
		if (!!pn || !!vn)
		{
			if (!pNode->Validate())
				return false;
		}
	}

	tsXmlNodeList list = ChildrenByName("Version");
	for (auto node : list)
	{
		std::shared_ptr<VersionNode> ver = std::dynamic_pointer_cast<VersionNode>(node);

		if (!!ver)
		{
			HasOID(HasOID() | ver->HasOID());
			HasVersion(HasVersion() | ver->HasVersion());
		}
	}

	list = ChildrenByName("Part");
	for (auto node : list)
	{
		std::shared_ptr<PartNode> part = std::dynamic_pointer_cast<PartNode>(node);

		if (!!part)
		{
			HasOID(HasOID() | part->HasOID());
			HasVersion(HasVersion() | part->HasVersion());
		}
	}

	for (size_t i = 0; i < Children().size(); i++)
	{
		std::shared_ptr<tsXmlNode> node = Children().at(i);
		std::shared_ptr<ChoiceNode> choice = std::dynamic_pointer_cast<ChoiceNode>(node);
		std::shared_ptr<PartNode> part = std::dynamic_pointer_cast<PartNode>(node);
		std::shared_ptr<VersionNode> ver = std::dynamic_pointer_cast<VersionNode>(node);
		std::shared_ptr<SequenceFieldNode> seq = std::dynamic_pointer_cast<SequenceFieldNode>(node);
		std::shared_ptr<SequenceOfNode> seqOf = std::dynamic_pointer_cast<SequenceOfNode>(node);
		std::shared_ptr<ElementContainer> cont = std::dynamic_pointer_cast<ElementContainer>(node);

		if (!!cont && !ver && !part)
		{
			for (auto n : cont->Elements())
			{
				std::shared_ptr<Element> ele = std::dynamic_pointer_cast<Element>(n);

				if (!!ele)
					AddDependency(ele);
			}
		}
		if (!!choice || !!part /*|| !!ver*/ || !!seq || !!seqOf)
		{
			std::shared_ptr<Element> ele = std::dynamic_pointer_cast<Element>(node);
			if (!!ele)
				AddDependency(ele);
		}

	}

	if (ParentType() != "Asn1DataBaseClass")
	{
		tsStringBaseList parts = ParentType().split(":");
		tsStringBase eleType = parts.back();

		_inheritedFrom = FindSequence(eleType);
	}
	return true;
}
bool SequenceNode::Process()
{

	return false;
}
std::shared_ptr<tsXmlNode> SequenceNode::CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes)
{
	std::shared_ptr<tsXmlNode> tmp;

	// TODO:  Synchronize with FileNode
	if (name == "Description")
	{
		tmp = IObject::Create<DescriptionNode>();
	}
	else  if (name == "Version")
	{
		tmp = IObject::Create<VersionNode>();
		Versions().push_back(std::dynamic_pointer_cast<VersionNode>(tmp));
	}
	else  if (name == "Part")
	{
		tmp = IObject::Create<PartNode>();
		Parts().push_back(std::dynamic_pointer_cast<PartNode>(tmp));

	}
	else  if (name == "Function")
	{
		tmp = IObject::Create<FunctionNode>();
		Functions().push_back(std::dynamic_pointer_cast<FunctionNode>(tmp));
	}
	else
	{
		tmp = BuildField(std::dynamic_pointer_cast<ElementContainer>(_me.lock()), name, Attributes, GetFileNode());
	}

	if (!!tmp)
	{
		tmp->Attributes() = Attributes;
		return tmp;
	}
	AddError("xml2Asn1CodeGen", "CreateNode", "Unable to create node " + name, 2000);
	return nullptr;
}


std::shared_ptr<tsXmlNode> SequenceNode::BuildField(std::shared_ptr<ElementContainer> container, const tsStringBase& name, const tsAttributeMap& Attributes, std::shared_ptr<FileNode> files)
{
	UNREFERENCED_PARAMETER(Attributes);

	std::shared_ptr<Element> tmp;

	if (::isBasicEleType(name))
	{
		tmp = IObject::Create<BasicFieldNode>();
		tmp->CppType(getCppType(name));
		tmp->Initializer(getInitializer(name));
		tmp->UseNumberHandling(getUseNumberHandling(name));
		tmp->ElementType(name);
	}
	else if (name == "Choice")
	{
		tmp = IObject::Create<ChoiceFieldNode>();
	}
	else if (name == "SequenceOf")
	{
		tmp = IObject::Create<SequenceOfFieldNode>();
	}
	else if (name == "Set" || name == "Sequence")
	{
		//if (Attributes.hasItem("ElementType"))
		//{
		tmp = IObject::Create<SequenceFieldNode>();
		//}
		//else
		//{
		//	tsCryptoString structName = container->StructureName() + "_" + Attributes.item("Name");

		//	// Create a top level Sequence
		//	std::shared_ptr<SequenceNode> topSequence = CryptoLocator()->Finish<SequenceNode>(new SequenceNode());
		//	topSequence->Attributes().AddItem("Name", structName);

		//	// And then create a SequenceField here that points to it.
		//	tmp = CryptoLocator()->Finish<Element>(new SequenceNode());
		//}
		// TODO:  Handle defineSequences
	}
	else
	{
		return nullptr;
	}

	tmp->Attributes() = Attributes;
	if (!container->AddElement(std::dynamic_pointer_cast<Element>(tmp)))
	{
		std::shared_ptr<Element> ele;
		if (!!(ele = std::dynamic_pointer_cast<Element>(container)))
			ele->AddError("xml2Asn1CodeGen", "CreateNode", "This field name is already used:  " + name, 2000);
		return nullptr;
	}
	return std::dynamic_pointer_cast<tsXmlNode>(tmp);
}

bool SequenceNode::WriteExportElements(std::shared_ptr<FileNode> files)
{
	if (!!_inheritedFrom)
	{
		if (!_inheritedFrom->WriteExportElements(files))
			return false;
	}
	for (auto& ele : Elements())
	{
		if (!ele->WriteExportElement(files))
			return false;
	}
	return true;
}

bool SequenceNode::WriteForwardReference(std::shared_ptr<FileNode> files)
{
	if (!ForwardsWritten())
	{
		ForwardsWritten(true);

		for (auto& ele : Dependencies())
		{
			if (!ele->WriteForwardReference(files))
				return false;
		}

		if (!Import())
		{
			files->Header()->SetNamespace(NameSpace());
			files->Header()->WriteLine("struct " + PODStructureName() + ";");

			if (Export())
			{
				tsStringBase line;

				files->Export()->SetNamespace(NameSpace());
				line.append("<").append(ElementType()).append(" Name=\"").append(StructureName()).append("\" Imported=\"true\"");
				if (Tag().size() > 0)
					line.append(" Tag=\"").append(Tag()).append("\"");
				if (Type().size() > 0)
					line.append(" Tag=\"").append(Type()).append("\"");
				if (HasOID())
					line.append(" HasOID=\"true\"");
				if (HasVersion())
					line += " HasVersion=\"true\"";
				files->Export()->WriteLine(line + ">");
				files->Export()->indent();

				if (!WriteExportElements(files))
					return false;

				files->Export()->outdent();
				files->Export()->WriteLine("</" + ElementType() + ">");
			}
		}
	}
	return true;
}
tsStringBase SequenceNode::buildInitializers(InitializerType type)
{
	tsStringBase tmp;

	if (!!_inheritedFrom)
	{
		if (tmp.size() != 0)
			tmp += ", ";
		switch (type)
		{
		case ForConstruct:
			tmp.append(_inheritedFrom->PODStructureName()).append("()");
			break;
		case ForCopy:
			tmp.append(_inheritedFrom->PODStructureName()).append("(obj)");
			break;
		case ForMove:
			tmp.append(_inheritedFrom->PODStructureName()).append("(std::move(obj))");
			break;
		}
	}
	if (HasOID() && !InheritedHasOID())
	{
		if (DefaultOID().size() != 0 || type != ForConstruct)
		{
			if (tmp.size() != 0)
				tmp += ", ";
			switch (type)
			{
			case ForConstruct:
				tmp.append("_OID(").append(DefaultOID()).append(", tscrypto::tsCryptoData::OID)");
				break;
			case ForCopy:
				tmp.append("_OID(obj._OID)");
				break;
			case ForMove:
				tmp.append("_OID(std::move(obj._OID))");
				break;
			}
		}
	}
	if (HasVersion() && !InheritedHasVersion())
	{
		if (tmp.size() != 0)
			tmp += ", ";
		switch (type)
		{
		case ForConstruct:
			tmp.append("_VERSION(").append(DefaultVersion()).append(")");
			break;
		case ForCopy:
			tmp.append("_VERSION(obj._VERSION)");
			break;
		case ForMove:
			tmp.append("_VERSION(std::move(obj._VERSION))");
			break;
		}
	}

	for (auto e : Elements())
	{
		if (e->IsOptional())
		{
			if (tmp.size() != 0)
				tmp += ", ";

			switch (type)
			{
			case ForConstruct:
				tmp += "_" + e->Name() + "_exists(false)";
				break;
			case ForCopy:
				tmp += "_" + e->Name() + "_exists(obj._" + e->Name() + "_exists)";
				break;
			case ForMove:
				tmp += "_" + e->Name() + "_exists(std::move(obj._" + e->Name() + "_exists))";
				break;
			}
		}
		e->BuildInitializer(type, tmp);
	}

	if (tmp.size() > 0)
		tmp.prepend(" : ");
	return tmp;
}
std::shared_ptr<Element> SequenceNode::FindElement(std::shared_ptr<Element> ele)
{
	for (auto e : Elements())
	{
		if (ele->IsArray() && !e->IsArray())
			continue;
		if (ele->IsArray())
		{
			if (e->Name() == ele->Name())
				return e;
		}
		else if (ele->ElementType() == "ChoiceField" || ele->ElementType() == "Choice")
		{
			if ((e->ElementType() == "Choice" || e->ElementType() == "ChoiceField") && e->Name() == ele->Name())
				return e;
		}
		else if (ele->ElementType() == "SequenceOfField" || ele->ElementType() == "SequenceOf")
		{
			if ((e->ElementType() == "SequenceOf" || e->ElementType() == "SequenceOfField") && e->Name() == ele->Name())
				return e;
		}
		else
		{
			if (e->ElementType() == ele->ElementType() && e->Name() == ele->Name())
				return e;
		}
	}
	if (!!_inheritedFrom)
	{
		return _inheritedFrom->FindElement(ele);
	}
	return nullptr;
}
bool SequenceNode::WriteMetadataLine(std::shared_ptr<FileNode> files, int& versionEleCount)
{
	if (!!_inheritedFrom)
	{
		if (!_inheritedFrom->WriteMetadataLine(files, versionEleCount))
			return false;
	}
	if (HasOID() && !InheritedHasOID())
	{
		tsStringBase tmp;

		tmp.append("{ (tscrypto::Asn1Metadata2::FieldFlags)(tscrypto::Asn1Metadata2::tp_oid), offsetof(").append(PODStructureName()).append(", _OID), -1, -1, -1, -1, nullptr, 0, tscrypto::TlvNode::Tlv_OID, tscrypto::TlvNode::Type_Universal, ");
		if (JSONName().size() > 0)
			tmp += "nullptr";
		else
			tmp.append("\"").append(JSONName()).append("\"");
		tmp.append(", \"_OID\", ");
		//if (DefaultOID().size() > 0 && DefaultOID() != "*")
		//{
		//	tmp << DefaultOID();
		//}
		//else
		tmp << "nullptr";
		tmp += ", nullptr, ";
		//		tmp += "nullptr, nullptr, nullptr";
		tmp += " },";
		files->Source()->WriteLine(tmp);
		versionEleCount++;
	}
	if (HasVersion() && !InheritedHasVersion())
	{
		tsStringBase tmp;

		tmp.append("{ (tscrypto::Asn1Metadata2::FieldFlags)(tscrypto::Asn1Metadata2::tp_int32), offsetof(").append(PODStructureName()).append(", _VERSION), -1, -1, -1, -1, nullptr, 0, tscrypto::TlvNode::Tlv_Number, tscrypto::TlvNode::Type_Universal, ");
		if (JSONName().size() > 0)
			tmp += "nullptr";
		else
			tmp.append("\"").append(JSONName()).append("\"");
		tmp.append(", \"_VERSION\", ");

		//tmp << "\"" << DefaultVersion() << "\"";
		tmp << "nullptr";

		tmp += ", nullptr, ";
		//		tmp += "nullptr, nullptr, nullptr";
		tmp += " },";
		files->Source()->WriteLine(tmp);
		versionEleCount++;
	}
	for (auto e : Elements())
	{
		files->Source()->WriteLine(e->BuildMetadataLine(FullStructureName(), PODStructureName()));
	}
	return true;
}
bool SequenceNode::WritePODStructure(std::shared_ptr<FileNode> files)
{
	tsStringBase ns;

	if (!!NameSpace())
	{
		ns = NameSpace()->ToString();
	}

	if (!Import())
	{
		tsStringBase PODparent;

		if (PODStructureWritten())
			return true;
		PODStructureWritten(true);

		for (auto ele : Dependencies())
		{
			std::shared_ptr<PartNode> part = std::dynamic_pointer_cast<PartNode>(ele);
			if (!!ele && !ele->PODStructureWritten() && !part)
			{
				if (!ele->WritePODStructure(files))
					return false;
			}
		}

		if (!!_inheritedFrom)
			PODparent << " : public " << _inheritedFrom->PODStructureName();


		files->Header()->SetNamespace(NameSpace());

		files->Header()->WriteLine("// ----------------------------------------------------------------");
		files->Header()->WriteLine();

		files->Header()->WriteLine("struct " + files->ExportSymbol() + PODStructureName() + (Final() ? " final" : "") + PODparent + " {");
		files->Source()->WriteLine("// " + PODStructureName());
		files->Header()->indent();
		// Allocators
		files->Header()->WriteLine("static void* operator new(std::size_t count) {");
		files->Header()->WriteLine("	return tscrypto::cryptoNew(count);");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("static void* operator new[](std::size_t count) {");
		files->Header()->WriteLine("	return tscrypto::cryptoNew(count);");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("	static void operator delete(void* ptr) {");
		files->Header()->WriteLine("	tscrypto::cryptoDelete(ptr);");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("static void operator delete[](void* ptr) {");
		files->Header()->WriteLine("	tscrypto::cryptoDelete(ptr);");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine();
		// Write parts
		files->Header()->WriteLine("typedef enum {");
		files->Header()->indent();
		files->Header()->WriteLine("Part_Main,");
		for (auto part : Parts())
		{
			files->Header()->WriteLine("Part_" + part->Name() + ",");
		}
		// TODO:  Versions and choice here?
		files->Header()->outdent();
		files->Header()->WriteLine("} parts;");
		files->Header()->WriteLine();
		files->Header()->outdent();
		files->Header()->WriteLine("private:");
		files->Header()->indent();
		files->Header()->WriteLine("// Data fields");
		if (HasOID() && !InheritedHasOID())
		{
			files->Header()->WriteLine("tscrypto::tsCryptoData _OID;");
		}
		if (HasVersion() && !InheritedHasVersion())
		{
			files->Header()->WriteLine("int _VERSION;");
		}
		for (auto e : Elements())
		{
			if (e->IsOptional())
			{
				files->Header()->WriteLine("bool _" + e->Name() + "_exists;");
			}
			if (!e->WritePODFieldDefinition(files))
			{
				AddError("xml2Asn1CodeGen", "", (tsStringBase().append("Element ").append(e->Name()).append(" in structure ").append(Name()).append(" failed to write.\n")));
				return false;
			}
		}
		files->Header()->outdent();
		files->Header()->WriteLine("public:");
		files->Header()->indent();

		files->Header()->WriteLine();
		files->Header()->WriteLine("// Constructors");
		// Default constructor
		files->Header()->WriteLine(PODStructureName() + "()" + buildInitializers(ForConstruct));
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("    static_assert(std::is_standard_layout<" + PODStructureName() + ">::value, \"" + PODStructureName() + " is not a standard layout type.\");");
		files->Header()->WriteLine("}");

		// Copy constructor
		files->Header()->WriteLine(PODStructureName() + "(const " + PODStructureName() + "& obj)" + buildInitializers(ForCopy));
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("}");


		// Move Constructor
		files->Header()->WriteLine(PODStructureName() + "(" + PODStructureName() + "&& obj)" + buildInitializers(ForMove));
		files->Header()->WriteLine("{");
		files->Header()->indent();

		if (HasVersion() && !InheritedHasVersion())
		{
			files->Header()->WriteLine(tsStringBase("obj._VERSION = ").append(DefaultVersion()).append(";"));
		}
		for (auto e : Elements())
		{
			if (e->IsOptional())
			{
				files->Header()->WriteLine("obj._" + e->Name() + "_exists = false;");
			}
			tsStringBase tmp = e->BuildClearForMove("obj.");
			if (!tmp.empty())
				files->Header()->WriteLine(tmp);
		}
		files->Header()->outdent();
		files->Header()->WriteLine("}");

		files->Header()->WriteLine();
		files->Header()->WriteLine("// Destructor");
		// Destructor
		files->Header()->WriteLine("~" + PODStructureName() + "()");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		// TODO:  Need to free optional structs here
		//for (auto& e : Elements())
		//{
		//	if (e->usesSeparateClass() && e->IsOptional())
		//	{
		//		files->Header()->WriteLine("if (_" + e->Name() + " != nullptr)");
		//		files->Header()->WriteLine("{");
		//		files->Header()->WriteLine("	delete _" + e->Name() + ";");
		//		files->Header()->WriteLine("}");
		//		files->Header()->WriteLine("_" + e->Name() + " = nullptr;");
		//	}
		//}
		files->Header()->outdent();
		files->Header()->WriteLine("}");



		files->Header()->WriteLine();
		files->Header()->WriteLine("// Assigment and move operators");
		// Assignment operator
		files->Header()->WriteLine(PODStructureName() + "& operator=(const " + PODStructureName() + "& obj)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("if (&obj != this)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		if (!!_inheritedFrom)
		{
			files->Header()->WriteLine("*(" + _inheritedFrom->PODStructureName() + "*)this = *(" + _inheritedFrom->PODStructureName() + "*)&obj;");
		}
		if (HasOID() && (!_inheritedFrom || !_inheritedFrom->HasOID()))
		{
			files->Header()->WriteLine("_OID = obj._OID;");
		}
		if (HasVersion() && (!_inheritedFrom || !_inheritedFrom->HasVersion()))
		{
			files->Header()->WriteLine("_VERSION = obj._VERSION;");
		}
		for (auto e : Elements())
		{
			if (e->IsOptional())
			{
				files->Header()->WriteLine("_" + e->Name() + "_exists = obj._"+e->Name()+"_exists;");
			}
			files->Header()->WriteLine(e->BuildCopyLine("obj."));
		}
		files->Header()->outdent();
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("return *this;");
		files->Header()->outdent();
		files->Header()->WriteLine("}");

		// Move operator
		files->Header()->WriteLine(PODStructureName() + "& operator=(" + PODStructureName() + "&& obj)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("if (&obj != this)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		if (!!_inheritedFrom)
		{
			files->Header()->WriteLine("*(" + _inheritedFrom->PODStructureName() + "*)this = std::move(*(" + _inheritedFrom->PODStructureName() + "*)&obj);");
		}
		if (HasOID() && (!_inheritedFrom || !_inheritedFrom->HasOID()))
		{
			files->Header()->WriteLine("_OID = std::move(obj._OID);");
		}
		if (HasVersion() && (!_inheritedFrom || !_inheritedFrom->HasVersion()))
		{
			files->Header()->WriteLine("_VERSION = obj._VERSION;");
			files->Header()->WriteLine(tsStringBase().append("obj._VERSION = ").append(DefaultVersion()).append(";"));
		}
		for (auto e : Elements())
		{
			if (e->IsOptional())
			{
				files->Header()->WriteLine("_" + e->Name() + "_exists = obj._" + e->Name() + "_exists;");
				files->Header()->WriteLine("obj._" + e->Name() + "_exists = false;");
			}
			files->Header()->WriteLine(e->BuildMoveLine("obj."));
		}
		files->Header()->outdent();
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("return *this;");
		files->Header()->outdent();
		files->Header()->WriteLine("}");

		// clear
		files->Header()->WriteLine("void clear() {");
		files->Header()->indent();
		files->Header()->WriteLine("ClearTlv((void*)this, __Metadata_main, __Metadata_main_count);");
		if (HasOID() && !DefaultOID().empty())
		{
			files->Header()->WriteLine("	_OID = tscrypto::tsCryptoData(" + DefaultOID() + ", tscrypto::tsCryptoData::OID);");
		}
		if (HasVersion() && DefaultVersion() != 0)
		{
			files->Header()->WriteLine("	_VERSION = " + tsStringBase().append(DefaultVersion()) + ";");
		}
		files->Header()->outdent();
		files->Header()->WriteLine("}");

		// Write data accessors
		files->Header()->WriteLine("// Accessors");
		if (HasOID() && !InheritedHasOID())
		{
			files->Header()->WriteLine("const tscrypto::tsCryptoData& get_OID() const { return _OID; }");
			files->Header()->WriteLine("void set_OID(const tscrypto::tsCryptoData& setTo) { _OID = setTo; }");
			files->Header()->WriteLine("void set_OID(const tscrypto::tsCryptoString& setTo) { _OID.FromOIDString(setTo); }");
			if (DefaultOID().empty())
			{
				files->Header()->WriteLine("void clear_OID() { _OID.clear(); }");
			}
			else
			{
				files->Header()->WriteLine("void clear_OID() { _OID = tscrypto::tsCryptoData(" + DefaultOID() + ", tscrypto::tsCryptoData::OID); }");
			}
			files->Header()->WriteLine();
		}
		if (HasVersion() && !InheritedHasVersion())
		{
			files->Header()->WriteLine("int32_t get_VERSION() const { return _VERSION; }");
			files->Header()->WriteLine("void set_VERSION(int32_t setTo) { _VERSION = setTo; }");
			files->Header()->WriteLine("void clear_VERSION() { _VERSION = " + (tsStringBase().append(DefaultVersion())) + "; }");
			files->Header()->WriteLine();
		}
		for (auto e : Elements())
		{
			e->WriteAccessors(files, PODStructureName());
		}
		files->Header()->WriteLine();

		// Write user functions
		files->Header()->WriteLine("// User Functions");
		for (auto f : Functions())
		{
			files->Header()->WriteLine(f->ReturnType() + " " + f->Name() + "(" + f->Parameters() + ")" + f->Suffix() + ";");
		}
		_WriteUserFunctions(files->Source());

		files->Header()->WriteLine("");
		files->Header()->WriteLine("// Metadata Helpers");
		//for (auto e : Elements())
		//{
		//	if (((e->IsOptional() && !e->IsArray()) || e->ContainedInArray()) && e->usesSeparateClass())
		//	{
		//		files->Header()->WriteLine("// " + e->Name());
		//		files->Header()->WriteLine("static void* Create_" + e->Name() + "() { return new " + e->PODStructureName() + "; }");
		//		files->Header()->WriteLine("static void Destroy_" + e->Name() + "(void* object) { if (object != nullptr) delete (" + e->PODStructureName() + "*)object; }");
		//		files->Header()->WriteLine("static void Clear_" + e->Name() + "(void* object) { if (object != nullptr) { " + e->PODStructureName() + "::clear(object); } }");
		//	}
		//}
		files->Header()->WriteLine("static void clear(void* object);");
		files->Source()->WriteLine("void " + ns + PODStructureName() + "::clear(void* object)");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	ClearTlv(object, " + ns + PODStructureName() + "::__Metadata_main, " + ns + PODStructureName() + "::__Metadata_main_count);");
		if (HasOID() && !DefaultOID().empty())
		{
			files->Source()->WriteLine("	((" + ns + PODStructureName() + "*)object)->_OID = tscrypto::tsCryptoData("+DefaultOID()+", tscrypto::tsCryptoData::OID);");
		}
		if (HasVersion() && DefaultVersion() != 0)
		{
			files->Source()->WriteLine("	((" + ns + PODStructureName() + "*)object)->_VERSION = " + tsStringBase().append(DefaultVersion()) + ";");
		}
		files->Source()->WriteLine("}");

		//Asn1DataBaseClass* (*creator)();
		//void(*destroyer)(Asn1DataBaseClass*);
		//void(*clearer)(Asn1DataBaseClass*);






		files->Header()->WriteLine("");
		files->Header()->WriteLine("// Metadata");

		//if (Export())
		//{
		//	files->Header()->WriteLine("const int __" + StructureName() + "_tag = " << BuildTagString() << ";");
		//	files->Header()->WriteLine("const int __" + StructureName() + "_type = " << BuildTypeString() << ";");
		//	files->Header()->WriteLine();
		//}
		//else
		//{
		files->Header()->WriteLine(tsStringBase().append("static const int __tag = ").append(BuildTagString()).append(";"));
		files->Header()->WriteLine(tsStringBase().append("static const int __type = ").append(BuildTypeString()).append(";"));
		files->Header()->WriteLine();
		//}

		if (!FieldMetadataWritten())
		{
			FieldMetadataWritten(true);
			files->Header()->SetNamespace(NameSpace());

			//if (Export())
			//{

			//	// Write the field metadata here
			//	files->Source()->WriteLine("const struct Asn1Metadata2 __" + StructureName() + "_Metadata_main[__" + StructureName() + "_Metadata_main_count] =");
			//	files->Source()->WriteLine("{");
			//	files->Source()->indent();
			//	for (auto e : Elements())
			//	{
			//		files->Source()->WriteLine(e->BuildMetadataLine(StructureName()));
			//	}
			//	files->Source()->outdent();
			//	files->Source()->WriteLine("};");
			//	files->Source()->WriteLine();

			//	files->Header()->WriteLine("const size_t __" + StructureName() + "_Metadata_main_count = " + (tsCryptoString() << Elements().size()) + ";");
			//	files->Header()->WriteLine("extern const struct Asn1Metadata2 __" + StructureName() + "_Metadata_main[__" + StructureName() + "_Metadata_main_count];");
			//	files->Header()->WriteLine();
			//}
			//else
			{
				size_t count = Elements().size();

				if (HasOID() && !InheritedHasOID())
				{
					count++;
				}
				if (HasVersion() && !InheritedHasVersion())
				{
					count++;
				}

				// Write the field metadata here
				files->Header()->WriteLine(tsStringBase().append("static const size_t __Metadata_main_count = ").append((int32_t)count).append(";"));

				files->Header()->WriteLine(tsStringBase().append("static const struct tscrypto::Asn1Metadata2 __Metadata_main[__Metadata_main_count];"));

				files->Source()->WriteLine(tsStringBase().append("const struct tscrypto::Asn1Metadata2 " + ns + PODStructureName() + "::__Metadata_main[" + ns + PODStructureName() + "::__Metadata_main_count] ="));
				files->Source()->WriteLine("{");
				files->Source()->indent();
				if (HasOID() && !InheritedHasOID())
				{
					tsStringBase tmp;

					tmp.append("{ (tscrypto::Asn1Metadata2::FieldFlags)(tscrypto::Asn1Metadata2::tp_oid), offsetof(").append(PODStructureName()).append(", _OID), -1, -1, -1, -1, nullptr, 0, tscrypto::TlvNode::Tlv_OID, tscrypto::TlvNode::Type_Universal, ");
					if (JSONName().size() > 0)
						tmp += "nullptr";
					else
						tmp.append("\"").append(JSONName()).append("\"");
					tmp.append(", \"_OID\", ");
					//if (DefaultOID().size() > 0 && DefaultOID() != "*")
					//{
					//	tmp << DefaultOID();
					//}
					//else
					tmp << "nullptr";
					tmp += ", nullptr, ";
					//		tmp += "nullptr, nullptr, nullptr";
					tmp += " },";
					files->Source()->WriteLine(tmp);
				}
				if (HasVersion() && !InheritedHasVersion())
				{
					tsStringBase tmp;

					tmp.append("{ (tscrypto::Asn1Metadata2::FieldFlags)(tscrypto::Asn1Metadata2::tp_int32), offsetof(").append(PODStructureName()).append(", _VERSION), -1, -1, -1, -1, nullptr, 0, tscrypto::TlvNode::Tlv_Number, tscrypto::TlvNode::Type_Universal, ");
					if (JSONName().size() > 0)
						tmp += "nullptr";
					else
						tmp.append("\"").append(JSONName()).append("\"");
					tmp.append(", \"_VERSION\", ");

					//tmp << "\"" << DefaultVersion() << "\"";
					tmp << "nullptr";

					tmp += ", nullptr, ";
					//		tmp += "nullptr, nullptr, nullptr";
					tmp += " },";
					files->Source()->WriteLine(tmp);
				}

				for (auto e : Elements())
				{
					files->Source()->WriteLine(e->BuildMetadataLine(FullStructureName(), ns + PODStructureName()));
				}

				files->Source()->outdent();
				files->Source()->WriteLine("};");
				files->Source()->WriteLine();


				// VERSION STUFF
				// Write version information here
				if (HasOID() || HasVersion())
				{
					for (auto ver : Versions())
					{
						tsStringBase tmp;

						tmp += "{";

						files->Source()->WriteLine("//   version Metadata - " + ver->Name());
						files->Source()->WriteLine("const tscrypto::Asn1Metadata2 " + ns + PODStructureName() + "::__Metadata_Version_" + ver->Name() + "[" + ns + PODStructureName() + "::__Metadata_Version_" + ver->Name() + "_count] = {");
						files->Source()->indent();
						int versionEleCount1 = 0;
						if (ver->HasOID())
						{
							tsStringBase tmp1;

							tmp1.append("{ (tscrypto::Asn1Metadata2::FieldFlags)(tscrypto::Asn1Metadata2::tp_oid), offsetof(").append(PODStructureName()).append(", _OID), -1, -1, -1, -1, nullptr, 0, tscrypto::TlvNode::Tlv_OID, tscrypto::TlvNode::Type_Universal, ");
							if (JSONName().size() > 0)
								tmp1 += "nullptr";
							else
								tmp1.append("\"").append(JSONName()).append("\"");
							tmp1.append(", \"_OID\", ");
							if (ver->OID().size() > 0 && ver->OID() != "*")
							{
								tmp1 << ver->OID();
							}
							else
								tmp1 << "nullptr";
							tmp1 += ", nullptr, ";
							//		tmp1 += "nullptr, nullptr, nullptr";
							tmp1 += " },";
							files->Source()->WriteLine(tmp1);
							versionEleCount1++;
						}
						if (ver->HasVersion())
						{
							tsStringBase tmp1;

							tmp1.append("{ (tscrypto::Asn1Metadata2::FieldFlags)(tscrypto::Asn1Metadata2::tp_int32), offsetof(").append(PODStructureName()).append(", _VERSION), -1, -1, -1, -1, nullptr, 0, tscrypto::TlvNode::Tlv_Number, tscrypto::TlvNode::Type_Universal, ");
							if (JSONName().size() > 0)
								tmp1 += "nullptr";
							else
								tmp1.append("\"").append(JSONName()).append("\"");
							tmp1.append(", \"_VERSION\", ");

							//tmp1 << "\"" << ver->maxVersion() << "\"";
							tmp1 << "nullptr";

							tmp1 += ", nullptr, ";
							//		tmp1 += "nullptr, nullptr, nullptr";
							tmp1 += " },";
							files->Source()->WriteLine(tmp1);
							versionEleCount1++;
						}

						for (auto ele : ver->Elements())
						{
							// Find the element to which this element refers.
							tsStringBase tmp1;

							//if ((ele->Name() == "OID" && HasOID()) || (ele->Name() == "VERSION" && HasVersion()))
							//{ 
							//	tmp1 = ele->BuildMetadataLine(StructureName());
							//	files->Source()->WriteLine(tmp1);
							//}
							//else
							{
								std::shared_ptr<TaggedElement> e = std::dynamic_pointer_cast<TaggedElement>(FindElement(ele));
								std::shared_ptr<TaggedElement> field = std::dynamic_pointer_cast<TaggedElement>(ele);
								if (!!e && !!field)
								{
									// NOTE:  Add overrides here as needed
									tsStringBase oldTag = e->Tag();
									tsStringBase oldType = e->Type();

									if (field->Tag().size() > 0)
										e->Tag(field->Tag());
									if (field->Type().size() > 0)
										e->Type(field->Type());

									tmp1 = e->BuildMetadataLine(FullStructureName(), PODStructureName());

									// Restore the original values
									e->Tag(oldTag);
									e->Type(oldType);

									files->Source()->WriteLine(tmp1);
								}
								else
								{
									files->Source()->WriteLine("#error  Element " + ele->ElementType() + " called " + ele->Name() + " was NOT found.");
								}
							}
							//file->WriteLine("&_" + StructureName() + "_" + ele->Name() + "_Metaitem_0,");
						}

						files->Source()->outdent();
						files->Source()->WriteLine("};");
						files->Header()->WriteLine("static const size_t __Metadata_Version_" + ver->Name() + "_count = " + (tsStringBase().append((int32_t)(ver->Elements().size() + versionEleCount1))) + ";");
						files->Header()->WriteLine("static const tscrypto::Asn1Metadata2 __Metadata_Version_" + ver->Name() + "[__Metadata_Version_" + ver->Name() + "_count];");
					}

					files->Source()->WriteLine("//   version table");
					files->Source()->WriteLine("const tscrypto::Asn1Version2 " + ns + PODStructureName() + "::__Metadata_VersionSelector[" + ns + PODStructureName() + "::__Metadata_VersionSelector_count] = {");
					files->Source()->indent();

					for (auto& ver : Versions())
					{
						tsStringBase tmp;

						tmp += "{";

						if (ver->HasOID())
						{
							if (ver->OID() == "*" || ver->OID()[0] == '0' || ver->OID()[0] == '1' || ver->OID()[0] == '2')
								tmp.append("\"").append(ver->OID()).append("\", ");
							else
								tmp.append(ver->OID()).append(", ");
						}
						else
						{
							tmp += "nullptr, ";
						}
						if (ver->HasVersion())
						{
							tmp.append("true, ").append(ver->minVersion()).append(", ").append(ver->maxVersion()).append(", ");
						}
						else
						{
							tmp += "false, -1, -1, ";
						}
						tmp.append(ns + PODStructureName() + "::__Metadata_Version_").append(ver->Name()).append(", " + ns + PODStructureName() + "::__Metadata_Version_" + ver->Name() + "_count},");
						files->Source()->WriteLine(tmp);
					}
					files->Source()->outdent();
					files->Source()->WriteLine("};");
					files->Header()->WriteLine("static const size_t __Metadata_VersionSelector_count = " + (tsStringBase().append((int32_t)Versions().size())) + ";");
					files->Header()->WriteLine("static const tscrypto::Asn1Version2 __Metadata_VersionSelector[__Metadata_VersionSelector_count];");
				}

				{
					tsStringBase tmp;

					tmp.append("const struct tscrypto::Asn1StructureDefinition2 " + ns + PODStructureName() + "::__Definition = {").append(BuildTagString()).append(", ").append(BuildTypeString()).append(", ");
					if (Versions().size() == 0)
					{
						tmp << ns << PODStructureName() << "::__Metadata_main, " << ns << PODStructureName() << "::__Metadata_main_count, nullptr, 0, ";
					}
					else
					{
						tmp.append("nullptr, 0, " + ns + PODStructureName() + "::__Metadata_VersionSelector, " + ns + PODStructureName() + "::__Metadata_VersionSelector_count, ");
					}
					if (DefaultOID().size() > 0 && DefaultOID() != "*")
						tmp.append(DefaultOID()).append(", ");
					else
						tmp += "nullptr, ";
					tmp.append("\"").append(DefaultVersion()).append("\", ").append((DontWrap() ? "true" : "false"));
					tmp += "};";
					files->Source()->WriteLine(tmp);
					files->Header()->WriteLine("static const struct tscrypto::Asn1StructureDefinition2 __Definition;");
				}
				for (auto ele : Parts())
				{
					if (!!ele && !ele->PODStructureWritten())
					{
						if (!ele->WritePODStructure(files))
							return false;
					}
				}

				files->Source()->WriteLine();

				files->Header()->WriteLine("static void deletor(void* obj)");
				files->Header()->WriteLine("{");
				files->Header()->WriteLine("	delete (" + ns + PODStructureName() + "*)obj;");
				files->Header()->WriteLine("}");
				files->Header()->WriteLine("static void* cloner(void* obj)");
				files->Header()->WriteLine("{");
				files->Header()->WriteLine("	return new " + ns + PODStructureName() + "(*(" + ns + PODStructureName() + "*)obj);");
				files->Header()->WriteLine("}");
				files->Header()->WriteLine("static tscrypto::Asn1ObjectWrapper creator()");
				files->Header()->WriteLine("{");
				files->Header()->WriteLine("	return tscrypto::Asn1ObjectWrapper(deletor, cloner, new " + ns + PODStructureName() + ");");
				files->Header()->WriteLine("}");
				files->Header()->WriteLine("static bool encoder(void* obj, std::shared_ptr<tscrypto::TlvNode> parent)");
				files->Header()->WriteLine("{");
				files->Header()->WriteLine("	return ((" + ns + PODStructureName() + "*)obj)->Encode(parent);");
				files->Header()->WriteLine("}");
				files->Header()->WriteLine("static bool decoder(void* obj, const std::shared_ptr<tscrypto::TlvNode> root)");
				files->Header()->WriteLine("{");
				files->Header()->WriteLine("	return ((" + ns + PODStructureName() + "*)obj)->DecodeChildren(root);");
				files->Header()->WriteLine("}");
				files->Header()->WriteLine("static void clearer(void* obj)");
				files->Header()->WriteLine("{");
				files->Header()->WriteLine("	ClearTlv(obj, __Metadata_main, __Metadata_main_count);");
				if (HasOID() && !DefaultOID().empty())
				{
					files->Header()->WriteLine("	((" + ns + PODStructureName() + "*)obj)->_OID = tscrypto::tsCryptoData(" + DefaultOID() + ", tscrypto::tsCryptoData::OID);");
				}
				if (HasVersion() && DefaultVersion() != 0)
				{
					files->Header()->WriteLine("	((" + ns + PODStructureName() + "*)obj)->_VERSION = " + tsStringBase().append(DefaultVersion()) + ";");
				}
				// TODO:  Add initialization items here
				files->Header()->WriteLine("}");
				files->Header()->WriteLine();

				// Encoders and Decoders
				files->Header()->WriteLine();
				// Encode
				files->Header()->WriteLine("bool Encode(tscrypto::tsCryptoData& output, bool withoutWrapper = false)");
				files->Header()->WriteLine("{");
				files->Header()->indent();
				files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
				files->Header()->WriteLine();
				files->Header()->WriteLine("output.clear();");
				files->Header()->WriteLine();
				files->Header()->WriteLine("doc->DocumentElement()->Tag(__Definition.tag);");
				files->Header()->WriteLine("doc->DocumentElement()->Type((uint8_t)__Definition.type);");
				files->Header()->WriteLine("if (!EncodeChildren(doc))");
				files->Header()->WriteLine("	return false;");
				files->Header()->WriteLine();
				files->Header()->WriteLine("if (withoutWrapper || __Definition.dontWrap)");
				files->Header()->WriteLine("{");
				files->Header()->indent();
				files->Header()->WriteLine("output = doc->DocumentElement()->InnerData();");
				files->Header()->outdent();
				files->Header()->WriteLine("}");
				files->Header()->WriteLine("else");
				files->Header()->WriteLine("{");
				files->Header()->WriteLine("	output = doc->DocumentElement()->OuterData();");
				files->Header()->WriteLine("}");
				files->Header()->WriteLine("return true;");
				files->Header()->outdent();
				files->Header()->WriteLine("}");

				files->Header()->WriteLine("tscrypto::tsCryptoData Encode(bool withoutWrapper = false)");
				files->Header()->WriteLine("{");
				files->Header()->indent();
				files->Header()->WriteLine("tscrypto::tsCryptoData output;");
				files->Header()->WriteLine("if (!Encode(output, withoutWrapper))");
				files->Header()->WriteLine("    output.clear();");
				files->Header()->WriteLine("return output;");
				files->Header()->outdent();
				files->Header()->WriteLine("}");

				files->Header()->WriteLine("bool Encode(std::shared_ptr<tscrypto::TlvNode> parent)");
				files->Header()->WriteLine("{");
				files->Header()->WriteLine("	std::shared_ptr<tscrypto::TlvNode> top;");
				files->Header()->WriteLine("	parent->AppendChild(top = parent->OwnerDocument().lock()->CreateTlvNode(__Definition.tag, (uint8_t)__Definition.type));");
				files->Header()->WriteLine("	if (!EncodeChildren(top))");
				files->Header()->WriteLine("		return false;");
				files->Header()->WriteLine("	return true;");
				files->Header()->WriteLine("}");

				// Decode
				files->Header()->WriteLine("bool Decode(const tscrypto::tsCryptoData& input, bool withoutWrapper = false)");
				files->Header()->WriteLine("{");
				files->Header()->indent();
				files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
				files->Header()->WriteLine();
				files->Header()->WriteLine("if (withoutWrapper || __Definition.dontWrap)");
				files->Header()->WriteLine("{");
				files->Header()->indent();
				files->Header()->WriteLine("doc->DocumentElement()->Tag(__Definition.tag);");
				files->Header()->WriteLine("doc->DocumentElement()->Type((uint8_t)__Definition.type);");
				files->Header()->WriteLine("if (doc->DocumentElement()->InnerTlv(input) == 0)");
				files->Header()->WriteLine("	return false;");
				files->Header()->outdent();
				files->Header()->WriteLine("}");
				files->Header()->WriteLine("else");
				files->Header()->WriteLine("{");
				files->Header()->indent();
				files->Header()->WriteLine("if (doc->DocumentElement()->OuterData(input) == 0)");
				files->Header()->WriteLine("	return false;");
				files->Header()->WriteLine("}");
				files->Header()->outdent();
				files->Header()->WriteLine();
				files->Header()->WriteLine("if (doc->DocumentElement()->Tag() != __Definition.tag || doc->DocumentElement()->Type() != (uint8_t)__Definition.type)");
				files->Header()->WriteLine("	return false;");
				files->Header()->WriteLine();
				files->Header()->WriteLine("return DecodeChildren(doc->DocumentElement());");
				files->Header()->outdent();
				files->Header()->WriteLine("}");

				for (auto part : Parts())
				{
					part->WriteStructure(files);
					files->Header()->WriteLine("bool Encode_" + part->Name() + "(tscrypto::tsCryptoData& output, bool withoutWrapper = false)");
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine();
					files->Header()->WriteLine("output.clear();");
					files->Header()->WriteLine();
					files->Header()->WriteLine("doc->DocumentElement()->Tag(__Definition_" + part->Name() + ".tag);");
					files->Header()->WriteLine("doc->DocumentElement()->Type((uint8_t)__Definition_" + part->Name() + ".type);");
					files->Header()->WriteLine("if (!EncodeChildren_" + part->Name() + "(doc))");
					files->Header()->WriteLine("	return false;");
					files->Header()->WriteLine();
					files->Header()->WriteLine("if (withoutWrapper || __Definition_" + part->Name() + ".dontWrap)");
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("output = doc->DocumentElement()->InnerData();");
					files->Header()->outdent();
					files->Header()->WriteLine("}");
					files->Header()->WriteLine("else");
					files->Header()->WriteLine("{");
					files->Header()->WriteLine("	output = doc->DocumentElement()->OuterData();");
					files->Header()->WriteLine("}");
					files->Header()->WriteLine("return true;");
					files->Header()->outdent();
					files->Header()->WriteLine("}");


					files->Header()->WriteLine("bool Decode_" + part->Name() + "(const tscrypto::tsCryptoData& input, bool withoutWrapper = false)");
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine();
					files->Header()->WriteLine("if (withoutWrapper || __Definition_" + part->Name() + ".dontWrap)");
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("doc->DocumentElement()->Tag(__Definition_" + part->Name() + ".tag);");
					files->Header()->WriteLine("doc->DocumentElement()->Type((uint8_t)__Definition_" + part->Name() + ".type);");
					files->Header()->WriteLine("if (doc->DocumentElement()->InnerTlv(input) == 0)");
					files->Header()->WriteLine("	return false;");
					files->Header()->outdent();
					files->Header()->WriteLine("}");
					files->Header()->WriteLine("else");
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("if (doc->DocumentElement()->OuterData(input) == 0)");
					files->Header()->WriteLine("	return false;");
					files->Header()->WriteLine("}");
					files->Header()->outdent();
					files->Header()->WriteLine();
					files->Header()->WriteLine("if (doc->DocumentElement()->Tag() != __Definition_" + part->Name() + ".tag || doc->DocumentElement()->Type() != (uint8_t)__Definition_" + part->Name() + ".type)");
					files->Header()->WriteLine("	return false;");
					files->Header()->WriteLine();
					files->Header()->WriteLine("return DecodeChildren_" + part->Name() + "(doc->DocumentElement());");
					files->Header()->outdent();
					files->Header()->WriteLine("}");
				}
				files->Header()->WriteLine();

				// Encode Children
				files->Header()->WriteLine("bool EncodeChildren(std::shared_ptr<tscrypto::TlvDocument> doc)");
				files->Header()->WriteLine("{");
				files->Header()->WriteLine("	return EncodeChildren(doc->DocumentElement());");
				files->Header()->WriteLine("}");

				files->Header()->WriteLine("bool EncodeChildren(std::shared_ptr<tscrypto::TlvNode> root)");
				files->Header()->WriteLine("{");
				files->Header()->indent();
				files->Header()->WriteLine("const tscrypto::Asn1Metadata2* metadata = nullptr;");
				files->Header()->WriteLine("size_t count = 0;");
				files->Header()->WriteLine("");
				files->Header()->WriteLine("if (!FindVersionToEncode(this, __Definition, metadata, count))");
				files->Header()->WriteLine("	return false;");
				files->Header()->WriteLine("return EncodeTlv(this, root, metadata, count);");
				files->Header()->outdent();
				files->Header()->WriteLine("}");

				// Decode Children
				files->Header()->WriteLine("bool DecodeChildren(const std::shared_ptr<tscrypto::TlvNode> root)");
				files->Header()->WriteLine("{");
				files->Header()->indent();
				files->Header()->WriteLine("const tscrypto::Asn1Metadata2* metadata = nullptr;");
				files->Header()->WriteLine("size_t count = 0;");
				files->Header()->WriteLine("if (!FindVersionToDecode(root, __Definition, metadata, count))");
				files->Header()->WriteLine("	return false;");
				files->Header()->WriteLine("return DecodeTlv(this, root, metadata, count);");
				files->Header()->outdent();
				files->Header()->WriteLine("}");

				for (auto part : Parts())
				{
					files->Header()->WriteLine("bool EncodeChildren_" + part->Name() + "(std::shared_ptr<tscrypto::TlvDocument> doc)");
					files->Header()->WriteLine("{");
					files->Header()->WriteLine("	return EncodeChildren_" + part->Name() + "(doc->DocumentElement());");
					files->Header()->WriteLine("}");

					files->Header()->WriteLine("bool EncodeChildren_" + part->Name() + "(std::shared_ptr<tscrypto::TlvNode> root)");
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("const tscrypto::Asn1Metadata2* metadata = nullptr;");
					files->Header()->WriteLine("size_t count = 0;");
					files->Header()->WriteLine("");
					files->Header()->WriteLine("if (!FindVersionToEncode(this, __Definition_" + part->Name() + ", metadata, count))");
					files->Header()->WriteLine("	return false;");
					files->Header()->WriteLine("return EncodeTlv(this, root, metadata, count);");
					files->Header()->outdent();
					files->Header()->WriteLine("}");

					files->Header()->WriteLine("bool DecodeChildren_" + part->Name() + "(const std::shared_ptr<tscrypto::TlvNode> root)");
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("const tscrypto::Asn1Metadata2* metadata = nullptr;");
					files->Header()->WriteLine("size_t count = 0;");
					files->Header()->WriteLine("if (!FindVersionToDecode(root, __Definition_" + part->Name() + ", metadata, count))");
					files->Header()->WriteLine("	return false;");
					files->Header()->WriteLine("return DecodeTlv(this, root, metadata, count);");
					files->Header()->outdent();
					files->Header()->WriteLine("}");
				}

				files->Header()->WriteLine();
				for (auto& ver : Versions())
				{
					files->Header()->WriteLine(tsStringBase().append("bool is_").append(ver->Name()).append("() const"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					if (HasOID() && (!ver->HasOID() || ver->OID() == "*"))
					{
						tsStringBase tmp;
						for (auto& ver1 : Versions())
						{
							if (ver1->HasOID())
							{
								if (tmp.size() > 0)
									tmp += " || ";
								tmp.append("is_").append(ver1->Name()).append("()");
							}
						}
						if (tmp.size() > 0)
						{
							files->Header()->WriteLine(tsStringBase().append("if (").append(tmp).append(")"));
							files->Header()->WriteLine("	return false;");
						}
					}
					else if (HasOID() && ver->HasOID())
					{
						if (ver->OID()[0] == '0' || ver->OID()[0] == '1' || ver->OID()[0] == '2')
						{
							files->Header()->WriteLine("if (_OID.ToOIDString() != \"" + ver->OID() + "\")");
						}
						else
						{
							files->Header()->WriteLine("if (_OID.ToOIDString() != " + ver->OID() + ")");
						}
						files->Header()->WriteLine("	return false;");
					}

					if (HasVersion() && ver->HasVersion())
					{
						if (ver->maxVersion() > -1)
						{
							files->Header()->WriteLine(tsStringBase().append("if (_VERSION > ").append(ver->maxVersion()).append(")"));
							files->Header()->WriteLine("	return false;");
						}
						if (ver->minVersion() > -1)
						{
							files->Header()->WriteLine(tsStringBase().append("if (_VERSION < ").append(ver->minVersion()).append(")"));
							files->Header()->WriteLine("	return false;");
						}
					}
					files->Header()->WriteLine("return true;");
					files->Header()->outdent();
					files->Header()->WriteLine("}");

					ver->WritePODVersionElementAccessors(files);
				}
			}
		}

		if (JSONName().size() > 0)
		{
			files->Header()->WriteLine("static const char* JSONName() { return \"" + JSONName() + "\"; }");

			if (Parts().size() > 0)
			{
				for (auto& part : Parts())
				{
					if (!part->WriteToJSON(files))
					{
						return false;
					}
					if (!part->WriteFromJSON(files))
					{
						return false;
					}
				}
			}

			files->Header()->WriteLine("tscrypto::JSONObject toJSON() const { tscrypto::JSONObject obj; if (!toJSON(obj)) obj.clear(); return obj; }");
			files->Header()->WriteLine("bool toJSON(tscrypto::JSONObject& obj) const");
			files->Header()->WriteLine("{");
			files->Header()->indent();

			for (auto e : Elements())
			{
				if (!e->WriteToJSON(files->Header()))
				{
					AddError("xml2Asn1CodeGen", "", "Failed to write JSON element");
					return false;
					//printf((tsCryptoString() << "Element " << e->Name() << " in structure " << Name() + " failed to write.\n").c_str());
					//return true;
				}
			}

			files->Header()->WriteLine("return true;");
			files->Header()->outdent();
			files->Header()->WriteLine("}");

			files->Header()->WriteLine("bool fromJSON(const tscrypto::tsCryptoStringBase& json) { tscrypto::JSONObject obj; if (!obj.FromJSON(json)) return false; return fromJSON(obj); }");
			files->Header()->WriteLine("bool fromJSON(const tscrypto::JSONObject& obj)");
			files->Header()->WriteLine("{");
			files->Header()->indent();
			files->Header()->WriteLine("clear();");

			for (auto e : Elements())
			{
				if (!e->WriteFromJSON(files->Header()))
				{
					AddError("xml2Asn1CodeGen", "", "Failed to write JSON element");
					return false;
					//printf((tsCryptoString() << "Element " << e->Name() << " in structure " << Name() + " failed to write.\n").c_str());
					//return true;
				}
			}

			files->Header()->WriteLine("");
			files->Header()->WriteLine("return true;");
			files->Header()->outdent();
			files->Header()->WriteLine("}");
		}

		files->Header()->outdent();
		files->Header()->WriteLine("};");
		files->Header()->WriteLine();

	}
	return true;
}
bool SequenceNode::WriteStructure(std::shared_ptr<FileNode> files)
{
#if 0
	if (!Import())
	{
		if (StructureWritten())
			return true;
		StructureWritten(true);

		for (auto ele : Dependencies())
		{
			std::shared_ptr<PartNode> part = std::dynamic_pointer_cast<PartNode>(ele);
			if (!!ele && !ele->StructureWritten() && !part)
			{
				if (!ele->WriteStructure(files))
					return false;
			}
		}

		files->Source()->SetNamespace(NameSpace());
		files->Source()->WriteLine("// ----------------------------------------------------------------");
		files->Source()->WriteLine("// " + StructureName());
		files->Source()->WriteLine();

		for (auto e : Elements())
		{
			e->WriteSubMetadata(files, StructureName(), PODStructureName());
		}


		files->Source()->WriteLine("static const struct Asn1Metadata __" + StructureName() + "_Metadata_main[] =");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		int versionEleCount = 0;
		WriteMetadataLine(files, versionEleCount);

		files->Source()->outdent();
		files->Source()->WriteLine("};");
		files->Source()->WriteLine("static const size_t __" + StructureName() + "_Metadata_main_count = " + (tsCryptoString().append((Elements().size() + versionEleCount))) + ";");
		files->Source()->WriteLine();




		// Write version information here
		if (HasOID() || HasVersion())
		{
			for (auto ver : Versions())
			{
				tsCryptoString tmp;

				tmp += "{";

				files->Source()->WriteLine("//   version Metadata - " + ver->Name());
				files->Source()->WriteLine("static const Asn1Metadata _" + StructureName() + "_Metadata_Version_" + ver->Name() + "[] = {");
				files->Source()->indent();
				int versionEleCount1 = 0;
				if (ver->HasOID())
				{
					tsCryptoString tmp1;

					tmp1.append("{ (Asn1Metadata::FieldFlags)(Asn1Metadata::tp_oid), offsetof(").append(PODStructureName()).append(", _OID), -1, -1, -1, -1, -1, nullptr, 0, tscrypto::TlvNode::Tlv_OID, tscrypto::TlvNode::Type_Universal, ");
					if (JSONName().size() > 0)
						tmp1 += "nullptr";
					else
						tmp1.append("\"").append(JSONName()).append("\"");
					tmp1.append(", \"_OID\", ");
					if (ver->OID().size() > 0 && ver->OID() != "*")
					{
						tmp1 << ver->OID();
					}
					else
						tmp1 << "nullptr";
					tmp1 += ", nullptr, ";
					//		tmp1 += "nullptr, nullptr, nullptr";
					tmp1 += " },";
					files->Source()->WriteLine(tmp1);
					versionEleCount1++;
				}
				if (ver->HasVersion())
				{
					tsCryptoString tmp1;

					tmp1.append("{ (Asn1Metadata::FieldFlags)(Asn1Metadata::tp_int32), offsetof(").append(PODStructureName()).append(", _VERSION), -1, -1, -1, -1, -1, nullptr, 0, TlvNode::Tlv_Number, TlvNode::Type_Universal, ");
					if (JSONName().size() > 0)
						tmp1 += "nullptr";
					else
						tmp1.append("\"").append(JSONName()).append("\"");
					tmp1.append(", \"_VERSION\", ");

					//tmp1 << "\"" << ver->maxVersion() << "\"";
					tmp1 << "nullptr";

					tmp1 += ", nullptr, ";
					//		tmp1 += "nullptr, nullptr, nullptr";
					tmp1 += " },";
					files->Source()->WriteLine(tmp1);
					versionEleCount1++;
				}

				for (auto ele : ver->Elements())
				{
					// Find the element to which this element refers.
					tsCryptoString tmp1;

					//if ((ele->Name() == "OID" && HasOID()) || (ele->Name() == "VERSION" && HasVersion()))
					//{ 
					//	tmp1 = ele->BuildMetadataLine(StructureName());
					//	files->Source()->WriteLine(tmp1);
					//}
					//else
					{
						std::shared_ptr<TaggedElement> e = std::dynamic_pointer_cast<TaggedElement>(FindElement(ele));
						std::shared_ptr<TaggedElement> field = std::dynamic_pointer_cast<TaggedElement>(ele);
						if (!!e && !!field)
						{
							// NOTE:  Add overrides here as needed
							tsCryptoString oldTag = e->Tag();
							tsCryptoString oldType = e->Type();

							if (field->Tag().size() > 0)
								e->Tag(field->Tag());
							if (field->Type().size() > 0)
								e->Type(field->Type());

							tmp1 = e->BuildMetadataLine(FullStructureName(), PODStructureName());

							// Restore the original values
							e->Tag(oldTag);
							e->Type(oldType);

							files->Source()->WriteLine(tmp1);
						}
						else
						{
							files->Source()->WriteLine("#error  Element " + ele->ElementType() + " called " + ele->Name() + " was NOT found.");
						}
					}
					//file->WriteLine("&_" + StructureName() + "_" + ele->Name() + "_Metaitem_0,");
				}

				files->Source()->outdent();
				files->Source()->WriteLine("};");
				files->Source()->WriteLine("static const size_t _" + StructureName() + "_Metadata_Version_" + ver->Name() + "_count = " + (tsCryptoString().append((ver->Elements().size() + versionEleCount1))) + ";");
			}


			files->Source()->WriteLine("//   version table");
			files->Source()->WriteLine("static const Asn1Version _" + StructureName() + "_Metadata_VersionSelector[] = {");
			files->Source()->indent();

			for (auto& ver : Versions())
			{
				tsCryptoString tmp;

				tmp += "{";

				if (ver->HasOID())
				{
					if (ver->OID() == "*" || ver->OID()[0] == '0' || ver->OID()[0] == '1' || ver->OID()[0] == '2')
						tmp.append("\"").append(ver->OID()).append("\", ");
					else
						tmp.append(ver->OID()).append(", ");
				}
				else
				{
					tmp += "nullptr, ";
				}
				if (ver->HasVersion())
				{
					tmp.append("true, ").append(ver->minVersion()).append(", ").append(ver->maxVersion()).append(", ");
				}
				else
				{
					tmp += "false, -1, -1, ";
				}
				tmp.append("_").append(StructureName()).append("_Metadata_Version_").append(ver->Name()).append(", _").append(StructureName()).append("_Metadata_Version_").append(ver->Name()).append("_count},");
				files->Source()->WriteLine(tmp);
			}
			files->Source()->outdent();
			files->Source()->WriteLine("};");
			files->Source()->WriteLine("static const size_t _" + StructureName() + "_Metadata_VersionSelector_count = " + (tsCryptoString().append(Versions().size())) + ";");
		}


		{
			tsCryptoString tmp;

			tmp.append("static const struct Asn1StructureDefinition __").append(StructureName()).append("_Definition = {").append(BuildTagString()).append(", ").append(BuildTypeString()).append(", ");
			if (Versions().size() == 0)
			{
				tmp.append("__").append(StructureName()).append("_Metadata_main, __").append(StructureName()).append("_Metadata_main_count, nullptr, 0, ");
			}
			else
			{
				tmp.append("nullptr, 0, _").append(StructureName()).append("_Metadata_VersionSelector, _").append(StructureName()).append("_Metadata_VersionSelector_count, ");
			}
			if (DefaultOID().size() > 0 && DefaultOID() != "*")
				tmp.append(DefaultOID()).append(", ");
			else
				tmp += "nullptr, ";
			tmp.append("\"").append(DefaultVersion()).append("\", ").append((DontWrap() ? "true" : "false"));
			tmp += "};";
			files->Source()->WriteLine(tmp);
		}
		files->Source()->WriteLine();

		//files->Header()->WriteLine("// IMPORTANT NOTE:  We are using offsetof on non-POD structs.  This may cause memory corruption in the future.  Consider rewriting with a different serializer (member functions, more specialized classes, ...");
		files->Header()->WriteLine("struct " + files->ExportSymbol() + StructureName() + (Final() ? " final" : "") + " : public " + ParentType() + " {");

		files->Header()->indent();
		// Basic constructor
		files->Header()->WriteLine(StructureName() + "();");
		files->Source()->WriteLine(StructureName() + "::" + StructureName() + "()");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("}");

		// Copy constructor
		files->Header()->WriteLine(StructureName() + "(const " + StructureName() + "& obj);");
		files->Source()->WriteLine(StructureName() + "::" + StructureName() + "(const " + StructureName() + "& obj) : _data(obj._data), _isOwner(false)");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("}");

		// Move constructor
		files->Header()->WriteLine(StructureName() + "(" + StructureName() + "&& obj);");
		files->Source()->WriteLine(StructureName() + "::" + StructureName() + "(" + StructureName() + "&& obj) : _data(std::move(obj._data)), _isOwner(obj._isOwner)");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("    obj._isOwner = false;");
		files->Source()->WriteLine("    obj._data = nullptr;");
		files->Source()->WriteLine("}");

		// Destructor
		files->Header()->WriteLine("virtual ~" + StructureName() + "();");
		files->Source()->WriteLine(StructureName() + "::~" + StructureName() + "()");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("clear();");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		// Creator
		files->Header()->WriteLine("static Asn1DataBaseClass* Create() { return new " + StructureName() + "; }");

		// Destroyer
		files->Header()->WriteLine("static void Destroy(Asn1DataBaseClass* object) { if (object != nullptr) delete object; }");

		// Clearer
		files->Header()->WriteLine("static void Clear(Asn1DataBaseClass* object) { if (object != nullptr) object->clear(); }");

		// Encoders and Decoders
		files->Header()->WriteLine();
		// Encode
		files->Header()->WriteLine("virtual bool Encode(tsCryptoData& output, bool withoutWrapper = false) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::Encode(tsCryptoData& output, bool withoutWrapper)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("std::shared_ptr<TlvDocument> doc = TlvDocument::Create();");
		files->Source()->WriteLine();
		files->Source()->WriteLine("output.clear();");
		files->Source()->WriteLine();
		files->Source()->WriteLine("doc->DocumentElement()->Tag(__" + StructureName() + "_Definition.tag);");
		files->Source()->WriteLine("doc->DocumentElement()->Type((uint8_t)__" + StructureName() + "_Definition.type);");
		files->Source()->WriteLine("if (!EncodeChildren(doc))");
		files->Source()->WriteLine("	return false;");
		files->Source()->WriteLine();
		files->Source()->WriteLine("if (withoutWrapper || __" + StructureName() + "_Definition.dontWrap)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("output = doc->DocumentElement()->InnerData();");
		files->Source()->outdent();
		files->Source()->WriteLine("}");
		files->Source()->WriteLine("else");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	output = doc->DocumentElement()->OuterData();");
		files->Source()->WriteLine("}");
		files->Source()->WriteLine("return true;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		files->Header()->WriteLine("virtual bool Encode(std::shared_ptr<TlvNode> parent) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::Encode(std::shared_ptr<TlvNode> parent)");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	std::shared_ptr<TlvNode> top;");
		files->Source()->WriteLine("	parent->AppendChild(top = parent->OwnerDocument().lock()->CreateTlvNode(__" + StructureName() + "_Definition.tag, (uint8_t)__" + StructureName() + "_Definition.type));");
		files->Source()->WriteLine("	if (!EncodeChildren(top))");
		files->Source()->WriteLine("		return false;");
		files->Source()->WriteLine("	return true;");
		files->Source()->WriteLine("}");

		// Decode
		files->Header()->WriteLine("virtual bool Decode(const tsCryptoData& input, bool withoutWrapper = false) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::Decode(const tsCryptoData& input, bool withoutWrapper)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("std::shared_ptr<TlvDocument> doc = TlvDocument::Create();");
		files->Source()->WriteLine();
		files->Source()->WriteLine("if (withoutWrapper || __" + StructureName() + "_Definition.dontWrap)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("doc->DocumentElement()->Tag(__" + StructureName() + "_Definition.tag);");
		files->Source()->WriteLine("doc->DocumentElement()->Type((uint8_t)__" + StructureName() + "_Definition.type);");
		files->Source()->WriteLine("if (doc->DocumentElement()->InnerTlv(input) == 0)");
		files->Source()->WriteLine("	return false;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");
		files->Source()->WriteLine("else");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("if (doc->DocumentElement()->OuterData(input) == 0)");
		files->Source()->WriteLine("	return false;");
		files->Source()->WriteLine("}");
		files->Source()->outdent();
		files->Source()->WriteLine();
		files->Source()->WriteLine("if (doc->DocumentElement()->Tag() != __" + StructureName() + "_Definition.tag || doc->DocumentElement()->Type() != (uint8_t)__" + StructureName() + "_Definition.type)");
		files->Source()->WriteLine("	return false;");
		files->Source()->WriteLine();
		files->Source()->WriteLine("return DecodeChildren(doc->DocumentElement());");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		for (auto part : Parts())
		{
			part->WriteStructure(files);
			files->Header()->WriteLine("bool Encode_" + part->Name() + "(tsCryptoData& output, bool withoutWrapper = false);");
			files->Source()->WriteLine("bool " + part->StructureName() + "::Encode_" + part->Name() + "(tsCryptoData& output, bool withoutWrapper)");
			files->Source()->WriteLine("{");
			files->Source()->indent();
			files->Source()->WriteLine("std::shared_ptr<TlvDocument> doc = TlvDocument::Create();");
			files->Source()->WriteLine();
			files->Source()->WriteLine("output.clear();");
			files->Source()->WriteLine();
			files->Source()->WriteLine("doc->DocumentElement()->Tag(__" + part->StructureName() + "_Definition_" + part->Name() + ".tag);");
			files->Source()->WriteLine("doc->DocumentElement()->Type((uint8_t)__" + part->StructureName() + "_Definition_" + part->Name() + ".type);");
			files->Source()->WriteLine("if (!EncodeChildren_" + part->Name() + "(doc))");
			files->Source()->WriteLine("	return false;");
			files->Source()->WriteLine();
			files->Source()->WriteLine("if (withoutWrapper || __" + part->StructureName() + "_Definition_" + part->Name() + ".dontWrap)");
			files->Source()->WriteLine("{");
			files->Source()->indent();
			files->Source()->WriteLine("output = doc->DocumentElement()->InnerData();");
			files->Source()->outdent();
			files->Source()->WriteLine("}");
			files->Source()->WriteLine("else");
			files->Source()->WriteLine("{");
			files->Source()->WriteLine("	output = doc->DocumentElement()->OuterData();");
			files->Source()->WriteLine("}");
			files->Source()->WriteLine("return true;");
			files->Source()->outdent();
			files->Source()->WriteLine("}");


			files->Header()->WriteLine("bool Decode_" + part->Name() + "(const tsCryptoData& input, bool withoutWrapper = false);");
			files->Source()->WriteLine("bool " + part->StructureName() + "::Decode_" + part->Name() + "(const tsCryptoData& input, bool withoutWrapper)");
			files->Source()->WriteLine("{");
			files->Source()->indent();
			files->Source()->WriteLine("std::shared_ptr<TlvDocument> doc = TlvDocument::Create();");
			files->Source()->WriteLine();
			files->Source()->WriteLine("if (withoutWrapper || __" + part->StructureName() + "_Definition_" + part->Name() + ".dontWrap)");
			files->Source()->WriteLine("{");
			files->Source()->indent();
			files->Source()->WriteLine("doc->DocumentElement()->Tag(__" + part->StructureName() + "_Definition_" + part->Name() + ".tag);");
			files->Source()->WriteLine("doc->DocumentElement()->Type((uint8_t)__" + part->StructureName() + "_Definition_" + part->Name() + ".type);");
			files->Source()->WriteLine("if (doc->DocumentElement()->InnerTlv(input) == 0)");
			files->Source()->WriteLine("	return false;");
			files->Source()->outdent();
			files->Source()->WriteLine("}");
			files->Source()->WriteLine("else");
			files->Source()->WriteLine("{");
			files->Source()->indent();
			files->Source()->WriteLine("if (doc->DocumentElement()->OuterData(input) == 0)");
			files->Source()->WriteLine("	return false;");
			files->Source()->WriteLine("}");
			files->Source()->outdent();
			files->Source()->WriteLine();
			files->Source()->WriteLine("if (doc->DocumentElement()->Tag() != __" + part->StructureName() + "_Definition_" + part->Name() + ".tag || doc->DocumentElement()->Type() != (uint8_t)__" + part->StructureName() + "_Definition_" + part->Name() + ".type)");
			files->Source()->WriteLine("	return false;");
			files->Source()->WriteLine();
			files->Source()->WriteLine("return DecodeChildren_" + part->Name() + "(doc->DocumentElement());");
			files->Source()->outdent();
			files->Source()->WriteLine("}");

		}
		files->Header()->WriteLine();

		// Encode Children
		files->Header()->WriteLine("virtual bool EncodeChildren(std::shared_ptr<TlvDocument> doc) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::EncodeChildren(std::shared_ptr<TlvDocument> doc)");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	return EncodeChildren(doc->DocumentElement());");
		files->Source()->WriteLine("}");

		files->Header()->WriteLine("virtual bool EncodeChildren(std::shared_ptr<TlvNode> root) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::EncodeChildren(std::shared_ptr<TlvNode> root)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("const Asn1Metadata* metadata = nullptr;");
		files->Source()->WriteLine("size_t count = 0;");
		files->Source()->WriteLine("");
		files->Source()->WriteLine("if (!FindVersionToEncode(this, __" + StructureName() + "_Definition, metadata, count))");
		files->Source()->WriteLine("	return false;");
		files->Source()->WriteLine("return EncodeTlv(this, root, metadata, count);");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		// Decode Children
		files->Header()->WriteLine("virtual bool DecodeChildren(const std::shared_ptr<TlvNode> root) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::DecodeChildren(const std::shared_ptr<TlvNode> root)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("const Asn1Metadata* metadata = nullptr;");
		files->Source()->WriteLine("size_t count = 0;");
		files->Source()->WriteLine("if (!FindVersionToDecode(root, __" + StructureName() + "_Definition, metadata, count))");
		files->Source()->WriteLine("	return false;");
		files->Source()->WriteLine("return DecodeTlv(this, root, metadata, count);");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		for (auto part : Parts())
		{
			files->Header()->WriteLine("bool EncodeChildren_" + part->Name() + "(std::shared_ptr<TlvDocument> doc);");
			files->Source()->WriteLine("bool " + part->StructureName() + "::EncodeChildren_" + part->Name() + "(std::shared_ptr<TlvDocument> doc)");
			files->Source()->WriteLine("{");
			files->Source()->WriteLine("	return EncodeChildren_" + part->Name() + "(doc->DocumentElement());");
			files->Source()->WriteLine("}");

			files->Header()->WriteLine("bool EncodeChildren_" + part->Name() + "(std::shared_ptr<TlvNode> root);");
			files->Source()->WriteLine("bool " + part->StructureName() + "::EncodeChildren_" + part->Name() + "(std::shared_ptr<TlvNode> root)");
			files->Source()->WriteLine("{");
			files->Source()->indent();
			files->Source()->WriteLine("const Asn1Metadata* metadata = nullptr;");
			files->Source()->WriteLine("size_t count = 0;");
			files->Source()->WriteLine("");
			files->Source()->WriteLine("if (!FindVersionToEncode(this, __" + part->StructureName() + "_Definition_" + part->Name() + ", metadata, count))");
			files->Source()->WriteLine("	return false;");
			files->Source()->WriteLine("return EncodeTlv(this, root, metadata, count);");
			files->Source()->outdent();
			files->Source()->WriteLine("}");

			files->Header()->WriteLine("bool DecodeChildren_" + part->Name() + "(const std::shared_ptr<TlvNode> root);");
			files->Source()->WriteLine("bool " + part->StructureName() + "::DecodeChildren_" + part->Name() + "(const std::shared_ptr<TlvNode> root)");
			files->Source()->WriteLine("{");
			files->Source()->indent();
			files->Source()->WriteLine("const Asn1Metadata* metadata = nullptr;");
			files->Source()->WriteLine("size_t count = 0;");
			files->Source()->WriteLine("if (!FindVersionToDecode(root, __" + part->StructureName() + "_Definition_" + part->Name() + ", metadata, count))");
			files->Source()->WriteLine("	return false;");
			files->Source()->WriteLine("return DecodeTlv(this, root, metadata, count);");
			files->Source()->outdent();
			files->Source()->WriteLine("}");
		}
		files->Header()->WriteLine();

		// Equality operator
		files->Header()->WriteLine("virtual bool operator==(const Asn1DataBaseClass& obj) const override;");
		files->Source()->WriteLine("bool " + StructureName() + "::operator==(const Asn1DataBaseClass& obj) const");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("const " + StructureName() + "* o = dynamic_cast<const " + StructureName() + "*>(&obj);");
		files->Source()->WriteLine();
		files->Source()->WriteLine("if (o == nullptr) return false;");
		files->Source()->WriteLine("if (o == this) return true;");
		if (!!_inheritedFrom)
		{
			files->Source()->WriteLine("if (*(" + _inheritedFrom->StructureName() + "*)this == *(" + _inheritedFrom->StructureName() + "*)&obj) return false;");
		}

		if (HasOID())
		{
			files->Source()->WriteLine("if (_data->_OID != o->_data->_OID) return false;");
		}
		if (HasVersion())
		{
			files->Source()->WriteLine("if (_data->_VERSION != o->_data->_VERSION) return false;");
		}

		for (auto e : Elements())
		{
			if (e->ElementType() != "Null")
				files->Source()->WriteLine("if (" + e->BuildInequalityTest("o->") + ") return false;");
		}

		files->Source()->WriteLine("return true;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");
		files->Source()->WriteLine();


		// clear
		files->Header()->WriteLine("virtual void clear() override;");
		files->Source()->WriteLine("void " + StructureName() + "::clear()");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	ClearTlv(this, __" + StructureName() + "_Metadata_main, __" + StructureName() + "_Metadata_main_count);");
		files->Source()->WriteLine("}");


		// clone
		files->Header()->WriteLine("virtual Asn1DataBaseClass* clone() const override;");
		files->Source()->WriteLine("Asn1DataBaseClass* " + StructureName() + "::clone() const");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine(StructureName() + " *o = new " + StructureName() + "(*this);");
		files->Source()->WriteLine("");
		files->Source()->WriteLine("return o;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		files->Header()->WriteLine();

		// Assignment operator
		files->Header()->WriteLine("virtual Asn1DataBaseClass& operator=(const Asn1DataBaseClass& obj) override;");
		files->Source()->WriteLine("Asn1DataBaseClass& " + StructureName() + "::operator=(const Asn1DataBaseClass& o)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("const " + StructureName() + "*obj = dynamic_cast<const " + StructureName() + "*>(&o);");
		files->Source()->WriteLine("if (obj != this && obj != nullptr)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("if (_isOwner && _data != nullptr) delete _data;");
		files->Source()->WriteLine("_data = obj->_data;");
		files->Source()->WriteLine("_isOwner = false;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");
		files->Source()->WriteLine("return *this;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		// Assignment operator
		files->Header()->WriteLine(StructureName() + "& operator=(const " + StructureName() + "& obj);");
		files->Source()->WriteLine(StructureName() + "& " + StructureName() + "::operator=(const " + StructureName() + "& obj)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("if (_isOwner && _data != nullptr) delete _data;");
		files->Source()->WriteLine("_data = obj._data;");
		files->Source()->WriteLine("_isOwner = false;");
		files->Source()->WriteLine("return *this;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		// Move operator
		files->Header()->WriteLine("virtual Asn1DataBaseClass& operator=(Asn1DataBaseClass&& obj) override;");
		files->Source()->WriteLine("Asn1DataBaseClass& " + StructureName() + "::operator=(Asn1DataBaseClass&& o)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine(StructureName() + "* obj = dynamic_cast<" + StructureName() + "*>(&o);");
		files->Source()->WriteLine("if (obj != this && obj != nullptr)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("_isOwner = std::move(obj->_isOwner);");
		files->Source()->WriteLine("obj->_isOwner = false;");
		files->Source()->WriteLine("_data = std::move(obj->_data);");
		files->Source()->WriteLine("obj->_data = nullptr;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");
		files->Source()->WriteLine("return *this;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		files->Header()->WriteLine();


		// Write parts
		files->Header()->WriteLine("typedef enum {");
		files->Header()->indent();
		files->Header()->WriteLine("Part_Main,");
		for (auto part : Parts())
		{
			files->Header()->WriteLine("Part_" + part->Name() + ",");
		}
		// TODO:  Versions and choice here?
		files->Header()->outdent();
		files->Header()->WriteLine("} parts;");
		files->Header()->WriteLine();

		// Write encode function definitions
		if (JSONName().size() > 0)
		{
			files->Header()->WriteLine("static const char* JSONName() { return \"" + JSONName() + "\"; }");

			files->Header()->WriteLine("virtual JSONObject toJSON() const override { return Asn1DataBaseClass::toJSON(); }");
			files->Header()->WriteLine("virtual bool fromJSON(const char* json) override { return Asn1DataBaseClass::fromJSON(json); }");
			files->Header()->WriteLine("virtual bool fromJSON(const tsCryptoStringBase& json) override { return Asn1DataBaseClass::fromJSON(json.c_str()); }");

			if (Parts().size() > 0)
			{
				for (auto& part : Parts())
				{
					if (!part->WriteToJSON(files))
					{
						return false;
					}
					if (!part->WriteFromJSON(files))
					{
						return false;
					}
				}
			}

			files->Header()->WriteLine("bool toJSON(JSONObject& obj) const override;");
			files->Source()->WriteLine("bool " + StructureName() + "::toJSON(JSONObject& obj) const");
			files->Source()->WriteLine("{");
			files->Source()->indent();

			for (auto e : Elements())
			{
				if (!e->WriteToJSON(files->Source()))
				{
					AddError("xml2Asn1CodeGen", "", "Failed to write JSON element");
					return false;
					//printf((tsCryptoString() << "Element " << e->Name() << " in structure " << Name() + " failed to write.\n").c_str());
					//return true;
				}
			}

			files->Source()->WriteLine("return true;");
			files->Source()->outdent();
			files->Source()->WriteLine("}");

			files->Header()->WriteLine("bool fromJSON(const JSONObject& obj) override;");
			files->Source()->WriteLine("bool " + StructureName() + "::fromJSON(const JSONObject& obj)");
			files->Source()->WriteLine("{");
			files->Source()->indent();
			files->Source()->WriteLine("clear();");

			for (auto e : Elements())
			{
				if (!e->WriteFromJSON(files->Source()))
				{
					AddError("xml2Asn1CodeGen", "", "Failed to write JSON element");
					return false;
					//printf((tsCryptoString() << "Element " << e->Name() << " in structure " << Name() + " failed to write.\n").c_str());
					//return true;
				}
			}

			files->Source()->WriteLine("");
			files->Source()->WriteLine("return true;");
			files->Source()->outdent();
			files->Source()->WriteLine("}");
		}

		// Write fields
		files->Header()->WriteLine("// Data fields");
		files->Header()->WriteLine("private:");
		files->Header()->WriteLine("bool _isOwner;");
		files->Header()->WriteLine(PODStructureName() + "* _data;");
		files->Header()->WriteLine("public:");
		files->Header()->WriteLine("virtual void* getData() override { return (void*)_data; }");
		files->Header()->WriteLine("virtual const void* getData() const override { return (const void*)_data; }");

		files->Header()->WriteLine();

		// Write data accessors
		files->Header()->WriteLine("// Accessors");
		if (HasOID() && !InheritedHasOID())
		{
			files->Header()->WriteLine("const Asn1OID& get_OID() const;");
			files->Source()->WriteLine("const Asn1OID& " + StructureName() + "::get_OID() const { return _data->_OID; }");
			files->Header()->WriteLine("void set_OID(const Asn1OID& setTo);");
			files->Source()->WriteLine("void " + StructureName() + "::set_OID(const Asn1OID& setTo) { _data->_OID = setTo; }");
			files->Header()->WriteLine("void clear_OID();");
			files->Source()->WriteLine("void " + StructureName() + "::clear_OID() { _data->_OID = Asn1OID(" + DefaultOID() + "); }");
			files->Header()->WriteLine();
		}
		if (HasVersion() && !InheritedHasVersion())
		{
			files->Header()->WriteLine("int32_t get_VERSION() const;");
			files->Source()->WriteLine("int32_t " + StructureName() + "::get_VERSION() const { return _data->_VERSION; }");
			files->Header()->WriteLine("void set_VERSION(int32_t setTo);");
			files->Source()->WriteLine("void " + StructureName() + "::set_VERSION(int32_t setTo) { _data->_VERSION = setTo; }");
			files->Header()->WriteLine("void clear_VERSION();");
			files->Source()->WriteLine("void " + StructureName() + "::clear_VERSION() { _data->_VERSION = " + (tsCryptoString().append(DefaultVersion())) + "; }");
			files->Header()->WriteLine();
		}
		for (auto e : Elements())
		{
			e->WriteAccessors(files, StructureName());
		}
		files->Header()->WriteLine();

		for (auto& ver : Versions())
		{
			files->Header()->WriteLine(tsCryptoString().append("bool is_").append(ver->Name()).append("() const;"));
			files->Source()->WriteLine(tsCryptoString().append("bool ").append(StructureName()).append("::is_").append(ver->Name()).append("() const"));
			files->Source()->WriteLine("{");
			files->Source()->indent();
			if (HasOID() && (!ver->HasOID() || ver->OID() == "*"))
			{
				tsCryptoString tmp;
				for (auto& ver1 : Versions())
				{
					if (ver1->HasOID())
					{
						if (tmp.size() > 0)
							tmp += " || ";
						tmp.append("is_").append(ver1->Name()).append("()");
					}
				}
				if (tmp.size() > 0)
				{
					files->Source()->WriteLine(tsCryptoString().append("if (").append(tmp).append(")"));
					files->Source()->WriteLine("	return false;");
				}
			}
			else if (HasOID() && ver->HasOID())
			{
				if (ver->OID()[0] == '0' || ver->OID()[0] == '1' || ver->OID()[0] == '2')
				{
					files->Source()->WriteLine("if (_data->_OID.oidString() != \"" + ver->OID() + "\")");
				}
				else
				{
					files->Source()->WriteLine("if (_data->_OID.oidString() != " + ver->OID() + ")");
				}
				files->Source()->WriteLine("	return false;");
			}

			if (HasVersion() && ver->HasVersion())
			{
				if (ver->maxVersion() > -1)
				{
					files->Source()->WriteLine(tsCryptoString().append("if (_data->_VERSION > ").append(ver->maxVersion()).append(")"));
					files->Source()->WriteLine("	return false;");
				}
				if (ver->minVersion() > -1)
				{
					files->Source()->WriteLine(tsCryptoString().append("if (_data->_VERSION < ").append(ver->minVersion()).append(")"));
					files->Source()->WriteLine("	return false;");
				}
			}
			files->Source()->WriteLine("return true;");
			files->Source()->outdent();
			files->Source()->WriteLine("}");

			ver->WriteVersionElementAccessors(files);
		}
		// Write user functions
		for (auto f : Functions())
		{
			files->Header()->WriteLine(f->ReturnType() + " " + f->Name() + "(" + f->Parameters() + ")" + f->Suffix() + ";");
		}

		files->Header()->outdent();
		files->Header()->WriteLine("};");

		_WriteUserFunctions(files->Source());


		// Write metadata externs
		files->Header()->WriteLine();

		//// Now write the encoder functions and metadata for each sequence/choice
		for (auto e : Elements())
		{
			if (!e->WriteUserFunctions(files->Source()))
			{
				AddError("xml2Asn1CodeGen", "", "Unable to write the user defined functions.\n");
				return false;
			}
		}
	}
#endif // 0
	return true;
}
bool SequenceNode::_WriteUserFunctions(File* file)
{
	tsStringBase ns;

	if (!!NameSpace())
		ns = NameSpace()->ToString();

	if (Functions().size() > 0)
	{
		file->WriteLine();
		file->WriteLine("// User defined functions");
	}
	for (auto f : Functions())
	{
		if (f->Description().size() > 0)
			file->WriteLine(f->Description());
		file->WriteLine(f->ReturnType() + " " + ns + PODStructureName() + "::" + f->Name() + "(" + f->Parameters() + ")" + f->Suffix());
		file->WriteLine("{");
		file->indent();

		file->WriteLine(f->Body().Trim("\r\n"));

		file->outdent();
		file->WriteLine("}");
		file->WriteLine();
	}
	return true;
}

tsStringBase SequenceNode::FullName()
{
	tsStringBase _fullname;

	std::shared_ptr<Namespace> ns = NameSpace();
	if (!!ns)
	{
		_fullname = ns->ToString() + Name();
	}
	else
		_fullname = Name();
	return _fullname;
}
tsStringBase SequenceNode::FullStructureName()
{
	tsStringBase _fullname;

	std::shared_ptr<Namespace> ns = NameSpace();
	if (!!ns)
	{
		_fullname = ns->ToString() + StructureName();
	}
	else
		_fullname = StructureName();
	return _fullname;
}
