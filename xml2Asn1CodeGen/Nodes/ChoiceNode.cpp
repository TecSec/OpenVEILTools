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
#include "ChoiceNode.h"
#include "DescriptionNode.h"
#include "BasicFieldNode.h"
#include "ChoiceNode.h"
#include "SequenceFieldNode.h"
#include "SetNode.h"
#include "FileNode.h"
#include "FunctionNode.h"

bool ChoiceNode::Validate()
{
	if (Validated())
		return true;
	Validated(true);
	if (!Attributes().hasItem("Name"))
	{
		AddError("xml2Asn1CodeGen", "", "Choice is missing the Name attribute.\n");
		return false;
	}

	Name(Attributes().item("Name"));

	std::shared_ptr<tsXmlNode> node = Parent().lock();

	while (!!node && !std::dynamic_pointer_cast<Element>(node))
		node = node->Parent().lock();

	if (!node)
	{
		AddError("xml2Asn1CodeGen", "", "Unable to find the node container for this choice.\n");
		return false;
	}
	tsStringBase parentName = std::dynamic_pointer_cast<Element>(node)->NameForParent();

	if (parentName.size() > 0)
		parentName.append("_");
	StructureName(parentName + Name());
	JSONName(Attributes().item("JSONName"));
	CppType(StructureName());
	IsOptional(Attributes().itemAsBoolean("Optional", false));
	Export(Attributes().itemAsBoolean("Exported", false));
	Import(Attributes().itemAsBoolean("Imported", false));

	for (size_t i = 0; i < Children().size(); i++)
	{
		std::shared_ptr<tsXmlNode> node1 = Children().at(i);
		std::shared_ptr<ProcessableNode> pNode = std::dynamic_pointer_cast<ProcessableNode>(node1);
		if (!pNode)
			return false;
		if (!pNode->Validate())
			return false;
	}
	return true;
}
bool ChoiceNode::Process()
{

	return false;
}
std::shared_ptr<tsXmlNode> ChoiceNode::CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes)
{
	std::shared_ptr<tsXmlNode> tmp;

	// TODO:  Synchronize with FileNode
	if (name == "Description")
	{
		tmp = IObject::Create<DescriptionNode>();
	}
	else  if (name == "Function")
	{
		tmp = IObject::Create<FunctionNode>();
		Functions().push_back(std::dynamic_pointer_cast<FunctionNode>(tmp));
	}
	else
	{
		tmp = SequenceNode::BuildField(std::dynamic_pointer_cast<ElementContainer>(_me.lock()), name, Attributes, GetFileNode());
	}


	if (!!tmp)
	{
		tmp->Attributes() = Attributes;
		return tmp;
	}
	AddError("xml2Asn1CodeGen", "CreateNode", "Unable to create node " + name, 2000);
	return nullptr;
}

bool ChoiceNode::WriteForwardReference(std::shared_ptr<FileNode> files)
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
				line.append("<Choice Name=\"").append(StructureName()).append("\" Imported=\"true\"");
				files->Export()->WriteLine(line + "/>");
			}
		}
	}
	return true;
}
tsStringBase ChoiceNode::buildInitializers(InitializerType type)
{
	tsStringBase tmp;

	switch (type)
	{
	case ForConstruct:
		tmp.append("selectedItem(choiceType::Choice_None)");
		break;
	case ForCopy:
		tmp.append("selectedItem(obj.selectedItem)");
		break;
	case ForMove:
		tmp.append("selectedItem(obj.selectedItem)");
		break;
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

bool ChoiceNode::WritePODStructure(std::shared_ptr<FileNode> files)
{
	tsStringBase ns;

	if (!!NameSpace())
	{
		ns = NameSpace()->ToString();
	}

	//SequenceNode* parent = dynamic_cast<SequenceNode*>(this->Parent());

	//if (parent != nullptr)
	//{
	//	if (!parent->WriteFieldMetadata(files->Source(), nullptr, "", "", 0))
	//		return false;
	//}

	if (PODStructureWritten())
		return true;
	PODStructureWritten(true);

	if (!Import())
	{
		for (auto& ele : Elements())
		{
			if (!ele->WritePODStructure(files))
			{
				return false;
			}
		}
		files->Header()->SetNamespace(NameSpace());

		files->Header()->WriteLine("// ----------------------------------------------------------------");
		files->Header()->WriteLine();

		files->Header()->WriteLine("struct " + files->ExportSymbol() + PODStructureName() + " {");
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

		// Write choice enum
		files->Header()->WriteLine("typedef enum {");
		files->Header()->indent();
		files->Header()->WriteLine("Choice_None, ");
		for (auto ele : Elements())
		{
			files->Header()->WriteLine("Choice_" + ele->Name() + ",");
		}
		files->Header()->outdent();
		files->Header()->WriteLine("}  choiceType;");
		files->Header()->WriteLine();
		// Write parts
		files->Header()->WriteLine("typedef enum {");
		files->Header()->indent();
		files->Header()->WriteLine("Part_Main,");
		files->Header()->outdent();
		files->Header()->WriteLine("} parts;");

		files->Header()->outdent();
		files->Header()->WriteLine("private:");
		files->Header()->indent();
		files->Header()->WriteLine("choiceType selectedItem;");

		for (auto e : Elements())
		{
			if (!e->WritePODFieldDefinition(files))
			{
				AddError("xml2Asn1CodeGen", "", (tsStringBase().append("Element ").append(e->Name()).append(" in structure ").append(Name()).append(" failed to write.\n")));
				return false;
			}
		}
		files->Header()->outdent();
		files->Header()->WriteLine("public:");
		files->Header()->indent();

		files->Header()->WriteLine("");
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
		files->Header()->WriteLine("obj.selectedItem = choiceType::Choice_None;");

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

		files->Header()->WriteLine("");
		files->Header()->WriteLine("// Assignment and Move operators");
		// Assignment operator
		files->Header()->WriteLine(PODStructureName() + "& operator=(const " + PODStructureName() + "& obj)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("if (&obj != this)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("selectedItem = obj.selectedItem;");
		for (auto e : Elements())
		{
			if (e->IsOptional())
			{
				files->Header()->WriteLine("_" + e->Name() + "_exists = obj._" + e->Name() + "_exists;");
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
		files->Header()->WriteLine("selectedItem = obj.selectedItem;");
		files->Header()->WriteLine("obj.selectedItem = choiceType::Choice_None;");
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
		files->Header()->WriteLine("void clear() { ClearTlv((void*)this, __Metadata_main, __Metadata_main_count); }");

		// Write data accessors
		files->Header()->WriteLine("// Accessors");
		files->Header()->WriteLine("choiceType get_selectedItem() const { return selectedItem; }");
		files->Header()->WriteLine("void set_selectedItem(choiceType setTo) { selectedItem = setTo; }");
		files->Header()->WriteLine();
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
		files->Header()->WriteLine("static tscrypto::Asn1Metadata2::matchResult NodeMatches(const std::shared_ptr<tscrypto::TlvNode> node, const tscrypto::Asn1Metadata2* metadata);");
		files->Source()->WriteLine("tscrypto::Asn1Metadata2::matchResult " + ns + PODStructureName() + "::NodeMatches(const std::shared_ptr<tscrypto::TlvNode> node, const tscrypto::Asn1Metadata2* metadata)");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	for (size_t i = 0; i < __Metadata_main_count; i++)");
		files->Source()->WriteLine("	{");
		files->Source()->WriteLine("		if (NodeMatchesMetadata(node, &__Metadata_main[i]) == tscrypto::Asn1Metadata2::good)");
		files->Source()->WriteLine("			return tscrypto::Asn1Metadata2::good;");
		files->Source()->WriteLine("	}");
		files->Source()->WriteLine("	if (metadata->fieldFlags & tscrypto::Asn1Metadata2::tp_optional)");
		files->Source()->WriteLine("	{");
		files->Source()->WriteLine("		return tscrypto::Asn1Metadata2::defaulted;");
		files->Source()->WriteLine("	}");
		files->Source()->WriteLine("	return tscrypto::Asn1Metadata2::mismatch;");
		files->Source()->WriteLine("}");

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
				// Write the field metadata here
				files->Header()->WriteLine(tsStringBase().append("static const size_t __Metadata_main_count = ").append((int32_t)Elements().size()).append(";"));

				files->Header()->WriteLine(tsStringBase().append("static const struct tscrypto::Asn1Metadata2 __Metadata_main[__Metadata_main_count];"));

				files->Source()->WriteLine(tsStringBase().append("const struct tscrypto::Asn1Metadata2 " + ns + PODStructureName() + "::__Metadata_main[" + ns + PODStructureName() + "::__Metadata_main_count] ="));
				files->Source()->WriteLine("{");
				files->Source()->indent();
				for (auto e : Elements())
				{
					files->Source()->WriteLine(e->BuildMetadataLine(FullStructureName(), ns + PODStructureName()));
				}
				files->Source()->outdent();
				files->Source()->WriteLine("};");
				files->Source()->WriteLine();

				files->Header()->WriteLine(tsStringBase().append("static const int __selectedItemInfo;"));
				files->Source()->WriteLine(tsStringBase().append("const int " + ns + PODStructureName() + "::__selectedItemInfo = offsetof(" + ns + PODStructureName() + ", selectedItem);"));
				files->Header()->WriteLine();
				files->Source()->WriteLine();

			}
		}

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
		files->Header()->WriteLine("doc->DocumentElement()->Tag(__tag);");
		files->Header()->WriteLine("doc->DocumentElement()->Type(__type);");
		files->Header()->WriteLine("if (!EncodeChildren(doc))");
		files->Header()->WriteLine("	return false;");
		files->Header()->WriteLine();
		files->Header()->WriteLine("output = doc->DocumentElement()->InnerData();");
		files->Header()->WriteLine("return true;");
		files->Header()->outdent();
		files->Header()->WriteLine("}");

		files->Header()->WriteLine("bool Encode(std::shared_ptr<tscrypto::TlvNode> parent)");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("	if (!EncodeChildren(parent))");
		files->Header()->WriteLine("		return false;");
		files->Header()->WriteLine("	return true;");
		files->Header()->WriteLine("}");

		// Decode
		files->Header()->WriteLine("bool Decode(const tscrypto::tsCryptoData& input, bool withoutWrapper = false)");
		files->Header()->WriteLine("{");
		files->Header()->indent();
		files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
		files->Header()->WriteLine();
		files->Header()->WriteLine("doc->DocumentElement()->Tag(__tag);");
		files->Header()->WriteLine("doc->DocumentElement()->Type((uint8_t)__type);");
		files->Header()->WriteLine("if (doc->DocumentElement()->InnerTlv(input) == 0)");
		files->Header()->WriteLine("	return false;");
		files->Header()->WriteLine();
		files->Header()->WriteLine("if (doc->DocumentElement()->Tag() != __tag || doc->DocumentElement()->Type() != __type)");
		files->Header()->WriteLine("	return false;");
		files->Header()->WriteLine();
		files->Header()->WriteLine("return DecodeChildren(doc->DocumentElement());");
		files->Header()->outdent();
		files->Header()->WriteLine("}");

		files->Header()->WriteLine();

		// Encode Children
		files->Header()->WriteLine("bool EncodeChildren(std::shared_ptr<tscrypto::TlvDocument> doc)");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("	return EncodeChoiceTlv(this, doc->DocumentElement(), selectedItem, __Metadata_main, __Metadata_main_count);");
		files->Header()->WriteLine("}");

		files->Header()->WriteLine("bool EncodeChildren(std::shared_ptr<tscrypto::TlvNode> root)");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("	return EncodeChoiceTlv(this, root, selectedItem, __Metadata_main, __Metadata_main_count);");
		files->Header()->WriteLine("}");

		// Decode Children
		files->Header()->WriteLine("bool DecodeChildren(const std::shared_ptr<tscrypto::TlvNode> root)");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("	return DecodeChoiceTlv(this, root, (int32_t*)&selectedItem, __Metadata_main, __Metadata_main_count);");
		files->Header()->WriteLine("}");

		files->Header()->WriteLine();

		// JSON functions
		files->Header()->WriteLine("// JSON functions");
		if (JSONName().size() > 0)
		{
			files->Header()->WriteLine("static const char* JSONName() { return \"" + JSONName() + "\"; }");

			files->Header()->WriteLine("tscrypto::JSONObject toJSON() const { tscrypto::JSONObject obj; if (!toJSON(obj)) obj.clear(); return obj; }");
			files->Header()->WriteLine("bool toJSON(tscrypto::JSONObject& obj) const");
			files->Header()->WriteLine("{");
			files->Header()->indent();

			files->Header()->WriteLine("switch (selectedItem)");
			files->Header()->WriteLine("{");
			for (auto& e : Elements())
			{
				if (e->JSONName().size() > 0)
				{
					files->Header()->WriteLine("case " + PODStructureName() + "::Choice_" + e->Name() + ":");
					files->Header()->indent();
					if (!e->WriteToJSON(files->Header()))
					{
						AddError("xml2Asn1CodeGen", "", "Failed to write JSON element");
						return false;
					}
					files->Header()->WriteLine("break;");
					files->Header()->outdent();
				}
			}
			files->Header()->WriteLine("default:");
			files->Header()->WriteLine("	return false;");
			files->Header()->WriteLine("}");
			files->Header()->WriteLine("return true;");
			files->Header()->outdent();
			files->Header()->WriteLine("}");

			files->Header()->WriteLine("bool fromJSON(const tscrypto::tsCryptoStringBase& json) { tscrypto::JSONObject obj; if (!obj.FromJSON(json)) return false; return fromJSON(obj); }");
			files->Header()->WriteLine("bool fromJSON(const tscrypto::JSONObject& obj)");
			files->Header()->WriteLine("{");
			files->Header()->indent();
			files->Header()->WriteLine("clear();");
			for (auto& e : Elements())
			{
				if (e->JSONName().size() > 0)
				{
					files->Header()->WriteLine("if (obj.hasField(\"" + e->JSONName() + "\"))");
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("selectedItem = " + PODStructureName() + "::Choice_" + e->Name() + ";");
					if (!e->WriteFromJSON(files->Header()))
					{
						AddError("xml2Asn1CodeGen", "", "Failed to write JSON element");
						return false;
						//printf((tsCryptoString() << "Element " << e->Name() << " in structure " << Name() + " failed to write.\n").c_str());
						//return true;
					}
					files->Header()->WriteLine("return true;");
					files->Header()->outdent();
					files->Header()->WriteLine("}");
				}
			}
			files->Header()->WriteLine("return false;");
			files->Header()->outdent();
			files->Header()->WriteLine("}");
		}


		files->Header()->outdent();
		files->Header()->WriteLine("};");
		files->Header()->WriteLine();
	}
	return true;
}
bool ChoiceNode::WriteStructure(std::shared_ptr<FileNode> files)
{
#if 0
	//SequenceNode* parent = dynamic_cast<SequenceNode*>(this->Parent());

	//if (parent != nullptr)
	//{
	//	if (!parent->WriteFieldMetadata(files->Source(), nullptr, "", "", 0))
	//		return false;
	//}

	if (StructureWritten())
		return true;
	StructureWritten(true);

	if (!Import())
	{
		for (auto& ele : Elements())
		{
			if (!ele->WriteStructure(files))
			{
				return false;
			}
		}
		files->Header()->SetNamespace(NameSpace());


		files->Source()->SetNamespace(NameSpace());
		files->Source()->WriteLine("// ----------------------------------------------------------------");
		files->Source()->WriteLine("// " + StructureName());
		files->Source()->WriteLine();


		files->Header()->SetNamespace(NameSpace());

		//files->Header()->WriteLine("// IMPORTANT NOTE:  We are using offsetof on non-POD structs.  This may cause memory corruption in the future.  Consider rewriting with a different serializer (member functions, more specialized classes, ...");
		files->Header()->WriteLine("struct " + files->ExportSymbol() + StructureName() + " final : public Asn1DataBaseClass {");

		files->Header()->indent();

		files->Header()->WriteLine(StructureName() + "() {}");
		files->Header()->WriteLine(StructureName() + "(const " + StructureName() + "& obj) : _data(obj._data)");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine(StructureName() + "(" + StructureName() + "&& obj) : _data(std::move(obj._data))");
		files->Header()->WriteLine("{");
		files->Header()->WriteLine("}");
		files->Header()->WriteLine("~" + StructureName() + "() { }");
		//files->Header()->WriteLine(StructureName() + "& operator=(const " + StructureName() + "& obj)");
		//files->Header()->WriteLine("{");
		//files->Header()->indent();
		//files->Header()->WriteLine("if (this == &obj)");
		//files->Header()->WriteLine("    return *this;");
		//files->Header()->WriteLine();

		//files->Header()->WriteLine("selectedItem = obj.selectedItem;");
		//if (!Elements().first_that([&files](Element* ele)->bool{ return !ele->WriteCopyLine(files->Header()); }).AtEnd())
		//{
		//	AddError("xml2Asn1CodeGen", "", "Unable to write the sequence Header()->\n");
		//	return false;
		//}
		//files->Header()->WriteLine("return *this;");
		//files->Header()->outdent();
		//files->Header()->WriteLine("}");


		// Equality operator
		files->Header()->WriteLine("virtual bool operator==(const Asn1DataBaseClass& obj) const override;");
		files->Source()->WriteLine("bool " + StructureName() + "::operator==(const Asn1DataBaseClass& obj) const");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("const " + StructureName() + "* o = dynamic_cast<const " + StructureName() + "*>(&obj);");
		files->Source()->WriteLine();
		files->Source()->WriteLine("if (o == nullptr) return false;");
		files->Source()->WriteLine("if (o == this) return true;");

		files->Source()->WriteLine("if (!(_data.selectedItem == o->_data.selectedItem)) return false;");
		for (auto e : Elements())
		{
			if (e->ElementType() != "Null")
				files->Source()->WriteLine("if (" + e->BuildInequalityTest("o->") + ") return false;");
		}

		files->Source()->WriteLine("return true;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");
		files->Source()->WriteLine();

		// clone
		files->Header()->WriteLine("virtual Asn1DataBaseClass* clone() const override;");
		files->Source()->WriteLine("Asn1DataBaseClass* " + StructureName() + "::clone() const");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine(StructureName() + " *o = new " + StructureName() + "();");
		files->Source()->WriteLine("");
		files->Source()->WriteLine("o->_data.selectedItem = _data.selectedItem;");
		for (auto e : Elements())
		{
			files->Source()->WriteLine(e->BuildCloneLine("o->"));
		}
		files->Source()->WriteLine("");
		files->Source()->WriteLine("return o;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		files->Header()->WriteLine();

		// Assignment operator
		files->Header()->WriteLine("virtual Asn1DataBaseClass& operator=(const Asn1DataBaseClass& o) override;");
		files->Source()->WriteLine("Asn1DataBaseClass& " + StructureName() + "::operator=(const Asn1DataBaseClass& o)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("const " + StructureName() + "* obj = dynamic_cast<const " + StructureName() + "*>(&o);");
		files->Source()->WriteLine("if (obj != this && obj != nullptr)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("_data = obj->_data;");
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
		files->Source()->WriteLine("_data = obj._data;");
		files->Source()->WriteLine("return *this;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		// Move operator
		files->Header()->WriteLine("virtual Asn1DataBaseClass& operator=(Asn1DataBaseClass&& o) override;");
		files->Source()->WriteLine("Asn1DataBaseClass& " + StructureName() + "::operator=(Asn1DataBaseClass&& o)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine(StructureName() + "* obj = dynamic_cast<" + StructureName() + "*>(&o);");
		files->Source()->WriteLine("if (obj != this && obj != nullptr)");
		files->Source()->WriteLine("{");
		files->Source()->indent();
		files->Source()->WriteLine("_data = std::move(obj->_data);");
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
		files->Header()->outdent();
		files->Header()->WriteLine("} parts;");
		// TODO:  Write encode function definitions

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
		files->Source()->WriteLine("doc->DocumentElement()->Tag(__" + StructureName() + "_tag);");
		files->Source()->WriteLine("doc->DocumentElement()->Type(__" + StructureName() + "_type);");
		files->Source()->WriteLine("if (!EncodeChildren(doc))");
		files->Source()->WriteLine("	return false;");
		files->Source()->WriteLine();
		files->Source()->WriteLine("output = doc->DocumentElement()->InnerData();");
		files->Source()->WriteLine("return true;");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		files->Header()->WriteLine("virtual bool Encode(std::shared_ptr<TlvNode> parent) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::Encode(std::shared_ptr<TlvNode> parent)");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	if (!EncodeChildren(parent))");
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
		files->Source()->WriteLine("doc->DocumentElement()->Tag(__" + StructureName() + "_tag);");
		files->Source()->WriteLine("doc->DocumentElement()->Type((uint8_t)__" + StructureName() + "_type);");
		files->Source()->WriteLine("if (doc->DocumentElement()->InnerTlv(input) == 0)");
		files->Source()->WriteLine("	return false;");
		files->Source()->WriteLine();
		files->Source()->WriteLine("if (doc->DocumentElement()->Tag() != __" + StructureName() + "_tag || doc->DocumentElement()->Type() != __" + StructureName() + "_type)");
		files->Source()->WriteLine("	return false;");
		files->Source()->WriteLine();
		files->Source()->WriteLine("return DecodeChildren(doc->DocumentElement());");
		files->Source()->outdent();
		files->Source()->WriteLine("}");

		files->Header()->WriteLine();

		// Encode Children
		files->Header()->WriteLine("virtual bool EncodeChildren(std::shared_ptr<TlvDocument> doc) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::EncodeChildren(std::shared_ptr<TlvDocument> doc)");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	return EncodeChoiceTlv(this, doc->DocumentElement(), _data.selectedItem, __" + StructureName() + "_Metadata_main, __" + StructureName() + "_Metadata_main_count);");
		files->Source()->WriteLine("}");

		files->Header()->WriteLine("virtual bool EncodeChildren(std::shared_ptr<TlvNode> root) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::EncodeChildren(std::shared_ptr<TlvNode> root)");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	return EncodeChoiceTlv(this, root, _data.selectedItem, __" + StructureName() + "_Metadata_main, __" + StructureName() + "_Metadata_main_count);");
		files->Source()->WriteLine("}");

		// Decode Children
		files->Header()->WriteLine("virtual bool DecodeChildren(const std::shared_ptr<TlvNode> root) override;");
		files->Source()->WriteLine("bool " + StructureName() + "::DecodeChildren(const std::shared_ptr<TlvNode> root)");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	return DecodeChoiceTlv(this, root, (int32_t*)&_data.selectedItem, __" + StructureName() + "_Metadata_main, __" + StructureName() + "_Metadata_main_count);");
		files->Source()->WriteLine("}");

		files->Header()->WriteLine();

		// JSON functions
		if (JSONName().size() > 0)
		{
			files->Header()->WriteLine("static const char* JSONName() { return \"" + JSONName() + "\"; }");

			files->Header()->WriteLine("virtual tscrypto::JSONObject toJSON() const override { return Asn1DataBaseClass::toJSON(); }");
			files->Header()->WriteLine("virtual bool fromJSON(const char* json) override { return Asn1DataBaseClass::fromJSON(json); }");
			files->Header()->WriteLine("virtual bool fromJSON(const tscrypto::tsCryptoStringBase& json) override { return Asn1DataBaseClass::fromJSON(json.c_str()); }");

			files->Header()->WriteLine("bool toJSON(tscrypto::JSONObject& obj) const override;");
			files->Source()->WriteLine("bool " + StructureName() + "::toJSON(tscrypto::JSONObject& obj) const");
			files->Source()->WriteLine("{");
			files->Source()->indent();

			files->Source()->WriteLine("switch (_data.selectedItem)");
			files->Source()->WriteLine("{");
			for (auto& e : Elements())
			{
				if (e->JSONName().size() > 0)
				{
					files->Source()->WriteLine("case " + PODStructureName() + "::Choice_" + e->Name() + ":");
					files->Source()->indent();
					if (!e->WriteToJSON(files->Source()))
					{
						AddError("xml2Asn1CodeGen", "", "Failed to write JSON element");
						return false;
					}
					files->Source()->WriteLine("break;");
					files->Source()->outdent();
				}
			}
			files->Source()->WriteLine("default:");
			files->Source()->WriteLine("	return false;");
			files->Source()->WriteLine("}");
			files->Source()->WriteLine("return true;");
			files->Source()->outdent();
			files->Source()->WriteLine("}");

			files->Header()->WriteLine("bool fromJSON(const JSONObject& obj) override;");
			files->Source()->WriteLine("bool " + StructureName() + "::fromJSON(const JSONObject& obj)");
			files->Source()->WriteLine("{");
			files->Source()->indent();
			files->Source()->WriteLine("clear();");
			for (auto& e : Elements())
			{
				if (e->JSONName().size() > 0)
				{
					files->Source()->WriteLine("if (obj.hasField(\"" + e->JSONName() + "\"))");
					files->Source()->WriteLine("{");
					files->Source()->indent();
					files->Source()->WriteLine("_data.selectedItem = " + PODStructureName() + "::Choice_" + e->Name() + ";");
					if (!e->WriteFromJSON(files->Source()))
					{
						AddError("xml2Asn1CodeGen", "", "Failed to write JSON element");
						return false;
						//printf((tsCryptoString() << "Element " << e->Name() << " in structure " << Name() + " failed to write.\n").c_str());
						//return true;
					}
					files->Source()->WriteLine("return true;");
					files->Source()->outdent();
					files->Source()->WriteLine("}");
				}
			}
			files->Source()->WriteLine("return false;");
			files->Source()->outdent();
			files->Source()->WriteLine("}");
		}

		// Write fields
		files->Header()->WriteLine("// Data fields");
		files->Header()->WriteLine("private:");
		files->Header()->WriteLine(PODStructureName() + " _data;");
		files->Header()->WriteLine("public:");
		files->Header()->WriteLine("virtual void* getData() override { return (void*)&_data; }");
		files->Header()->WriteLine("virtual const void* getData() const override { return (const void*)&_data; }");
		files->Header()->WriteLine();

		// Accessors
		files->Header()->WriteLine("// Accessors");
		files->Header()->WriteLine(PODStructureName() + "::choiceType get_selectedItem() const { return _data.selectedItem; }");
		files->Header()->WriteLine("void set_selectedItem(" + PODStructureName() + "::choiceType setTo) { _data.selectedItem = setTo; }");
		files->Header()->WriteLine("void clear_selectedItem() { _data.selectedItem = " + PODStructureName() + "::choiceType::Choice_None; }");
		files->Header()->WriteLine();
		for (auto e : Elements())
		{
			e->WriteAccessors(files, StructureName());
		}
		files->Header()->WriteLine();




		// clear
		files->Header()->WriteLine("virtual void clear() override;");
		files->Source()->WriteLine("void " + StructureName() + "::clear()");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	_data.selectedItem = " + PODStructureName() + "::Choice_None;");
		files->Source()->WriteLine("	ClearTlv(this, __" + StructureName() + "_Metadata_main, __" + StructureName() + "_Metadata_main_count);");
		files->Source()->WriteLine("}");

		files->Header()->WriteLine("static Asn1Metadata::matchResult NodeMatches(const std::shared_ptr<TlvNode> node, const Asn1Metadata* metadata);");
		files->Source()->WriteLine("Asn1Metadata::matchResult " + FullStructureName() + "::NodeMatches(const std::shared_ptr<TlvNode> node, const Asn1Metadata* metadata)");
		files->Source()->WriteLine("{");
		files->Source()->WriteLine("	for (size_t i = 0; i < __" + StructureName() + "_Metadata_main_count; i++)");
		files->Source()->WriteLine("	{");
		files->Source()->WriteLine("		if (NodeMatchesMetadata(node, &__" + StructureName() + "_Metadata_main[i]) == Asn1Metadata::good)");
		files->Source()->WriteLine("			return Asn1Metadata::good;");
		files->Source()->WriteLine("	}");
		files->Source()->WriteLine("	if (metadata->fieldFlags & Asn1Metadata::tp_optional)");
		files->Source()->WriteLine("	{");
		files->Source()->WriteLine("		return Asn1Metadata::defaulted;");
		files->Source()->WriteLine("	}");
		files->Source()->WriteLine("	return Asn1Metadata::mismatch;");
		files->Source()->WriteLine("}");

		// Write user functions
		for (auto f : Functions())
		{
			files->Header()->WriteLine(f->ReturnType() + " " + f->Name() + "(" + f->Parameters() + ")" + f->Suffix() + ";");
		}
		_WriteUserFunctions(files->Source());


		files->Header()->outdent();
		files->Header()->WriteLine("};");
		files->Header()->WriteLine();

		//// Now write the encoder functions and metadata for each sequence/choice
		//if (!Elements().first_that([this, files](Element* e)->bool{
		//	if (!e->WriteEncoderFunctions(files->Source()))
		//	{
		//		AddError("xml2Asn1CodeGen", "", "Unable to write the encoders.\n");
		//		return true;
		//	}
		//	if (!e->WriteMetadata(files->Source()))
		//	{
		//		AddError("xml2Asn1CodeGen", "", "Unable to write the metadata.\n");
		//		return true;
		//	}
		//	if (!e->WriteUserFunctions(files->Source()))
		//	{
		//		AddError("xml2Asn1CodeGen", "", "Unable to write the user defined functions.\n");
		//		return true;
		//	}
		//	return false;
		//}).AtEnd())
		//{
		//	return false;
		//}
	}
#endif // 0
	return true;
}
bool ChoiceNode::_WriteUserFunctions(File* file)
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
bool ChoiceNode::WritePODFieldDefinition(std::shared_ptr<FileNode> files)
{
	//if (IsOptional())
	//{
	//	files->Header()->WriteLine("Asn1OptionalStruct _" + Name() + ";");
	//}
	//else
	{
		if (!!NameSpace())
			files->Header()->WriteLine(NameSpace()->ToString() + PODStructureName() + " _" + Name() + ";");
		else
			files->Header()->WriteLine(PODStructureName() + " _" + Name() + ";");
	}
	return true;
}
tsStringBase ChoiceNode::BuildMoveLine(const tsStringBase& rightObject)
{
	tsStringBase tmp;

	if (IsOptional())
	{
		tmp.append("_").append(Name()).append(" = std::move(").append(rightObject).append("_").append(Name()).append(");");
	}
	else
	{
		tmp.append("_").append(Name()).append(" = std::move(").append(rightObject).append("_").append(Name()).append(");");
	}

	return tmp;
}
tsStringBase ChoiceNode::BuildClearForMove(const tsStringBase& rightObject)
{
	return "";
}

bool ChoiceNode::WriteToJSON(File* file)
{
	if (JSONName().size() == 0)
	{
		file->WriteLine("// NOTE:  optional field _" + Name() + " does not have a JSON name");
		return true;
	}

	tsStringBase type = Elements()[0]->ElementType();
	tsStringBase tmp;

	if (IsOptional())
	{
		file->WriteLine("if (_" + Name() + "_exists)");
		file->WriteLine("{");
		file->indent();
		tmp = getToOptionalJsonLine(type);
	}
	else
		tmp = getToJsonLine(type);

	if (tmp.size() > 0)
	{
		tmp.Replace("{JSONName}", JSONName()).Replace("{Name}", "list[i]").Replace("{ElementName}", "");
	}
	else
	{
		file->WriteLine("#error  Missing optional support for " + Elements()[0]->JSONName() + " on field _" + Elements()[0]->Name());
		return false;
	}

	file->WriteLine("if (!obj.hasField(\"" + JSONName() + "\"))");
	file->WriteLine("	obj.createArrayField(\"" + JSONName() + "\");");

	file->WriteLine(tsStringBase().append("for (size_t i = 0; i < _list.size(); i++)"));
	file->WriteLine("{");
	file->indent();
	file->WriteLine(tmp);
	file->outdent();
	file->WriteLine("}");

	if (IsOptional())
	{
		file->outdent();
		file->WriteLine("}");
	}

	return true;
}
bool ChoiceNode::WriteFromJSON(File* file)
{
	if (JSONName().size() == 0)
	{
		file->WriteLine("// NOTE:  optional field _" + Name() + " does not have a JSON name");
		return true;
	}

	if (IsOptional())
	{
		file->WriteLine("if (obj.hasField(\"" + JSONName() + "\"))");
		file->WriteLine("{");
		file->indent();
	}
	std::shared_ptr<SequenceFieldNode> sequence = std::dynamic_pointer_cast<SequenceFieldNode>(Elements()[0]);

	if (!!sequence)
	{
		file->WriteLine("obj.foreach(\"" + JSONName() + "\", [this](const tscrypto::JSONField&fld){");
		file->WriteLine("");
		file->WriteLine("	if (fld.Type() == tscrypto::JSONField::jsonObject)");
		file->WriteLine("	{");
		file->WriteLine("		xxx data;");
		file->WriteLine("");
		file->WriteLine("		if (data.fromJSON(fld.AsObject()))");
		if (IsOptional())
		{
			file->WriteLine("			this->_list.add(std::move(data));");
		}
		else
		{
			file->WriteLine("			this->_list.push_back(data.clone());");
		}
		file->WriteLine("	}");
		file->WriteLine("});");
	}
	else
		file->WriteLine(" #error  Implement me - SequenceOf - WriteFromJSON");
	if (IsOptional())
	{
		file->outdent();
		file->WriteLine("}");
	}
	return true;

}

tsStringBase ChoiceNode::FullName()
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
tsStringBase ChoiceNode::FullStructureName()
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
