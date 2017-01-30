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
#include "PartNode.h"
#include "DescriptionNode.h"
#include "VersionNode.h"
#include "FileNode.h"
#include "BasicFieldNode.h"
#include "ChoiceFieldNode.h"
#include "SequenceFieldNode.h"
#include "SequenceOfFieldNode.h"

bool PartNode::Validate()
{
	if (Validated())
		return true;
	Validated(true);
	if (!Attributes().hasItem("Name"))
	{
		AddError("xml2Asn1CodeGen", "", "Part is missing the Name attribute.\n");
		return false;
	}

	Name(Attributes().item("Name"));
	StructureName(Name());
	DontWrap(Attributes().itemAsBoolean("DontWrap", false));
	Export(Attributes().itemAsBoolean("Export", false));
	ParentType(Attributes().item("ParentType"));
	if (ParentType().size() == 0)
		ParentType("Asn1DataBaseClass");
	DefaultVersion(Attributes().itemAsNumber("DefaultVersion", 0));
	DefaultOID(Attributes().item("DefaultOID"));
	Type(Attributes().item("Type"));
	//if (Type().size() == 0)
	//	Type("Universal");
	Tag(Attributes().item("Tag"));
	//if (Tag().size() == 0)
	//	Tag(DefaultTag(std::dynamic_pointer_cast<tsXmlNode>(_me.lock())));
	JSONName(Attributes().item("JSONName"));

	std::shared_ptr<tsXmlNode> node = Parent().lock();

	while (!!node && !std::dynamic_pointer_cast<SequenceNode>(node))
	{
		node = node->Parent().lock();
	}
	if (!!node)
		StructureName(std::dynamic_pointer_cast<SequenceNode>(node)->StructureName());

	for (size_t i = 0; i < Children().size(); i++)
	{
		std::shared_ptr<tsXmlNode> node1 = Children().at(i);
		std::shared_ptr<ProcessableNode> pNode = std::dynamic_pointer_cast<ProcessableNode>(node1);
		if (!pNode)
			return false;
		if (!pNode->Validate())
			return false;
	}

	tsXmlNodeList list = ChildrenByName("Version");

	for (auto node1 : list)
	{
		std::shared_ptr<VersionNode> ver = std::dynamic_pointer_cast<VersionNode>(node1);

		if (!!ver)
		{
			HasOID(HasOID() | ver->HasOID());
			HasVersion(HasVersion() | ver->HasVersion());
		}
	}

	//for (auto node : *Children())
	//{
	//	std::shared_ptr<ArrayNode> ary = std::dynamic_pointer_cast<ArrayNode>(node);
	//	std::shared_ptr<ChoiceNode> choice = std::dynamic_pointer_cast<ChoiceNode>(node);
	//	std::shared_ptr<PartNode> part = std::dynamic_pointer_cast<PartNode>(node);
	//	std::shared_ptr<VersionNode> ver = std::dynamic_pointer_cast<VersionNode>(node);
	//	std::shared_ptr<SequenceFieldNode> seq = std::dynamic_pointer_cast<SequenceFieldNode>(node);
	//	std::shared_ptr<ElementContainer> cont = std::dynamic_pointer_cast<ElementContainer>(node);

	//	if (!!ary || !!choice || !!part /*|| !!ver*/ || !!seq)
	//		Dependencies().push_back(std::dynamic_pointer_cast<Element>(node));
	//	if (!!cont)
	//	{
	//		for (auto n : cont->Elements())
	//		{
	//			std::shared_ptr<Element> ele = std::dynamic_pointer_cast<Element>(n);

	//			if (!!ele)
	//				Dependencies().push_back(std::dynamic_pointer_cast<Element>(ele));
	//		}
	//	}
	//}
	return true;
}
bool PartNode::Process()
{

	return false;
}
std::shared_ptr<tsXmlNode> PartNode::CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes)
{
	std::shared_ptr<tsXmlNode> tmp = nullptr;

	if (name == "Description")
	{
		tmp = IObject::Create<DescriptionNode>();
	}
	else if (name == "Version")
	{
		tmp = IObject::Create<VersionNode>();
		Versions().push_back(std::dynamic_pointer_cast<VersionNode>(tmp));
	}
	else if (name == "Choice")
	{
		if (Attributes.hasItem("ElementType"))
			tmp = IObject::Create<ChoiceFieldNode>();
		else
			tmp = IObject::Create<ChoiceNode>();
		tmp->Attributes() = Attributes;
		if (!AddElement(std::dynamic_pointer_cast<Element>(tmp)))
		{
			AddError("xml2Asn1CodeGen", "CreateNode", "This field name is already used:  " + name, 2000);
			return nullptr;
		}
	}
	else if (name == "Set" || name == "Sequence")
	{
		tmp = IObject::Create<SequenceFieldNode>();
		tmp->Attributes() = Attributes;
		if (!AddElement(std::dynamic_pointer_cast<Element>(tmp)))
		{
			AddError("xml2Asn1CodeGen", "CreateNode", "This field name is already used:  " + name, 2000);
			return nullptr;
		}
	}
	else if (name == "SequenceOf")
	{
		tmp = IObject::Create<SequenceOfFieldNode>();
		tmp->Attributes() = Attributes;
		if (!AddElement(std::dynamic_pointer_cast<Element>(tmp)))
		{
			AddError("xml2Asn1CodeGen", "CreateNode", "This field name is already used:  " + name, 2000);
			return nullptr;
		}
	}
	else
	{
		tmp = SequenceNode::BuildField(std::dynamic_pointer_cast<ElementContainer>(_me.lock()), name, Attributes, GetFileNode());
	}

	// TODO:  Needs sequence fields here


	if (!!tmp)
	{
		tmp->Attributes() = Attributes;
		return tmp;
	}
	AddError("xml2Asn1CodeGen", "CreateNode", "Unable to create node " + name, 2000);
	return nullptr;
}

std::shared_ptr<Element> PartNode::FindElement(std::shared_ptr<Element> ele)
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
	return nullptr;
}

bool PartNode::WritePODStructure(std::shared_ptr<FileNode> files)
{
	tsStringBase ns;

	if (!!NameSpace())
		ns = NameSpace()->ToString();

	if (StructureWritten())
		return true;
	StructureWritten(true);

	for (auto ele : Dependencies())
	{
		if (!!ele && !ele->PODStructureWritten())
		{
			if (!ele->WritePODStructure(files))
				return false;
		}
	}

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

	files->Header()->WriteLine("// ----------------------------------------------------------------");
	files->Header()->WriteLine("// " + PODStructureName() + " for part " + Name());
	files->Header()->WriteLine();

	files->Source()->WriteLine("// ----------------------------------------------------------------");
	files->Source()->WriteLine("// " + PODStructureName() + " for part " + Name());
	files->Source()->WriteLine();

	//files->Source()->WriteLine("static const int __" + StructureName() + "_" + Name() + "_tag = " << BuildTagString() << ";");
	//files->Source()->WriteLine("static const int __" + StructureName() + "_" + Name() + "_type = " << BuildTypeString() << ";");
	//files->Source()->WriteLine();







	files->Source()->WriteLine("const struct tscrypto::Asn1Metadata2 " + ns + PODStructureName() + "::__Metadata_" + Name() + "[] =");
	files->Source()->WriteLine("{");
	files->Source()->indent();
	int32_t versionEleCount = 0;
	if (HasOID())
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
		tmp.append(", nullptr, nullptr, nullptr, nullptr },");
		files->Source()->WriteLine(tmp);
		versionEleCount++;
	}
	if (HasVersion())
	{
		tsStringBase tmp;

		tmp.append("{ (tscrypto::Asn1Metadata2::FieldFlags)(tscrypto::Asn1Metadata2::tp_int32), offsetof(").append(PODStructureName()).append(", _VERSION), -1, -1, -1, -1, nullptr, 0, tscrypto::TlvNode::Tlv_Number, tscrypto::TlvNode::Type_Universal, ");
		if (JSONName().size() > 0)
			tmp += "nullptr";
		else
			tmp.append("\"").append(JSONName()).append("\"");
		tmp.append(", \"_VERSION\", ");
		
		//tmp << "\"" << DefaultVersion() << "\", ";
		tmp << "nullptr, ";

		tmp += "nullptr, nullptr, nullptr, nullptr },";
		files->Source()->WriteLine(tmp);
		versionEleCount++;
	}
	for (auto ele : Elements())
	{

		// Find the element to which this element refers.
		tsStringBase tmp;

		if ((ele->Name() == "OID" && ParentSequence()->HasOID()) || (ele->Name() == "VERSION" && ParentSequence()->HasVersion()))
		{
			tmp = ele->BuildMetadataLine(FullStructureName(), PODStructureName());
			files->Source()->WriteLine(tmp);
		}
		else
		{
			std::shared_ptr<TaggedElement> e = std::dynamic_pointer_cast<TaggedElement>(ParentSequence()->FindElement(ele));
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

				tmp = e->BuildMetadataLine(FullStructureName(), PODStructureName());

				// Restore the original values
				e->Tag(oldTag);
				e->Type(oldType);

				files->Source()->WriteLine(tmp);
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
	files->Source()->WriteLine();

	files->Header()->WriteLine("static const size_t __Metadata_" + Name() + "_count = " + (tsStringBase().append((int32_t)(Elements().size() + versionEleCount))).append(";"));
	files->Header()->WriteLine("static const struct tscrypto::Asn1Metadata2 __Metadata_" + Name() + "[__Metadata_" + Name() + "_count];");
	files->Header()->WriteLine();


	// Write version information here
	if (HasOID() || HasVersion())
	{
		for (auto ver : Versions())
		{
			tsStringBase tmp;

			tmp += "{";

			files->Header()->WriteLine("//   version Metadata for part " + PODStructureName() + " - " + ver->Name());
			files->Source()->WriteLine("//   version Metadata for part " + PODStructureName() + " - " + ver->Name());
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
				//if (ver->OID().size() > 0 && ver->OID() != "*")
				//{
				//	tmp1 << ver->OID();
				//}
				//else
					tmp1 << "nullptr";
				tmp1 += ", nullptr, nullptr, nullptr, nullptr },";
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
				tmp1 += "nullptr";

				tmp1 += ", nullptr, nullptr, nullptr, nullptr },";
				files->Source()->WriteLine(tmp1);
				versionEleCount1++;
			}

			for (auto ele : ver->Elements())
			{
				// Find the element to which this element refers.
				tsStringBase tmp1;

				std::shared_ptr<TaggedElement> seqEle = std::dynamic_pointer_cast<TaggedElement>(ParentSequence()->FindElement(ele));
				std::shared_ptr<TaggedElement> partEle = std::dynamic_pointer_cast<TaggedElement>(FindElement(ele));
				std::shared_ptr<TaggedElement> verEle = std::dynamic_pointer_cast<TaggedElement>(ele);
				if (!!seqEle && !!partEle && !!verEle)
				{
					tsStringBase oldTag(seqEle->Tag());
					tsStringBase oldType(seqEle->Type());

					if (verEle->Tag().size() != 0)
					{
						seqEle->Tag(verEle->Tag());
					}
					else if (partEle->Tag().size() != 0)
					{
						seqEle->Tag(partEle->Tag());
					}
					if (verEle->Type().size() != 0)
					{
						seqEle->Type(verEle->Type());
					}
					else if (partEle->Type().size() != 0)
					{
						seqEle->Type(partEle->Type());
					}

					tmp1 = seqEle->BuildMetadataLine(FullStructureName(), PODStructureName());

					seqEle->Tag(oldTag);
					seqEle->Type(oldType);

					files->Source()->WriteLine(tmp1);
				}
				else
				{
					files->Source()->WriteLine("#error  Element " + ele->ElementType() + " called " + ele->Name() + " was NOT found.");
				}
				//for (auto e : ParentSequence()->Elements())
				//{
				//	if (ele->IsArray() && !e->IsArray())
				//		continue;
				//	if (ele->IsArray())
				//	{
				//		foundIt = (e->Name() == ele->Name());
				//		{
				//			tmp1 = e->BuildMetadataLine(StructureName());
				//			files->Source()->WriteLine(tmp1);
				//			foundIt = true;
				//			break;
				//		}
				//	}
				//	else if (ele->ElementType() == "ChoiceField")
				//	{
				//		foundIt = e->ElementType() == "Choice" && e->Name() == ele->Name();
				//	}
				//	else
				//		foundIt = e->ElementType() == ele->ElementType() && e->Name() == ele->Name();
				//	if (foundIt)
				//	{
				//		tmp1 = e->BuildMetadataLine(StructureName());
				//		files->Source()->WriteLine(tmp1);
				//		foundIt = true;
				//		break;
				//	}
				//}
				//if (!foundIt)
				//{
				//	files->Source()->WriteLine("#error  Element " + ele->ElementType() + " called " + ele->Name() + " was NOT found.");
				//}
				//file->WriteLine("&_" + StructureName() + "_" + ele->Name() + "_Metaitem_0,"); 
			}

			files->Source()->outdent();
			files->Source()->WriteLine("};");

			files->Header()->WriteLine("static const size_t __Metadata_Version_" + ver->Name() + "_count = " + (tsStringBase().append((int32_t)(ver->Elements().size() + versionEleCount1))).append(";"));
			files->Header()->WriteLine("static const tscrypto::Asn1Metadata2 __Metadata_Version_" + ver->Name() + "[__Metadata_Version_" + ver->Name() + "_count];");
			files->Header()->WriteLine();
		}

		files->Header()->WriteLine("//   version table");
		files->Source()->WriteLine("//   version table");
		files->Source()->WriteLine("const tscrypto::Asn1Version2 " + ns + PODStructureName() + "::__Metadata_VersionSelector_" + Name() + "[] = {");
		files->Source()->indent();

		for (auto ver : Versions())
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
			tmp.append(ns + PODStructureName() + "::__Metadata_Version_").append(ver->Name()).append(", " + ns + PODStructureName() + "::__Metadata_Version_").append(ver->Name()).append("_count},");
			files->Source()->WriteLine(tmp);
		}
		files->Source()->outdent();
		files->Source()->WriteLine("};");
		files->Header()->WriteLine();

		files->Header()->WriteLine(tsStringBase().append("static const size_t __Metadata_VersionSelector_").append(Name()).append("_count = ").append((int32_t)Versions().size()).append(";"));
		files->Header()->WriteLine("static const tscrypto::Asn1Version2 __Metadata_VersionSelector_" + Name() + "[__Metadata_VersionSelector_" + Name() + "_count];");
		files->Header()->WriteLine();
	}

	{
	tsStringBase tmp;

		tmp.append("const struct tscrypto::Asn1StructureDefinition2 " + ns + PODStructureName() + "::__Definition_").append(Name()).append(" = {").append(BuildTagString()).append(", ").append(BuildTypeString()).append(", ");
		if (Versions().size() == 0)
		{
			tmp.append(ns + PODStructureName() + "::__Metadata_").append(Name()).append(", " + ns + PODStructureName() + "::__Metadata_").append(Name()).append("_count, nullptr, 0, ");
		}
		else
		{
			tmp.append("nullptr, 0, " + ns + PODStructureName() + "::__Metadata_VersionSelector_").append(Name()).append(", " + ns + PODStructureName() + "::__Metadata_VersionSelector_").append(Name()).append("_count, ");
		}
		if (DefaultOID().size() > 0)
			tmp.append(DefaultOID()).append(", ");
		else
			tmp += "nullptr, ";
		tmp.append("\"").append(DefaultVersion()).append("\", ").append((DontWrap() ? "true" : "false"));
		tmp += "};";
		files->Source()->WriteLine(tmp);
		files->Header()->WriteLine("static const struct tscrypto::Asn1StructureDefinition2 __Definition_" + Name() + ";");
	}
	files->Source()->WriteLine();



	// Now write the encoder functions and metadata for each sequence/choice
	if (!WriteUserFunctions(files->Source()))
	{
		AddError("xml2Asn1CodeGen", "", "Unable to write the user defined functions.\n");
		return false;
	}

	return true;
}

bool PartNode::WriteToJSON(std::shared_ptr<FileNode> files)
{
	files->Header()->WriteLine("bool " + Name() + "_toJSON(tscrypto::JSONObject& obj) const");
	files->Header()->WriteLine("{");
	files->Header()->indent();

	for (auto& e : Elements())
	{
		std::shared_ptr<Element> element;

		if ((ParentSequence()->HasOID() && e->Name() == "OID") || (ParentSequence()->HasVersion() && e->Name() == "VERSION"))
		{
			if (!e->WriteToJSON(files->Header()))
			{
				AddError("xml2Asn1CodeGen", "", (tsStringBase().append("Element ").append(e->Name()).append(" in structure ").append(Name()).append(" and part ").append(Name()).append(" failed to write.\n").c_str()));
				return false;
			}
		}
		else
		{
			if (!!ParentSequence())
				element = std::dynamic_pointer_cast<Element>(ParentSequence()->FindElement(e));

			if (!element)
			{
				AddError("xml2Asn1CodeGen", "", "Part field refers to an element that is not in the structure.\n");
				return false;
			}
			tsStringBase oldJsonName = element->JSONName();

			element->JSONName(e->JSONName());

			if (!element->WriteToJSON(files->Header()))
			{
				element->JSONName(oldJsonName);
				AddError("xml2Asn1CodeGen", "", (tsStringBase().append("Element ").append(e->Name()).append(" in structure ").append(Name()).append(" and part ").append(Name()).append(" failed to write.\n").c_str()));
				return false;
			}
			element->JSONName(oldJsonName);
		}
	}

	files->Header()->WriteLine("return true;");
	files->Header()->outdent();
	files->Header()->WriteLine("}");
	return true;
}
bool PartNode::WriteFromJSON(std::shared_ptr<FileNode> files)
{
	files->Header()->WriteLine("bool " + Name() + "_fromJSON(const tscrypto::tsCryptoStringBase& json)");
	files->Header()->WriteLine("{");
	files->Header()->indent();
	files->Header()->WriteLine("tscrypto::JSONObject obj;");
	files->Header()->WriteLine("");
	files->Header()->WriteLine("if (!obj.FromJSON(json))");
	files->Header()->WriteLine("    return false;");
	files->Header()->WriteLine("");
	files->Header()->WriteLine("return " + Name() + "_fromJSON(obj);");
	files->Header()->outdent();
	files->Header()->WriteLine("}");

	files->Header()->WriteLine("bool " + Name() + "_fromJSON(const tscrypto::JSONObject& obj)");
	files->Header()->WriteLine("{");
	files->Header()->indent();
	files->Header()->WriteLine("clear();");

	for (auto& e : Elements())
	{
		std::shared_ptr<Element> element;

		if ((ParentSequence()->HasOID() && e->Name() == "OID") || (ParentSequence()->HasVersion() && e->Name() == "VERSION"))
		{
			if (!e->WriteFromJSON(files->Header()))
			{
				AddError("xml2Asn1CodeGen", "", (tsStringBase().append("Element ").append(e->Name()).append(" in structure ").append(Name()).append(" and part ").append(Name()).append(" failed to write.\n").c_str()));
				return false;
			}
		}
		else
		{
			if (!!ParentSequence())
				element = std::dynamic_pointer_cast<Element>(ParentSequence()->FindElement(e));

			if (!element)
			{
				AddError("xml2Asn1CodeGen", "", "Part field refers to an element that is not in the structure.\n");
				return false;
			}
			tsStringBase oldJsonName = element->JSONName();

			element->JSONName(e->JSONName());

			if (!element->WriteFromJSON(files->Header()))
			{
				element->JSONName(oldJsonName);
				AddError("xml2Asn1CodeGen", "", (tsStringBase().append("Element ").append(e->Name()).append(" in structure ").append(Name()).append(" and part ").append(Name()).append(" failed to write.\n").c_str()));
				return false;
			}
			element->JSONName(oldJsonName);
		}
	}

	files->Header()->WriteLine("");
	files->Header()->WriteLine("return true;");
	files->Header()->outdent();
	files->Header()->WriteLine("}");

	return true;
}
