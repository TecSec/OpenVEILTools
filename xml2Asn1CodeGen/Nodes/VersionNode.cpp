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
#include "VersionNode.h"
#include "DescriptionNode.h"
#include "BasicFieldNode.h"
#include "ChoiceFieldNode.h"
#include "SequenceFieldNode.h"
#include "SequenceOfFieldNode.h"
#include "FileNode.h"

bool VersionNode::Validate()
{
	if (Validated())
		return true;
	Validated(true);
	if (!Attributes().hasItem("Name"))
	{
		AddError("xml2Asn1CodeGen", "", "Version is missing the Name attribute.\n");
		return false;
	}
	Name(Attributes().item("Name"));
	if (Attributes().hasItem("OID"))
	{
		HasOID(true);
		OID(Attributes().item("OID"));
	}
	if (Attributes().hasItem("MinNumber") || Attributes().hasItem("MaxNumber"))
	{
		HasVersion(true);
		if (!Attributes().hasItem("MinNumber") || !Attributes().hasItem("MaxNumber"))
		{
			AddError("xml2Asn1CodeGen", "", "The sequence version is missing the required 'MinNumber' or 'MaxNumber' attribute.  Both are required if either is specified.\n");
			return false;
		}
		minVersion(Attributes().itemAsNumber("MinNumber", 0));
		maxVersion(Attributes().itemAsNumber("MaxNumber", 0));
		if (minVersion() > maxVersion())
		{
			AddError("xml2Asn1CodeGen", "", "The minimum version must be less than or equal to the maximum version number.\n");
			return false;
		}
		if (minVersion() < 0)
		{
			AddError("xml2Asn1CodeGen", "", "The version number may not be negative.\n");
			return false;
		}
	}

	std::shared_ptr<Element> parent = std::dynamic_pointer_cast<Element>(Parent().lock());
	if (!!parent)
	{
		StructureName(parent->StructureName() + "_" + Name());
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
bool VersionNode::Process()
{

	return false;
}
std::shared_ptr<tsXmlNode> VersionNode::CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes)
{
	std::shared_ptr<tsXmlNode> tmp;

	// TODO:  Synchronize with FileNode
	if (name == "Description")
	{
		tmp = IObject::Create<DescriptionNode>();
	}
	else if (::isBasicEleType(name))
	{
		tmp = IObject::Create<BasicFieldNode>();
		tmp->Attributes() = Attributes;
		if (!AddElement(std::dynamic_pointer_cast<Element>(tmp)))
		{
			AddError("xml2Asn1CodeGen", "CreateNode", "This field name is already used:  " + name, 2000);
			return nullptr;
		}
	}
	else if (name == "Choice")
	{
		//if (Attributes.hasItem("ElementType"))
		//	tmp = CryptoLocator()->Finish<Element>(new ChoiceFieldNode());
		//else
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


	if (!!tmp)
	{
		tmp->Attributes() = Attributes;
		return tmp;
	}
	AddError("xml2Asn1CodeGen", "CreateNode", "Unable to create node " + name, 2000);
	return nullptr;
}
void VersionNode::WritePODVersionElementAccessors(std::shared_ptr<FileNode> files)
{
	std::shared_ptr<Element> parent = std::dynamic_pointer_cast<Element>(Parent().lock());

	if (!!parent)
	{
		for (auto& ele : Elements())
		{
			if (ele->EncodedType().size() > 0)
			{
				tsStringBase accessorName = ele->EncodedAccessor();
				tsStringBaseList typeParts = ele->EncodedType().split(":");
				tsStringBase typeName = typeParts.back();
				std::shared_ptr<EnumNode> Enum = FindEnum(typeName);
				std::shared_ptr<BitstringNode> bitstring = FindBitstring(typeName);
				std::shared_ptr<SetNode> Set = FindSet(typeName);
				std::shared_ptr<ChoiceNode> Choice = FindChoice(typeName);
				std::shared_ptr<SequenceNode> Sequence = FindSequence(typeName);
				std::shared_ptr<SequenceOfNode> SequenceOf = FindSequenceOf(typeName);

				if (accessorName.size() == 0)
				{
					accessorName.append(Name()).append("_").append(typeName);
				}

				// TODO:  Add more encoders support here
				if (ele->EncodedType() == "Int32")
				{
					files->Header()->WriteLine(tsStringBase().append("int get_").append(accessorName).append("() const"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine(tsStringBase().append("if (!is_").append(Name()).append("())"));
					files->Header()->WriteLine("	return 0;");
					files->Header()->WriteLine("");
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine(tsStringBase().append("if (!doc->LoadTlv(this->get_").append(ele->Name()).append("()) || doc->DocumentElement()->IsNumber())"));
					files->Header()->WriteLine("	return 0;");
					files->Header()->WriteLine("return (int)doc->DocumentElement()->InnerDataAsNumber();");
					files->Header()->outdent();
					files->Header()->WriteLine("}");

					files->Header()->WriteLine(tsStringBase().append("void set_").append(accessorName).append("(int setTo)"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine("doc->DocumentElement()->Tag(tscrypto::TlvNode::Tlv_Number);");
					files->Header()->WriteLine("doc->DocumentElement()->Type(tscrypto::TlvNode::Type_Universal);");
					files->Header()->WriteLine("doc->DocumentElement()->InnerDataAsNumber(setTo);");
					files->Header()->WriteLine("this->set_"+ ele->Name() +"(doc->SaveTlv());");
					if (HasOID())
					{
						files->Header()->WriteLine(tsStringBase().append("set_OID(").append(OID()).append(");"));
					}
					if (HasVersion() && maxVersion() > -1)
					{
						files->Header()->WriteLine(tsStringBase().append("set_VERSION(").append(maxVersion()).append(");"));
					}
					files->Header()->outdent();
					files->Header()->WriteLine("}");

					files->Header()->WriteLine();
				}
				else if (ele->EncodedType() == "OctetString")
				{
					files->Header()->WriteLine(tsStringBase().append("tscrypto::tsCryptoData get_").append(accessorName).append("() const"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine(tsStringBase().append("if (!is_").append(Name()).append("())"));
					files->Header()->WriteLine("	return tscrypto::tsCryptoData();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine(tsStringBase().append("if (!doc->LoadTlv(this->get_").append(ele->Name()).append("()) || doc->DocumentElement()->IsOctet())"));
					files->Header()->WriteLine("	return tscrypto::tsCryptoData();");
					files->Header()->WriteLine("return doc->DocumentElement()->InnerData();");
					files->Header()->outdent();
					files->Header()->WriteLine("}");

					files->Header()->WriteLine(tsStringBase().append("void set_").append(accessorName).append("(const tscrypto::tsCryptoData& setTo)"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine("doc->DocumentElement()->Tag(tscrypto::TlvNode::Tlv_Octet);");
					files->Header()->WriteLine("doc->DocumentElement()->Type(tscrypto::TlvNode::Type_Universal);");
					files->Header()->WriteLine("doc->DocumentElement()->InnerData(setTo);");
					files->Header()->WriteLine("this->set_" + ele->Name() + "(doc->SaveTlv());");
					if (HasOID())
					{
						files->Header()->WriteLine(tsStringBase().append("set_OID(").append(OID()).append(");"));
					}
					if (HasVersion() && maxVersion() > -1)
					{
						files->Header()->WriteLine(tsStringBase().append("set_VERSION(").append(maxVersion()).append(");"));
					}
					files->Header()->outdent();
					files->Header()->WriteLine("}");
					files->Header()->WriteLine();
				}
				else if (ele->EncodedType() == "OID")
				{
					files->Header()->WriteLine(tsStringBase().append("tscrypto::tsCryptoData get_").append(accessorName).append("() const"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine(tsStringBase().append("if (!is_").append(Name()).append("())"));
					files->Header()->WriteLine("	return tscrypto::tsCryptoData();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine(tsStringBase().append("if (!doc->LoadTlv(this->get_").append(ele->Name()).append("()) || doc->DocumentElement()->IsOIDNode())"));
					files->Header()->WriteLine("	return tscrypto::tsCryptoData();");
					files->Header()->WriteLine("return doc->DocumentElement()->InnerData();");
					files->Header()->outdent();
					files->Header()->WriteLine("}");

					files->Header()->WriteLine(tsStringBase().append("void set_").append(accessorName).append("(const tscrypto::tsCryptoData& setTo)"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine("doc->DocumentElement()->Tag(tscrypto::TlvNode::Tlv_OID);");
					files->Header()->WriteLine("doc->DocumentElement()->Type(tscrypto::TlvNode::Type_Universal);");
					files->Header()->WriteLine("doc->DocumentElement()->InnerData(setTo);");
					files->Header()->WriteLine("this->set_" + ele->Name() + "(doc->SaveTlv());");
					if (HasOID())
					{
						files->Header()->WriteLine(tsStringBase().append("set_OID(").append(OID()).append(");"));
					}
					if (HasVersion() && maxVersion() > -1)
					{
						files->Header()->WriteLine(tsStringBase().append("set_VERSION(").append(maxVersion()).append(");"));
					}
					files->Header()->outdent();
					files->Header()->WriteLine("}");
					files->Header()->WriteLine();
				}
				else if (ele->EncodedType() == "GeneralizedTime")
				{
					files->Header()->WriteLine(tsStringBase().append("tscrypto::tsCryptoDate get_").append(accessorName).append("() const"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine(tsStringBase().append("if (!is_").append(Name()).append("())"));
					files->Header()->WriteLine("	return tscrypto::tsCryptoDate();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine(tsStringBase().append("if (!doc->LoadTlv(this->get_").append(ele->Name()).append("()) || doc->DocumentElement()->IsDate())"));
					files->Header()->WriteLine("	return tscrypto::tsCryptoDate();");
					files->Header()->WriteLine("return tscrypto::tsCryptoDate(doc->DocumentElement()->InnerData().ToUtf8String(), tscrypto::tsCryptoDate::Zulu);");
					files->Header()->outdent();
					files->Header()->WriteLine("}");

					files->Header()->WriteLine(tsStringBase().append("void set_").append(accessorName).append("(const tscrypto::tsCryptoDate& setTo)"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine("doc->DocumentElement()->Tag(tscrypto::TlvNode::Tlv_GeneralizedTime);");
					files->Header()->WriteLine("doc->DocumentElement()->Type(tscrypto::TlvNode::Type_Universal);");
					files->Header()->WriteLine("doc->DocumentElement()->InnerData(setTo.AsZuluTime().ToUTF8Data());");
					files->Header()->WriteLine("this->set_" + ele->Name() + "(doc->SaveTlv());");
					if (HasOID())
					{
						files->Header()->WriteLine(tsStringBase().append("set_OID(").append(OID()).append(");"));
					}
					if (HasVersion() && maxVersion() > -1)
					{
						files->Header()->WriteLine(tsStringBase().append("set_VERSION(").append(maxVersion()).append(");"));
					}
					files->Header()->outdent();
					files->Header()->WriteLine("}");
					files->Header()->WriteLine();
				}
				else if (!!Sequence || !!Set || !!Choice || !!SequenceOf)
				{
					std::shared_ptr<SequenceNode> linkedSequence = FindSequence(ele->EncodedType());
					std::shared_ptr<SequenceOfNode> linkedSequenceOf = FindSequenceOf(ele->EncodedType());
					std::shared_ptr<SetNode> linkedSet = FindSet(ele->EncodedType());
					std::shared_ptr<ChoiceNode> linkedChoice = FindChoice(ele->EncodedType());
					tsStringBase structName;

					if (!!linkedSequence)
					{
						structName = linkedSequence->PODStructureName();
						if (!!linkedSequence->NameSpace())
							structName.prepend(linkedSequence->NameSpace()->ToString());
					}
					else if (!!linkedSequenceOf)
					{
						structName = linkedSequenceOf->PODStructureName();
						if (!!linkedSequenceOf->NameSpace())
							structName.prepend(linkedSequenceOf->NameSpace()->ToString());
					}
					else if (!!linkedSet)
					{
						structName = linkedSet->PODStructureName();
						if (!!linkedSet->NameSpace())
							structName.prepend(linkedSet->NameSpace()->ToString());
					}
					else if (!!linkedChoice)
					{
						structName = linkedChoice->PODStructureName();
						if (!!linkedChoice->NameSpace())
							structName.prepend(linkedChoice->NameSpace()->ToString());
					}
					else
					{
						throw std::runtime_error(("encoded element " + ele->EncodedType() + " is not found").c_str());
					}

					files->Header()->WriteLine(tsStringBase().append(structName).append(" get_").append(accessorName).append("() const"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine(tsStringBase().append("if (!is_").append(Name()).append("())"));
					files->Header()->WriteLine(tsStringBase().append("    return ").append(structName).append("();"));
					files->Header()->WriteLine(tsStringBase().append(structName).append(" tmp;"));
					files->Header()->WriteLine("");
					files->Header()->WriteLine(tsStringBase().append("if (!tmp.Decode(this->get_").append(ele->Name()).append("()))"));
					files->Header()->WriteLine("	tmp.clear();");
					files->Header()->WriteLine("return tmp;");
					files->Header()->outdent();
					files->Header()->WriteLine("}");


					files->Header()->WriteLine(tsStringBase().append("void set_").append(accessorName).append("(").append(structName).append("&& setTo)"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("tscrypto::tsCryptoData tmp;");
					files->Header()->WriteLine(tsStringBase().append(structName).append(" val(std::move(setTo));"));
					files->Header()->WriteLine("");
					if (HasOID())
					{
						files->Header()->WriteLine(tsStringBase().append("set_OID(").append(OID()).append(");"));
					}
					if (HasVersion() && maxVersion() > -1)
					{
						files->Header()->WriteLine(tsStringBase().append("set_VERSION(").append(maxVersion()).append(");"));
					}
					files->Header()->WriteLine("if (!val.Encode(tmp))");
					files->Header()->WriteLine("	return;");
					files->Header()->WriteLine(tsStringBase().append("this->set_").append(ele->Name()).append("(std::move(tmp));"));
					files->Header()->outdent();
					files->Header()->WriteLine("}");


					files->Header()->WriteLine(tsStringBase().append("void set_").append(accessorName).append("(const ").append(structName).append("& setTo)"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("tscrypto::tsCryptoData tmp;");
					files->Header()->WriteLine(tsStringBase().append(structName).append(" val(setTo);"));
					files->Header()->WriteLine("");
					if (HasOID())
					{
						files->Header()->WriteLine(tsStringBase().append("set_OID(").append(OID()).append(");"));
					}
					if (HasVersion() && maxVersion() > -1)
					{
						files->Header()->WriteLine(tsStringBase().append("set_VERSION(").append(maxVersion()).append(");"));
					}
					files->Header()->WriteLine("if (!val.Encode(tmp))");
					files->Header()->WriteLine("	return;");
					files->Header()->WriteLine(tsStringBase().append("this->set_").append(ele->Name()).append("(std::move(tmp));"));
					files->Header()->outdent();
					files->Header()->WriteLine("}");
					files->Header()->WriteLine();
				}
				else if (!!Enum)
				{
					files->Header()->WriteLine(tsStringBase().append(ele->EncodedType()).append(" get_").append(accessorName).append("() const"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine(tsStringBase().append("if (!is_").append(Name()).append("())"));
					files->Header()->WriteLine(tsStringBase().append("	return ").append(ele->EncodedType()).append("();"));
					files->Header()->WriteLine("");
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine(tsStringBase().append("if (!doc->LoadTlv(this->get_").append(ele->Name()).append("()) || doc->DocumentElement()->IsConstructed() || doc->DocumentElement()->Tag() != tscrypto::TlvNode::Tlv_Enumerated || doc->DocumentElement()->Type() != tscrypto::TlvNode::Type_Universal)"));
					files->Header()->WriteLine(tsStringBase().append("	return ").append(ele->EncodedType()).append("();"));
					files->Header()->WriteLine(tsStringBase().append("return (").append(ele->EncodedType()).append(")doc->DocumentElement()->InnerDataAsNumber();"));
					files->Header()->outdent();
					files->Header()->WriteLine("}");

					files->Header()->WriteLine(tsStringBase().append("void set_").append(accessorName).append("(").append(ele->EncodedType()).append(" setTo)"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine("doc->DocumentElement()->Tag(tscrypto::TlvNode::Tlv_Enumerated);");
					files->Header()->WriteLine("doc->DocumentElement()->Type(tscrypto::TlvNode::Type_Universal);");
					files->Header()->WriteLine("doc->DocumentElement()->InnerDataAsNumber(setTo);");
					files->Header()->WriteLine("this->set_" + ele->Name() + "(doc->SaveTlv());");
					if (HasOID())
					{
						files->Header()->WriteLine(tsStringBase().append("set_OID(").append(OID()).append(");"));
					}
					if (HasVersion() && maxVersion() > -1)
					{
						files->Header()->WriteLine(tsStringBase().append("set_VERSION(").append(maxVersion()).append(");"));
					}
					files->Header()->outdent();
					files->Header()->WriteLine("}");
					files->Header()->WriteLine();
				}
				else if (!!bitstring)
				{
					files->Header()->WriteLine(tsStringBase().append("bool get_").append(accessorName).append("(").append(ele->EncodedType()).append(" bit) const"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine(tsStringBase().append("if (!is_").append(Name()).append("())"));
					files->Header()->WriteLine("	return false;");
					files->Header()->WriteLine("");
					files->Header()->WriteLine("tscrypto::Asn1Bitstring tmp;");
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine(tsStringBase().append("if (!doc->LoadTlv(this->get_").append(ele->Name()).append("()) || doc->DocumentElement()->IsConstructed() || doc->DocumentElement()->Tag() != tscrypto::TlvNode::Tlv_BitString || doc->DocumentElement()->Type() != tscrypto::TlvNode::Type_Universal)"));
					files->Header()->WriteLine("	return false;");
					files->Header()->WriteLine("tmp.rawData(doc->DocumentElement()->InnerData());");
					files->Header()->WriteLine("return tmp.testBit(bit);");
					files->Header()->outdent();
					files->Header()->WriteLine("}");

					files->Header()->WriteLine(tsStringBase().append("tscrypto::tsCryptoData getbits_").append(accessorName).append("() const"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine(tsStringBase().append("if (!is_").append(Name()).append("())"));
					files->Header()->WriteLine("	return tscrypto::tsCryptoData();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine("tscrypto::Asn1Bitstring tmp;");
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine(tsStringBase().append("if (!doc->LoadTlv(this->get_").append(ele->Name()).append("()) || doc->DocumentElement()->IsConstructed() || doc->DocumentElement()->Tag() != tscrypto::TlvNode::Tlv_BitString || doc->DocumentElement()->Type() != tscrypto::TlvNode::Type_Universal)"));
					files->Header()->WriteLine("	return tscrypto::tsCryptoData();");
					files->Header()->WriteLine("tmp.rawData(doc->DocumentElement()->InnerData());");
					files->Header()->WriteLine(tsStringBase().append("return tmp.bits();"));
					files->Header()->outdent();
					files->Header()->WriteLine("}");

					files->Header()->WriteLine(tsStringBase().append("void set_").append(accessorName).append("(").append(ele->EncodedType()).append(" bit)"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("tscrypto::Asn1Bitstring tmp;");
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine(tsStringBase().append("if (doc->LoadTlv(this->get_").append(ele->Name()).append("()) && !doc->DocumentElement()->IsConstructed() && doc->DocumentElement()->Tag() == tscrypto::TlvNode::Tlv_BitString && doc->DocumentElement()->Type() == tscrypto::TlvNode::Type_Universal)"));
					files->Header()->WriteLine("	tmp.rawData(doc->DocumentElement()->InnerData());");
					files->Header()->WriteLine("tmp.setBit(bit);");
					files->Header()->WriteLine(tsStringBase().append("this->set_").append(ele->Name()).append("(tmp.toData());"));
					if (HasOID())
					{
						files->Header()->WriteLine(tsStringBase().append("set_OID(").append(OID()).append(");"));
					}
					if (HasVersion() && maxVersion() > -1)
					{
						files->Header()->WriteLine(tsStringBase().append("set_VERSION(").append(maxVersion()).append(");"));
					}
					files->Header()->outdent();
					files->Header()->WriteLine("}");

					files->Header()->WriteLine(tsStringBase().append("void setbits_").append(accessorName).append("(const tscrypto::tsCryptoData& setTo)"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("tscrypto::Asn1Bitstring tmp;");
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine(tsStringBase().append("if (doc->LoadTlv(this->get_").append(ele->Name()).append("()) && !doc->DocumentElement()->IsConstructed() && doc->DocumentElement()->Tag() == tscrypto::TlvNode::Tlv_BitString && doc->DocumentElement()->Type() == tscrypto::TlvNode::Type_Universal)"));
					files->Header()->WriteLine("	tmp.rawData(doc->DocumentElement()->InnerData());");
					files->Header()->WriteLine("tmp.bits(setTo);");
					files->Header()->WriteLine(tsStringBase().append("this->set_").append(ele->Name()).append("(tmp.toData());"));
					if (HasOID())
					{
						files->Header()->WriteLine(tsStringBase().append("set_OID(").append(OID()).append(");"));
					}
					if (HasVersion() && maxVersion() > -1)
					{
						files->Header()->WriteLine(tsStringBase().append("set_VERSION(").append(maxVersion()).append(");"));
					}
					files->Header()->outdent();
					files->Header()->WriteLine("}");

					files->Header()->WriteLine(tsStringBase().append("void clear_").append(accessorName).append("(").append(ele->EncodedType()).append(" bit)"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("tscrypto::Asn1Bitstring tmp;");
					files->Header()->WriteLine("std::shared_ptr<tscrypto::TlvDocument> doc = tscrypto::TlvDocument::Create();");
					files->Header()->WriteLine("");
					files->Header()->WriteLine(tsStringBase().append("if (doc->LoadTlv(this->get_").append(ele->Name()).append("()) && !doc->DocumentElement()->IsConstructed() && doc->DocumentElement()->Tag() == tscrypto::TlvNode::Tlv_BitString && doc->DocumentElement()->Type() == tscrypto::TlvNode::Type_Universal)"));
					files->Header()->WriteLine("	tmp.rawData(doc->DocumentElement()->InnerData());");
					files->Header()->WriteLine("tmp.clearBit(bit);");
					files->Header()->WriteLine(tsStringBase().append("this->set_").append(ele->Name()).append("(tmp.toData());"));
					if (HasOID())
					{
						files->Header()->WriteLine(tsStringBase().append("set_OID(").append(OID()).append(");"));
					}
					if (HasVersion() && maxVersion() > -1)
					{
						files->Header()->WriteLine(tsStringBase().append("set_VERSION(").append(maxVersion()).append(");"));
					}
					files->Header()->outdent();
					files->Header()->WriteLine("}");

					files->Header()->WriteLine(tsStringBase().append("void clearAll_").append(accessorName).append("()"));
					files->Header()->WriteLine("{");
					files->Header()->indent();
					files->Header()->WriteLine("tscrypto::Asn1Bitstring tmp;");
					files->Header()->WriteLine("");
					files->Header()->WriteLine(tsStringBase().append("this->set_").append(ele->Name()).append("(tmp.toData());"));
					if (HasOID())
					{
						files->Header()->WriteLine(tsStringBase().append("set_OID(").append(OID()).append(");"));
					}
					if (HasVersion() && maxVersion() > -1)
					{
						files->Header()->WriteLine(tsStringBase().append("set_VERSION(").append(maxVersion()).append(");"));
					}
					files->Header()->outdent();
					files->Header()->WriteLine("}");
					files->Header()->WriteLine();

				}
			}
		}
	}
}
