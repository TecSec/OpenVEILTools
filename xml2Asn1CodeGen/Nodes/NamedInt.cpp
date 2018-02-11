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
#include "NamedInt.h"
#include "FileNode.h"

bool NamedInt::WriteForwardReference(std::shared_ptr<FileNode> files)
{
	if (!ForwardsWritten())
	{
		ForwardsWritten(true);

		for (auto& ele : Dependencies())
		{
			if (!ele->WriteForwardReference(files))
				return false;
		}

		files->Header()->SetNamespace(NameSpace());

		if (!Import())
		{
			if (Description().size() != 0)
				files->Header()->WriteLine(Description());

			if (Extends().empty())
			{
				if (BaseType().empty())
				{
					BaseType("int32_t");
				}
				files->Header()->WriteLine("typedef " + BaseType() + " " + Name() + ";");
			}
			else
			{
				files->Header()->WriteLine("// Extending " + Extends());
				Name(Extends());
			}
			files->Header()->WriteLine("namespace _" + Name() /*+ "_Values"*/);
			files->Header()->WriteLine("{");
			files->Header()->indent();
			tsStringBase prior;
			for (size_t i = 0; i < Children().size(); i++)
			{
				std::shared_ptr<tsXmlNode> node = Children().at(i);
				std::shared_ptr<NamedIntElement> item = std::dynamic_pointer_cast<NamedIntElement>(node);
				if (!!item)
				{
					if (item->Description().size() > 0)
						files->Header()->WriteLine(item->Description());
					if (!gUseConst)
					{
						
						files->Header()->WriteLine("#ifdef HAVE_CONSTEXPR");
					if (item->Value().size() == 0)
					{
						if (prior.empty())
							files->Header()->WriteLine("constexpr " + BaseType() + " " + item->Name() + " = 0;");
						else
							files->Header()->WriteLine("constexpr " + BaseType() + " " + item->Name() + " = " + prior + " + 1;");
					}
					else
						files->Header()->WriteLine("constexpr " + BaseType() + " " + item->Name() + " = " + item->Value() + ";");
						files->Header()->WriteLine("#else");
					if (item->Value().size() == 0)
					{
						if (prior.empty())
							files->Header()->WriteLine("const " + BaseType() + " " + item->Name() + " = 0;");
						else
							files->Header()->WriteLine("const " + BaseType() + " " + item->Name() + " = " + prior + " + 1;");
					}
					else
						files->Header()->WriteLine("const " + BaseType() + " " + item->Name() + " = " + item->Value() + ";");
						files->Header()->WriteLine("#endif // HAVE_CONSTEXPR");
					}
					else
					{
						if (item->Value().size() == 0)
						{
							if (prior.empty())
								files->Header()->WriteLine("const " + BaseType() + " " + item->Name() + " = 0;");
							else
								files->Header()->WriteLine("const " + BaseType() + " " + item->Name() + " = " + prior + " + 1;");
						}
						else
							files->Header()->WriteLine("const " + BaseType() + " " + item->Name() + " = " + item->Value() + ";");
					}
					prior = item->Name();
				}
			}
			files->Header()->outdent();
			files->Header()->WriteLine("};");
			files->Header()->WriteLine();

			if (Export())
			{
				files->Export()->SetNamespace(NameSpace());
				files->Export()->WriteLine("<NamedInt Name=\"" + Name() + "\" BaseType=\"" + BaseType() + "\" Imported=\"true\"/>");
			}
		}
	}
	return true;
}
tsStringBase NamedInt::Extends() const
{
	return Attributes().item("Extends");
}
tsStringBase NamedInt::BaseType() const
{
	return Attributes().item("BaseType");
}
void NamedInt::BaseType(const tsStringBase setTo)
{
	Attributes().AddItem("BaseType", setTo);
}
bool NamedInt::WriteStructure(std::shared_ptr<FileNode> files)
{
	if (StructureWritten())
		return true;
	StructureWritten(true);

	files->Header()->SetNamespace(nullptr);

	//files->Header()->WriteLine("template <>");
	//files->Header()->WriteLine("struct tlvmeta_traits<" + NameSpace()->ToString() + Name() + "> : public tlvmeta_traits<int>");
	//files->Header()->WriteLine("{");
	//files->Header()->WriteLine("    static " + NameSpace()->ToString() + Name() + " fromString(const tsCryptoString& obj) { return (" + NameSpace()->ToString() + Name() + ")tsStrToInt(obj); }");
	//files->Header()->WriteLine("    static " + NameSpace()->ToString() + Name() + " initialize() { return (" + NameSpace()->ToString() + Name() + ")0; }");
	//files->Header()->WriteLine("    static " + NameSpace()->ToString() + Name() + "* convertArrayElementToElementType(Asn1DataBaseClass* object) { return reinterpret_cast<" + NameSpace()->ToString() + Name() + "*>(object); }");
	//files->Header()->WriteLine("    static " + NameSpace()->ToString() + Name() + " NodeToData(const std::shared_ptr<TlvNode>& node) { return (" + NameSpace()->ToString() + Name() + ")node->InnerDataAsNumber(); }");
	//files->Header()->WriteLine("    static " + NameSpace()->ToString() + Name() + " NumberNodeToData(const std::shared_ptr<TlvNode>& node) { return (" + NameSpace()->ToString() + Name() + ")node->InnerDataAsNumber(); }");
	//files->Header()->WriteLine("};");
	//files->Header()->WriteLine();

	return true;
}
tsStringBase NamedInt::FullName()
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
