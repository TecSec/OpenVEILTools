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



#ifndef __FILENODE_H__
#define __FILENODE_H__

#pragma once

#include "Namespace.h"
#include "ElementContainer.h"
#include "ChoiceNode.h"
#include "IncludeNode.h"
#include "ElementModifier.h"
#include "BitstringNode.h"
#include "SequenceOfNode.h"
#include "ImportNode.h"
#include "NamedInt.h"
#include "OIDNode.h"

class File
{
public:
	File(const tsStringBase &filename, const tsStringBase& language) : _language(language), stream(nullptr), _atStartOfLine(true)
	{
		if (fopen_s(&stream, filename.c_str(), "wt") != 0)
		{
			printf("Unable to open file %s for output.\n", filename.c_str());
			return;
		}
	}
	bool isValid() { return stream != nullptr; }
	void Close()
	{
		_currentNamespace.reset();
		fclose(stream);
		stream = nullptr;
	}
	tsStringBase Language() const { return _language; }
	void indent()
	{
		_indent += "    ";
	}
	void outdent()
	{
		_indent.DeleteAt(0, 4);
	}
	void Write(const tsStringBase& _data)
	{
		tsStringBase data(_data);
		tsStringBase tmp;

		if (_atStartOfLine && _indent.size() > 0)
			fwrite(_indent.c_str(), 1, _indent.size(), stream);
		_atStartOfLine = false;
		data = data.Replace("\r\n", "\n");

		if (data.find('\n') != tsStringBase::npos)
		{
			tsStringBaseList lines = data.split("\n");

			for (int i = 0; i < (int)lines.size() - 1; i++)
			{
				tmp.clear();
				tmp.append(lines.at(i)).append('\n').append(_indent);
				fwrite(tmp.c_str(), 1, tmp.size(), stream);
			}
			if (data.size() > 0 && data[data.size() - 1] == '\n')
			{
				tmp.clear();
				tmp.append(lines.at(lines.size() - 1)).append('\n');
				fwrite(tmp.c_str(), 1, tmp.size(), stream);
				_atStartOfLine = true;
			}
			else
			{
				fwrite(lines.at(lines.size() - 1).c_str(), 1, lines.at(lines.size() - 1).size(), stream);
			}
		}
		else
		{
			fwrite(data.c_str(), 1, data.size(), stream);
		}
	}
	void WriteLine(const tsStringBase& _data)
	{
		tsStringBase data(_data);
		tsStringBaseList lines = data.Replace("\r\n", "\n").split("\n");

		for (int i = 0; i < (int)lines.size(); i++)
		{
			if (_atStartOfLine && _indent.size() > 0)
				fwrite(_indent.c_str(), 1, _indent.size(), stream);
			_atStartOfLine = false;
			fwrite(lines.at(i).c_str(), 1, lines.at(i).size(), stream);
			fwrite("\n", 1, 1, stream);
			_atStartOfLine = true;
		}
	}
	void WriteLine()
	{
		fwrite("\n", 1, 1, stream);
		_atStartOfLine = true;
	}

	tsStringBase ExportSymbol() { return _exportSymbol; }
	void ExportSymbol(const tsStringBase& setTo) { _exportSymbol = setTo; }
	tsStringBase TemplateExternSymbol() { return _templateExternSymbol; }
	void TemplateExternSymbol(const tsStringBase& setTo) { _templateExternSymbol = setTo; }
	std::shared_ptr<Namespace> CurrentNamespace() const { return _currentNamespace; }
	void SetNamespace(const std::shared_ptr<Namespace>& n)
	{
		if (!CurrentNamespace())
		{
			_currentNamespace = n;
			if (!!n)
				n->Open(this);
		}
		else if (n != CurrentNamespace())
		{
			CurrentNamespace()->Close(this);
			_currentNamespace = n;
			if (n != nullptr)
				n->Open(this);
		}
	}

protected:
	tsStringBase _indent;
	tsStringBase _language;
	FILE* stream;
	bool _atStartOfLine;
	tsStringBase _exportSymbol;
	tsStringBase _templateExternSymbol;
	std::shared_ptr<Namespace> _currentNamespace;
};

class FileNode : public ProcessableNode, public ElementContainer
{
public:
	FileNode() : _headerFile(nullptr), _sourceFile(nullptr), _exportFile(nullptr) {}
	~FileNode() {}

	File* Header() const { return _headerFile; }
	File* Source() const { return _sourceFile; }
	File* Export() const { return _exportFile; }
	bool Process() override
	{
		std::vector<tsStringBase> optionalStructures;

		if (!Open(gOutputPath))
			return false;

		for (auto& i : Includes())
		{
			Header()->SetNamespace(i->NameSpace());
			Header()->WriteLine("#include \"" + i->Attributes().item("Name") + "\"");
		}

		if (_libraryNamespace.size() > 0)
		{
			Header()->WriteLine("namespace " + _libraryNamespace + " {");
			Header()->indent();
			Source()->WriteLine("namespace " + _libraryNamespace + " {");
			Source()->indent();
		}
		// Find all optional structures defined/used
		for (auto e : Elements())
		{
			std::shared_ptr<ElementContainer> c = std::dynamic_pointer_cast<ElementContainer>(e);

			if (!!c)
			{
				for (auto fld : c->Elements())
				{
					if (fld->IsOptional() && fld->StructureName().size() > 0)
					{
						if (fld->IsArray())
						{
							//if (fld->IsOptional())
							//{
							//	std::shared_ptr<ArrayNode> ary = std::dynamic_pointer_cast<ArrayNode>(fld);
							//	tsCryptoString name = ary->StructureName();
							//	tsCryptoString elename = ary->ElementName();

							//	auto it = std::find_if(optionalStructures.begin(), optionalStructures.end(), [&name](tsCryptoString& val) { return name == val; });
							//	if (it == optionalStructures.end())
							//		optionalStructures.push_back(name);
							//	it = std::find_if(optionalStructures.begin(), optionalStructures.end(), [&elename](tsCryptoString& val) { return elename == val; });
							//	if (it == optionalStructures.end())
							//		optionalStructures.push_back(elename);
							//}
						}
						else
						{
							auto it = std::find_if(optionalStructures.begin(), optionalStructures.end(), [&fld](tsStringBase& val) { return val == fld->StructureName(); });
							if (it == optionalStructures.end())
								optionalStructures.push_back(fld->StructureName());
						}
					}
				}
			}
		}

		// Now mark the structures that are used with optional attributes
		for (auto e : Elements())
		{
			std::shared_ptr<SequenceNode> seq = std::dynamic_pointer_cast<SequenceNode>(e);

			if (!!seq)
			{
				auto it1 = std::find_if(optionalStructures.begin(), optionalStructures.end(), [&seq](tsStringBase& val) {return seq->StructureName() == val; });
				auto it2 = std::find_if(optionalStructures.begin(), optionalStructures.end(), [&seq](tsStringBase& val) {return ("std::vector<" + seq->StructureName() + " >") == val; });

				if (it1 != optionalStructures.end() || it2 != optionalStructures.end() || seq->Export())
				{
					seq->UsedWithOptional(true);
				}
			}
		}

		// Write out the OID strings defined in this file.
		for (auto node : OIDs())
		{
			node->WriteOID(std::dynamic_pointer_cast<FileNode>(_me.lock()));
		}

		if (!WriteForwardReferences())
		{
			AddError("xml2Asn1CodeGen", "", "The forward references had an error.\n");
			Close();
			return false;
		}
		if (ExportSymbol().size() > 0)
		{
			if (!WriteArrayDeclarations())
			{
				AddError("xml2Asn1CodeGen", "", "The forward array references had an error.\n");
				Close();
				return false;
			}
		}
		if (!ProcessContainerElementMetadata(std::dynamic_pointer_cast<tsXmlNode>(_me.lock())))
		{
			AddError("xml2Asn1CodeGen", "", "The processing of the element metadata failed.\n");
			Close();
			return false;
		}
		if (!WritePODStructures())
		{
			AddError("xml2Asn1CodeGen", "", "The writing of the structures failed.\n");
			Close();
			return false;
		}
		if (!WriteStructures())
		{
			AddError("xml2Asn1CodeGen", "", "The writing of the structures failed.\n");
			Close();
			return false;
		}

		Source()->SetNamespace(nullptr);
		Source()->WriteLine();

		Header()->SetNamespace(nullptr);
		Header()->WriteLine();

		if (_libraryNamespace.size() > 0)
		{
			Header()->WriteLine("}");
			Header()->outdent();
			Source()->WriteLine("}");
			Source()->outdent();
		}

		Close();
		return true;
	}
	virtual bool Validate() override {
		if (Validated())
			return true;
		Validated(true);
		if (!Attributes().hasItem("Name"))
		{
			AddError("xml2Asn1CodeGen", "", "File is missing the Name attribute.\n");
			return false;
		}
		_baseFileName = Attributes().item("Name");
		_SourceFilename = Attributes().item("SourceFile");
		if (_SourceFilename.size() == 0)
			_SourceFilename.append(_baseFileName).append(".cpp");
		_HeaderFilename = Attributes().item("HeaderFile");
		if (_HeaderFilename.size() == 0)
			_HeaderFilename.append(_baseFileName).append(".h");
		_ExportFilename = Attributes().item("ExportFile");
		if (_ExportFilename.size() == 0)
			_ExportFilename.append(_baseFileName).append(".export");
		_headerPrefix = Attributes().item("HeaderPrefix");

		if (Attributes().hasItem("ExportSymbol"))
			_ExportSymbol = Attributes().item("ExportSymbol") + " ";
		if (Attributes().hasItem("TemplateExternSymbol"))
			_TemplateExternSymbol = Attributes().item("TemplateExternSymbol") + " ";
		if (Attributes().hasItem("LibraryNamespace"))
			_libraryNamespace = Attributes().item("LibraryNamespace") + " ";

		for (auto& i : Imports())
		{
			if (!i->Validate())
				return false;
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
	static std::shared_ptr<tsXmlNode> Create() { return IObject::Create<FileNode>(); }

	tsStringBase ExportSymbol() { return _ExportSymbol; }
	void ExportSymbol(const tsStringBase& setTo) { _ExportSymbol = setTo; }
	tsStringBase TemplateExternSymbol() { return _TemplateExternSymbol; }
	void TemplateExternSymbol(const tsStringBase& setTo) { _TemplateExternSymbol = setTo; }
	virtual tsStringBase StructureName() const override { return ""; }
	virtual void StructureName(const tsStringBase& setTo) override { UNREFERENCED_PARAMETER(setTo); }
	virtual std::shared_ptr<Namespace> NameSpace() override { return nullptr; }

	std::vector<std::shared_ptr<IDNode>>& OIDs() { return _oids; }
	const std::vector<std::shared_ptr<IncludeNode>>& Includes() const { return _includes; }
	bool AddInclude(std::shared_ptr<IncludeNode> ele)
	{
		tsStringBase eleName = ele->Attributes().item("Name");
		for (auto& e : _includes)
		{
			if (e->Attributes().item("Name") == eleName)
			{
				return false;
			}
		}
		_includes.push_back(ele);
		return true;
	}
	std::vector<std::shared_ptr<ImportNode>>& Imports() { return _imports; }

	bool WriteStructures()
	{
		//
		// TODO:  Disabled for the moment- Reenable me
		//for (auto ele : Elements())
		//{
		//	if (!ele->WriteStructure(std::dynamic_pointer_cast<FileNode>(_me.lock())))
		//	{
		//		return false;
		//	}
		//}
		return true;
	}

	bool WritePODStructures()
	{
		for (auto ele : Elements())
		{
			if (!ele->WritePODStructure(std::dynamic_pointer_cast<FileNode>(_me.lock())))
			{
				return false;
			}
		}
		return true;
	}

protected:
	File* _headerFile;
	File* _sourceFile;
	File* _exportFile;
	tsStringBase _SourceFilename;
	tsStringBase _HeaderFilename;
	tsStringBase _ExportFilename;
	tsStringBase _ExportSymbol;
	tsStringBase _TemplateExternSymbol;
	tsStringBase _baseFileName;
	std::vector<std::shared_ptr<IDNode>> _oids;
	std::vector<std::shared_ptr<IncludeNode>> _includes;
	std::vector<std::shared_ptr<ImportNode>> _imports;
	tsStringBase _libraryNamespace;
	tsStringBase _headerPrefix;

	virtual std::shared_ptr<tsXmlNode> CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes) override
	{
		std::shared_ptr<tsXmlNode> tmp;

		// TODO:  Synchronize with NamespaceNode
		if (name == "Namespace")
		{
			tmp = IObject::Create<NamespaceNode>();
		}
		else  if (name == "Include")
		{
			tmp = IObject::Create<IncludeNode>();
			tmp->Attributes() = Attributes;
			AddInclude(std::dynamic_pointer_cast<IncludeNode>(tmp));
		}
		else  if (name == "ID")
		{
			tmp = IObject::Create<IDNode>();
			OIDs().push_back(std::dynamic_pointer_cast<IDNode>(tmp));
		}
		else  if (name == "Alias")
		{
			tmp = IObject::Create<AliasNode>();
			tmp->Attributes() = Attributes;
			if (!AddElement(std::dynamic_pointer_cast<Element>(tmp)))
			{
				AddError("xml2Asn1CodeGen", "CreateNode", "This alias name is already used:  " + name, 2000);
				return nullptr;
			}
		}
		else  if (name == "Enum")
		{
			tmp = IObject::Create<EnumNode>();
			tmp->Attributes() = Attributes;
			if (!AddElement(std::dynamic_pointer_cast<Element>(tmp)))
			{
				AddError("xml2Asn1CodeGen", "CreateNode", "This enum name is already used:  " + name, 2000);
				return nullptr;
			}
		}
		else  if (name == "Bitstring")
		{
			tmp = IObject::Create<BitstringNode>();
			tmp->Attributes() = Attributes;
			if (!AddElement(std::dynamic_pointer_cast<Element>(tmp)))
			{
				AddError("xml2Asn1CodeGen", "CreateNode", "This bitstring name is already used:  " + name, 2000);
				return nullptr;
			}
		}
		else  if (name == "Sequence")
		{
			tmp = IObject::Create<SequenceNode>();
			tmp->Attributes() = Attributes;
			if (!AddElement(std::dynamic_pointer_cast<Element>(tmp)))
			{
				AddError("xml2Asn1CodeGen", "CreateNode", "This sequence name is already used:  " + name, 2000);
				return nullptr;
			}
		}
		else  if (name == "SequenceOf")
		{
			tmp = IObject::Create<SequenceOfNode>();
			tmp->Attributes() = Attributes;
			if (!AddElement(std::dynamic_pointer_cast<Element>(tmp)))
			{
				AddError("xml2Asn1CodeGen", "CreateNode", "This sequenceof name is already used:  " + name, 2000);
				return nullptr;
			}
		}
		else  if (name == "Set")
		{
			tmp = IObject::Create<SetNode>();
			tmp->Attributes() = Attributes;
			if (!AddElement(std::dynamic_pointer_cast<Element>(tmp)))
			{
				AddError("xml2Asn1CodeGen", "CreateNode", "This set name is already used:  " + name, 2000);
				return nullptr;
			}
		}
		else  if (name == "NamedInt")
		{
			tmp = IObject::Create<NamedInt>();
			tmp->Attributes() = Attributes;
			if (!AddElement(std::dynamic_pointer_cast<Element>(tmp)))
			{
				AddError("xml2Asn1CodeGen", "CreateNode", "This NamedInt name is already used:  " + name, 2000);
				return nullptr;
			}
		}
		else  if (name == "Import")
		{
			tmp = IObject::Create<ImportNode>();
			Imports().push_back(std::dynamic_pointer_cast<ImportNode>(tmp));
		}

		if (!!tmp)
		{
			tmp->Attributes() = Attributes;
			return tmp;
		}
		AddError("xml2Asn1CodeGen", "CreateNode", "Unable to create node " + name, 2000);
		return nullptr;
	}
	bool Open(const tsStringBase& OutputPath)
	{
		tsStringBase baseName(_baseFileName);

		baseName.ToUpper();

		_headerFile = new File(OutputPath + _HeaderFilename, "C++");
		_sourceFile = new File(OutputPath + _SourceFilename, "C++");
		_exportFile = new File(OutputPath + _ExportFilename, "XASN");
		Header()->ExportSymbol(_ExportSymbol);
		Source()->ExportSymbol(_ExportSymbol);
		Export()->ExportSymbol(_ExportSymbol);
		Header()->TemplateExternSymbol(_TemplateExternSymbol);
		Source()->TemplateExternSymbol(_TemplateExternSymbol);
		Export()->TemplateExternSymbol(_TemplateExternSymbol);

		WriteFileHeader(Header(), _HeaderFilename);
		WriteFileHeader(Source(), _SourceFilename);

		Header()->WriteLine("#if !defined(__" + baseName + "_H__)");
		Header()->WriteLine("#define __" + baseName + "_H__");
		Header()->WriteLine();
		Header()->WriteLine("#pragma once");
		Header()->WriteLine();


		Source()->WriteLine("#include \"stdafx.h\"");
		Source()->WriteLine("#include \"" + _headerPrefix + _HeaderFilename + "\"");
		Source()->WriteLine();

		Export()->WriteLine("<?xml version=\"1.0\" encoding=\"utf-8\" ?>");
		Export()->WriteLine("<Asn1Export xmlns=\"http://schemas.tecsec.com/xml2asn1codegen/2015\">");
		Export()->indent();
		WriteFileHeader(Export(), _ExportFilename);
		//Export()->WriteLine("<Include Name=\"" + _headerPrefix + _HeaderFilename + "\"/>");
		return true;

	}
	bool Close()
	{
		tsStringBase baseName(_baseFileName);

		baseName.ToUpper();

		Header()->SetNamespace(nullptr);
		Source()->SetNamespace(nullptr);
		Export()->SetNamespace(nullptr);

		Header()->WriteLine("");
		Header()->WriteLine("#endif // __" + baseName + "_H__");
		Header()->Close();

		Source()->Close();

		Export()->outdent();
		Export()->WriteLine("</Asn1Export>");
		Export()->Close();
		_headerFile = nullptr;
		_sourceFile = nullptr;
		_exportFile = nullptr;
		return true;

	}
	void WriteFileHeader(File* file, const tsStringBase& filename)
	{
		if (file->Language() == "C++")
		{
			file->WriteLine("//");
			file->WriteLine("// This file is the property of TecSec, Inc. (c) 2017 TecSec, Inc.");
			file->WriteLine("// All rights are reserved to TecSec.");
			file->WriteLine("//");
			file->WriteLine("// The information in this file may be protected by one or more of the following");
			file->WriteLine("// U.S. patents, as well as pending U.S. patent applications and foreign patents:");
			file->WriteLine("// 5,369,702; 5,369,707; 5,375,169; 5,410,599; 5,432,851; 5,440,290; 5,680,452; ");
			file->WriteLine("// 5,787,173; 5,898,781; 6,075,865; 6,229,445; 6,266,417; 6,490,680; 6,542,608; ");
			file->WriteLine("// 6,549,623; 6,606,386; 6,608,901; 6,684,330; 6,694,433; 6,754,820; 6,845,453; ");
			file->WriteLine("// 6,868,598; 7,016,495; 7,069,448; 7,079,653; 7,089,417; 7,095,851; 7,095,852; ");
			file->WriteLine("// 7,111,173; 7,131,009; 7,178,030; 7,212,632; 7,490,240; 7,539,855; 7,738,660; ");
			file->WriteLine("// 7,817,800; 7,974,410; 8,077,870; 8,083,808; 8,285,991; 8,308,820; 8,712,046. ");
			file->WriteLine("//");
			file->WriteLine();
			file->WriteLine("// GENERATED FILE - Do not edit - Regenerate using Xml2Asn1CodeGenerator.exe");
			file->WriteLine();
			file->WriteLine("////////////////////////////////////////////////////////////////////////////////////////////////////");
			file->WriteLine("/// \\file   " + filename);
			file->WriteLine("///");
			file->WriteLine("/// \\brief  This file is a set of ASN1 data classes");
			file->WriteLine("////////////////////////////////////////////////////////////////////////////////////////////////////");
			file->WriteLine();
		}
		else
		{
			file->WriteLine("<!--");
			file->WriteLine("This file is the property of TecSec, Inc. (c) 2017 TecSec, Inc.");
			file->WriteLine("All rights are reserved to TecSec.");
			file->WriteLine("");
			file->WriteLine("The information in this file may be protected by one or more of the following");
			file->WriteLine("U.S. patents, as well as pending U.S. patent applications and foreign patents:");
			file->WriteLine("5,369,702; 5,369,707; 5,375,169; 5,410,599; 5,432,851; 5,440,290; 5,680,452; ");
			file->WriteLine("5,787,173; 5,898,781; 6,075,865; 6,229,445; 6,266,417; 6,490,680; 6,542,608; ");
			file->WriteLine("6,549,623; 6,606,386; 6,608,901; 6,684,330; 6,694,433; 6,754,820; 6,845,453; ");
			file->WriteLine("6,868,598; 7,016,495; 7,069,448; 7,079,653; 7,089,417; 7,095,851; 7,095,852; ");
			file->WriteLine("7,111,173; 7,131,009; 7,178,030; 7,212,632; 7,490,240; 7,539,855; 7,738,660; ");
			file->WriteLine("7,817,800; 7,974,410; 8,077,870; 8,083,808; 8,285,991; 8,308,820; 8,712,046. ");
			file->WriteLine("");
			file->WriteLine();
			file->WriteLine("GENERATED FILE - Do not edit - Regenerate using Xml2Asn1CodeGenerator.exe");
			file->WriteLine("-->");

		}
	}
	bool ProcessContainerElementMetadata(std::shared_ptr<tsXmlNode> parent)
	{
		for (auto child : parent->Children())
		{
			if (!ProcessContainerElementMetadata(child))
				return false;
		}
		return true;
	}
	bool WriteForwardReferences()
	{
		Header()->WriteLine();
		Header()->WriteLine("// Forward references");
		for (auto ele : Elements())
		{
			if (!ele->WriteForwardReference(std::dynamic_pointer_cast<FileNode>(_me.lock())))
				return false;
		}
		return true;
	}
	bool WriteArrayDeclarations()
	{
		std::vector<tsStringBase> arrays;
		tsStringBase name;

		// First collect all of the array referenced/referencable structures
		for (auto ele : Elements())
		{
			std::shared_ptr<SequenceNode> seq = std::dynamic_pointer_cast<SequenceNode>(ele);
			std::shared_ptr<ChoiceNode> ch = std::dynamic_pointer_cast<ChoiceNode>(ele);

			if (!!seq)
			{
				if (seq->Export())
				{
					auto it = std::find_if(arrays.begin(), arrays.end(), [&seq](tsStringBase& val) {return val == (seq->NameSpace()->ToString() + seq->StructureName()); });
					if (it == arrays.end())
						arrays.push_back(seq->NameSpace()->ToString() + seq->StructureName());
				}
				for (auto fld : seq->Elements())
				{
					name = fld->GetArrayElementStructureName();
					if (fld->IsArray() && name.size() > 0)
					{
						std::shared_ptr<ElementContainer> modi = std::dynamic_pointer_cast<ElementContainer>(fld);

						if (modi->Elements()[0]->StructureName().size() > 0)
						{
							auto it = std::find_if(Elements().begin(), Elements().end(), [&name](std::shared_ptr<Element> e)->bool { return e->StructureName() == name; });
							if (it != Elements().end())
							{
								tsStringBase ns = (*it)->NameSpace()->ToString();

								ns += name;
								auto it1 = std::find_if(arrays.begin(), arrays.end(), [&ns](tsStringBase& val) {return ns == val; });
								if (it1 == arrays.end())
									arrays.push_back(ns);
							}
							else
							{
								// TODO:  This is probably an error
							}
						}
					}
				}
			}
			else if (!!ch)
			{
				for (auto fld : ch->Elements())
				{
					name = fld->GetArrayStructureName();
					if (fld->IsArray() && name.size() > 0)
					{
						auto it = std::find_if(Elements().begin(), Elements().end(), [&name](std::shared_ptr<Element> e)->bool { return e->StructureName() == name; });
						if (it != Elements().end())
						{
							tsStringBase ns = (*it)->NameSpace()->ToString();

							ns += name;
							auto it1 = std::find_if(arrays.begin(), arrays.end(), [&ns](tsStringBase& val) {return ns == val; });
							if (it1 == arrays.end())
								arrays.push_back(ns + name);
						}
					}
				}
			}
		}

		// Now write out the references
		//if (arrays.size() > 0)
		//{
		//	Header()->SetNamespace(nullptr);
		//	Header()->WriteLine();
		//	Header()->WriteLine("#ifdef _MSC_VER");
		//	Header()->WriteLine("#pragma warning(push)");
		//	Header()->WriteLine("#pragma warning(disable:4231)");

		//	for (auto& s : arrays)
		//	{
		//		tsCryptoStringList parts = s.split(':');

		//		auto it = std::find_if(Elements().begin(), Elements().end(), [&parts](std::shared_ptr<Element> e)->bool { return e->StructureName() == parts->back(); });
		//		SequenceNode* seq = dynamic_cast<SequenceNode*>(it->get());
		//		if (seq != nullptr)
		//			seq->UsedWithArray(true);

		//		tsCryptoString tmp;
		//		for (size_t i = 0; i < parts->size() - 1; i++)
		//			tmp << parts->at(i) << "::";
		//		tmp << "_POD_" << parts->back();
		//		Header()->WriteLine(TemplateExternSymbol() + "template class " + ExportSymbol() + "standardLayoutList<" + tmp + ">;");
		//	}

		//	Header()->WriteLine("#pragma warning(pop)");
		//	Header()->WriteLine("#endif // _MSC_VER");
		//}
		return true;
	}

};



#endif // __FILENODE_H__
