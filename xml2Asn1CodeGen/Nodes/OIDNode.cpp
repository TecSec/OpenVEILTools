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
#include "OIDNode.h"
#include "FileNode.h"

static std::shared_ptr<IDNode> FindOIDNode(std::shared_ptr<FileNode> files, const tsStringBase& name)
{
	for (auto& oid : files->OIDs())
	{
		if (oid->Name() == name)
			return oid;
	}
	return nullptr;
}
void IDNode::WriteOID(std::shared_ptr<FileNode> files)
{
	size_t start = 0, end, pos;
	tsStringBase name;


	if (Export())
	{
		files->Export()->SetNamespace(NameSpace());
		files->Export()->WriteLine("<ID Name=\"" + Name() + "\" Value=\"" + Value() + "\" Imported=\"true\"/>");
	}

	while ((pos = Value().find('{', start)) != tsStringBase::npos)
	{
		end = Value().find('}', pos + 1);
		if (end != tsStringBase::npos)
		{
			name = Value().substr(pos + 1, end - pos - 1);
			std::shared_ptr<IDNode> node = FindOIDNode(files, name);
			if (!node)
				start = end;
			else
			{
				Value(Value().replace(pos, end + 1, node->Value()));
			}
		}
		else
			break;
	}

	if (!Import())
	{
		files->Header()->SetNamespace(NameSpace());

		tsStringBase tmp = Description();
		if (tmp.size() > 0)
			files->Header()->WriteLine(tmp);
#if !defined(USE_CONST) || defined(HAVE_CONSTEXPR)
		files->Header()->WriteLine("constexpr const char* " + Name() + " = \"" + Value() + "\";");
#else
		files->Header()->WriteLine("static const char* " + Name() + " = \"" + Value() + "\";");
#endif
	}
}

std::shared_ptr<Namespace> IDNode::NameSpace()
{
	if (!!_namespace)
		return _namespace;

	std::shared_ptr<tsXmlNode> node = std::dynamic_pointer_cast<tsXmlNode>(_me.lock());

	while (!!node)
	{
		std::shared_ptr<NamespaceNode> nn = std::dynamic_pointer_cast<NamespaceNode>(node);

		if (!!nn)
		{
			_namespace = nn->CreateNamespace();
			return _namespace;
		}
		node = node->Parent().lock();
	}
	return std::shared_ptr<Namespace>(new RootNamespace());
}
std::shared_ptr<Element> IDNode::GetParentElement()
{
	std::shared_ptr<tsXmlNode> node = this->Parent().lock();

	while (!!node)
	{
		std::shared_ptr<Element> ele = std::dynamic_pointer_cast<Element>(node);

		if (!!ele)
		{
			return ele;
		}
		node = node->Parent().lock();
	}
	return nullptr;
}
std::shared_ptr<NamespaceNode> IDNode::ParentNamespace()
{
	std::shared_ptr<Element> ele = GetParentElement();
	std::shared_ptr<NamespaceNode> ns;

	while (!!ele && !(ns = std::dynamic_pointer_cast<NamespaceNode>(ele)))
		ele = ele->GetParentElement();

	return ns;
}
