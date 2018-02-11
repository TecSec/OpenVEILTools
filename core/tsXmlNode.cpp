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


#include "stdafx.h"

static const char gEbNamespace[] = "http://soap.tecsec.com/eb_ws";
static const char gSoap12Namespace[] = "http://www.w3.org/2003/05/soap-envelope";

NamespaceSupport::NamespaceSupport()
{
	m_namespaces.AddItem("xmlns", gEbNamespace);
}

NamespaceSupport::~NamespaceSupport()
{
}

void NamespaceSupport::extractNamespaceAttributes(tsAttributeMap &attrs)
{
	for (ptrdiff_t i = attrs.count() - 1; i >= 0; i--)
	{
		tsStringBase name = attrs.name(i);
		if (strcmp(name.c_str(), "xmlns") == 0)
		{
			m_namespaces.RemoveItem("xmlns");
			m_namespaces.AddItem("xmlns", attrs.item(i));
			attrs.RemoveItem(i);
		}
		else if (strncmp(name.c_str(), "xmlns:", 6) == 0)
		{
			name.DeleteAt(0, 6);
			m_namespaces.RemoveItem(name.c_str());
			m_namespaces.AddItem(name.c_str(), attrs.item(i));
			attrs.RemoveItem(i);
		}
	}
}

void NamespaceSupport::addNamespacesToAttributeList(tsAttributeMap &attrs)
{
	for (size_t i = 0; i < m_namespaces.count(); i++)
	{
		tsStringBase name = m_namespaces.name(i);

		if (strcmp(name.c_str(), "xmlns") != 0)
		{
			name.prepend("xmlns:");
		}
		attrs.AddItem(name.c_str(), m_namespaces.item(i));
	}
}

tsStringBase NamespaceSupport::getDefaultNamespace() const
{
	return m_namespaces.item("xmlns");
}

void NamespaceSupport::removeDefaultNamespace()
{
	m_namespaces.RemoveItem("xmlns");
}

tsStringBase NamespaceSupport::getEBNamespaceName() const
{
	for (size_t i = 0; i < m_namespaces.count(); i++)
	{
		if (tsStriCmp(m_namespaces.item(i).c_str(), gEbNamespace) == 0)
		{
			return m_namespaces.name(i);
		}
	}
	return "";
}

bool NamespaceSupport::EbNamespaceIsDefault() const
{
	tsStringBase ns = getEBNamespaceName();

	return (strcmp(ns.c_str(), "xmlns") == 0);
}

tsStringBase NamespaceSupport::getSoap12NamespaceName() const
{
	for (size_t i = 0; i < m_namespaces.count(); i++)
	{
		if (tsStriCmp(m_namespaces.item(i).c_str(), gSoap12Namespace) == 0)
		{
			return m_namespaces.name(i);
		}
	}
	return "";
}

void NamespaceSupport::addNamespace(const tsStringBase& name, const tsStringBase& value)
{
	m_namespaces.RemoveItem(name);
	if (value != NULL && value[0] != 0)
	{
		m_namespaces.AddItem(name, value);
	}
}

std::shared_ptr<tsXmlNode> tsXmlNode::Create()
{
	std::shared_ptr<tsXmlNode> obj = std::shared_ptr<tsXmlNode>(new tsXmlNode);
	if (!obj)
		return nullptr;
	obj->Me = obj;
	obj->_me = obj;
	return obj;
}

tsXmlNode::tsXmlNode() :
	m_wantsXmlContents(false),
	m_wantsTextContents(true),
	m_addTsIDs(true),
	m_useFormattedOutput(false),
	m_attrNodeType(suffixedWithAtt)
{
	m_lNextID = 1;
	m_bProcessed = false;
	m_bHasErrors = false;
	m_bHasWarnings = false;
	m_bHash = false;
	m_bMakeDom = true;
	m_bProtect = false;
	m_RunnableParseNode = NULL;
	m_RootNode = NULL;
	m_forceHashChecks = false;
	m_needsReauth = false;
	NodeName("Root");
}

tsXmlNode::~tsXmlNode()
{

}

//void *tsXmlNode::operator new(size_t bytes)
//{
//    return FrameworkAllocator(bytes);
//}
//
//void tsXmlNode::operator delete(void *ptr)
//{
//    return FrameworkDeallocator(ptr);
//}

bool tsXmlNode::AddTsIDs(void) const
{
	return m_addTsIDs;
}

void tsXmlNode::AddTsIDs(bool setTo)
{
	m_addTsIDs = setTo;
}

bool tsXmlNode::StartNode(std::shared_ptr<tsXmlNode> parent, const tsAttributeMap &pAttributes)
{

	if (!m_Parent.expired())
		return false;

	m_Attributes = pAttributes;
	m_Parent = parent;
	m_needsReauth = false;
	return true;
}

std::shared_ptr<tsXmlNode> tsXmlNode::StartSubnode(const tsStringBase &name)
{
	tsAttributeMap map;

	return StartSubnode(name, map);
}

std::shared_ptr<tsXmlNode> tsXmlNode::StartTextSubnode(const tsStringBase &name, const tsStringBase& text)
{
	std::shared_ptr<tsXmlNode> node = StartSubnode(name);

	if (node != nullptr)
		node->NodeText(text);
	return node;
}

std::shared_ptr<tsXmlNode> tsXmlNode::StartTextSubnode(const tsStringBase &name, bool setTo)
{
	return StartTextSubnode(name, tsStringBase(setTo ? "true" : "false"));
}

std::shared_ptr<tsXmlNode> tsXmlNode::StartTextSubnode(const tsStringBase &name, const char* setTo)
{
	return StartTextSubnode(name, tsStringBase(setTo));
}

std::shared_ptr<tsXmlNode> tsXmlNode::StartTextSubnode(const tsStringBase &name, int setTo)
{
	return StartTextSubnode(name, (tsStringBase().append(setTo)));
}

std::shared_ptr<tsXmlNode> tsXmlNode::StartTextSubnode(const tsStringBase &name, int64_t setTo)
{
	char buffer[100];

	tsSnPrintf(buffer, sizeof(buffer), "%lld", setTo);
	return StartTextSubnode(name, buffer);
}

std::shared_ptr<tsXmlNode> tsXmlNode::StartTextSubnode(const tsStringBase &name, size_t setTo)
{
	char buffer[100];

	tsSnPrintf(buffer, sizeof(buffer), "%lld", setTo);
	return StartTextSubnode(name, buffer);
}

std::shared_ptr<tsXmlNode> tsXmlNode::StartTextSubnode(const tsStringBase &name, const tsData& setTo)
{
	return StartTextSubnode(name, setTo.ToBase64());
}

std::shared_ptr<tsXmlNode> tsXmlNode::CreateNode(const tsStringBase &name, const tsAttributeMap &Attributes)
{
	UNREFERENCED_PARAMETER(name);
	UNREFERENCED_PARAMETER(Attributes);

	return tsXmlNode::Create();
}

std::shared_ptr<tsXmlNode> tsXmlNode::StartSubnode(const tsStringBase &name, const tsAttributeMap &Attributes)
{
	std::shared_ptr<tsXmlNode> pNode;

	if (name.size() == 0)
		return NULL;
	//if (name == "Error")
	//{
	//	AddError(Attributes.item("Component"), Attributes.item("Method"), Attributes.item("Value"), Attributes.itemAsNumber("Number", 1));
	//	return NULL;
	//}
	//else
	{
		pNode = CreateNode(name, Attributes);
		if (pNode == nullptr)
			return nullptr;

		pNode->AddTsIDs(AddTsIDs());
		tsAttributeMap AttributesCopy = Attributes;
		if (AddTsIDs() && !AttributesCopy.hasItem("TSID"))
		{
			AddTSID(AttributesCopy);
		}
		pNode->AddTsIDs(AddTsIDs());
		if (!pNode->StartNode(std::dynamic_pointer_cast<tsXmlNode>(_me.lock()), AttributesCopy)) {
			return NULL;
		}

		pNode->NodeName(name);
		pNode->AddTsIDs(AddTsIDs());
		m_Children.push_back(pNode);
	}
	return pNode;
}

std::weak_ptr<tsXmlNode> tsXmlNode::Parent() const
{
	return m_Parent;
}

const tsStringBase &tsXmlNode::NodeName() const
{
	return m_NodeName;
}

void tsXmlNode::NodeName(const tsStringBase &name)
{
	m_NodeName = name;
}

tsStringBase tsXmlNode::NodeNamespace() const
{
	if (strchr(m_NodeName.c_str(), ':') != nullptr)
	{
		tsStringBaseList list = m_NodeName.split(":");
		return list.at(0);
	}
	return "";
}

tsStringBase tsXmlNode::NodeLocalName() const
{
	if (strchr(m_NodeName.c_str(), ':') != nullptr)
	{
		tsStringBaseList list = m_NodeName.split(":");
		return list.back();
	}
	return m_NodeName;
}

tsStringBase tsXmlNode::NodeText() const
{
	return m_Text;
}

bool tsXmlNode::NodeText(const tsStringBase &setTo)
{
	if (!WantsTextContents())
		return false;
	m_Text = setTo;
	return true;
}

int tsXmlNode::NodeTextAsNumber() const
{
	return tsStrToInt(NodeText().c_str());
}

void tsXmlNode::NodeTextAsNumber(int setTo)
{
	NodeText((tsStringBase().append(setTo)));
}

bool tsXmlNode::NodeTextAsBool() const
{
	return NodeTextAsNumber() != 0;
}

void tsXmlNode::NodeTextAsBool(bool setTo)
{
	NodeText(setTo ? "1" : "0");
}

bool tsXmlNode::AppendText(const tsStringBase &setTo)
{
	if (!WantsTextContents())
		return false;
	m_Text = setTo;
	return true;
}


tsAttributeMap& tsXmlNode::Attributes()
{
	return m_Attributes;
}

const tsAttributeMap& tsXmlNode::Attributes() const
{
	return m_Attributes;
}

tsXmlNodeList& tsXmlNode::Children()
{
	return m_Children;
}

const tsXmlNodeList& tsXmlNode::Children() const
{
	return m_Children;
}


std::shared_ptr<tsXmlNode> tsXmlNode::ChildAt(const size_t idx)
{
	if (idx > ChildrenCount())
		return NULL;

	return m_Children.at(idx);
}

std::shared_ptr<tsXmlNode> tsXmlNode::ChildAt(const size_t idx) const
{
	if (idx > ChildrenCount())
		return NULL;

	return m_Children.at(idx);
}

bool tsXmlNode::Processed() const
{
	return m_bProcessed;
}

bool tsXmlNode::HasErrors() const
{
	return m_bHasErrors;
}

bool tsXmlNode::HasWarnings() const
{
	return m_bHasWarnings;
}

void tsXmlNode::HasErrors(bool has_errors)
{
	m_bHasErrors = has_errors;
}

void tsXmlNode::HasWarnings(bool has_warnings)
{
	m_bHasWarnings = has_warnings;
}

size_t tsXmlNode::ErrorCount() const
{
	return m_Errors.size();;
}

size_t tsXmlNode::WarningCount() const
{
	return m_Warnings.size();
}

const std::shared_ptr<tsXmlError> tsXmlNode::ErrorAt(size_t idx) const
{
	if (idx > ErrorCount())
		return NULL;
	return m_Errors.at(idx);
}

const std::shared_ptr<tsXmlError> tsXmlNode::WarningAt(size_t idx) const
{
	if (idx > WarningCount())
		return NULL;
	return m_Warnings.at(idx);
}

size_t tsXmlNode::ChildrenCount() const
{
	return m_Children.size();
}

void tsXmlNode::ClearAll()
{
	ClearChildren();
	Attributes().ClearAll();
	ClearErrors();
	ClearWarnings();
}

void tsXmlNode::ClearChildren()
{
	m_Children.clear();
}

std::shared_ptr<tsXmlNode> tsXmlNode::ExtractChild(const size_t idx)
{
	if (idx < m_Children.size())
	{
		std::shared_ptr<tsXmlNode> node = m_Children.at(idx);

		RemoveChild(node);
		return node;
	}
	else
		return NULL;
}

void tsXmlNode::RemoveChild(const size_t idx)
{
	auto it = m_Children.begin();
	std::advance(it, idx);
	if (it != m_Children.end())
	{
		m_Children.erase(it);
	}
}
void tsXmlNode::RemoveChild(std::shared_ptr<tsXmlNode> pChild)
{
	auto it = std::find_if(m_Children.begin(), m_Children.end(), [&pChild](std::shared_ptr<tsXmlNode>& pTemp)->bool { return pChild.get() == pTemp.get(); });
	if (it != m_Children.end())
		m_Children.erase(it);
}

void tsXmlNode::AddChild(std::shared_ptr<tsXmlNode> pChild)
{
	pChild->m_Parent = std::dynamic_pointer_cast<tsXmlNode>(_me.lock());
	m_Children.push_back(pChild);
}
// TODO:  rdbj  Removed as it should no longer be needed
//bool CtsXmlNode::RequiresHash()
//{
//	return m_bHash;
//}
//
//void CtsXmlNode::RequiresHash(bool bDoHash)
//{
//	m_bHash = bDoHash;
//}

bool tsXmlNode::RequiresProtection() const
{
	return m_bProtect;
}

void tsXmlNode::RequiresProtection(bool setTo)
{
	m_bProtect = setTo;
}

std::shared_ptr<tsXmlError> tsXmlNode::CreateErrorNode()
{
	std::shared_ptr<tsXmlError> obj = std::shared_ptr<tsXmlError>(new tsXmlError);
	if (!!obj)
		obj->_me = obj;
	return obj;
}

void tsXmlNode::AddError(const tsStringBase &comp, const tsStringBase &meth, const tsStringBase &desc, int32_t num)
{
	std::shared_ptr<tsXmlError> err = CreateErrorNode();
	if (err) {
		err->Component(comp);
		err->Method(meth);
		err->Description(desc);
		err->Number(num);
		if (num < 1000 || num > 1999)
		{
			m_Errors.push_back(err);
			HasErrors(true);
		}
		else
		{
			m_Warnings.push_back(err);
			HasWarnings(true);
		}
	}
}

void tsXmlNode::AddFirstError(const tsStringBase &comp, const tsStringBase &meth, const tsStringBase &desc, int32_t num)
{
	std::shared_ptr<tsXmlError> err = CreateErrorNode();
	if (err) {
		err->Component(comp);
		err->Method(meth);
		err->Description(desc);
		err->Number(num);
		if (num < 1000 || num > 1999)
		{
			m_Errors.push_back(err);
			HasErrors(true);
		}
		else
		{
			m_Warnings.push_back(err);
			HasWarnings(true);
		}
	}
}

void tsXmlNode::_AddError(tsStringBase &Results, int32_t Number, ...)
{
	va_list vArg;
	va_start(vArg, Number);
	TSAddXMLError(Results, "EBClient", m_NodeName, Number, vArg);
	va_end(vArg);
}

std::shared_ptr<tsXmlNode> tsXmlNode::ChildByTSID(const tsStringBase &tsid)
{
	tsStringBase value;

	for (size_t i = 0; i < ChildrenCount(); i++)
	{
		if ((*m_Children.at(i)).Attributes().hasItem("TSID"))
		{
			value = (*m_Children.at(i)).Attributes().item("TSID");
			if ((strcmp(tsid.c_str(), value.c_str()) == 0)) {
				return m_Children.at(i);
			}
		}
	}
	return NULL;
}

std::shared_ptr<tsXmlNode> tsXmlNode::ChildByTSID(const tsStringBase &tsid) const
{
	for (size_t i = 0; i < ChildrenCount(); i++)
	{
		if ((*m_Children.at(i)).Attributes().hasItem("TSID"))
		{
			if ((strcmp(tsid.c_str(), (*m_Children.at(i)).Attributes().item("TSID").c_str()) == 0)) {
				return m_Children.at(i);
			}
		}
	}
	return NULL;
}

void tsXmlNode::AddTSID(tsAttributeMap &Attributes)
{
	while (ChildByTSID((tsStringBase().append(m_lNextID))) != NULL)
	{
		m_lNextID++;
	}
	tsStringBase strTemp;

	strTemp.append(m_lNextID++);

	Attributes.RemoveItem("TSID");
	if (AddTsIDs())
	{
		Attributes.AddItem("TSID", strTemp.c_str());
	}
}

void tsXmlNode::CopyFrom(std::shared_ptr<tsXmlNode> srcNode, bool bDoChildren)
{
	size_t i;
	size_t childCount;
	std::shared_ptr<tsXmlNode> ndSrcChild;
	std::shared_ptr<tsXmlNode> ndThisChild;

	if (!!srcNode)
	{
		this->ClearChildren();
		this->m_NodeName = srcNode->m_NodeName;
		this->m_Text = srcNode->m_Text;
		this->m_Attributes = srcNode->m_Attributes;
		this->m_bHash = srcNode->m_bHash;
		this->m_bProcessed = false;
		if (bDoChildren)
		{
			childCount = srcNode->ChildrenCount();
			for (i = 0; i < childCount; i++)
			{
				ndSrcChild = srcNode->ChildAt(i);
				if (ndSrcChild != NULL)
				{
					// create a duplicate child
					// the name will be reset when the contents are copied.
					ndThisChild = this->StartSubnode("CHILD_NODE_YOU_SHOULD_NOT_SEE_THIS");
					// recurse and create all children
					if (ndThisChild != NULL)
					{
						ndThisChild->CopyFrom(ndSrcChild, bDoChildren);
					}
				}
			}
		}
	}



}

void tsXmlNode::BuildStartNodeXML(tsStringBase &output) const
{
	tsStringBase tmp;

	output = "<";
	output += NodeName();
	Attributes().ToXML(tmp);
	if (tmp.size() > 0)
	{
		output += " ";
		output += tmp;
	}
	output += ">";
}

void tsXmlNode::BuildEndNodeXML(tsStringBase &output) const
{
	output = "</";
	output += NodeName();
	output += ">";
}

void tsXmlNode::AppendStartNodeXML(tsStringBase &output) const
{
	tsStringBase tmp;

	output += "<";
	output += NodeName();
	Attributes().ToXML(tmp);
	if (tmp.size() > 0)
	{
		output += " ";
		output += tmp;
	}
	output += ">";
}

void tsXmlNode::AppendSingleNodeXML(tsStringBase &output) const
{
	tsStringBase tmp;

	output += "<";
	output += NodeName();
	Attributes().ToXML(tmp);
	if (tmp.size() > 0)
	{
		output += " ";
		output += tmp;
	}
	output += "/>";
}

void tsXmlNode::AppendEndNodeXML(tsStringBase &output) const
{
	output += "</";
	output += NodeName();
	output += ">";
}

bool tsXmlNode::CheckErrorHandling() const
{
	if (!Attributes().hasItem("Errors"))
		return false;
	return (tsStriCmp(Attributes().item("Errors").c_str(), ("Ignore")) == 0);
}

void tsXmlNode::ClearErrors()
{
	m_Errors.clear();
	m_bHasErrors = false;
}

void tsXmlNode::ClearWarnings()
{
	m_Warnings.clear();
	m_bHasWarnings = false;
}

tsXmlErrorList tsXmlNode::GetErrorList(bool recursive) const
{
	tsXmlErrorList tmp;

	size_t count = m_Errors.size();

	for (size_t i = 0; i < count; i++)
		tmp.push_back(m_Errors.at(i));
	if (recursive)
	{
		count = ChildrenCount();
		for (size_t i = 0; i < count; i++)
		{
			tsXmlErrorList tmp2 = ChildAt(i)->GetErrorList(recursive);

			size_t cnt = tmp2.size();
			for (size_t j = 0; j < cnt; j++)
			{
				tmp.push_back(tmp2.at(j));
			}
		}
	}
	return tmp;
}

tsXmlErrorList tsXmlNode::GetWarningList(bool recursive) const
{
	tsXmlErrorList tmp;

	size_t count = m_Warnings.size();

	for (size_t i = 0; i < count; i++)
		tmp.push_back(m_Warnings.at(i));
	if (recursive)
	{
		count = ChildrenCount();
		for (size_t i = 0; i < count; i++)
		{
			tsXmlErrorList tmp2 = ChildAt(i)->GetWarningList(recursive);

			size_t cnt = tmp2.size();
			for (size_t j = 0; j < cnt; j++)
			{
				tmp.push_back(tmp2.at(j));
			}
		}
	}
	return tmp;
}

bool tsXmlNode::BuildXML(tsStringBase &Results, bool useAttributesForErrors)
{
	bool retVal = true;
	tsStringBase tmp, tmp1;
	bool textOnly;
	bool formatIt = false;
	int parentCount = 0;
	std::shared_ptr<tsXmlNode> node = std::dynamic_pointer_cast<tsXmlNode>(_me.lock());

	while (!node->Parent().expired())
	{
		parentCount++;
		node = std::dynamic_pointer_cast<tsXmlNode>(node->Parent().lock());
	}

	if (!!node)
		formatIt = node->UseFormattedOutput();

	try
	{
		RunChildren(tmp);
		textOnly = (tmp.size() == 0);
		//if (formatIt && !textOnly && NodeText().size() > 0)
		//{
		//	tmp += "\n" + tsStringBase(' ', (parentCount + 1) * 2);
		//}
		TSPatchValueForXML(NodeText(), tmp1);
		tmp += tmp1;

		// CheckErrorHandling()??

		if (HasErrors())
		{
			size_t count = ErrorCount();
			std::shared_ptr<tsXmlError> err;

			for (size_t i = 0; i < count; i++)
			{
				err = ErrorAt(i);
				if (!!err)
				{
					err->ToXML(tmp, useAttributesForErrors);
				}
			}
		}
		if (HasWarnings())
		{
			size_t count = WarningCount();
			std::shared_ptr<tsXmlError> err;

			for (size_t i = 0; i < count; i++)
			{
				err = WarningAt(i);
				if (!!err)
				{
					err->ToXML(tmp, useAttributesForErrors);
				}
			}
		}

		if (RequiresProtection())
		{
			if (!EncryptForChannel(tmp, Results))
				return false;
		}
		// TODO:  rdbj  Removed as it should no longer be needed
//		else if ( RequiresHash() )
//		{
//			tsByteString Hash;
//			tsStringBase sHash;
//			long i;
//			long count;
//
//			Attributes().RemoveItem("Hash");
//
//			if ( FAILED(TSIncrementalHashStart(Hash)) )
//			{
//				AddError("AgentRequestor", "BuildXML", "Can't build hash.", IDS_E_XML_CANT_GENERATE);
//				return false;
//			}
//			count = Attributes().count();
//			for ( i = 0; i < count; i++ )
//			{
//#ifndef TARGET221
//				if ( FAILED(TSIncrementalHash(Attributes().name(i), Hash)) )
//				{
//					AddError("AgentRequestor", "BuildXML", "Can't build hash.", IDS_E_XML_CANT_GENERATE);
//					return false;
//				}
//#endif // TARGET221
//				if ( FAILED(TSIncrementalHash(Attributes().item(i), Hash)) )
//				{
//					AddError("AgentRequestor", "BuildXML", "Can't build hash.", IDS_E_XML_CANT_GENERATE);
//					return false;
//				}
//			}
//
//			if ( tmp.size() > 0 && FAILED(TSIncrementalHash(tmp, Hash)) )
//			{
//				AddError("AgentRequestor", "BuildXML", "Can't build hash.", IDS_E_XML_CANT_GENERATE);
//				return false;
//			}
//			if ( m_Text.size() > 0 && FAILED(TSIncrementalHash(m_Text, Hash)) )
//			{
//				AddError("AgentRequestor", "BuildXML", "Can't build hash.", IDS_E_XML_CANT_GENERATE);
//				return false;
//			}
//			if ( FAILED(TSIncrementalHashFinish(Hash)) )
//			{
//				AddError("AgentRequestor", "BuildXML", "Can't build hash.", IDS_E_XML_CANT_GENERATE);
//				return false;
//			}
//			TSEncodeXML(Hash, sHash);
//			Attributes().AddItem("Hash", sHash.c_str());
//		}
		if (formatIt)
		{
			if (parentCount > 0)
			{
				if (Results.size() > 0)
					Results += "\n";
				Results += tsStringBase(' ', parentCount * 2);
			}
		}
		if (tmp.size() == 0)
			AppendSingleNodeXML(Results);
		else
		{
			AppendStartNodeXML(Results);
			if (textOnly)
			{
				Results += tmp;
				AppendEndNodeXML(Results);
			}
			else
			{
				Results += "\n";
				Results += tmp;
				Results += "\n";
				Results += tsStringBase(' ', parentCount * 2);
				AppendEndNodeXML(Results);
			}
		}
	}
	catch (...)
	{
		tsStringBase buff;

		buff.append("An error occurred while trying to run the request for the ").append(m_NodeName).append(" node.");
		AddError("AgentRequestor", "BuildXML", buff, 0);
		return false;
	}
	return retVal;
}

////void CtsXmlNode::RunChildren(tsStringBase &Results)
////{
////	// Run the children of this node using the static
////	// function __RunNodes passed to each element
////	// of the linked list of children.
////	// See the rbSinglyLinkedList code
////	// for more details on the iteration of functions
////	// over elements.
////
////	m_Children.forEach(__RunNodes, &Results);
////
////}

int tsXmlNode::__RunNodes(std::shared_ptr<tsXmlNode> node, tsStringBase *params)
{
	if (!node->Run(*params, true)) // TODO:  Review this
	{
		if (!node->Parent().expired())
			return !node->Parent().lock()->CheckErrorHandling();
		return 1;
	}
	return 0;
}

bool tsXmlNode::MigrateErrors(tsStringBase &Results)
{
	size_t i = 0;
	std::shared_ptr<tsXmlError> err;
	bool retVal = false;

	for (i = 0; i < ErrorCount(); i++) {
		err = ErrorAt(i);
		if (err) {
			AppendXMLError(Results, err->Component(), err->Method(), err->Number(), err->Description());
			retVal = true;
		}
	}
	std::shared_ptr<tsXmlNode> nd = std::dynamic_pointer_cast<tsXmlNode>(_me.lock());
	while (!nd->Parent().expired()) {
		nd = nd->Parent().lock();
		for (i = 0; i < nd->ErrorCount(); i++) {
			err = nd->ErrorAt(i);
			if (err) {
				AppendXMLError(Results, err->Component(), err->Method(), err->Number(), err->Description());
				retVal = true;
			}
		}
	}
	return retVal;
}

bool tsXmlNode::MigrateWarnings(tsStringBase &Results)
{
	size_t i = 0;
	std::shared_ptr<tsXmlError> err;
	bool retVal = false;

	for (i = 0; i < WarningCount(); i++) {
		err = WarningAt(i);
		if (err) {
			AppendXMLError(Results, err->Component(), err->Method(), err->Number(), err->Description());
			retVal = true;
		}
	}
	std::shared_ptr<tsXmlNode> nd = std::dynamic_pointer_cast<tsXmlNode>(_me.lock());
	while (!nd->Parent().expired()) {
		nd = nd->Parent().lock();
		for (i = 0; i < nd->WarningCount(); i++) {
			err = nd->WarningAt(i);
			if (err) {
				AppendXMLError(Results, err->Component(), err->Method(), err->Number(), err->Description());
				retVal = true;
			}
		}
	}
	return retVal;
}

void tsXmlNode::MakeDOMChildren(void* bVal)
{
	for (std::shared_ptr<tsXmlNode>& node : m_Children)
	{
		__MakeDOMChildren(node, bVal);
	}
}

void tsXmlNode::__MakeDOMChildren(std::shared_ptr<tsXmlNode> node, void* params)
{
	node->MakeDOM(*(bool*)params);
	node->MakeDOMChildren(params);
}

void tsXmlNode::MakeDOM(bool val)
{
	m_bMakeDom = val;
	MakeDOMChildren(&val);
}

bool tsXmlNode::MakeDOM() const
{
	return m_bMakeDom;
}

void tsXmlNode::AppendXMLError(tsStringBase &Results, const tsStringBase &Component, const tsStringBase &Method, int32_t Number, const tsStringBase &Desc)
{
	Results += "<Error><NumberAtt>";
	Results.append(Number);
	Results += "</NumberAtt><ComponentAtt>";
	Results += Component;
	Results += "</ComponentAtt><MethodAtt>";
	Results += Method;
	Results += "</MethodAtt><ValueAtt>";
	Results += Desc;
	Results += "</ValueAtt></Error>";
}

bool tsXmlNode::WantsXMLContents() const
{
	return m_wantsXmlContents;
}

void tsXmlNode::WantsXMLContents(bool setTo)
{
	m_wantsXmlContents = setTo;
}

const tsStringBase &tsXmlNode::XMLContents() const
{
	return m_xmlContents;
}

bool tsXmlNode::XMLContents(const tsStringBase &setTo)
{
	if (!WantsXMLContents())
		return false;
	m_xmlContents = setTo;
	return true;
}

/* These methods are used for reintegration of responses */

tsXmlParserCallback::resultCodes tsXmlNode::StartResponse(const tsStringBase &/*NodeName*/, const tsStringBase &/*InnerXML*/, bool /*singleNode*/)
{
	// Start the response.
	return tsXmlParserCallback::rcSuccess;
}

tsXmlParserCallback::resultCodes tsXmlNode::EndResponse(const tsStringBase &/*NodeName*/)
{
	// the response has been parsed.  set this nodes
	// processed flag to true.
	m_bProcessed = true;
	return tsXmlParserCallback::rcSuccess;
}

tsXmlParserCallback::resultCodes tsXmlNode::ResponseText(const tsStringBase &newVal)
{
	// dump the response text into this nodes XML
	m_Text = newVal;
	return tsXmlParserCallback::rcSuccess;
}

bool tsXmlNode::WantsTextContents() const
{
	return m_wantsTextContents;
}

void tsXmlNode::WantsTextContents(bool setTo)
{
	m_wantsTextContents = setTo;
}

bool tsXmlNode::RunChildren(tsStringBase &Results)
{
	auto it = std::find_if(m_Children.begin(), m_Children.end(), [&Results, this](std::shared_ptr<tsXmlNode>& node)->bool { return __RunNodes(node, &Results) != 0; });
	return it == m_Children.end();
}

bool tsXmlNode::RunnableNode()
{
	return true;
}

bool tsXmlNode::Run(tsStringBase &Results, bool useAttributesForErrors)
{
	bool retVal = true;
	tsStringBase tmp;
	bool textOnly;
	bool formatIt = false;
	int parentCount = 0;
	std::shared_ptr<tsXmlNode> node = std::dynamic_pointer_cast<tsXmlNode>(_me.lock());

	try
	{
		if (RunnableNode())
		{
			while (!node->Parent().expired())
			{
				parentCount++;
				node = node->Parent().lock();
			}

			if (node != NULL)
				formatIt = node->UseFormattedOutput();

			retVal = InternalRunStart(tmp);
			if (!retVal)
				retVal = CheckErrorHandling();
			if (retVal)
			{
				retVal = RunChildren(tmp);
				if (retVal)
				{
					retVal = InternalRunEnd(tmp);
					if (!retVal)
						retVal = CheckErrorHandling();
				}
			}

			if (HasErrors())
			{
				size_t count = ErrorCount();
				std::shared_ptr<tsXmlError> err;

				for (size_t i = 0; i < count; i++)
				{
					err = ErrorAt(i);
					if (err != NULL)
					{
						err->ToXML(tmp, useAttributesForErrors);
					}
				}
			}
			if (HasWarnings())
			{
				size_t count = WarningCount();
				std::shared_ptr<tsXmlError> err;

				for (size_t i = 0; i < count; i++)
				{
					err = WarningAt(i);
					if (err != NULL)
					{
						err->ToXML(tmp, useAttributesForErrors);
					}
				}
			}
			textOnly = (tmp.size() == 0);
			tmp += NodeText();

			if (RequiresProtection())
			{
				if (!EncryptForChannel(tmp, Results))
					return false;
			}
			if (formatIt)
			{
				if (parentCount > 0)
				{
					if (Results.size() > 0)
						Results += "\n";
					Results += tsStringBase(' ', parentCount * 2);
				}
			}
			if (tmp.size() == 0)
				AppendSingleNodeXML(Results);
			else
			{
				AppendStartNodeXML(Results);
				if (textOnly)
				{
					Results += tmp;
					AppendEndNodeXML(Results);
				}
				else
				{
					Results += "\n";
					Results += tmp;
					Results += "\n" + tsStringBase(' ', parentCount * 2);
					AppendEndNodeXML(Results);
				}
			}
		}
	}
	catch (...)
	{
		tsStringBase buff;

		buff.append("<Error><ValueAtt>An error occurred while trying to run the request for the ")
			.append(m_NodeName).append(" node.</ValueAtt><NumberAtt>1</NumberAtt><MethodAtt>RunableParseNode::Run</MethodAtt><ComponentAtt>EBSNetSrv32</ComponentAtt></Error>");
		Results += buff;
		Results += tmp;
		return false;
	}
	return retVal;
}

bool tsXmlNode::InternalRunStart(tsStringBase &/*Results*/)
{
	return true;
}

bool tsXmlNode::InternalRunEnd(tsStringBase &/*Results*/)
{
	return true;
}

bool tsXmlNode::Validate(tsStringBase &Results, bool useAttributesForErrors)
{
	tsStringBase tmpResults;
	tsStringBase tmp;

	try
	{
		if (!InternalValidate(tmpResults) || !ValidateChildren(tmpResults))
		{
			//
			// We had a failure, so wrap the results in this nodes' information.
			//
			if (HasErrors())
			{
				size_t count = ErrorCount();
				std::shared_ptr<tsXmlError> err;

				for (size_t i = 0; i < count; i++)
				{
					err = ErrorAt(i);
					if (err != NULL)
					{
						err->ToXML(tmpResults, useAttributesForErrors);
					}
				}
			}
			if (HasWarnings())
			{
				size_t count = WarningCount();
				std::shared_ptr<tsXmlError> err;

				for (size_t i = 0; i < count; i++)
				{
					err = WarningAt(i);
					if (err != NULL)
					{
						err->ToXML(tmpResults, useAttributesForErrors);
					}
				}
			}
			if (RequiresProtection())
			{
				if (!EncryptForChannel(tmpResults, Results))
					return false;
			}
			BuildStartNodeXML(tmp);
			Results.prepend(tmp);
			Results += tmpResults;
			AppendEndNodeXML(Results);
			return false;
		}
	}
	catch (...)
	{
		tsStringBase buff;

		buff.append("<Error><ValueAtt>An error occurred while trying to verify the request for the ")
			.append(m_NodeName).append(" node.</ValueAtt><NumberAtt>1</NumberAtt><MethodAtt>RunableParseNode::Validate</MethodAtt><ComponentAtt>EBSNetSrv32</ComponentAtt></Error>");
		Results += buff;
		Results += tmp;
		return false;
	}

	return true;
}

int tsXmlNode::__VerifyNodes(std::shared_ptr<tsXmlNode> node, tsStringBase *params)
{
	if (!node->Validate(*params, true)) // TODO:  Review this
		return 1;
	return 0;
}

bool tsXmlNode::ValidateChildren(tsStringBase &Results)
{
	auto it = std::find_if(m_Children.begin(), m_Children.end(), [&Results, this](std::shared_ptr<tsXmlNode>& node)->bool {return __VerifyNodes(node, &Results) != 0; });
	return it == m_Children.end();
}

bool tsXmlNode::InternalValidate(tsStringBase & /*Results*/)
{
	return true;
}

//void CtsXmlNode::HashValue(const tsByteString &/*hash*/)
//{
//}

void tsXmlNode::ForceHashChecks(bool setTo)
{
	m_forceHashChecks = setTo;
}

bool tsXmlNode::ForceHashChecks(void) const
{
	return m_forceHashChecks;
}


/****************************************************************************
/ tsXMLParserCallback
/ **************************************************************************/

tsXmlParserCallback::resultCodes tsXmlNode::ProcessInstruction(const tsStringBase & /*contents*/, tsStringBase &/*Results*/)
{
	return tsXmlParserCallback::rcSuccess;
}

/*
 * verify a hash on a node
 * Not actually a callback method.  Used by submit class
 * to check hashes.
 */
tsXmlParserCallback::resultCodes tsXmlNode::VerifyHash(const tsStringBase &NodeName,
	tsAttributeMap &attributes,
	const tsStringBase &InnerXML)
{
	UNREFERENCED_PARAMETER(NodeName);
	UNREFERENCED_PARAMETER(attributes);
	UNREFERENCED_PARAMETER(InnerXML);

	return tsXmlParserCallback::rcSuccess;
}

bool tsXmlNode::EncryptForChannel(tsStringBase &/*contents*/, tsStringBase &/*Results*/)
{
	return false;
}

bool tsXmlNode::DecryptForChannel(tsStringBase &/*Results*/)
{
	return false;
}

tsXmlParserCallback::resultCodes tsXmlNode::StartNode(const tsStringBase &NodeName,
	const tsAttributeMap &attributes,
	const tsStringBase &InnerXML,
	bool SingleNode,
	tsStringBase &Results)
{

	if (NodeName.empty())
	{
		AddError("AgentRequestor", "CARNodeSubmit::StartNode()", "Node Name was NULL", 0);
		return tsXmlParserCallback::rcAbort;
	}
	/*if ( tsStrCmp(NodeName, ("Error")) == 0 )
	{
		if (!m_RunnableParseNode) {
			tsXmlNode::AddError("AgentRequestor", "CARNodeSubmit::StartNode()", "Unexpected null node", 0);
		}
	}
	else*/ if (strcmp(NodeName.c_str(), ("Reauth")) == 0)
	{
		m_RootNode->m_needsReauth = true;
		return tsXmlParserCallback::rcSuccess;
	}

	if (!m_RunnableParseNode)
	{
		m_RootNode = std::dynamic_pointer_cast<tsXmlNode>(_me.lock());
		m_RootNode->NodeName(NodeName);
		m_RunnableParseNode = m_RootNode;
		m_RootNode->Attributes() = attributes;
	}
	else
	{
		std::shared_ptr<tsXmlNode> pNode;

		if (attributes.hasItem("TSID"))
		{
			pNode = m_RunnableParseNode->ChildByTSID(attributes.item("TSID"));
		}

		if (!pNode)
		{
			tsAttributeMap map = attributes;
			//
			// We have a new node, so therefore we need to create a new node if possible.
			//
			//if (NodeName == "Error")
			//{
			//	m_RunnableParseNode->StartSubnode(NodeName, map);
			//	pNode = m_RunnableParseNode;
			//}
			//else
			{
				pNode = m_RunnableParseNode->StartSubnode(NodeName, map);
				if (!pNode) {
					AddError("AgentRequestor", "CARNodeSubmit::StartNode", "Failed to StartSubnode()", IDS_E_XML_GENERAL_ERROR);
					return tsXmlParserCallback::rcAbort;
				}
			}
		}
		else
			pNode->Attributes() = attributes;

		m_RunnableParseNode = pNode;
	}

	//    if ( m_RunnableParseNode && NodeName != "Error" )
	{
		m_RunnableParseNode->StartResponse(tsStringBase(NodeName), tsStringBase(InnerXML), SingleNode);
	}

	if (m_forceHashChecks)
	{
		if (strcmp(NodeName.c_str(), ("EnterpriseBuilder")) == 0 ||
			strcmp(NodeName.c_str(), ("EnterpriseBuilderAdmin")) == 0 ||
			strcmp(NodeName.c_str(), ("CKMSystemConfig")) == 0 ||
			strcmp(NodeName.c_str(), ("Auth")) == 0)
		{
			m_RunnableParseNode->RequiresProtection(strcmp(NodeName.c_str(), ("Auth")) != 0);
		}
	}
	if (m_RunnableParseNode->RequiresProtection())
	{
		if (!m_RunnableParseNode->DecryptForChannel(Results))
			return tsXmlParserCallback::rcAbort;
		return tsXmlParserCallback::rcSkipInner;
	}

	if (!(m_RunnableParseNode->MakeDOM())) {
		m_RunnableParseNode->NodeText(InnerXML);
		return tsXmlParserCallback::rcSkipInner;

	}

	return tsXmlParserCallback::rcSuccess;
}


tsXmlParserCallback::resultCodes
tsXmlNode::EndNode(const tsStringBase &NodeName, tsStringBase &/*Results*/)
{
	std::shared_ptr<tsXmlNode> pNode;
	size_t lCount, i;

	if (NodeName == NULL)
	{
		// originally this error was NODE_NAME_NULL
		AddError("AgentRequestor", "CARNodeSubmit::EndNode()", "End NodeName NULL", IDS_E_XML_GENERAL_ERROR);
		return tsXmlParserCallback::rcAbort;
	}

	if (m_RunnableParseNode)
	{
		lCount = m_RunnableParseNode->ChildrenCount();
		for (i = 0; i < lCount; i++)
		{
			pNode = m_RunnableParseNode->ChildAt(i);
			if (!pNode) {
				AddError("AgentRequestor", "CARNodeSubmit::EndNode()", "ChildAt() found NULL child.", IDS_E_XML_GENERAL_ERROR);
				return tsXmlParserCallback::rcAbort;
			}

			if (pNode->HasErrors())
			{
				// recurse errors up
				m_RunnableParseNode->HasErrors(true);
				break;
			}
		}
	}

	if (m_RunnableParseNode)
	{
		m_RunnableParseNode->EndResponse(tsStringBase(NodeName));
		pNode = m_RunnableParseNode->Parent().lock();
		if (pNode)
			m_RunnableParseNode = pNode;
	}

	return tsXmlParserCallback::rcSuccess;
}

tsXmlParserCallback::resultCodes
tsXmlNode::Comment(const tsStringBase & /*Contents*/,
	tsStringBase &/*Results*/)
{
	return tsXmlParserCallback::rcSuccess;
}

tsXmlParserCallback::resultCodes
tsXmlNode::CData(const tsStringBase & /*Contents*/,
	tsStringBase &/*Results*/)
{
	return tsXmlParserCallback::rcSuccess;
}

tsXmlParserCallback::resultCodes
tsXmlNode::Text(const tsStringBase &Contents,
	tsStringBase &/*Results*/)
{
	if (Contents == NULL)
	{
		// originally IDS_TEXT_NULL
		AddError("AgentRequestor", "CARNodeSubmit::Text", "Tried to start text.  Text was NULL", IDS_E_XML_GENERAL_ERROR);
		return tsXmlParserCallback::rcAbort;
	}

	if (m_RunnableParseNode)
	{
		return m_RunnableParseNode->ResponseText(tsStringBase(Contents));
	}

	return tsXmlParserCallback::rcSuccess;
}

void tsXmlNode::AddParseError(const tsStringBase &ErrorStr, tsStringBase &/*Results*/)
{
	// signals that the parser had an error.
	AddError("AgentRequestor", "CARNodeSubmit Parser Error", tsStringBase(ErrorStr), IDS_E_XML_GENERAL_ERROR);
}

bool tsXmlNode::Parse(const tsStringBase &sXML, tsStringBase &Results, bool nodesToAttributes, bool processErrors)
{
	tsXmlParser Parser;

	m_needsReauth = false;
	bool retVal = Parser.Parse(sXML, this, Results);

	if (nodesToAttributes)
	{
		ConvertNodesToAttributes();
	}
	if (processErrors)
		ConvertErrorNodes();
	m_RootNode = NULL;
	m_RunnableParseNode = NULL;
	return retVal;
}

void tsXmlNode::__convertNodesToAttrs(std::shared_ptr<tsXmlNode> pNode, tsXmlNode::attributeNodeType typeOfConversion)
{
	if (typeOfConversion == attribute)
		return;

	size_t count = pNode->ChildrenCount();

	for (ptrdiff_t i = count - 1; i >= 0; i--)
	{
		std::shared_ptr<tsXmlNode> child = pNode->ChildAt(i);

		if (typeOfConversion == suffixedWithAtt)
		{
			const char *c;
			c = strrchr(child->NodeName().c_str(), ATTRIBUTE_RSEARCH);

			if (c != NULL && strcmp(c, ATTRIBUTE_SUFFIX) == 0)
			{
				tsStringBase name(child->NodeName());

				name.DeleteAt((uint32_t)(name.length() - strlen(ATTRIBUTE_SUFFIX)), (uint32_t)strlen(ATTRIBUTE_SUFFIX));
				pNode->Attributes().AddItem(name, child->NodeText());
				pNode->RemoveChild(i);
			}
		}
		else if (typeOfConversion == textNode)
		{
			if (child->Attributes().count() == 0 && child->NodeText().size() > 0)
			{
				pNode->Attributes().AddItem(child->NodeName(), child->NodeText());
				pNode->RemoveChild(i);
			}
		}
	}
	count = pNode->ChildrenCount();
	for (ptrdiff_t i = count - 1; i >= 0; i--)
	{
		std::shared_ptr<tsXmlNode> child = pNode->ChildAt(i);
		__convertNodesToAttrs(child, typeOfConversion);
	}
}

void tsXmlNode::ConvertNodesToAttributes()
{
	__convertNodesToAttrs(std::dynamic_pointer_cast<tsXmlNode>(_me.lock()), AttributeNodeType());
}

void tsXmlNode::__convertErrorNode(std::shared_ptr<tsXmlNode> pNode, std::shared_ptr<tsXmlNode> errorNode)
{
	pNode->AddFirstError(errorNode->Attributes().item("Component"), errorNode->Attributes().item("Method"), errorNode->Attributes().item("Value"), tsStrToInt(errorNode->Attributes().item("Number").c_str()));
}

void tsXmlNode::__convertErrorNodes(std::shared_ptr<tsXmlNode> pNode)
{
	size_t count = pNode->ChildrenCount();

	for (ptrdiff_t i = count - 1; i >= 0; i--)
	{
		std::shared_ptr<tsXmlNode> child = pNode->ChildAt(i);
		if (child->NodeName() == "ErrorCollection")
		{
			size_t subcount = child->ChildrenCount();
			for (size_t j = 0; j < subcount; j++)
			{
				__convertErrorNode(pNode, child->ChildAt(j));
			}
			pNode->RemoveChild(i);
		}
		else if (child->NodeName() == "Error")
		{
			__convertErrorNode(pNode, child);
			pNode->RemoveChild(i);
		}
	}
	count = pNode->ChildrenCount();
	for (ptrdiff_t i = count - 1; i >= 0; i--)
	{
		std::shared_ptr<tsXmlNode> child = pNode->ChildAt(i);
		__convertErrorNodes(child);
	}
}

void tsXmlNode::ConvertErrorNodes()
{
	__convertErrorNodes(Me.lock());
}

bool tsXmlNode::NeedsReauthentication() const
{
	return m_needsReauth;
}

void tsXmlNode::SetNeedsReauth(bool setTo)
{
	std::shared_ptr<tsXmlNode> node;

	node = Me.lock();
	while (!node->Parent().expired())
	{
		node = node->Parent().lock();
	}
	node->m_needsReauth = setTo;
}

std::shared_ptr<tsXmlNode> tsXmlNode::ChildByName(const tsStringBase &_name)
{
	const char *ptr = NULL;
	tsStringBase name(_name);

	for (size_t i = 0; i < ChildrenCount(); i++)
	{
		ptr = (*m_Children.at(i)).NodeName().c_str();

		if ((ptr) && (strcmp(name.c_str(), ptr) == 0)) {
			return m_Children.at(i);
		}
	}
	return NULL;
}

tsXmlNodeList tsXmlNode::ChildrenByName(const tsStringBase &_name)
{
	const char *ptr = NULL;
	tsStringBase name(_name);
	tsXmlNodeList list;

	for (size_t i = 0; i < ChildrenCount(); i++)
	{
		ptr = (*m_Children.at(i)).NodeName().c_str();

		if ((ptr) && (strcmp(name.c_str(), ptr) == 0)) {
			list.push_back(m_Children.at(i));
		}
	}
	return list;
}

tsXmlNodeList tsXmlNode::ChildrenByName(const tsStringBase &_name) const
{
	const char *ptr = NULL;
	tsStringBase name(_name);
	tsXmlNodeList list;

	for (size_t i = 0; i < ChildrenCount(); i++)
	{
		ptr = (*m_Children.at(i)).NodeName().c_str();

		if ((ptr) && (strcmp(name.c_str(), ptr) == 0)) {
			list.push_back(m_Children.at(i));
		}
	}
	return list;
}

std::shared_ptr<tsXmlNode> tsXmlNode::ChildByName(const tsStringBase &_name) const
{
	const char *ptr = NULL;
	tsStringBase name(_name);

	for (size_t i = 0; i < ChildrenCount(); i++)
	{
		ptr = (*m_Children.at(i)).NodeName().c_str();

		if ((ptr) && (strcmp(name.c_str(), ptr) == 0)) {
			return m_Children.at(i);
		}
	}
	return nullptr;
}

std::shared_ptr<tsXmlNode> tsXmlNode::ChildByNameWithAttributeValue(const tsStringBase &_name, const tsStringBase &attributeName, const tsStringBase &attributeValue)
{
	for (size_t i = 0; i < ChildrenCount(); i++)
	{
		std::shared_ptr<tsXmlNode> node = m_Children.at(i);

		if (strcmp(_name.c_str(), node->NodeName().c_str()) == 0)
		{
			if (node->Attributes().hasItem(attributeName) && tsStriCmp(node->Attributes().item(attributeName).c_str(), tsStringBase(attributeValue).c_str()) == 0)
			{
				return node;
			}
		}
	}
	return nullptr;
}

std::shared_ptr<tsXmlNode> tsXmlNode::ChildByNameWithAttributeValue(const tsStringBase &_name, const tsStringBase &attributeName, const tsStringBase &attributeValue) const
{
	for (size_t i = 0; i < ChildrenCount(); i++)
	{
		std::shared_ptr<tsXmlNode> node = m_Children.at(i);

		if (strcmp(_name.c_str(), node->NodeName().c_str()) == 0)
		{
			if (node->Attributes().hasItem(attributeName) && tsStriCmp(node->Attributes().item(attributeName).c_str(), tsStringBase(attributeValue).c_str()) == 0)
			{
				return node;
			}
		}
	}
	return nullptr;
}

std::shared_ptr<tsXmlNode> tsXmlNode::ChildByNameWithAttributeValueExact(const tsStringBase &_name, const tsStringBase &attributeName, const tsStringBase &attributeValue)
{
	for (size_t i = 0; i < ChildrenCount(); i++)
	{
		std::shared_ptr<tsXmlNode> node = m_Children.at(i);

		if (strcmp(_name.c_str(), node->NodeName().c_str()) == 0)
		{
			if (node->Attributes().hasItem(attributeName) && strcmp(node->Attributes().item(attributeName).c_str(), tsStringBase(attributeValue).c_str()) == 0)
			{
				return node;
			}
		}
	}
	return nullptr;
}

std::shared_ptr<tsXmlNode> tsXmlNode::ChildByNameWithAttributeValueExact(const tsStringBase &_name, const tsStringBase &attributeName, const tsStringBase &attributeValue) const
{
	for (size_t i = 0; i < ChildrenCount(); i++)
	{
		std::shared_ptr<tsXmlNode> node = m_Children.at(i);

		if (strcmp(_name.c_str(), node->NodeName().c_str()) == 0)
		{
			if (node->Attributes().hasItem(attributeName) && strcmp(node->Attributes().item(attributeName).c_str(), tsStringBase(attributeValue).c_str()) == 0)
			{
				return node;
			}
		}
	}
	return NULL;
}

std::shared_ptr<tsXmlNode> tsXmlNode::ChildByNameRecursive(const tsStringBase &name)
{
	std::shared_ptr<tsXmlNode> found;

	found = ChildByName(name);
	if (!!found)
		return found;

	for (size_t i = 0; i < ChildrenCount(); i++)
	{
		found = (*m_Children.at(i)).ChildByName(name);

		if (!!found)
			return found;
	}
	return nullptr;
}

std::shared_ptr<tsXmlNode> tsXmlNode::ChildByNameRecursive(const tsStringBase &name) const
{
	std::shared_ptr<tsXmlNode> found;

	found = ChildByName(name);
	if (!!found)
		return found;

	for (size_t i = 0; i < ChildrenCount(); i++)
	{
		found = (*m_Children.at(i)).ChildByName(name);

		if (!!found)
			return found;
	}
	return nullptr;
}

static std::shared_ptr<tsXmlNode> findRoot(std::shared_ptr<tsXmlNode> node)
{
	if (!node)
		return node;
	while (!node->Parent().expired())
	{
		node = node->Parent().lock();
	}
	return node;
}

static const char *eatWhitespace(const char *query)
{
	while (query && (query[0] == ' ' || query[0] == '\t' || query[0] == '\r' || query[0] == '\n'))
		query++;
	return query;
}

static void parseFieldName(const char *&posi, tsStringBase &name)
{
	while ((*posi >= 'A' && *posi <= 'Z') || (*posi >= 'a' && *posi <= 'z') || (*posi >= '0' && *posi <= '9' && name.size() > 0) || (*posi == ':' && name.size() > 0) || *posi == '_' || (*posi == '-' && name.size() > 0))
	{
		name += *posi;
		posi++;
	}
}

static void parseOperator(const char *&posi, tsStringBase &op)
{
	op.clear();

	if ((*posi == '<' && posi[1] == '=') || (posi[0] == '>' && posi[1] == '=') || (posi[0] == '!' && posi[1] == '='))
	{
		op = posi[0];
		op += posi[1];
		posi += 2;
		return;
	}
	if (*posi == '<' || *posi == '>' || *posi == '=')
	{
		op = posi[0];
		posi++;
		return;
	}
	// TODO: Other operators should be detected here

	return;
}

static void parseValue(const char *&posi, tsStringBase &value)
{
	value.clear();

	if (*posi == '\'')
	{
		posi++;

		value += '\'';
		while (*posi != '\'')
		{
			if (*posi == 0)
			{
				value.clear();
				return;
			}
			value += *posi;
			posi++;
		}
		value += '\'';
		posi++;
	}
	else if (*posi == '"')
	{
		posi++;

		value += '\'';
		while (*posi != '"')
		{
			if (*posi == 0)
			{
				value.clear();
				return;
			}
			value += *posi;
			posi++;
		}
		value += '\'';
		posi++;
	}
	else
	{
		while ((*posi >= '0' && *posi <= '9') || (*posi == '-') || (*posi == '+') || (*posi == '.'))
		{
			if (*posi == 0)
			{
				value.clear();
				return;
			}
			value += *posi;
			posi++;
		}
	}
	return;
}

static bool processAttributePredicate(std::shared_ptr<tsXmlNode> node, const tsStringBase &name, const tsStringBase &op, const tsStringBase &value)
{
	if (node == NULL || name.size() == 0 || !node->Attributes().hasItem(name.c_str()))
		return false;
	if (op.size() == 0)
	{
		return true;
	}
	if (value[0] == '\'' || value[0] == '"')
	{
		tsStringBase testValue = value;

		testValue.DeleteAt(0, 1);
		testValue.resize(testValue.size() - 1);

		if (strcmp(op.c_str(), ("=")) == 0)
		{
			return (strcmp(node->Attributes().item(name).c_str(), testValue.c_str()) == 0);
		}
		else if (strcmp(op.c_str(), ("!=")) == 0)
		{
			return (strcmp(node->Attributes().item(name).c_str(), testValue.c_str()) != 0);
		}
		else if (strcmp(op.c_str(), ("<=")) == 0)
		{
			return (strcmp(node->Attributes().item(name).c_str(), testValue.c_str()) <= 0);
		}
		else if (strcmp(op.c_str(), (">=")) == 0)
		{
			return (strcmp(node->Attributes().item(name).c_str(), testValue.c_str()) >= 0);
		}
		else if (strcmp(op.c_str(), ("<")) == 0)
		{
			return (strcmp(node->Attributes().item(name).c_str(), testValue.c_str()) < 0);
		}
		else if (strcmp(op.c_str(), (">")) == 0)
		{
			return (strcmp(node->Attributes().item(name).c_str(), testValue.c_str()) > 0);
		}
		else
		{
			return false;
		}
	}
	else if (strchr(value.c_str(), '.') != NULL || strchr(node->Attributes().item(name).c_str(), '.') != NULL)
	{
		double left = tsStrToDouble(node->Attributes().item(name).c_str());
		double right = tsStrToDouble(value.c_str());

		if (strcmp(op.c_str(), ("=")) == 0)
		{
			return left == right;
		}
		else if (strcmp(op.c_str(), ("!=")) == 0)
		{
			return left != right;
		}
		else if (strcmp(op.c_str(), ("<=")) == 0)
		{
			return left <= right;
		}
		else if (strcmp(op.c_str(), (">=")) == 0)
		{
			return left >= right;
		}
		else if (strcmp(op.c_str(), ("<")) == 0)
		{
			return left < right;
		}
		else if (strcmp(op.c_str(), (">")) == 0)
		{
			return left > right;
		}
		else
		{
			return false;
		}
	}
	else
	{
		int64_t left = tsStrToInt64(node->Attributes().item(name).c_str());
		int64_t right = tsStrToInt64(value.c_str());

		if (strcmp(op.c_str(), ("=")) == 0)
		{
			return left == right;
		}
		else if (strcmp(op.c_str(), ("!=")) == 0)
		{
			return left != right;
		}
		else if (strcmp(op.c_str(), ("<=")) == 0)
		{
			return left <= right;
		}
		else if (strcmp(op.c_str(), (">=")) == 0)
		{
			return left >= right;
		}
		else if (strcmp(op.c_str(), ("<")) == 0)
		{
			return left < right;
		}
		else if (strcmp(op.c_str(), (">")) == 0)
		{
			return left > right;
		}
		else
		{
			return false;
		}
	}
}

static bool processNodePredicate(std::shared_ptr<tsXmlNode> node, const tsStringBase &name, const tsStringBase &op, const tsStringBase &value)
{
	if (!node || name.size() == 0)
		return false;

	if (op.size() == 0)
	{
		return node->ChildByName(name.c_str()) != NULL;
	}

	size_t count = node->ChildrenCount();
	size_t i;

	for (i = 0; i < count; i++)
	{
		tsStringBase nodeText = node->Children().at(i)->NodeText();

		if (value[0] == '\'' || value[0] == '"')
		{
			tsStringBase testValue = value;

			testValue.DeleteAt(0, 1);
			testValue.resize(testValue.size() - 1);

			if (strcmp(op.c_str(), ("=")) == 0)
			{
				if (strcmp(nodeText.c_str(), testValue.c_str()) == 0)
				{
					return true;
				}
			}
			else if (strcmp(op.c_str(), ("!=")) == 0)
			{
				if (strcmp(nodeText.c_str(), testValue.c_str()) != 0)
				{
					return true;
				}
			}
			else if (strcmp(op.c_str(), ("<=")) == 0)
			{
				if (strcmp(nodeText.c_str(), testValue.c_str()) <= 0)
				{
					return true;
				}
			}
			else if (strcmp(op.c_str(), (">=")) == 0)
			{
				if (strcmp(nodeText.c_str(), testValue.c_str()) >= 0)
				{
					return true;
				}
			}
			else if (strcmp(op.c_str(), ("<")) == 0)
			{
				if (strcmp(nodeText.c_str(), testValue.c_str()) < 0)
				{
					return true;
				}
			}
			else if (strcmp(op.c_str(), (">")) == 0)
			{
				if (strcmp(nodeText.c_str(), testValue.c_str()) > 0)
				{
					return true;
				}
			}
			else
			{
				return false;
			}
		}
		else if (strchr(value.c_str(), '.') != NULL || strchr(nodeText.c_str(), '.') != NULL)
		{
			double left = tsStrToDouble(nodeText.c_str());
			double right = tsStrToDouble(value.c_str());

			if (strcmp(op.c_str(), ("=")) == 0)
			{
				if (left == right)
				{
					return true;
				}
			}
			else if (strcmp(op.c_str(), ("!=")) == 0)
			{
				if (left != right)
				{
					return true;
				}
			}
			else if (strcmp(op.c_str(), ("<=")) == 0)
			{
				if (left <= right)
				{
					return true;
				}
			}
			else if (strcmp(op.c_str(), (">=")) == 0)
			{
				if (left >= right)
				{
					return true;
				}
			}
			else if (strcmp(op.c_str(), ("<")) == 0)
			{
				if (left < right)
				{
					return true;
				}
			}
			else if (strcmp(op.c_str(), (">")) == 0)
			{
				if (left > right)
				{
					return true;
				}
			}
			else
			{
				return false;
			}
		}
		else
		{
			int64_t left = tsStrToInt64(nodeText.c_str());
			int64_t right = tsStrToInt64(value.c_str());

			if (strcmp(op.c_str(), ("=")) == 0)
			{
				if (left == right)
				{
					return true;
				}
			}
			else if (strcmp(op.c_str(), ("!=")) == 0)
			{
				if (left != right)
				{
					return true;
				}
			}
			else if (strcmp(op.c_str(), ("<=")) == 0)
			{
				if (left <= right)
				{
					return true;
				}
			}
			else if (strcmp(op.c_str(), (">=")) == 0)
			{
				if (left >= right)
				{
					return true;
				}
			}
			else if (strcmp(op.c_str(), ("<")) == 0)
			{
				if (left < right)
				{
					return true;
				}
			}
			else if (strcmp(op.c_str(), (">")) == 0)
			{
				if (left > right)
				{
					return true;
				}
			}
			else
			{
				return false;
			}
		}
	}
	return false;
}

static void processPredicate(tsXmlNodeList &nodesToTest, const char *&posi)
{
	// We have a predicate   Only doing rudimentary processing
	tsStringBase nodeName;
	tsStringBase op;
	tsStringBase value;
	bool isAttribute = false;
	size_t count;

	posi++;

	posi = eatWhitespace(posi);

	if (*posi == '@')
	{
		posi++;
		posi = eatWhitespace(posi);
		isAttribute = true;
	}

	nodeName.clear();
	parseFieldName(posi, nodeName);
	posi = eatWhitespace(posi);

	parseOperator(posi, op);
	posi = eatWhitespace(posi);

	if (op.size() != 0)
	{
		parseValue(posi, value);
		posi = eatWhitespace(posi);
	}

	if (*posi != ']')
	{
		return;
	}
	posi++;
	posi = eatWhitespace(posi);

	tsXmlNodeList list2;

	count = nodesToTest.size();
	for (size_t i = 0; i < count; i++)
	{
		if (isAttribute)
		{
			if (processAttributePredicate(nodesToTest.at(i), nodeName, op, value))
			{
				list2.push_back(nodesToTest.at(i));
			}
		}
		else
		{
			if (processNodePredicate(nodesToTest.at(i), nodeName, op, value))
			{
				list2.push_back(nodesToTest.at(i));
			}
		}
	}
	nodesToTest = list2;
}

static void processNode(std::shared_ptr<tsXmlNode> startNode, const char *posi, tsXmlNodeList &list)
{
	tsStringBase nodeName;
	size_t count;
	size_t i;
	tsXmlNodeList nodesToTest;

	posi = eatWhitespace(posi);

	parseFieldName(posi, nodeName);

	if (nodeName.size() == 0)
		return;

	count = startNode->ChildrenCount();

	for (i = 0; i < count; i++)
	{
		std::shared_ptr<tsXmlNode> node = startNode->Children().at(i);
		if (strcmp(node->NodeName().c_str(), nodeName.c_str()) == 0)
		{
			nodesToTest.push_back(node);
		}
	}
	posi = eatWhitespace(posi);
	if (*posi == 0 || *posi == '|')
	{
		count = nodesToTest.size();
		for (size_t j = 0; j < count; j++)
		{
			list.push_back(nodesToTest.at(j));
		}
		return;
	}
	while (*posi == '[')
	{
		// We have a predicate   Only doing rudimentary processing
		processPredicate(nodesToTest, posi);
	}
	posi = eatWhitespace(posi);
	if (*posi == 0 || *posi == '|')
	{
		count = nodesToTest.size();
		for (size_t j = 0; j < count; j++)
		{
			list.push_back(nodesToTest.at(j));
		}
		return;
	}
	if (*posi == '/')
	{
		posi++;
		count = nodesToTest.size();
		for (size_t j = 0; j < count; j++)
		{
			processNode(nodesToTest.at(j), posi, list);
		}
		return;
	}
	else
	{
		return;
	}
}

static void collectAllNodesOfName(std::shared_ptr<tsXmlNode> node, const tsStringBase &nodeName, tsXmlNodeList &nodesFound)
{
	if (node == NULL)
		return;

	if (strcmp(node->NodeName().c_str(), nodeName.c_str()) == 0)
	{
		nodesFound.push_back(node);
	}

	size_t count = node->ChildrenCount();
	size_t i;

	for (i = 0; i < count; i++)
	{
		collectAllNodesOfName(node->Children().at(i), nodeName, nodesFound);
	}
}

static const char *processStartNode(std::shared_ptr<tsXmlNode> startNode, const char *posi, tsXmlNodeList &list)
{
	tsStringBase name;
	tsXmlNodeList nodesToTest;

	if (posi[0] == '/' && posi[1] == '/')
	{
		startNode = findRoot(startNode);
		posi += 2;

		parseFieldName(posi, name);

		collectAllNodesOfName(startNode, name, nodesToTest);
	}
	else if (posi[0] == '/')
	{
		posi++;
		posi = eatWhitespace(posi);

		startNode = findRoot(startNode);

		if (posi[0] == 0)
		{
			nodesToTest.push_back(startNode);
		}
		else
		{
			parseFieldName(posi, name);

			if (strcmp(name.c_str(), startNode->NodeName().c_str()) == 0)
			{
				nodesToTest.push_back(startNode);
			}
		}
	}
	else if (posi[0] == '.' && posi[1] == '.')
	{
		posi += 2;
		startNode = startNode->Parent().lock();
		if (startNode != NULL)
		{
			nodesToTest.push_back(startNode);
		}
	}
	else if (posi[0] == '.')
	{
		posi += 1;
		nodesToTest.push_back(startNode);
	}

	//
	// We now have the starting point.  Start the search.  NOTE:  we do not support attributes outside of a predicate
	//

	posi = eatWhitespace(posi);

	if (posi[0] == 0)
	{
		size_t count = nodesToTest.size();
		size_t i;

		for (i = 0; i < count; i++)
		{
			list.push_back(nodesToTest.at(i));
		}
		return posi;
	}
	else if (posi[0] == '|')
	{
		size_t count = nodesToTest.size();
		size_t i;

		for (i = 0; i < count; i++)
		{
			list.push_back(nodesToTest.at(i));
		}
		return posi;
	}

	//
	// Now process subnodes...
	//

	if (posi[0] != '/')
	{
		return posi;
	}

	posi++;

	posi = eatWhitespace(posi);

	size_t i;
	size_t count = nodesToTest.size();

	for (i = 0; i < count; i++)
	{
		processNode(nodesToTest.at(i), posi, list);
	}

	while (*posi != 0 && *posi != '|')
	{
		posi++;
	}

	return posi;
}

tsXmlNodeList tsXmlNode::findNodes(const tsStringBase &xpathQuery)
{
	tsXmlNodeList list;
	tsXmlNodeList nodesToTest;
	const char *posi = xpathQuery.c_str();

	std::shared_ptr<tsXmlNode> startNode = Me.lock();

	if (xpathQuery == NULL)
		return list;

	posi = processStartNode(startNode, posi, list);

	//
	// We now have the starting point.  Start the search.  NOTE:  we do not support attributes outside of a predicate
	//

	posi = eatWhitespace(posi);

	if (posi[0] == 0)
	{
		return list;
	}
	while (posi[0] == '|')
	{
		posi++;
		posi = eatWhitespace(posi);
		posi = processStartNode(startNode, posi, list);
	}
	return list;
}

tsXmlNodeList tsXmlNode::findNodes(const tsStringBase &xpathQuery) const
{
	tsXmlNodeList list;
	tsXmlNodeList nodesToTest;
	const char *posi = xpathQuery.c_str();

	std::shared_ptr<tsXmlNode> startNode = Me.lock();

	if (xpathQuery == NULL)
		return list;

	posi = processStartNode(startNode, posi, list);

	//
	// We now have the starting point.  Start the search.  NOTE:  we do not support attributes outside of a predicate
	//

	posi = eatWhitespace(posi);

	if (posi[0] == 0)
	{
		return list;
	}
	while (posi[0] == '|')
	{
		posi++;
		posi = eatWhitespace(posi);
		posi = processStartNode(startNode, posi, list);
	}
	return list;
}

bool tsXmlNode::UseFormattedOutput() const
{
	return m_useFormattedOutput;
}

void tsXmlNode::UseFormattedOutput(bool setTo)
{
	m_useFormattedOutput = setTo;
}

tsXmlNode::attributeNodeType tsXmlNode::AttributeNodeType() const
{
	return m_attrNodeType;
}

void tsXmlNode::AttributeNodeType(tsXmlNode::attributeNodeType setTo)
{
	m_attrNodeType = setTo;
}

tsStringBase tsXmlNode::GetNamedChildNodeText(const tsStringBase &name) const
{
	std::shared_ptr<tsXmlNode> child = ChildByName(name);

	if (child == nullptr)
		return "";
	return child->NodeText();
}

void tsXmlNode::SetNamedChildNodeText(const tsStringBase& name, const tsStringBase& value)
{
	std::shared_ptr<tsXmlNode> child = ChildByName(name);

	if (child == nullptr)
	{
		StartTextSubnode(name, value);
	}
	else
		child->NodeText(value);
}

void tsXmlNode::RemoveAllNamespaces()
{
	Attributes().remove_if([](const char* name, const char* item) -> bool {
		if (tsStrCmp(name, "xmlns") == 0 || tsStrnCmp(name, "xmlns:", 6) == 0)
			return true;
		return false;
	});
	Attributes().foreach([this](const char* name, const char* item) {
		if (tsStrChr(name, ':') != nullptr)
		{
            const char* p = tsStrChr(name, ':');
            tsStringBase newName = p + 1;
			if (!this->Attributes().hasItem(newName))
			{
                Attributes().RenameItem(name, newName);
			}
		}
	});
	if (strchr(NodeName().c_str(), ':') != nullptr)
	{
		tsStringBaseList parts = NodeName().split(":");
		tsStringBase newName = parts.back();

		NodeName(newName);
	}
	for (std::shared_ptr<tsXmlNode>& node : m_Children)
	{
		node->RemoveAllNamespaces();
	}
}


