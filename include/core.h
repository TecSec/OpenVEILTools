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


#include "core/compilerconfig.h"
#ifdef __APPLE__
#   include "CyberVEIL/CyberVEIL.h"
#else
#   include "CyberVEIL.h"
#endif

#include <initializer_list>
#include <vector>
#include <memory>
#include <functional>
#include <algorithm>
#include <iostream>

#include "SimpleOpt.h"

extern void* cryptoNew(size_t size);
extern void cryptoDelete(void* ptr);

#include "tsData.h"
#include "tsStringBase.h"

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Convert XML reserved characters into the xml escape sequences.</summary>
///
/// <param name="value">The string to patch.</param>
/// <param name="out">  [in,out] The destination.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
void TSPatchValueForXML(const tsStringBase &value, tsStringBase &out);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Convert the error information into an XML string and append it to Results</summary>
///
/// <param name="Results">	  [in,out] The results.</param>
/// <param name="component">  The component where the error occurred.</param>
/// <param name="NodeName">   Name of the node.</param>
/// <param name="ErrorNumber">The error number.</param>
/// <param name="vArg">		  The arguments to the error message.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
void TSAddXMLError(tsStringBase &Results, const tsStringBase &component, const tsStringBase &NodeName, int32_t ErrorNumber, va_list vArg);
void TSAddToXML(tsStringBase &xml, const tsStringBase& AttrName, const tsStringBase& value);
extern void TSGuidToString(const GUID &id, tsStringBase &out);
extern tsStringBase TSGuidToString(const GUID &id);
void xp_SplitPath(const tsStringBase &inPath, tsStringBase &path, tsStringBase &name, tsStringBase &ext);
bool xp_ReadAllText(const tsStringBase& filename, tsStringBase& contents);
bool xp_ReadAllBytes(const tsStringBase& filename, tsData& contents);
bool xp_WriteText(const tsStringBase& filename, const tsStringBase& contents);
bool xp_WriteBytes(const tsStringBase& filename, const tsData& contents);


typedef class IObject
{
public:
	virtual ~IObject() 
	{
	}
	virtual void OnConstructionFinished()
	{
	}

	template <class T, typename... args>
	static std::shared_ptr<T> Create(args... Args)
	{
		std::shared_ptr<T> obj = std::shared_ptr<T>(new T(Args...));

		if (!!obj)
		{
			obj->_me = obj;
			obj->OnConstructionFinished();
		}
		return obj;
	}

	std::weak_ptr<IObject> _me;
} IObject;

class ToBool //: public boost::static_visitor<bool>
{
public:
	//bool operator()(bool i) const
	//{
	//    return i;
	//}
	//
	bool operator()(int i) const
	{
		return i != 0;
	}

	bool operator()(const tsStringBase & str) const
	{
		return atoi(str.c_str()) != 0;
	}

#ifdef INCLUDE_DATASET
	bool operator()(std::shared_ptr<ObservableDataset> data) const
	{
		return data->rowCount() != 0;
	}
#endif // INCLUDE_DATASET
	bool operator()(GUID data) const
	{
		UNREFERENCED_PARAMETER(data);
		return false;
	}
	//bool operator()(const tscrypto::tsCryptoDate& dt) const
	//{
	//	return dt.GetStatus() == tscrypto::tsCryptoDate::valid;
	//}
#ifdef INCLUDE_DATASET
	bool operator()(DatasetRow* data) const
	{
		return data != nullptr;
	}
	bool operator()(DatasetColumn* data) const
	{
		return data != nullptr;
	}
#endif // #ifndef INCLUDE_DATASET

	//bool operator()(std::shared_ptr<EnterpriseBuilder::IrootNode> obj)
	//{
	//	return obj.get() != nullptr;
	//}
};

#include "tsAttributeMap.h"
#include "tsXmlError.h"
#include "tsXmlParser.h"
#include "tsXmlNode.h"
