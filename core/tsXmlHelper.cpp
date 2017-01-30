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
#include <stdio.h>
#include <stdarg.h>

//static tsStringBase localGetErrorString(int /*errorNumber*/);
//static GetErrorStringFn errorStringFn = &localGetErrorString;

static tsStringBase localGetErrorString(int /*errorNumber*/)
{
	return "unknown error";
}

//tsStringBase GetErrorString(int errorNumber)
//{
//	return errorStringFn(errorNumber);
//}
//
////HIDDEN
//void SetErrorStringFunction(GetErrorStringFn fn)
//{
//	if (fn == NULL)
//		errorStringFn = &localGetErrorString;
//	else
//	{
//		errorStringFn = fn;
//	}
//}

//HIDDEN
void TSAddToXML(tsStringBase &xml, const tsStringBase& AttrName, const tsStringBase& value)
{
	tsStringBase tmp;

	if (value == NULL)
		return;

	if (AttrName != NULL && AttrName[0] != 0)
	{
		xml += " ";
		xml += AttrName;
		xml += "=";
	}
	xml += "\"";
	TSPatchValueForXML(value, tmp);
	xml += tmp;
	xml += "\"";
}

//HIDDEN
void TSAddGuidToXML(tsStringBase &xml, const tsStringBase& AttrName, const GUID &id)
{
	tsStringBase tmp;
	tsStringBase value;

	if (AttrName != NULL && AttrName[0] != 0)
	{
		xml += " ";
		xml += AttrName;
		xml += "=";
	}
	xml += "\"";
	TSGuidToString(id, value);
	TSPatchValueForXML(value, tmp);
	xml += tmp;
	xml += "\"";
}

//HIDDEN
void TSAddXMLError(tsStringBase &Results, const tsStringBase &component, const tsStringBase &NodeName, int32_t ErrorNumber, va_list vArg)
{
	tsStringBase buffer;
	tsStringBase tmp;

	//buffer.FormatArg(errorStringFn(ErrorNumber).c_str(), vArg);
	buffer.FormatArg("Error", vArg);

	Results += "<Error><NumberAtt>";
	Results.append(ErrorNumber);
	Results += "</NumberAtt><ValueAtt>";
	TSPatchValueForXML(buffer, tmp);
	Results += tmp;
	Results += "</ValueAtt><MethodAtt>";
	Results += NodeName;
	Results += "</MethodAtt><ComponentAtt>";
	Results += component;
	Results += "</ComponentAtt></Error>";
}
