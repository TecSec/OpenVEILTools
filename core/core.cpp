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

void* cryptoNew(size_t size)
{
    return tsAllocate(size);
}
void cryptoDelete(void* ptr)
{
    tsFree(ptr);
}
//void * operator new(std::size_t n) throw(std::bad_alloc)
//{
//    return cryptoNew(n);
//}
//void operator delete(void * p) throw()
//{
//    cryptoDelete(p);
//}
//void* operator new(size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber)
//{
//    return _internal_TS_Allocate_dbg(_Size, _BlockUse, _FileName, _LineNumber);
//}
//
//void* operator new[](size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber)
//{
//    return _internal_TS_Allocate_dbg(_Size, _BlockUse, _FileName, _LineNumber);
//}
//
//void* operator new(std::size_t count, const std::nothrow_t& tag)
//{
//    return _internal_TS_Allocate(count);
//}
//void* operator new[](std::size_t count, const std::nothrow_t& tag)
//{
//    return _internal_TS_Allocate(count);
//}
//
//void operator delete(void* _Block, int _BlockUse, char const* _FileName, int _LineNumber) throw()
//{
//    _internal_TSFree_dbg(_Block, _BlockUse);
//}
//void operator delete[](void* _Block, int _BlockUse, char const* _FileName, int _LineNumber) throw()
//{
//    _internal_TSFree_dbg(_Block, _BlockUse);
//}
//void operator delete(void* ptr, const std::nothrow_t& tag)
//{
//    _internal_TSFree(ptr);
//}

void TSPatchValueForXML(const tsStringBase &value, tsStringBase &out)
{
	size_t count;
	size_t i;
	char val;

	out.resize(0);
	count = value.size();
	for (i = 0; i < count; i++)
	{
		val = value.data()[i];
		if (val == '<')
			out += "&lt;";
		else if (val == '>')
			out += "&gt;";
		else if (val == '&')
			out += "&amp;";
		else if (val == '"')
			out += "&quot;";
		else if (val == '\'')
			out += "&apos;";
		else
			out += val;
	}
}
void TSGuidToString(const GUID &id, tsStringBase &out)  // taken from RTE guid_functions.cpp
{
    out.resize(50);
    tsGuidToString(&id, out.rawData(), (uint32_t)out.size());
    out.resize(tsStrLen(out.c_str()));
}

tsStringBase TSGuidToString(const GUID &id)
{
	tsStringBase tmp;

	TSGuidToString(id, tmp);
	return tmp;
}
void xp_SplitPath(const tsStringBase &inPath, tsStringBase &path, tsStringBase &name, tsStringBase &ext)
{
    uint32_t dirLen = 0, fileLen = 0, extLen = 0;
    const char* _dir = nullptr, *_file = nullptr, *_ext = nullptr;

    tsSplitPath(inPath.c_str(), &_dir, &dirLen, &_file, &fileLen, &_ext, &extLen);

    path.assign(_dir, dirLen);
    name.assign(_file, fileLen);
    ext.assign(_ext, extLen);
}
bool xp_ReadAllText(const tsStringBase& filename, tsStringBase& contents)
{
    TSFILE file = nullptr;
	uint32_t count;

    if (tsFOpen(&file, filename.c_str(), "rb", tsShare_DenyWR) != 0)
		return false;

    int64_t size = tsGetFileSize64FromHandle(file);
	if (size > 0x7fffffff)
	{
        tsCloseFile(file);
		return false;
	}
	contents.resize((size_t)size);
    count = (uint32_t)tsReadFile(contents.rawData(), 1, (uint32_t)size, file);
	if (count != size)
	{
		contents.clear();
        tsCloseFile(file);
		return false;
	}
	contents.resize(count);
    tsCloseFile(file);
	return true;
}
bool xp_ReadAllBytes(const tsStringBase& filename, tsData& contents)
{
    TSFILE file = nullptr;
	uint32_t count;

    if (tsFOpen(&file, filename.c_str(), "rb", tsShare_DenyWR) != 0)
		return false;

    int64_t size = tsGetFileSize64FromHandle(file);
	if (size > 0x7fffffff)
	{
        tsCloseFile(file);
		return false;
	}
	contents.resize((uint32_t)size);
    count = (uint32_t)tsReadFile(contents.rawData(), 1, (uint32_t)size, file);
	if (count != size)
	{
		contents.clear();
        tsCloseFile(file);
		return false;
	}
	contents.resize(count);
    tsCloseFile(file);
	return true;
}
bool xp_WriteText(const tsStringBase& filename, const tsStringBase& contents)
{
    return tsWriteByteArray(filename.c_str(), (const uint8_t*)contents.c_str(), (uint32_t)contents.size());
}
bool xp_WriteBytes(const tsStringBase& filename, const tsData& contents)
{
    return tsWriteByteArray(filename.c_str(), contents.c_str(), (uint32_t)contents.size());
}
