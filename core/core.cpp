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
	return malloc(size);
}
void cryptoDelete(void* ptr)
{
	free(ptr);
}
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
void TSPatchValueFromXML(const tsStringBase &value, tsStringBase &out)
{
	size_t count;
	size_t i;
	char val;

	out.resize(0);
	count = value.size();
	for (i = 0; i < count; i++)
	{
		val = value.c_at(i);
		if (val == '&')
		{
			if (count < i + 4)
				out += val;
			else
			{
				if (value.c_at(i + 1) == 'l' && value.c_at(i + 2) == 't' &&
					value.c_at(i + 3) == ';')
				{
					out += '<';
					i += 3;
				}
				else if (value.c_at(i + 1) == 'g' && value.c_at(i + 2) == 't' &&
					value.c_at(i + 3) == ';')
				{
					out += '>';
					i += 3;
				}
				else if (count < i + 5)
					out += val;
				else {
					if (value.c_at(i + 1) == 'a' && value.c_at(i + 2) == 'm' &&
						value.c_at(i + 3) == 'p' && value.c_at(i + 4) == ';')
					{
						out += '&';
						i += 4;
					}
					else if (count < i + 6)
						out += val;
					else
					{
						if (value.c_at(i + 1) == 'q' && value.c_at(i + 2) == 'u' &&
							value.c_at(i + 3) == 'o' && value.c_at(i + 4) == 't' &&
							value.c_at(i + 5) == ';')
						{
							out += '"';
							i += 5;
						}
						else if (value.c_at(i + 1) == 'a' && value.c_at(i + 2) == 'p' &&
							value.c_at(i + 3) == 'o' && value.c_at(i + 4) == 's' &&
							value.c_at(i + 5) == ';')
						{
							out += '\'';
							i += 5;
						}
						else
							out += val;
					}
				}
			}
		}
		else
			out += val;
	}
}
void TSGuidToString(const GUID &id, tsStringBase &out)  // taken from RTE guid_functions.cpp
{
	unsigned char * pStr;

	pStr = (unsigned char *)&id;
	out.Format("{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		pStr[3], pStr[2], pStr[1], pStr[0], pStr[5], pStr[4], pStr[7], pStr[6], pStr[8], pStr[9],
		pStr[10], pStr[11], pStr[12], pStr[13], pStr[14], pStr[15]);
	return;
}

tsStringBase TSGuidToString(const GUID &id)
{
	tsStringBase tmp;

	TSGuidToString(id, tmp);
	return tmp;
}
void xp_SplitPath(const tsStringBase &inPath, tsStringBase &path, tsStringBase &name, tsStringBase &ext)
{
	tsStringBase iPath(inPath);

	path.clear();
	name.clear();
	ext.clear();

	if (strrchr(iPath.c_str(), XP_PATH_SEP_CHAR) != 0)
	{
		name = strrchr(iPath.c_str(), XP_PATH_SEP_CHAR) + 1;
		iPath.resize(iPath.size() - name.size());
	}
	else
	{
		name = iPath;
		iPath.clear();
	}

	if (strrchr(name.c_str(), '.') != NULL)
	{
		ext = strrchr(name.c_str(), '.');
		name.resize(name.size() - ext.size());
	}

	// Get the file path
	path = iPath;
}
static int64_t getFileSize(FILE* file)
{
#if defined(HAVE_FTELLO64)
	int64_t posi = ftello64(file);
	fseeko64(file, 0, SEEK_END);
	int64_t len = ftello64(file);
	fseeko64(file, posi, SEEK_SET);
	return len;
#elif defined(HAVE__FTELLI64)
	int64_t posi = _ftelli64(file);
	_fseeki64(file, 0, SEEK_END);
	int64_t len = _ftelli64(file);
	_fseeki64(file, posi, SEEK_SET);
	return len;
#else
	long posi = ftell(file);
	fseek(file, 0, SEEK_END);
	long len = ftell(file);
	fseek(file, posi, SEEK_SET);
	return len;
#endif
}
bool xp_ReadAllText(const tsStringBase& filename, tsStringBase& contents)
{
	FILE* file = nullptr;
	uint32_t count;

	if (fopen_s(&file, filename.c_str(), "rb") != 0)
		return false;

	int64_t size = getFileSize(file);
	if (size > 0x7fffffff)
	{
		fclose(file);
		return false;
	}
	contents.resize((size_t)size);
	count = (uint32_t)fread(contents.rawData(), 1, (uint32_t)size, file);
	if (count != size)
	{
		contents.clear();
		fclose(file);
		return false;
	}
	contents.resize(count);
	fclose(file);
	return true;
}
bool xp_ReadAllBytes(const tsStringBase& filename, tsData& contents)
{
	FILE* file = nullptr;
	uint32_t count;

	if (fopen_s(&file, filename.c_str(), "rb") != 0)
		return false;

	int64_t size = getFileSize(file);
	if (size > 0x7fffffff)
	{
		fclose(file);
		return false;
	}
	contents.resize((uint32_t)size);
	count = (uint32_t)fread(contents.rawData(), 1, (uint32_t)size, file);
	if (count != size)
	{
		contents.clear();
		fclose(file);
		return false;
	}
	contents.resize(count);
	fclose(file);
	return true;
}
bool xp_WriteText(const tsStringBase& filename, const tsStringBase& contents)
{
	FILE* file = nullptr;

	if (fopen_s(&file, filename.c_str(), "wb") != 0)
		return false;

	if (fwrite(contents.c_str(), 1, (uint32_t)contents.size(), file) != (uint32_t)contents.size())
	{
		fclose(file);
		return false;
	}
	fclose(file);
	return true;
}
bool xp_WriteBytes(const tsStringBase& filename, const tsData& contents)
{
	FILE* file = nullptr;

	if (fopen_s(&file, filename.c_str(), "wb") != 0)
		return false;

	if (fwrite(contents.c_str(), 1, (uint32_t)contents.size(), file) != (uint32_t)contents.size())
	{
		fclose(file);
		return false;
}
	fclose(file);
	return true;
}
bool xp_FileExists(const tsStringBase &path)
{
#ifdef _WIN32
	return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
#else
	struct stat st;

	if (stat(path.c_str(), &st) != 0)
		return FALSE;
	return true;
#endif
}
bool xp_CreateDirectory(const tsStringBase &path, bool UserOnly)
{
#ifdef _WIN32
	MY_UNREFERENCED_PARAMETER(UserOnly);
	return CreateDirectoryA(path.c_str(), NULL) != FALSE;
#else
	return (mkdir(path.c_str(), (UserOnly ? 0700 : 0764)) == 0) ? true : false;
#endif
}
