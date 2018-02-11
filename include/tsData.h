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

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \file   tsData.h
///
/// <summary>This file defines a common byte array container.</summary>
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __TSDATA_H__
#define __TSDATA_H__

#pragma once

class tsStringBase;

	/// <summary>a common byte array container implemented with protection mechanisms for FIPS and CC.</summary>
class tsData
{
public:
	typedef uint8_t value_type;
	typedef uint32_t size_type;
	typedef ptrdiff_t difference_type;
	typedef uint8_t* pointer;
	typedef uint8_t& reference;
	typedef const uint8_t* const_pointer;
	typedef const uint8_t& const_reference;
	typedef tsData self_type;
	typedef tsData* container_type;
	typedef const tsData* const_container_type;

	static const size_type npos;

	/// <summary>Specifies the type of string that is to be converted</summary>
	typedef enum DataStringType {
		ASCII,  /*!< Ascii string.  */
		OID,	/*!< OID in string form.  */
		HEX,	/*!< Data in HEX.  */
		BASE64, /*!< Data in Base 64.  */
		BASE64URL, /*!< Data in Base 64 (URL safe form  RFC-4648).  */
	} DataStringType;

	typedef enum {
		encode_Ascii,		///< Encode(d) as Ascii
		encode_Utf8,		///< Encode(d) as UTF-8
		encode_Utf16BE,		///< Encode(d) as UTF-16 big endian
		encode_Utf16LE,		///< Encode(d) as UTF-16 little endian (windows unicode)
		encode_Utf32BE,		///< Encode(d) as UTF-32 big endian
		encode_Utf32LE,		///< Encode(d) as UTF-32 little endian
		encode_Utf7,		///< Encode(d) as UTF-7
		encode_Utf1,		///< Encode(d) as UTF-1
	} UnicodeEncodingType;  ///< Type of the unicode encoding

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Default constructor.</summary>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsData();
	tsData(size_type count, value_type value);
	tsData(const tsData &obj, size_type pos);
	tsData(const tsData &obj, size_type pos, size_type count);
	tsData(const_pointer data, size_type Len);
	tsData(const_pointer data);
	template <class InputIt>
	tsData(InputIt first, InputIt last) :
		_data(tsCreateBuffer())
	{
		assign(first, last);
	}
	tsData(const tsData &obj);
	tsData(tsData &&obj);
	tsData(std::initializer_list<value_type> init);

	tsData(const char* value, DataStringType type);
	explicit tsData(const char* value); // ASCII only
	explicit tsData(std::initializer_list<char> init);
	tsData(value_type ch);
	explicit tsData(char ch);

	~tsData();

	tsData &operator=(const tsData &obj);
	tsData &operator=(tsData &&obj);
	tsData &operator=(const_pointer data); /* zero terminated */
	tsData &operator=(value_type obj);
	tsData &operator=(std::initializer_list<value_type> iList);
	tsData &operator=(const char *data); // zero terminated - tecsec addition

	tsData& assign(size_type count, value_type ch);
	tsData& assign(const tsData &obj);
	tsData& assign(const tsData &obj, size_type pos, size_type count = npos);
	tsData& assign(tsData &&obj);
	tsData& assign(const_pointer newData, size_type count);
	tsData& assign(const_pointer newData);
	template <class InputIt>
	tsData& assign(InputIt first, InputIt last)
	{
		clear();
		for (auto it = first; it != last; ++it)
		{
			append(*it);
		}
		return *this;
	}
	tsData &assign(std::initializer_list<value_type> iList);

	reference at(size_type index);
	const_reference at(size_type index) const;
	const_pointer data() const;
	pointer data();
	const_pointer c_str() const;
	reference front();
	const_reference front() const;
	reference back();
	const_reference back() const;
	reference operator[](size_type Index);
	const_reference operator[](size_type Index) const;

	bool empty() const;
	size_type size() const;
	size_type length() const;
	size_type max_size() const;
	void reserve(size_type newSize = 0);
	size_type capacity() const;
	void clear();

	tsData& insert(size_type index, size_type count, value_type ch);
	tsData& insert(size_type index, value_type ch);
	tsData& insert(size_type index, const_pointer s);
	tsData& insert(size_type index, const_pointer s, size_type count);
	tsData& insert(size_type index, const tsData& str);
	tsData& insert(size_type index, const tsData& str, size_type index_str, size_type count = npos);

	tsData& erase(size_type pos = 0, size_type count = npos);

	void push_back(value_type ch);
	void pop_back();

	tsData &append(size_type len, value_type ch);
	tsData &append(const tsData &obj);
	tsData &append(const tsData &obj, size_type pos, size_type count = npos);
	tsData &append(const_pointer data, size_type count);
	tsData &append(const_pointer data);
	template <class InputIt>
	tsData &append(InputIt first, InputIt last)
	{
		size_type oldsize = size();
		resize(size() + (last - first));
		uint8_t* ptr = rawData();
		for (auto it = first; it != last; ++it)
		{
			ptr[oldsize++] = *it;
		}
		return *this;
	}
	tsData &append(std::initializer_list<value_type> list);

	tsData &operator += (const tsData &obj);
	tsData &operator += (value_type data);
	tsData &operator += (const_pointer data);
	tsData &operator += (std::initializer_list<value_type> init);

	int compare(const tsData& str) const;
	int compare(size_type pos1, size_type count1, const tsData& str) const;
	int compare(size_type pos1, size_type count1, const tsData& str, size_type pos2, size_type count2) const;
	int compare(const_pointer s) const;
	int compare(size_type pos1, size_type count1, const_pointer s) const;
	int compare(size_type pos1, size_type count1, const_pointer s, size_type count2) const;

	tsData& replace(size_type pos, size_type count, const tsData& str);
	tsData& replace(size_type pos, size_type count, const tsData& str, size_type pos2, size_type count2 = npos);
	tsData& replace(size_type pos, size_type count, const_pointer s, size_type count2);
	tsData& replace(size_type pos, size_type count, const_pointer s);
	tsData& replace(size_type pos, size_type count, size_type count2, value_type ch);

	tsData substr(size_type start = 0, size_type count = npos) const;
	size_type copy(pointer dest, size_type count, size_type pos = 0) const;
	void resize(size_type newSize);
	void resize(size_type newSize, value_type value);
	void swap(tsData &obj);

	size_type find(const tsData& str, size_type pos = 0) const;
	size_type find(const_pointer s, size_type pos, size_type count) const;
	size_type find(const_pointer s, size_type pos = 0) const;
	size_type find(value_type ch, size_type pos = 0) const;

	size_type rfind(const tsData& str, size_type pos = npos) const;
	size_type rfind(const_pointer s, size_type pos, size_type count) const;
	size_type rfind(const_pointer s, size_type pos = npos) const;
	size_type rfind(value_type ch, size_type pos = npos) const;

	size_type find_first_of(const tsData& str, size_type pos = 0) const;
	size_type find_first_of(const_pointer s, size_type pos, size_type count) const;
	size_type find_first_of(const_pointer s, size_type pos = 0) const;
	size_type find_first_of(value_type ch, size_type pos = 0) const;

	size_type find_first_not_of(const tsData& str, size_type pos = 0) const;
	size_type find_first_not_of(const_pointer s, size_type pos, size_type count) const;
	size_type find_first_not_of(const_pointer s, size_type pos = 0) const;
	size_type find_first_not_of(value_type ch, size_type pos = 0) const;

	size_type find_last_of(const tsData& str, size_type pos = npos) const;
	size_type find_last_of(const_pointer s, size_type pos, size_type count) const;
	size_type find_last_of(const_pointer s, size_type pos = npos) const;
	size_type find_last_of(value_type ch, size_type pos = npos) const;

	size_type find_last_not_of(const tsData& str, size_type pos = npos) const;
	size_type find_last_not_of(const_pointer s, size_type pos, size_type count) const;
	size_type find_last_not_of(const_pointer s, size_type pos = npos) const;
	size_type find_last_not_of(value_type ch, size_type pos = npos) const;




	// TecSec Extensions
	void FromHexString(const char* inValue);
	void FromOIDString(const char* inValue);
	void FromBase64(const char* inValue, bool base64Url = false, bool padWithEquals = true);
	tsData substring(size_type start, size_type length) const;
	tsData& assign(const char *newData, size_type count);
	tsData& assign(const char *newData);
	tsData &assign(std::initializer_list<char> iList);
	tsData &assign(value_type data);
	tsData &assign(char data);
	tsData &assign(int16_t val);
	tsData &assign(int32_t val);
	tsData &assign(int64_t val);
	tsData &assign(uint16_t val);
	tsData &assign(uint32_t val);
	tsData &assign(uint64_t val);

	value_type c_at(size_type index) const;
	pointer rawData();
	tsData& insert(size_type index, size_type count, char ch);
	tsData& insert(size_type index, char ch);
	tsData& insert(size_type index, const char* s);
	tsData& insert(size_type index, const char* s, size_type count);
	tsData &operator=(std::initializer_list<char> iList);
	void push_back(char ch);

	tsData &append(size_type len, char ch);
	tsData &append(const char* data, size_type count);
	tsData &append(const char* data);
	tsData &append(std::initializer_list<char> list);
	tsData &append(value_type data);
	tsData &append(char data);
	tsData &append(int16_t val);
	tsData &append(int32_t val);
	tsData &append(int64_t val);
	tsData &append(uint16_t val);
	tsData &append(uint32_t val);
	tsData &append(uint64_t val);

	tsData &operator += (char data);
	tsData &operator += (const char* data);
	tsData &operator += (std::initializer_list<char> init);
	tsData &operator += (int16_t val);
	tsData &operator += (int32_t val);
	tsData &operator += (int64_t val);
	tsData &operator += (uint16_t val);
	tsData &operator += (uint32_t val);
	tsData &operator += (uint64_t val);

	int compare(const char* s) const;
	int compare(size_type pos1, size_type count1, const char* s) const;
	int compare(size_type pos1, size_type count1, const char* s, size_type count2) const;

	tsData& replace(size_type pos, size_type count, const char* s, size_type count2);
	tsData& replace(size_type pos, size_type count, const char* s);
	tsData& replace(size_type pos, size_type count, size_type count2, char ch);
	void reverse();
	tsData &XOR(const tsData &value);
	tsData &AND(const tsData &value);
	tsData &OR(const tsData &value);
	tsData &NOT();
	tsData right(size_type length) const;
	tsData left(size_type length) const;
	tsData &padLeft(size_type length, value_type value = 0);
	tsData &padRight(size_type length, value_type value = 0);
	tsData &truncOrPadLeft(size_type length, value_type value = 0);
	tsStringBase ToHexString() const;
	tsStringBase ToHexStringWithSpaces() const;
	tsStringBase ToHexDump() const;
	tsStringBase ToBase64(bool base64Url = false, bool padWithEquals = true) const;
	tsStringBase ToUtf8String() const;
	tsStringBase ToOIDString() const;
	uint64_t ToUint64() const;
	void AsciiFromString(const tsStringBase& str);
	void UTF8FromString(const tsStringBase& str);
	//tsData PartialDecode(DataStringType type, size_type numberOfBytes, size_type offset = 0);
	//tsCryptoString PartialEncode(DataStringType type, size_type numberOfBytes, size_type offset = 0);
	tsData &increment(value_type step = 1);
	tsData &decrement(value_type step = 1);
	UnicodeEncodingType EncodingType() const;
	UnicodeEncodingType EncodingType(uint8_t *data, uint32_t size) const;
	bool hasEncodingBOM() const;
	bool hasEncodingBOM(uint8_t *data, uint32_t size) const;
	uint32_t BOMByteCount() const;
	uint32_t BOMByteCount(const uint8_t *data, uint32_t size) const;
	static tsData computeBOM(UnicodeEncodingType type);
	tsData &prependBOM(UnicodeEncodingType type);

protected:
    mutable TSBYTE_BUFF _data;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Copies from the object specified in 'obj'.</summary>
	///
	/// <param name="obj">The object to copy.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void copyFrom(const tsData &obj);
	tsData FromHexString(size_type maxSize, size_type offset = 0) const;
	tsData FromBase64(size_type maxSize, size_type offset = 0, bool base64Url = false, bool padWithEquals = true) const;
};

bool operator==(const tsData& lhs, const tsData& rhs);
bool operator==(const tsData&& lhs, const tsData&& rhs);
bool operator!=(const tsData& lhs, const tsData& rhs);
bool operator<(const tsData& lhs, const tsData& rhs);
bool operator<=(const tsData& lhs, const tsData& rhs);
bool operator>(const tsData& lhs, const tsData& rhs);
bool operator>=(const tsData& lhs, const tsData& rhs);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Concatenate two byte arrays</summary>
///
/// <param name="lhs">[in,out] The first value.</param>
/// <param name="rhs">A value to append.</param>
///
/// <returns>The result of the operation.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline tsData operator+(const tsData &lhs, const tsData &rhs)
{
	tsData tmp;

	tmp = lhs;
	tmp += rhs;
	return tmp;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Concatenate two byte arrays</summary>
///
/// <param name="lhs">[in,out] The first value.</param>
/// <param name="rhs">A value to append (zero terminated).</param>
///
/// <returns>The result of the operation.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline tsData operator+(tsData &lhs, const unsigned char *rhs)
{
	tsData tmp;

	tmp = lhs;
	tmp += rhs;
	return tmp;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Concatenate two byte arrays</summary>
///
/// <param name="lhs">[in,out] The first value (zero terminated).</param>
/// <param name="rhs">A value to append.</param>
///
/// <returns>The result of the operation.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline tsData operator+(const unsigned char *lhs, const tsData &rhs)
{
	tsData tmp;

	tmp = lhs;
	tmp += rhs;
	return tmp;
}

void swap(tsData &lhs, tsData &rhs);

//std::ostream & operator << (std::ostream &Output, const tsData &obj);
//std::wostream & operator << (std::wostream &Output, const tsData &obj);

template <class T>
tsData& operator<<(tsData&& string, const T& val)
{
	string << val;
	return string;
}

tsData& operator<<(tsData& string, char val);
tsData& operator<<(tsData& string, int8_t val);
tsData& operator<<(tsData& string, int16_t val);
tsData& operator<<(tsData& string, int32_t val);
tsData& operator<<(tsData& string, int64_t val);
tsData& operator<<(tsData& string, uint8_t val);
tsData& operator<<(tsData& string, uint16_t val);
tsData& operator<<(tsData& string, uint32_t val);
tsData& operator<<(tsData& string, uint64_t val);
tsData& operator<<(tsData& string, const char* val);
//tsData& operator<<(tsData& string, const tsCryptoStringBase& val);
tsData& operator<<(tsData& string, const tsData& val);


#endif // __TSDATA_H__

