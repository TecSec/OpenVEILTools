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

#ifndef __TSSTRINGBASE_H__
#define __TSSTRINGBASE_H__

#pragma once

class tsStringBase;

typedef std::vector<tsStringBase> tsStringBaseList;

	/// <summary>the TecSec Standard Ascii string class that automatically overwrites its contents on
	/// 		 resize or destruction</summary>
class tsStringBase
{
public:
	typedef char value_type;
	typedef size_t size_type;
	typedef ptrdiff_t difference_type;
	typedef char* pointer;
	typedef char& reference;
	typedef const char* const_pointer;
	typedef const char& const_reference;
	typedef tsStringBase self_type;
	typedef tsStringBase* container_type;
	typedef const tsStringBase* const_container_type;

	static const size_type npos;

		/// <summary>Default constructor.</summary>
	tsStringBase();
	tsStringBase(tsStringBase &&obj);
	tsStringBase(std::initializer_list<value_type> init);
	template <class InputIt>
	tsStringBase(InputIt first, InputIt last) :
		_data(tsCreateBuffer())
	{
		assign(first, last);
	}


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Copy constructor.</summary>
	///
	/// <param name="obj">The object to copy</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase(const tsStringBase &obj);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Constructor.</summary>
	///
	/// <param name="data">The data.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase(const_pointer data);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Constructor.</summary>
	///
	/// <param name="data">The data.</param>
	/// <param name="len"> The length.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase(const_pointer data, size_type len);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Constructor that fills tsStringBase of size numChars with the character data..</summary>
	///
	/// <param name="data">	   The data.</param>
	/// <param name="numChars">Number of characters.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase(value_type data, size_type numChars);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Destructor.</summary>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	~tsStringBase();

	tsStringBase &operator=(tsStringBase &&obj);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Assignment operator.</summary>
	///
	/// <param name="obj">The object to copy</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &operator = (const tsStringBase &obj);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Assignment operator.</summary>
	///
	/// <param name="data">The zero terminated data to assign.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &operator = (const_pointer data);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Assignment operator.</summary>
	///
	/// <param name="data">The zero terminated data to assign.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &operator = (value_type data);
	tsStringBase &operator=(std::initializer_list<value_type> iList);

	tsStringBase &operator += (const tsStringBase &obj);
	tsStringBase &operator += (value_type data);
	tsStringBase &operator += (const_pointer data);
	tsStringBase &operator += (std::initializer_list<value_type> init);


	// NOT WORKING  operator const char * () const;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the number of characters in the string</summary>
	///
	/// <returns>the number of characters in the string not including the null terminator</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	size_type size() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the number of characters in the string</summary>
	///
	/// <returns>the number of characters in the string not including the null terminator</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	size_type length() const;
	/// <summary>Overwrites any existing data in the string and then set the string to 0 length</summary>
	void clear();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Resizes the string to a new size.</summary>
	///
	/// <param name="newSize">The new size of the string in characters.</param>
	///
	/// <returns>The final size of the string in characters</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void resize(size_type newSize);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Resizes the string to a new size.</summary>
	///
	/// <param name="newSize">The new size of the string in characters.</param>
	/// <param name="value">  The character that shall be used to extend the string</param>
	///
	/// <returns>The final size of the string in characters.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void resize(size_type newSize, value_type value);
	void reserve(size_type newSize = 0);
	size_type capacity() const;
	size_type max_size() const;
	void push_back(value_type ch);
	void pop_back();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Retrieves a reference to the character the given index.</summary>
	///
	/// <param name="index">Zero-based index of the character.</param>
	///
	/// <returns>a reference to the character the given index</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	reference at(size_type index);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Retrieves a const reference to the character the given index.</summary>
	///
	/// <param name="index">Zero-based index of the character.</param>
	///
	/// <returns>a const reference to the character the given index</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const_reference at(size_type index) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Retrieves the character the given index.</summary>
	///
	/// <param name="index">Zero-based index of the character.</param>
	///
	/// <returns>the character the given index</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	value_type c_at(size_type index) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns a pointer to the UTF8 string contained in this object</summary>
	///
	/// <returns>a pointer to the UTF8 string</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const_pointer data() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns a pointer used to access the UTF8 string contents directly</summary>
	///
	/// <remarks>In all cases this will return a buffer for this class instance only.</remarks>
	///
	/// <returns>a pointer used to access the UTF8 string contents directly</returns>
	/// \warning NOTE:  Do not access data beyond size() characters.
	////////////////////////////////////////////////////////////////////////////////////////////////////
	pointer data();
    pointer rawData() { return (pointer)tsGetBufferDataPtr(_data); }
	reference front();
	const_reference front() const;
	reference back();
	const_reference back() const;
	bool empty() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns a const pointer used to access the UTF8 string contents directly</summary>
	///
	/// <remarks>In all cases this will return a buffer for this class instance only.</remarks>
	///
	/// <returns>a const pointer used to access the UTF8 string contents directly</returns>
	/// \warning NOTE:  Do not access data beyond size() characters.
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const_pointer c_str() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns a const pointer used to access the UTF8 string contents directly</summary>
	///
	/// <remarks>In all cases this will return a buffer for this class instance only.</remarks>
	///
	/// <returns>a const pointer used to access the UTF8 string contents directly</returns>
	/// \warning NOTE:  Do not access data beyond size() characters.
	////////////////////////////////////////////////////////////////////////////////////////////////////
	//operator const char *() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns a pointer used to access the UTF8 string contents directly</summary>
	///
	/// <remarks>In all cases this will return a buffer for this class instance only.</remarks>
	///
	/// <returns>a pointer used to access the UTF8 string contents directly</returns>
	/// \warning NOTE:  Do not access data beyond size() characters.
	////////////////////////////////////////////////////////////////////////////////////////////////////
	//operator char *();

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns a reference to a character in the string</summary>
	///
	/// <returns>Returns a reference to a character in the string at index. If index >= size then return m_junk</returns>
	/// \warning NOTE:  Do not access data beyond size() characters.
	////////////////////////////////////////////////////////////////////////////////////////////////////
	reference operator [] (size_type index);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns a character in the string</summary>
	///
	/// <returns>Returns a character in the string at index. If index >= size then return m_junk</returns</returns>
	/// \warning NOTE:  Do not access data beyond size() characters.
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const_reference operator [] (size_type index) const;

	tsStringBase &assign(size_type size, value_type ch);
	tsStringBase &assign(const tsStringBase &obj);
	tsStringBase &assign(const tsStringBase &obj, size_type pos, size_type = npos);
	tsStringBase &assign(tsStringBase &&obj);
	tsStringBase &assign(const_pointer newData, size_type count);
	template <class InputIt>
	tsStringBase& assign(InputIt first, InputIt last)
	{
		clear();
		for (auto it = first; it != last; ++it)
		{
			append(*it);
		}
		return *this;
	}
	tsStringBase &assign(std::initializer_list<value_type> iList);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Prepends the specified string to this object.</summary>
	///
	/// <param name="data">The data to prepend.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &prepend(const_pointer data);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Prepends the specified string to this object.</summary>
	///
	/// <param name="data">The data to prepend.</param>
	/// <param name="len"> The length of the data to prepend in characters.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &prepend(const_pointer data, size_type len);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Prepends the specified character to this object.</summary>
	///
	/// <param name="data">The data to prepend.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &prepend(value_type data);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Prepends the specified BYTE to this object.</summary>
	///
	/// <param name="data">The data to prepend.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &prepend(uint8_t data);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Prepends the specified string to this object.</summary>
	///
	/// <param name="obj">The string to prepend.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &prepend(const tsStringBase &obj);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Prepends the specified long integer to this object.</summary>
	///
	/// <param name="Value">The long integer convert into a string and prepend.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	//tsStringBase &prepend(long Value);

	tsStringBase &append(size_type len, value_type ch);
	tsStringBase &append(const tsStringBase &obj);
	tsStringBase &append(const tsStringBase &obj, size_type pos, size_type count = npos);
	tsStringBase &append(const_pointer data, size_type len);
	tsStringBase &append(const_pointer data);
	template <class InputIt>
	tsStringBase &append(InputIt first, InputIt last)
	{
		size_type oldsize = size();
		resize(size() + (last - first));
		char* ptr = rawData();
		for (auto it = first; it != last; ++it)
		{
			ptr[oldsize++] = *it;
		}
		return *this;
	}
	tsStringBase &append(std::initializer_list<value_type> list);

	tsStringBase &append(value_type data);
	tsStringBase &append(uint8_t data);

	//tsStringBase &append(long Value);
	//tsStringBase &append(int8_t val);
	tsStringBase &append(int16_t val);
	tsStringBase &append(int32_t val);
#ifdef _MSC_VER
	tsStringBase &append(long val);
	tsStringBase &append(unsigned long val);
#endif
	tsStringBase &append(int64_t val);
	//tsStringBase &append(uint8_t val);
	tsStringBase &append(uint16_t val);
	tsStringBase &append(uint32_t val);
	tsStringBase &append(uint64_t val);

	tsStringBase& erase(size_type pos = 0, size_type count = npos);

	size_type copy(pointer dest, size_type count, size_type pos = 0) const;
	void swap(tsStringBase &obj);

	tsStringBase& insert(size_type index, size_type count, value_type ch);
	tsStringBase& insert(size_type index, value_type ch);
	tsStringBase& insert(size_type index, const_pointer s);
	tsStringBase& insert(size_type index, const_pointer s, size_type count);
	tsStringBase& insert(size_type index, const tsStringBase& str);
	tsStringBase& insert(size_type index, const tsStringBase& str, size_type index_str, size_type count = npos);
	tsStringBase& insert(size_type pos, std::initializer_list<value_type> iList);

	int compare(const tsStringBase& str) const;
	int compare(size_type pos1, size_type count1, const tsStringBase& str) const;
	int compare(size_type pos1, size_type count1, const tsStringBase& str, size_type pos2, size_type count2) const;
	int compare(const_pointer s) const;
	int compare(size_type pos1, size_type count1, const_pointer s) const;
	int compare(size_type pos1, size_type count1, const_pointer s, size_type count2) const;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Inserts a character into the string at the specified zero based index.</summary>
	///
	/// <param name="offset">The zero based position in the string.</param>
	/// <param name="value"> The character to insert.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &InsertAt(size_type offset, value_type value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Inserts a character string into the string at the specified zero based index.</summary>
	///
	/// <param name="offset">The zero based position in the string.</param>
	/// <param name="value"> The character string to insert.</param>
	/// <param name="len">   (optional) the length of the string to insert or -1 to look for the null terminator.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &InsertAt(size_type offset, const_pointer value, int32_t len = -1);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Inserts a character string into the string at the specified zero based index.</summary>
	///
	/// <param name="offset">The zero based position in the string.</param>
	/// <param name="value"> The character string to insert.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &InsertAt(size_type offset, const tsStringBase &value);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Deletes characters from the string</summary>
	///
	/// <param name="offset">The offset at which the delete starts (zero based)</param>
	/// <param name="count"> The number of characters to delete</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &DeleteAt(size_type offset, size_type count);


	tsStringBase& replace(size_type pos, size_type count, const tsStringBase& str);
	tsStringBase& replace(size_type pos, size_type count, const tsStringBase& str, size_type pos2, size_type count2 = npos);
	tsStringBase& replace(size_type pos, size_type count, const_pointer s, size_type count2);
	tsStringBase& replace(size_type pos, size_type count, const_pointer s);
	tsStringBase& replace(size_type pos, size_type count, size_type count2, value_type ch);


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Replaces one string for another within this object.</summary>
	///
	/// <param name="find">		  The search string that will be replaced.</param>
	/// <param name="replacement">The replacement string.</param>
	/// <param name="count">	  (optional) the number of times to replace.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &Replace(const_pointer find, const_pointer replacement, int32_t count = -1);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Replaces one string for another within this object.</summary>
	///
	/// <param name="find">		  The search string that will be replaced.</param>
	/// <param name="replacement">The replacement string.</param>
	/// <param name="count">	  (optional) the number of times to replace.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &Replace(const tsStringBase &find, const tsStringBase &replacement, int32_t count = -1);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Replaces one string for another within this object.</summary>
	///
	/// <param name="i_Begin">		  The beginning offset to replace (zero based)</param>
	/// <param name="i_End">		  The ending offset that will be replaced (zero based)</param>
	/// <param name="i_newData">	  The data to replace with</param>
	/// <param name="i_newDataLength">(optional) length of the replacement data in characters.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &Replace(size_type i_Begin, size_type i_End, const_pointer i_newData, int32_t i_newDataLength = -1);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Converts this object to an UTF 8 string</summary>
	///
	/// <returns>This object as a tsStringBase.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase ToUTF8() const;

	size_type find(const tsStringBase& str, size_type pos = 0) const;
	size_type find(const_pointer s, size_type pos, size_type count) const;
	size_type find(const_pointer s, size_type pos = 0) const;
	size_type find(value_type ch, size_type pos = 0) const;

	size_type rfind(const tsStringBase& str, size_type pos = npos) const;
	size_type rfind(const_pointer s, size_type pos, size_type count) const;
	size_type rfind(const_pointer s, size_type pos = npos) const;
	size_type rfind(value_type ch, size_type pos = npos) const;

	size_type find_first_of(const tsStringBase& str, size_type pos = 0) const;
	size_type find_first_of(const_pointer s, size_type pos, size_type count) const;
	size_type find_first_of(const_pointer s, size_type pos = 0) const;
	size_type find_first_of(value_type ch, size_type pos = 0) const;

	size_type find_first_not_of(const tsStringBase& str, size_type pos = 0) const;
	size_type find_first_not_of(const_pointer s, size_type pos, size_type count) const;
	size_type find_first_not_of(const_pointer s, size_type pos = 0) const;
	size_type find_first_not_of(value_type ch, size_type pos = 0) const;

	size_type find_last_of(const tsStringBase& str, size_type pos = npos) const;
	size_type find_last_of(const_pointer s, size_type pos, size_type count) const;
	size_type find_last_of(const_pointer s, size_type pos = npos) const;
	size_type find_last_of(value_type ch, size_type pos = npos) const;

	size_type find_last_not_of(const tsStringBase& str, size_type pos = npos) const;
	size_type find_last_not_of(const_pointer s, size_type pos, size_type count) const;
	size_type find_last_not_of(const_pointer s, size_type pos = npos) const;
	size_type find_last_not_of(value_type ch, size_type pos = npos) const;


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Assigns this object to the output of a printf style of string formatting</summary>
	///
	/// <param name="msg">The message to be formatted</param>
	///
	/// <returns>A reference to this object</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &Format(const char *msg, ...);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Assigns this object to the output of a printf style of string formatting</summary>
	///
	/// <param name="msg">The message to be formatted</param>
	///
	/// <returns>A reference to this object</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &Format(tsStringBase msg, ...);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Assigns this object to the output of a printf style of string formatting using a va_list</summary>
	///
	/// <param name="msg">The message to be formatted</param>
	///
	/// <returns>A reference to this object</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &FormatArg(const char *msg, va_list arg);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Assigns this object to the output of a printf style of string formatting using a va_list</summary>
	///
	/// <param name="msg">The message to be formatted</param>
	///
	/// <returns>A reference to this object</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &FormatArg(const tsStringBase& msg, va_list arg);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Converts this string to upper case</summary>
	///
	/// <returns>A reference to this object</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &ToUpper();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Converts this string to lower case</summary>
	///
	/// <returns>A reference to this object</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &ToLower();

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Extracts a portion of this string and creates a new string</summary>
	///
	/// <param name="start"> The starting offset to copy</param>
	/// <param name="length">The number of characters to copy</param>
	///
	/// <returns>the new string containing the specified characters</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase substring(size_type start, size_type length) const;
	tsStringBase substr(size_type start, size_type length) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns a string containing the last 'length' characters</summary>
	///
	/// <param name="length">The number of characters to extract from the right of the string</param>
	///
	/// <returns>the new string</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase right(size_type length) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns a string containing the first 'length' characters</summary>
	///
	/// <param name="length">The number of characters to extract from the left of the string</param>
	///
	/// <returns>the new string</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase left(size_type length) const;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Removes spaces, carriage returns, line feeds and tabs from both ends of the string</summary>
	///
	/// <returns>A reference to this object</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &Trim();

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Removes the specifed characters from both ends of the string.</summary>
	///
	/// <param name="trimmers">The character set that is to be removed from the string</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &Trim(const_pointer trimmers);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Removes spaces, carriage returns, line feeds and tabs from both the beginning of the string</summary>
	///
	/// <returns>A reference to this object</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &TrimStart();

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Removes the specifed characters from the beginning of the string.</summary>
	///
	/// <param name="trimmers">The character set that is to be removed from the string</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &TrimStart(const_pointer trimmers);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Removes spaces, carriage returns, line feeds and tabs from the end of the string</summary>
	///
	/// <returns>A reference to this object</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &TrimEnd();

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Removes the specifed characters from the end of the string.</summary>
	///
	/// <param name="trimmers">The character set that is to be removed from the string</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase &TrimEnd(const_pointer trimmers);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Pad the left size of the string with the specified padding if the length is less than 'width'</summary>
	///
	/// <param name="width">  The minimum width of the output string.</param>
	/// <param name="padding">The padding character.</param>
	///
	/// <returns>The padded string</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase PadLeft(size_type width, value_type padding) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Pad the right size of the string with the specified padding if the length is less than 'width'</summary>
	///
	/// <param name="width">  The minimum width of the output string.</param>
	/// <param name="padding">The padding character.</param>
	///
	/// <returns>The padded string</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase PadRight(size_type width, value_type padding) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Pad the left size of the string with the specified padding or truncates if neccessary based on 'width'</summary>
	///
	/// <param name="width">  The minimum width of the output string.</param>
	/// <param name="padding">The padding character.</param>
	///
	/// <returns>The padded/truncated string</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase TruncOrPadLeft(size_type width, value_type padding) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Pad the right size of the string with the specified padding or truncates if neccessary based on 'width'</summary>
	///
	/// <param name="width">  The minimum width of the output string.</param>
	/// <param name="padding">The padding character.</param>
	///
	/// <returns>The padded/truncated string</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsStringBase TruncOrPadRight(size_type width, value_type padding) const;

	tsStringBaseList split(value_type splitter, size_type maxSegments = 1000000, bool allowBlankSegments = false) const
	{
		tsStringBase::size_type start, end;
		tsStringBaseList tmp;
		size_type itemsFound = 1;
		size_type m_used = size();
		const_pointer m_data = data();

		if (size() == 0)
		{
			tmp.push_back(tsStringBase());
			return tmp;
		}
		start = 0;
		while (start < m_used)
		{
			end = start;
			while (end < m_used && m_data[end] != splitter)
			{
				end++;
			}
			if (start != end || itemsFound >= maxSegments || allowBlankSegments)
			{
				if (itemsFound++ >= maxSegments)
				{
					tmp.push_back(tsStringBase(&m_data[start], m_used - start));
					return tmp;
				}
				else
				{
					tmp.push_back(tsStringBase(&m_data[start], end - start));
				}
			}
			start = end + 1;
			if (start == m_used && (allowBlankSegments || tmp.size() == 0))
			{
				tmp.push_back(tsStringBase());
			}
		}
		return tmp;
	}

	tsStringBaseList split(const_pointer _splitters, size_type maxSegments = 1000000, bool allowBlankSegments = false) const
	{
		tsStringBase::size_type start, end;
		tsStringBaseList tmp;
		tsStringBase splitters(_splitters);
		size_type itemsFound = 1;
		size_type m_used = size();
		const_pointer m_data = data();

		if (size() == 0)
		{
			tmp.push_back(tsStringBase());
			return tmp;
		}
		start = 0;
		while (start < m_used)
		{
			end = start;
			while (end < m_used && strchr(splitters.c_str(), m_data[end]) == nullptr)
			{
				end++;
			}
			if (start != end || itemsFound >= maxSegments || allowBlankSegments)
			{
				if (itemsFound++ >= maxSegments)
				{
					tmp.push_back(tsStringBase(&m_data[start], m_used - start));
					return tmp;
				}
				else
				{
					tmp.push_back(tsStringBase(&m_data[start], end - start));
				}
			}
			start = end + 1;
			if (start == m_used && (allowBlankSegments || tmp.size() == 0))
			{
				tmp.push_back(tsStringBase());
			}
		}
		return tmp;
	}

protected:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Copies the specified string into this string</summary>
	///
	/// <param name="obj">The string to copy</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void copyFrom(const tsStringBase &obj);

private:
    mutable TSBYTE_BUFF _data;
};

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Concatenate two strings</summary>
///
/// <param name="lhs">[in,out] The first value.</param>
/// <param name="rhs">A value to add to it.</param>
///
/// <returns>The result of the operation.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline tsStringBase operator+(const tsStringBase &lhs, const tsStringBase &rhs)
{
	tsStringBase tmp;

	tmp.append(lhs).append(rhs);
	return tmp;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Concatenate two strings</summary>
///
/// <param name="lhs">[in,out] The first value.</param>
/// <param name="rhs">A value to add to it.</param>
///
/// <returns>The result of the operation.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline tsStringBase operator+(const tsStringBase &lhs, const char *rhs)
{
	tsStringBase tmp;

	tmp.append(lhs).append(rhs);
	return tmp;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Concatenate two strings</summary>
///
/// <param name="lhs">[in,out] The first value.</param>
/// <param name="rhs">A value to add to it.</param>
///
/// <returns>The result of the operation.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline tsStringBase operator+(const char *lhs, const tsStringBase &rhs)
{
	tsStringBase tmp;

	tmp.append(lhs).append(rhs);
	return tmp;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
///// <summary>Concatenate two strings</summary>
/////
///// <param name="lhs">[in,out] The first value.</param>
///// <param name="rhs">A value to add to it.</param>
/////
///// <returns>The result of the operation.</returns>
//////////////////////////////////////////////////////////////////////////////////////////////////////
//inline tsStringBase operator+(const tsStringBase &lhs, const tsStringBase &rhs)
//{
//	tsStringBase tmp;
//
//	tmp.append(lhs).append(rhs);
//	return tmp;
//}
//
//////////////////////////////////////////////////////////////////////////////////////////////////////
///// <summary>Concatenate two strings</summary>
/////
///// <param name="lhs">[in,out] The first value.</param>
///// <param name="rhs">A value to add to it.</param>
/////
///// <returns>The result of the operation.</returns>
//////////////////////////////////////////////////////////////////////////////////////////////////////
//inline tsStringBase operator+(const tsStringBase &lhs, const char *rhs)
//{
//	tsStringBase tmp;
//
//	tmp.append(lhs).append(rhs);
//	return tmp;
//}
//
//////////////////////////////////////////////////////////////////////////////////////////////////////
///// <summary>Concatenate two strings</summary>
/////
///// <param name="lhs">[in,out] The first value.</param>
///// <param name="rhs">A value to add to it.</param>
/////
///// <returns>The result of the operation.</returns>
//////////////////////////////////////////////////////////////////////////////////////////////////////
//inline tsStringBase operator+(const char *lhs, const tsStringBase &rhs)
//{
//	tsStringBase tmp;
//
//	tmp.append(lhs).append(rhs);
//	return tmp;
//}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Stream insertion operator.</summary>
///
/// <param name="Output">[in,out] The stream object.</param>
/// <param name="obj">   The data to stream.</param>
///
/// <returns>the stream object</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::ostream & operator << (std::ostream &Output, const tsStringBase &obj);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Stream insertion operator.</summary>
///
/// <param name="Output">[in,out] The stream object.</param>
/// <param name="obj">   The data to stream.</param>
///
/// <returns>the stream object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
std::wostream & operator << (std::wostream &Output, const tsStringBase &obj);

void swap(tsStringBase &lhs, tsStringBase &rhs);

bool operator==(const tsStringBase& lhs, const tsStringBase& rhs);
bool operator!=(const tsStringBase& lhs, const tsStringBase& rhs);
bool operator<(const tsStringBase& lhs, const tsStringBase& rhs);
bool operator<=(const tsStringBase& lhs, const tsStringBase& rhs);
bool operator>(const tsStringBase& lhs, const tsStringBase& rhs);
bool operator>=(const tsStringBase& lhs, const tsStringBase& rhs);

//template <class T>
//tsStringBase& operator<<(tsStringBase&& string, const T& val)
//{
//	string << val;
//	return string;
//}

tsStringBase& operator<<(tsStringBase& string, char val);
tsStringBase& operator<<(tsStringBase& string, int8_t val);
tsStringBase& operator<<(tsStringBase& string, int16_t val);
#ifdef _MSC_VER
tsStringBase& operator<<(tsStringBase& string, long val);
tsStringBase& operator<<(tsStringBase& string, unsigned long val);
#endif
tsStringBase& operator<<(tsStringBase& string, int32_t val);
tsStringBase& operator<<(tsStringBase& string, int64_t val);
tsStringBase& operator<<(tsStringBase& string, uint8_t val);
tsStringBase& operator<<(tsStringBase& string, uint16_t val);
tsStringBase& operator<<(tsStringBase& string, uint32_t val);
tsStringBase& operator<<(tsStringBase& string, uint64_t val);
tsStringBase& operator<<(tsStringBase& string, const tsStringBase& val);

enum SpecialStrings {
	endl,
	tab,
	nullchar,
	cr,
	lf,
	crlf,
};
tsStringBase& operator<<(tsStringBase& string, enum SpecialStrings val);

#endif // __TSSTRINGBASE_H__
