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

#ifndef __CRYPTOUTF16_H__
#define __CRYPTOUTF16_H__

#pragma once

	class CryptoUtf16
	{
	public:
		typedef ts_wchar value_type;
		typedef size_t size_type;
		typedef ptrdiff_t difference_type;
		typedef ts_wchar* pointer;
		typedef ts_wchar& reference;
		typedef const ts_wchar* const_pointer;
		typedef const ts_wchar& const_reference;
		typedef CryptoUtf16 self_type;
		typedef CryptoUtf16* container_type;
		typedef const CryptoUtf16* const_container_type;

		static const size_type npos;

		static void* operator new(std::size_t count) {
			return cryptoNew(count);
		}
		static void* operator new[](std::size_t count) {
			return cryptoNew(count);
		}
		static void operator delete(void* ptr) {
			cryptoDelete(ptr);
		}
		static void operator delete[](void* ptr) {
			cryptoDelete(ptr);
		}


		CryptoUtf16();
		CryptoUtf16(size_type count, value_type ch);
		CryptoUtf16(const CryptoUtf16 &obj, size_type pos);
		CryptoUtf16(const CryptoUtf16 &obj, size_type pos, size_type count);
		CryptoUtf16(const_pointer data, size_type count);
		CryptoUtf16(const_pointer data);
		template <class InputIt>
		CryptoUtf16(InputIt first, InputIt last) :
			m_data(nullptr),
			m_used(0),
			m_allocated(-1)
		{
			assign(first, last);
		}
		CryptoUtf16(const CryptoUtf16 &obj);
		CryptoUtf16(CryptoUtf16 &&obj);
		CryptoUtf16(std::initializer_list<value_type> init);

		explicit CryptoUtf16(const char *data);
		explicit CryptoUtf16(const tsStringBase& data);
		explicit CryptoUtf16(size_type count, char ch);
		explicit CryptoUtf16(const char *data, size_type count);
		explicit CryptoUtf16(std::initializer_list<char> init);
		~CryptoUtf16();

		CryptoUtf16 &operator=(const CryptoUtf16 &obj);
		CryptoUtf16 &operator=(CryptoUtf16 &&obj);
		CryptoUtf16 &operator=(const_pointer data); /* zero terminated */
		CryptoUtf16 &operator=(value_type obj);
		CryptoUtf16 &operator=(std::initializer_list<value_type> iList);
		CryptoUtf16 &operator=(const tsStringBase& setTo);
		CryptoUtf16 &operator=(const char* setTo);

		CryptoUtf16& assign(size_type count, value_type ch);
		CryptoUtf16& assign(const CryptoUtf16 &obj);
		CryptoUtf16& assign(const CryptoUtf16 &obj, size_type pos, size_type count = npos);
		CryptoUtf16& assign(CryptoUtf16 &&obj);
		CryptoUtf16& assign(const_pointer newData, size_type count);
		CryptoUtf16& assign(const_pointer newData);
		template <class InputIt>
		CryptoUtf16& assign(InputIt first, InputIt last)
		{
			clear();
			for (auto it = first; it != last; ++it)
			{
				append(*it);
			}
			return *this;
		}
		CryptoUtf16 &assign(std::initializer_list<value_type> iList);

		reference at(size_type index);
		const_reference at(size_type index) const;
		pointer data();
		const_pointer data() const;
		const_pointer c_str() const;
		reference front();
		const_reference front() const;
		reference back();
		const_reference back() const;
		reference operator[](size_type index);
		const_reference operator[](size_type index) const;

		bool empty() const;
		size_type size() const;
		size_type length() const;
		size_type max_size() const;
		_Post_satisfies_(this->m_data != 0) void reserve(size_type newSize);
		size_type capacity() const;
		void clear();

		CryptoUtf16& insert(size_type index, size_type count, value_type ch);
		CryptoUtf16& insert(size_type index, value_type ch);
		CryptoUtf16& insert(size_type index, const_pointer s);
		CryptoUtf16& insert(size_type index, const_pointer s, size_type count);
		CryptoUtf16& insert(size_type index, const CryptoUtf16& str);
		CryptoUtf16& insert(size_type index, const CryptoUtf16& str, size_type index_str, size_type count = npos);

		CryptoUtf16& erase(size_type pos = 0, size_type count = npos);

		void push_back(ts_wchar ch);
		void pop_back();

		CryptoUtf16 &append(size_type len, value_type ch);
		CryptoUtf16 &append(const CryptoUtf16 &obj);
		CryptoUtf16 &append(const CryptoUtf16 &obj, size_type pos, size_type count = npos);
		CryptoUtf16 &append(const_pointer data, size_type count);
		CryptoUtf16 &append(const_pointer data);
		template <class InputIt>
		CryptoUtf16 &append(InputIt first, InputIt last)
		{
			size_type oldsize = size();
			resize(size() + (last - first));
			for (auto it = first; it != last; ++it)
			{
				m_data[oldsize++] = *it;
			}
			return *this;
		}
		CryptoUtf16 &append(std::initializer_list<value_type> list);

		CryptoUtf16 &operator += (const CryptoUtf16& str);
		CryptoUtf16 &operator += (value_type ch);
		CryptoUtf16 &operator += (const_pointer s);
		CryptoUtf16 &operator += (std::initializer_list<value_type> init);

		int compare(const CryptoUtf16& str) const;
		int compare(size_type pos1, size_type count1, const CryptoUtf16& str) const;
		int compare(size_type pos1, size_type count1, const CryptoUtf16& str, size_type pos2, size_type count2) const;
		int compare(const_pointer s) const;
		int compare(size_type pos1, size_type count1, const_pointer s) const;
		int compare(size_type pos1, size_type count1, const_pointer s, size_type count2) const;

		CryptoUtf16& replace(size_type pos, size_type count, const CryptoUtf16& str);
		CryptoUtf16& replace(size_type pos, size_type count, const CryptoUtf16& str, size_type pos2, size_type count2 = npos);
		CryptoUtf16& replace(size_type pos, size_type count, const_pointer s, size_type count2);
		CryptoUtf16& replace(size_type pos, size_type count, const_pointer s);
		CryptoUtf16& replace(size_type pos, size_type count, size_type count2, value_type ch);

		CryptoUtf16 substr(size_type index = 0, size_type count = npos) const;
		size_type copy(pointer dest, size_type count, size_type pos = 0) const;
		_Post_satisfies_(this->m_data != nullptr) void resize(size_type newSize);
		_Post_satisfies_(this->m_data != nullptr) void resize(size_type newSize, ts_wchar value);
		void swap(CryptoUtf16 &obj);

		size_type find(const CryptoUtf16& str, size_type pos = 0) const;
		size_type find(const_pointer s, size_type pos, size_type count) const;
		size_type find(const_pointer s, size_type pos = 0) const;
		size_type find(value_type ch, size_type pos = 0) const;

		size_type rfind(const CryptoUtf16& str, size_type pos = npos) const;
		size_type rfind(const_pointer s, size_type pos, size_type count) const;
		size_type rfind(const_pointer s, size_type pos = npos) const;
		size_type rfind(value_type ch, size_type pos = npos) const;

		size_type find_first_of(const CryptoUtf16& str, size_type pos = 0) const;
		size_type find_first_of(const_pointer s, size_type pos, size_type count) const;
		size_type find_first_of(const_pointer s, size_type pos = 0) const;
		size_type find_first_of(value_type ch, size_type pos = 0) const;

		size_type find_first_not_of(const CryptoUtf16& str, size_type pos = 0) const;
		size_type find_first_not_of(const_pointer s, size_type pos, size_type count) const;
		size_type find_first_not_of(const_pointer s, size_type pos = 0) const;
		size_type find_first_not_of(value_type ch, size_type pos = 0) const;

		size_type find_last_of(const CryptoUtf16& str, size_type pos = npos) const;
		size_type find_last_of(const_pointer s, size_type pos, size_type count) const;
		size_type find_last_of(const_pointer s, size_type pos = npos) const;
		size_type find_last_of(value_type ch, size_type pos = npos) const;

		size_type find_last_not_of(const CryptoUtf16& str, size_type pos = npos) const;
		size_type find_last_not_of(const_pointer s, size_type pos, size_type count) const;
		size_type find_last_not_of(const_pointer s, size_type pos = npos) const;
		size_type find_last_not_of(value_type ch, size_type pos = npos) const;

		// TecSec Extensions
		tsStringBase toUtf8() const;
		CryptoUtf16& assign(const char *newData, size_type count); 
		CryptoUtf16& assign(const char *newData); 
		CryptoUtf16& assign(const tsStringBase &obj);
		CryptoUtf16 &assign(std::initializer_list<char> iList);
		CryptoUtf16 &assign(value_type data);
		CryptoUtf16 &assign(char data);
		CryptoUtf16 &assign(int16_t val);
		CryptoUtf16 &assign(int32_t val);
		CryptoUtf16 &assign(int64_t val);
		//CryptoUtf16 &assign(uint16_t val);
		CryptoUtf16 &assign(uint32_t val);
		CryptoUtf16 &assign(uint64_t val);
		value_type c_at(size_type index) const;
		pointer rawData(); 
		CryptoUtf16& insert(size_type index, size_type count, char ch);
		CryptoUtf16& insert(size_type index, char ch);
		CryptoUtf16& insert(size_type index, const char* s);
		CryptoUtf16& insert(size_type index, const char* s, size_type count);
		CryptoUtf16& insert(size_type index, const tsStringBase& str);
		CryptoUtf16& insert(size_type index, const tsStringBase& str, size_type index_str, size_type count = npos);
		CryptoUtf16 &operator=(std::initializer_list<char> iList);
		void push_back(char ch);

		CryptoUtf16 &append(size_type len, char ch);
		CryptoUtf16 &append(const tsStringBase &obj);
		CryptoUtf16 &append(const tsStringBase &obj, size_type pos, size_type count = npos);
		CryptoUtf16 &append(const char* data, size_type count);
		CryptoUtf16 &append(const char* data);
		CryptoUtf16 &append(std::initializer_list<char> list);
		CryptoUtf16 &append(value_type data);
		CryptoUtf16 &append(char data);
		CryptoUtf16 &append(int16_t val);
		CryptoUtf16 &append(int32_t val);
		CryptoUtf16 &append(int64_t val);
		//CryptoUtf16 &append(uint16_t val);
		CryptoUtf16 &append(uint32_t val);
		CryptoUtf16 &append(uint64_t val);

		CryptoUtf16 &operator += (const tsStringBase &obj);
		CryptoUtf16 &operator += (char data);
		CryptoUtf16 &operator += (const char* data);
		CryptoUtf16 &operator += (std::initializer_list<char> init);
		CryptoUtf16 &operator += (int16_t val);
		CryptoUtf16 &operator += (int32_t val);
		CryptoUtf16 &operator += (int64_t val);
		//CryptoUtf16 &operator += (uint16_t val);
		CryptoUtf16 &operator += (uint32_t val);
		CryptoUtf16 &operator += (uint64_t val);

		int compare(const tsStringBase& str) const;
		int compare(size_type pos1, size_type count1, const tsStringBase& str) const;
		int compare(size_type pos1, size_type count1, const tsStringBase& str, size_type pos2, size_type count2) const;
		int compare(const char* s) const;
		int compare(size_type pos1, size_type count1, const char* s) const;
		int compare(size_type pos1, size_type count1, const char* s, size_type count2) const;

		CryptoUtf16& replace(size_type pos, size_type count, const tsStringBase& str);
		CryptoUtf16& replace(size_type pos, size_type count, const tsStringBase& str, size_type pos2, size_type count2 = npos);
		CryptoUtf16& replace(size_type pos, size_type count, const char* s, size_type count2);
		CryptoUtf16& replace(size_type pos, size_type count, const char* s);
		CryptoUtf16& replace(size_type pos, size_type count, size_type count2, char ch);

		CryptoUtf16 right(size_type length) const;
		CryptoUtf16 left(size_type length) const;
		CryptoUtf16 &padLeft(size_type length, value_type value = 0);
		CryptoUtf16 &padRight(size_type length, value_type value = 0);
		CryptoUtf16 &truncOrPadLeft(size_type length, value_type value = 0);

	protected:
		pointer m_data; ///< the ponter to either m_defaultData or the allocated data for this UTF16 class
		size_type m_used; ///< the number of characters currently in use for this string (length)
		difference_type m_allocated; ///< how many characters are allocated for this string
		void copyFrom(const CryptoUtf16 &obj);
		static const_pointer WcsChr(const_pointer list, value_type ch, size_type count);
	};
	void swap(CryptoUtf16 &lhs, CryptoUtf16 &rhs);
	bool operator==(const CryptoUtf16& lhs, const CryptoUtf16& rhs);
	bool operator!=(const CryptoUtf16& lhs, const CryptoUtf16& rhs);
	bool operator<(const CryptoUtf16& lhs, const CryptoUtf16& rhs);
	bool operator<=(const CryptoUtf16& lhs, const CryptoUtf16& rhs);
	bool operator>(const CryptoUtf16& lhs, const CryptoUtf16& rhs);
	bool operator>=(const CryptoUtf16& lhs, const CryptoUtf16& rhs);

	TS_INLINE CryptoUtf16 operator+(const CryptoUtf16 &lhs, const CryptoUtf16 &rhs)
	{
		CryptoUtf16 tmp;

		tmp = lhs;
		tmp += rhs;
		return tmp;
	}
	TS_INLINE CryptoUtf16 operator+(CryptoUtf16 &lhs, const ts_wchar *rhs)
	{
		CryptoUtf16 tmp;

		tmp = lhs;
		tmp += rhs;
		return tmp;
	}
	TS_INLINE CryptoUtf16 operator+(const ts_wchar *lhs, const CryptoUtf16 &rhs)
	{
		CryptoUtf16 tmp;

		tmp = lhs;
		tmp += rhs;
		return tmp;
	}
	std::ostream & operator << (std::ostream &Output, const CryptoUtf16 &obj);
	std::wostream & operator << (std::wostream &Output, const CryptoUtf16 &obj);
	
	template <class T>
	CryptoUtf16& operator<<(CryptoUtf16&& string, const T& val)
	{
		string << val;
		return string;
	}

	CryptoUtf16& operator<<(CryptoUtf16& string, char val);
	CryptoUtf16& operator<<(CryptoUtf16& string, int8_t val);
	CryptoUtf16& operator<<(CryptoUtf16& string, int16_t val);
	CryptoUtf16& operator<<(CryptoUtf16& string, int32_t val);
	CryptoUtf16& operator<<(CryptoUtf16& string, int64_t val);
	CryptoUtf16& operator<<(CryptoUtf16& string, uint8_t val);
	//CryptoUtf16& operator<<(CryptoUtf16& string, uint16_t val);
	CryptoUtf16& operator<<(CryptoUtf16& string, uint32_t val);
	CryptoUtf16& operator<<(CryptoUtf16& string, uint64_t val);
	CryptoUtf16& operator<<(CryptoUtf16& string, const char* val);
	CryptoUtf16& operator<<(CryptoUtf16& string, const tsStringBase& val);
	CryptoUtf16& operator<<(CryptoUtf16& string, const CryptoUtf16& val);


#endif // __CRYPTOUTF16_H__
