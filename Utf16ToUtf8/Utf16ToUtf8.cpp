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

// hex2file.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

int main(int argc, const char* argv[])
{
	tsData data;
	tsStringBase outData;

    if ( argc != 2 && argc != 3 )
    {
        printf ("Utf16ToUtf8 <file> [<outfile>]\n"
            "Utf16ToUtf8 reads a file as Utf16LE and converts it into Utf8.\n");
        return 1;
    }
	if (!xp_ReadAllBytes(argv[1], data))
	{
		printf("Unable to open the input file '%s'\n", argv[1]);
	}
	if (data.hasEncodingBOM())
	{
		outData = data.ToUtf8String();
	}
	else
	{
		CryptoUtf16 tmp((const ts_wchar*)data.data(), data.size() / sizeof(ts_wchar));
		outData = tmp.toUtf8();
	}

	tsData outBuffer;
	outBuffer.UTF8FromString(outData);
	if (argc == 3)
	{
		if (!xp_WriteBytes(argv[2], outBuffer))
		{
			printf("Unable to save to the output file '%s'\n", argv[2]);
			return 1;
		}
	}
	else
	{
		if (!xp_WriteBytes(argv[1], outBuffer))
		{
			printf("Unable to save to the output file '%s'\n", argv[1]);
			return 1;
		}
	}
	return 0;
}

