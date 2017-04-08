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

// SdkOptionParser2.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Nodes/Asn1DatasetNode.h"

tsStringBase gOutputPath;
tsStringBase gInputPath;
tsStringBase gExportPath;
bool gUseConst = false;

enum {
	OPT_HELP = 0, OPT_OUTPUT, OPT_EXPORTS, OPT_USE_CONST
};

CSimpleOpt::SOption g_rgOptions1[] =
{
	{ OPT_HELP, "-?", SO_NONE },
	{ OPT_HELP, "-h", SO_NONE },
	{ OPT_HELP, "-help", SO_NONE },
	{ OPT_HELP, "--help", SO_NONE },
	{ OPT_OUTPUT, "-o", SO_REQ_SEP },
	{ OPT_OUTPUT, "--output", SO_REQ_SEP },
	{ OPT_EXPORTS, "-e", SO_REQ_SEP },
	{ OPT_EXPORTS, "--exports", SO_REQ_SEP },
	{ OPT_USE_CONST, "-c", SO_NONE },
	{ OPT_USE_CONST, "--use-const", SO_NONE },
	SO_END_OF_OPTIONS
};

static void Usage()
{
	printf("USAGE:  -o=dir or --output=dir -e=dir or --exports=dir fileToProcess   -c or --use-const   [filetoprocess]*\n");
}

static void ProcessFile(const char *filename)
{
	std::shared_ptr<Asn1DatasetNode> data = Asn1DatasetNode::CreateAsn1DatasetNode();
	tsStringBase contents;
	tsStringBase Results;
	tsStringBase file, ext;

	if (!xp_ReadAllText(filename, contents))
	{
		printf("Unable to open file %s\n", filename);
		return;
	}
	data->OutputPath = gOutputPath;
	xp_SplitPath(filename, gInputPath, file, ext);

	if (!data->Parse(contents, Results, false, false))
	{
		tsStringBase errors = data->Errors();
		printf("The contents of the file %s could not be processed.\n", filename);
		printf("%s\n", errors.c_str());
		return;
	}

	data->OutputPath = gOutputPath;
	if (!data->Validate())
	{
		printf("File %s aborted due to node validation failure.\n", filename);
		tsStringBase errors = data->Errors();
		printf("-------------Errors---------------\n%s\n-----------End Errors------------\n", errors.c_str());
	}
	else
	{
		if (!data->Process())
		{
			printf("The processing of file %s failed.\n", filename);
			tsStringBase errors = data->Errors();
			printf("-------------Errors---------------\n%s\n-----------End Errors------------\n", errors.c_str());
		}
	}
}

typedef struct builtins {
	const char* eleType;
	const char* cppType;
	const char* initializer;
	bool basicType;
	bool canEncode;
	bool useNumberHandling;
	bool setElementType;
	bool needsChoiceField;
	bool hasSubMetafields;
	bool isSequence;
	const char* metadataType;
	const char* toOptionalJsonLine;
	const char* toJsonLine;
	const char* fromJsonLine;
	const char* fromJsonLineForArray;
	const char* classInitializer;
	const char* elementTag;
	const char* listIteratorType;
} builtins;

static builtins gBuiltins[] =
{
	{ "OID",			"tscrypto::tsCryptoData",		"",			 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_oid",			"obj.add(\"{JSONName}\", _{Name}.ToOIDString());",					"obj.add(\"{JSONName}\", _{Name}.ToOIDString());",					"_{Name}.FromOIDString(obj.AsString(\"{JSONName}\"));",											"tmp.FromOIDString(fld.AsString());",											"_{Name}({Initializer})",															"OID",				"tscrypto::tsCryptoData", },
	{ "OctetString",	"tscrypto::tsCryptoData",		"",			 true,  true,  false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_data",			"obj.add(\"{JSONName}\", _{Name}.ToBase64());",						"obj.add(\"{JSONName}\", _{Name}.ToBase64());",						"_{Name} = obj.AsString(\"{JSONName}\").Base64ToData();",										"tmp = fld.AsString().Base64ToData();",											"_{Name}(tscrypto::tsCryptoData(\"{Initializer}\", tscrypto::tsCryptoData::HEX))",	"Octet",			"tscrypto::tsCryptoData", },
	{ "Number",			"tscrypto::tsCryptoData",		"",			 true,  true,  true,  false, false, false, false, "tscrypto::Asn1Metadata2::tp_number",			"obj.add(\"{JSONName}\", _{Name}.ToBase64());",						"obj.add(\"{JSONName}\", _{Name}.ToBase64());",						"_{Name} = obj.AsString(\"{JSONName}\").Base64ToData();",										"tmp = fld.AsString().Base64ToData();",											"_{Name}(tscrypto::tsCryptoData(\"{Initializer}\", tscrypto::tsCryptoData::HEX))",	"Number",			"tscrypto::tsCryptoData", },
	{ "Bitstring",		"tscrypto::Asn1Bitstring",		"",			 true,  true,  false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_bits",			"obj.add(\"{JSONName}\", _{Name}.ToBase64());",						"obj.add(\"{JSONName}\", _{Name}.rawData().ToBase64());",			"_{Name}.rawData(obj.AsString(\"{JSONName}\").Base64ToData());",								"tmp.rawData(fld.AsString().Base64ToData());",									"_{Name}({Initializer})",															"BitString",		"tscrypto::Asn1Bitstring", },
	{ "Int8",			"int8_t",						"0",		 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_int8",			"obj.add(\"{JSONName}\", (int64_t)_{Name});",						"obj.add(\"{JSONName}\", (int64_t)_{Name});",						"_{Name} = (unsigned char)TsStrToInt64(obj.AsString(\"{JSONName}\"));",							"tmp = (unsigned char)TsStrToInt64(fld.AsString());",							"_{Name}({Initializer})",															"Number",			"int8_t", },
	{ "Char",			"char",							"0",		 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_char",			"obj.add(\"{JSONName}\", (int64_t)_{Name});",						"obj.add(\"{JSONName}\", (int64_t)_{Name});",						"_{Name} = (char)TsStrToInt64(obj.AsString(\"{JSONName}\"));",									"tmp = (char)TsStrToInt64(fld.AsString());",									"_{Name}({Initializer})",															"Number",			"char", },
	{ "Int16",			"int16_t",						"0",		 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_int16",			"obj.add(\"{JSONName}\", (int64_t)_{Name});",						"obj.add(\"{JSONName}\", (int64_t)_{Name});",						"_{Name} = (short)TsStrToInt64(obj.AsString(\"{JSONName}\"));",									"tmp = (short)TsStrToInt64(fld.AsString());",									"_{Name}({Initializer})",															"Number",			"int16_t", },
	{ "Int32",			"int32_t",						"0",		 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_int32",			"obj.add(\"{JSONName}\", (int64_t)_{Name});",						"obj.add(\"{JSONName}\", (int64_t)_{Name});",						"_{Name} = (int)TsStrToInt64(obj.AsString(\"{JSONName}\"));",									"tmp = (int)TsStrToInt64(fld.AsString());",										"_{Name}({Initializer})",															"Number",			"int32_t", },
	{ "Int64",			"int64_t",						"0",		 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_int64",			"obj.add(\"{JSONName}\", (int64_t)_{Name});",						"obj.add(\"{JSONName}\", (int64_t)_{Name});",						"_{Name} = TsStrToInt64(obj.AsString(\"{JSONName}\"));",										"tmp = TsStrToInt64(fld.AsString());",											"_{Name}({Initializer})",															"Number",			"int64_t", },
	{ "String",			"tscrypto::tsCryptoStringBase",	"",			 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_string",			"obj.add(\"{JSONName}\", _{Name});",								"obj.add(\"{JSONName}\", _{Name});",								"_{Name} = obj.AsString(\"{JSONName}\");",														"tmp = fld.AsString();",														"_{Name}({Initializer})",															"UTF8String",		"tscrypto::tsCryptoStringBase", },
	{ "TeletexString",	"tscrypto::tsCryptoStringBase",	"",			 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_string",			"obj.add(\"{JSONName}\", _{Name});",								"obj.add(\"{JSONName}\", _{Name});",								"_{Name} = obj.AsString(\"{JSONName}\");",														"tmp = fld.AsString();",														"_{Name}({Initializer})",															"T61String",		"tscrypto::tsCryptoStringBase", },
	{ "T61String",		"tscrypto::tsCryptoStringBase",	"",			 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_string",			"obj.add(\"{JSONName}\", _{Name});",								"obj.add(\"{JSONName}\", _{Name});",								"_{Name} = obj.AsString(\"{JSONName}\");",														"tmp = fld.AsString();",														"_{Name}({Initializer})",															"T61String",		"tscrypto::tsCryptoStringBase", },
	{ "PrintableString","tscrypto::tsCryptoStringBase",	"",			 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_string",			"obj.add(\"{JSONName}\", _{Name});",								"obj.add(\"{JSONName}\", _{Name});",								"_{Name} = obj.AsString(\"{JSONName}\");",														"tmp = fld.AsString();",														"_{Name}({Initializer})",															"PrintableString",	"tscrypto::tsCryptoStringBase", },
	{ "BMPString",		"tscrypto::tsCryptoStringBase",	"",			 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_string",			"obj.add(\"{JSONName}\", _{Name});",								"obj.add(\"{JSONName}\", _{Name});",								"_{Name} = obj.AsString(\"{JSONName}\");",														"tmp = fld.AsString();",														"_{Name}({Initializer})",															"BmpString",		"tscrypto::tsCryptoStringBase", },
	{ "UniversalString","tscrypto::tsCryptoStringBase",	"",			 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_string",			"obj.add(\"{JSONName}\", _{Name});",								"obj.add(\"{JSONName}\", _{Name});",								"_{Name} = obj.AsString(\"{JSONName}\");",														"tmp = fld.AsString();",														"_{Name}({Initializer})",															"UniversalString",	"tscrypto::tsCryptoStringBase", },
	{ "UTF8String",		"tscrypto::tsCryptoStringBase",	"",			 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_string",			"obj.add(\"{JSONName}\", _{Name});",								"obj.add(\"{JSONName}\", _{Name});",								"_{Name} = obj.AsString(\"{JSONName}\");",														"tmp = fld.AsString();",														"_{Name}({Initializer})",															"UTF8String",		"tscrypto::tsCryptoStringBase", },
	{ "IA5String",		"tscrypto::tsCryptoStringBase",	"",			 true,  false, false, true,  false, false, false, "tscrypto::Asn1Metadata2::tp_string",			"obj.add(\"{JSONName}\", _{Name});",								"obj.add(\"{JSONName}\", _{Name});",								"_{Name} = obj.AsString(\"{JSONName}\");",														"tmp = fld.AsString();",														"_{Name}({Initializer})",															"IA5String",		"tscrypto::tsCryptoStringBase", },
	{ "VisibleString",	"tscrypto::tsCryptoStringBase",	"",			 true,  false, false, true,  false, false, false, "tscrypto::Asn1Metadata2::tp_string",			"obj.add(\"{JSONName}\", _{Name});",								"obj.add(\"{JSONName}\", _{Name});",								"_{Name} = obj.AsString(\"{JSONName}\");",														"tmp = fld.AsString();",														"_{Name}({Initializer})",															"VisibleString",	"tscrypto::tsCryptoStringBase", },
	{ "Bool",			"bool",							"false",	 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_bool",			"obj.add(\"{JSONName}\", _{Name});",								"obj.add(\"{JSONName}\", _{Name});",								"_{Name} = obj.AsBool(\"{JSONName}\", {Initializer});",											"tmp = fld.AsBool({Initializer});",												"_{Name}({Initializer})",															"Boolean",			"bool", },
	{ "Guid",			"GUID",							"GUID_NULL", true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_guid",			"obj.add(\"{JSONName}\", tscrypto::TSGuidToString(_{Name}));",		"obj.add(\"{JSONName}\", tscrypto::TSGuidToString(_{Name}));",		"_{Name} = tscrypto::TSStringToGuid(obj.AsString(\"{JSONName}\"));",							"tmp = tscrypto::TSStringToGuid(fld.AsString());",								"_{Name}({Initializer})",															"Octet",			"GUID", },
	{ "Date",			"tscrypto::tsCryptoDate",		"",			 true,  false, false, true,  false, false, false, "tscrypto::Asn1Metadata2::tp_date",			"obj.add(\"{JSONName}\", ZuluToDateTime(_{Name}.AsZuluTime()));",	"obj.add(\"{JSONName}\", ZuluToDateTime(_{Name}.AsZuluTime()));",	"_{Name} = tscrypto::tsCryptoDate(obj.AsString(\"{JSONName}\"), tscrypto::tsCryptoDate::ODBC);","tmp = tscrypto::tsCryptoDate(fld.AsString(), tscrypto::tsCryptoDate::ODBC);",	"_{Name}({Initializer})",															"GeneralizedTime",	"tscrypto::tsCryptoDate", },
	{ "GeneralizedTime","tscrypto::tsCryptoDate",		"",			 true,  false, false, true,  false, false, false, "tscrypto::Asn1Metadata2::tp_date",			"obj.add(\"{JSONName}\", ZuluToDateTime(_{Name}.AsZuluTime()));",	"obj.add(\"{JSONName}\", ZuluToDateTime(_{Name}.AsZuluTime()));",	"_{Name} = tscrypto::tsCryptoDate(obj.AsString(\"{JSONName}\"), tscrypto::tsCryptoDate::ODBC);","tmp = tscrypto::tsCryptoDate(fld.AsString(), tscrypto::tsCryptoDate::ODBC);",	"_{Name}({Initializer})",															"GeneralizedTime",	"tscrypto::tsCryptoDate", },
	{ "UTCTime",		"tscrypto::tsCryptoDate",		"",			 true,  false, false, true,  false, false, false, "tscrypto::Asn1Metadata2::tp_date",			"obj.add(\"{JSONName}\", ZuluToDateTime(_{Name}.AsZuluTime()));",	"obj.add(\"{JSONName}\", ZuluToDateTime(_{Name}.AsZuluTime()));",	"_{Name} = tscrypto::tsCryptoDate(obj.AsString(\"{JSONName}\"), tscrypto::tsCryptoDate::ODBC);","tmp = tscrypto::tsCryptoDate(fld.AsString(), tscrypto::tsCryptoDate::ODBC);",	"_{Name}({Initializer})",															"UTCTime",			"tscrypto::tsCryptoDate", },
	{ "Enum",			"enum",							"0",		 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_int32",			"obj.add(\"{JSONName}\", (int64_t)_{Name});",						"obj.add(\"{JSONName}\", (int64_t)_{Name});",						"_{Name} = ({CppType})TsStrToInt64(obj.AsString(\"{JSONName}\"));",								"tmp = ({CppType})TsStrToInt64(fld.AsString());",								"_{Name}({Initializer})",															"Enumerated",		"enum", },
	{ "Null",			"tscrypto::Asn1NULL",			"",			 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_null",			"obj.add(\"{JSONName}\");",											"obj.add(\"{JSONName}\");",											"/* null field */",																				"/* null field */",																"_{Name}({Initializer})",															"NULL",				"tscrypto::Asn1NULL", },
	{ "Any",			"tscrypto::Asn1AnyField",		"",			 true,  true,  false, false, false, true,  false, "tscrypto::Asn1Metadata2::tp_any",			"obj.add(\"{JSONName}\", _{Name}.toJSON());",						"obj.add(\"{JSONName}\", _{Name}.toJSON());",						"_{Name}.fromJSON(obj.AsObject(\"{JSONName}\"));",												"tmp.fromJSON(fld.AsObject());",												"_{Name}({Initializer})",															"",					"tscrypto::Asn1AnyField", },
	{ "NamedInt",		"NamedInt",						"0",		 true,  false, false, false, false, false, false, "tscrypto::Asn1Metadata2::tp_int32",			"obj.add(\"{JSONName}\", (int64_t)_{Name});",						"obj.add(\"{JSONName}\", (int64_t)_{Name});",						"_{Name} = ({CppType})TsStrToInt64(obj.AsString(\"{JSONName}\"));",								"tmp = ({CppType})TsStrToInt64(fld.AsString());",								"_{Name}({Initializer})",															"Enumerated",		"tscrypto::NamedInt", },

	{ "Sequence",		"tscrypto::Asn1DataBaseClass",	"",			 false,  false, false, false, false, true,  true,  "tscrypto::Asn1Metadata2::tp_struct",		"obj.add(\"{JSONName}\", _{Name}.toJSON());",						"obj.add(\"{JSONName}\", (({struct}*)_{Name}.get())->toJSON());",	"",																								"",																				"_{Name}(nullptr)",																	"Sequence",			"std::shared_ptr<tscrypto::Asn1DataBaseClass>", },
	{ "SequenceField",	"tscrypto::Asn1DataBaseClass",	"",			 false,  false, false, false, false, true,  true,  "tscrypto::Asn1Metadata2::tp_struct",		"obj.add(\"{JSONName}\", _{Name}.toJSON());",						"obj.add(\"{JSONName}\", (({struct}*)_{Name}.get())->toJSON());",	"",																								"",																				"_{Name}(nullptr)",																	"Sequence",			"std::shared_ptr<tscrypto::Asn1DataBaseClass>", },
	{ "Set",			"tscrypto::Asn1DataBaseClass",	"",			 false,  false, false, false, false, true,  true,  "tscrypto::Asn1Metadata2::tp_set",			"obj.add(\"{JSONName}\", _{Name}.toJSON());",						"obj.add(\"{JSONName}\", (({struct}*)_{Name}.get())->toJSON());",	"",																								"",																				"_{Name}(nullptr)",																	"Set",				"std::shared_ptr<tscrypto::Asn1DataBaseClass>", },
	{ "Choice",			"tscrypto::Asn1DataBaseClass",	"",			 false,  false, false, false, false, true,  true,  "tscrypto::Asn1Metadata2::tp_choice",		"obj.add(\"{JSONName}\", _{Name}.toJSON());",						"obj.add(\"{JSONName}\", (({struct}*)_{Name}.get())->toJSON());",	"",																								"",																				"_{Name}({Initializer})",															"",					"std::shared_ptr<tscrypto::Asn1DataBaseClass>", },
	{ "ChoiceField",	"tscrypto::Asn1DataBaseClass",	"",			 false,  false, false, false, false, true,  true,  "tscrypto::Asn1Metadata2::tp_choice",		"obj.add(\"{JSONName}\", _{Name}.toJSON());",						"obj.add(\"{JSONName}\", (({struct}*)_{Name}.get())->toJSON());",	"",																								"",																				"_{Name}({Initializer})",															"",					"std::shared_ptr<tscrypto::Asn1DataBaseClass>", },
	{ "Version",		"",								"",			 false,  false, false, false, false, false, false, "",											"",																	"",																	"",																								"",																				"",																					"Sequence",			"", },
	{ "Part",			"",								"",			 false,  false, false, false, false, false, false, "",											"",																	"",																	"",																								"",																				"",																					"Sequence",			"", },
	{ "SequencePart",	"",								"",			 false,  false, false, false, false, false, false, "",											"",																	"",																	"",																								"",																				"",																					"Sequence",			"", },
	{ "SequenceOf",		"tscrypto::Asn1DataBaseClass",	"",			 false,  false, false, false, false, true,  true,  "tscrypto::Asn1Metadata2::tp_sequenceOfRef",	"obj.add(\"{JSONName}\", _{Name}.toJSON());",						"obj.add(\"{JSONName}\", (({struct}*)_{Name}.get())->toJSON());",	"",																								"",																				"",																					"Sequence",			"std::shared_ptr<tscrypto::Asn1DataBaseClass>", },
	{ "SequenceOfField","tscrypto::Asn1DataBaseClass",	"",			 false,  false, false, false, false, true,  true,  "tscrypto::Asn1Metadata2::tp_sequenceOfRef",	"obj.add(\"{JSONName}\", _{Name}.toJSON());",						"obj.add(\"{JSONName}\", (({struct}*)_{Name}.get())->toJSON());",	"",																								"",																				"",																					"Sequence",			"std::shared_ptr<tscrypto::Asn1DataBaseClass>", },
};

bool isBasicEleType(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.basicType;
	}
	return false;
}

bool isSequence(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.isSequence;
	}
	return false;
}

bool getNeedsChoiceField(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.needsChoiceField;
	}
	return false;
}

bool hasSubMetafields(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.hasSubMetafields;
	}
	return false;
}

bool getCanEncode(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.canEncode;
	}
	return false;
}

bool getNeedsSetElementType(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.setElementType;
	}
	return false;
}

bool getUseNumberHandling(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.useNumberHandling;
	}
	return false;
}

const char* getMetadataType(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.metadataType;
	}
	return "";
}

const char* getListIteratorType(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.listIteratorType;
	}
	return "";
}

const char* getCppType(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.cppType;
	}
	return "";
}

const char* getInitializer(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.initializer;
	}
	return "";
}

const char* getToOptionalJsonLine(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.toOptionalJsonLine;
	}
	return "";
}

const char* getToJsonLine(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.toJsonLine;
	}
	return "";
}

const char* getFromJsonLine(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.fromJsonLine;
	}
	return "";
}

const char* getFromJsonLineForArray(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.fromJsonLineForArray;
	}
	return "";
}

const char* getClassInitializer(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.classInitializer;
	}
	return "";
}

const char* getElementTag(const tsStringBase& eleType)
{
	for (auto& b : gBuiltins)
	{
		if (eleType == b.eleType)
			return b.elementTag;
	}
	return "";
}

int main(int argc, char* argv[])
{
	//std::cout << std::boolalpha;
	//std::cout << "'tsCryptoData' is standardLayout:  " << std::is_standard_layout<tsCryptoData>::value << std::endl;
	//std::cout << "'tsCryptoString' is standardLayout:  " << std::is_standard_layout<tsCryptoString>::value << std::endl;
	//std::cout << "'tsCryptoDate' is standardLayout:  " << std::is_standard_layout<tsCryptoDate>::value << std::endl;
	//std::cout << "'tsCryptoData' is standardLayout:  " << std::is_standard_layout<tsCryptoData>::value << std::endl;
	//std::cout << "'tsCryptoData' is standardLayout:  " << std::is_standard_layout<tsCryptoData>::value << std::endl;
	//std::cout << "'tsCryptoData' is standardLayout:  " << std::is_standard_layout<tsCryptoData>::value << std::endl;



	CSimpleOpt args(argc, argv, g_rgOptions1, SO_O_NOERR | SO_O_ICASE | SO_O_SHORTARG);

	while (args.Next())
	{
		if (args.LastError() == SO_SUCCESS)
		{
			if (args.OptionId() == OPT_HELP)
			{
				Usage();
				return 0;
			}
			else if (args.OptionId() == OPT_OUTPUT)
			{
				gOutputPath = args.OptionArg();
			}
			else if (args.OptionId() == OPT_EXPORTS)
			{
				gExportPath = args.OptionArg();
				if (gExportPath.size() > 0 && gExportPath[gExportPath.size() - 1] != XP_PATH_SEP_CHAR)
					gExportPath.append(XP_PATH_SEP_STR);
			}
			else if (args.OptionId() == OPT_USE_CONST)
			{
				gUseConst = true;
			}
		}
	}

	if (args.FileCount() == 0)
	{
		Usage();
		return 1;
	}

	if (gOutputPath.size() == 0)
	{
#ifdef _WIN32
		gOutputPath = "C:\\TecSec\\Logs\\";
#else
		gOutputPath = "~/";
#endif
	}

	if (gOutputPath[gOutputPath.size() - 1] != XP_PATH_SEP_CHAR)
	{
		gOutputPath += XP_PATH_SEP_STR;
	}

	if (!xp_FileExists(gOutputPath))
	{
		xp_CreateDirectory(gOutputPath, false);
	}
	if (gExportPath.size() > 0)
	{
		if (!xp_FileExists(gExportPath))
		{
			xp_CreateDirectory(gExportPath, false);
		}
	}

	try
	{
		for (int i = 0; i < args.FileCount(); i++)
		{
			ProcessFile(args.File(i));
		}
	}
	catch (std::exception& e)
	{
		printf("ERROR:  %s\n", e.what());
		return 1;
	}


	return 0;
}

