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

tsStringBase gOutputPath;
tsStringBase gPrefix;
tsStringBase gBuildType;

enum {
	OPT_HELP = 0, OPT_OUTPUT, OPT_BUILDTYPE, OPT_PREFIX
};

CSimpleOpt::SOption g_rgOptions1[] =
{
	{ OPT_HELP, "-?", SO_NONE },
	{ OPT_HELP, "-h", SO_NONE },
	{ OPT_HELP, "-help", SO_NONE },
	{ OPT_HELP, "--help", SO_NONE },
	{ OPT_OUTPUT, "-o", SO_REQ_SEP },
	{ OPT_OUTPUT, "--output", SO_REQ_SEP },
	{ OPT_BUILDTYPE, "-b", SO_REQ_SEP },
	{ OPT_BUILDTYPE, "--build", SO_REQ_SEP },
	{ OPT_PREFIX, "-p", SO_REQ_SEP },
	{ OPT_PREFIX, "--prefix", SO_REQ_SEP },
	SO_END_OF_OPTIONS
};

static void Usage()
{
	printf("USAGE: \n   -o=dir or --output=dir \n   -p=prefix or --prefix=prefix \n   -b=buildType or --build=buildtype    - where buildtype is MSSQL, SQLITE, ORACLE, MYSQL, SQL, H, CPP, CODE, ALL\n   fileToProcess [filetoprocess]*\n");
}

static std::vector<tsStringBase> SplitString(const tsStringBase& src, const tsStringBase& splitOnString)
{
	std::vector<tsStringBase> parts;
	char *start;
	tsStringBase m_sql(src);

	start = (char *)m_sql.c_str();
	while (start != NULL && *start)
	{
		char *end = strstr(start, splitOnString.c_str());

		if (end != NULL)
		{
			*end = 0;
		}

		parts.push_back(start);

		if (end != NULL)
			start = end + splitOnString.size();
		else
			start = NULL;
	}
	return parts;
}
static void SendOutputToFiles(std::shared_ptr<SQLHelper> builder, std::vector<tsStringBase> fileNames, const tsStringBase& schemaFilename, SQLHelper::SchemaPartType schemaPart)
{
	tsStringBase sql;

	sql = builder->BuildSchema(schemaFilename, schemaPart);

	std::vector<tsStringBase> parts = SplitString(sql, "<<<<NEXT FILE>>>>");

	for (int i = 0; i < (int)fileNames.size(); i++)
	{
		if ((int)parts.size() > i)
			xp_WriteText(fileNames[i], parts[i]);
	}
}

static tsStringBase ToLower(const tsStringBase& value)
{
	tsStringBase tmp(value);

	tmp.ToLower();
	return tmp;
}

static bool ProcessFile(const char *filename)
{

	std::shared_ptr<SQLHelper> builder;
	std::vector<tsStringBase> fileNames;

	try
	{
		if (gBuildType == "MSSQL" || gBuildType == "SQL" || gBuildType == "ALL")
		{
			builder = std::shared_ptr<SQLHelper>(dynamic_cast<SQLHelper*>(new SqlServerHelper()));
			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mssql.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AllParts);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mssql_dr.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::DropPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mssql_ct.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::CreateTablePart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mssql_ad.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddDataPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mssql_ak.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddKeysPart);
		}
		if (gBuildType == "SQLITE" || gBuildType == "SQL" || gBuildType == "ALL")
		{
			builder = std::shared_ptr<SQLHelper>(dynamic_cast<SQLHelper*>(new SqliteHelper()));
			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "sqlite.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AllParts);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "sqlite_dr.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::DropPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "sqlite_ct.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::CreateTablePart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "sqlite_ad.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddDataPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "sqlite_ak.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddKeysPart);
		}
		if (gBuildType == "ORACLE" || gBuildType == "SQL" || gBuildType == "ALL")
		{
			builder = std::shared_ptr<SQLHelper>(dynamic_cast<SQLHelper*>(new OracleHelper()));
			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "oracle.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AllParts);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "oracle_dr.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::DropPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "oracle_ct.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::CreateTablePart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "oracle_ad.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddDataPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "oracle_ak.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddKeysPart);
		}
		if (gBuildType == "MYSQL" || gBuildType == "SQL" || gBuildType == "ALL")
		{
			builder = std::shared_ptr<SQLHelper>(dynamic_cast<SQLHelper*>(new MySqlHelper()));
			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mysql.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AllParts);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mysql_dr.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::DropPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mysql_ct.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::CreateTablePart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mysql_ad.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddDataPart);

			fileNames.clear();
			fileNames.push_back(gOutputPath + ToLower(gPrefix) + "mysql_ak.sql");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AddKeysPart);
		}
		if (gBuildType == "H" || gBuildType == "CPP" || gBuildType == "CODE" || gBuildType == "ALL")
		{
			builder = std::shared_ptr<SQLHelper>(dynamic_cast<SQLHelper*>(new CppHelper(gBuildType != "CPP", gBuildType != "H")));
			fileNames.clear();
			if (gBuildType != "CPP")
				fileNames.push_back(gOutputPath + gPrefix + "_Data.h");
			if (gBuildType != "H")
				fileNames.push_back(gOutputPath + gPrefix + "_Data.cpp");
			SendOutputToFiles(builder, fileNames, filename, SQLHelper::AllParts);
		}
		printf("The output file is stored in '%s'.\n", gOutputPath.c_str());
		return true;
	}
	catch (std::exception& ex)
	{
		printf("ERROR:  %s\n", ex.what());
		return false;
	}
}

int main(int argc, char* argv[])
{
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
			else if (args.OptionId() == OPT_PREFIX)
			{
				gPrefix = args.OptionArg();
			}
			else if (args.OptionId() == OPT_BUILDTYPE)
			{
				gBuildType = args.OptionArg();
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

	gBuildType.ToUpper();
	if (gBuildType.size() == 0)
		gBuildType = "ALL";

	if (gBuildType != "MSSQL" && gBuildType != "SQLITE" && gBuildType != "ORACLE" && gBuildType != "MYSQL" && gBuildType != "SQL" && gBuildType != "H" && gBuildType != "CPP" && gBuildType != "CODE" && gBuildType != "ALL")
	{
		printf("The buildtype is not valid.\n");
		return 1;
	}

	if (gPrefix.size() == 0)
	{
		printf("You need to specify the prefix.\n");
		return 1;
	}

	try
	{
		for (int i = 0; i < args.FileCount(); i++)
		{
			if (!ProcessFile(args.File(i)))
				return 1;
		}
	}
	catch (std::exception& e)
	{
		printf("ERROR:  %s\n", e.what());
		return 1;
	}


	return 0;
}

