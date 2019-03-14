#pragma once
#ifndef EVENTLOGEDITDLL_H
#define EVENTLOGEDITDLL_H

typedef struct _OFFSETBLOCK
{
	DWORD FileVersionMS;
	DWORD FileVersionLS;
	DWORD Offset[15];
} OFFSETBLOCK, *POFFSETBLOCK;

typedef int(__thiscall *EVENT_FILE_FULLFLUSH)(PVOID, ULONG_PTR);
typedef int(__thiscall *FILE_NOTIFYREADERS)(PVOID, ULONG_PTR);
typedef int(__thiscall *FILE_READFILEHEADER)(PVOID);
typedef int(__stdcall *UPDATECRC32)(PVOID, ULONG, ULONG);


// hxxps://github.com/libyal/libevtx/blob/master/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
#pragma pack(1)
typedef struct _ELFFILE_HEADER
{
	ULONG64 Signature;							// 0
	ULONG64 FirstChunkNumber;					// 8
	ULONG64 LastChunkNumber;					// 16
	ULONG64 NextRecordIdentifier;				// 24
	ULONG HeaderSize;							// 32
	WORD MinorVersion;							// 36
	WORD MajorVersion;							// 38
	WORD ChunkDataOffset;						// 40
	ULONG NumberOfChunks;						// 42
	UCHAR Unknown[74];							// 46
	ULONG FileFlags;							// 120
	ULONG Checksum;								// 124, CRC32 of the first 120 bytes of the file header
												// 128 ...
} ELFFILE_HEADER, *PELFFILE_HEADER;

typedef struct _CHUNK_HEADER
{
	ULONG64 Signature;							// 0
	ULONG64 FirstEventRecordNumber;				// 8
	ULONG64 LastEventRecordNumber;				// 16
	ULONG64 FirstEventRecorIdentifier;			// 24
	ULONG64 LastEventRecordIdentifier;			// 32
	ULONG HeaderSize;							// 40
	ULONG LastEventRecordDataOffset;			// 44
	ULONG FreeSpaceOffset;						// 48
	ULONG EventRecordsChunksum;					// 52
	UCHAR Unknown1[64];							// 56
	ULONG Unknown2;								// 120
	ULONG Checksum;								// 124, CRC32 of the first 120 bytes and bytes 128 to 512 of the chunk.
												// 128 ...
} CHUNK_HEADER, *PCHUNK_HEADER;

typedef struct _EVENT_RECORD
{
	ULONG Signature;							// 0
	ULONG Size;									// 4
	ULONG64 EventRecordIdentifier;				// 8
	ULONG64 WrittenDateAndTime;					// 16
												// 24, Event, Contains binary XML
} EVENT_RECORD, *PEVENT_RECORD;
#pragma pack()

#endif
