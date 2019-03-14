#pragma once
#ifndef COMMON_H
#define COMMON_H

#define SUCCESSED 0
#define FAILURE 1
#define FAILURE_OBJECT_NOT_FOUND 2
#define FAILURE_NOT_MAP_FILE 3
#define FAILURE_INVALID_RECORD 4

typedef struct _TARGET_RECORD
{
	ULONG64 RecordNumber;
	WCHAR EventLogName[0x50];
} TARGET_RECORD, *PTARGET_RECORD;

#endif
