/*
*   comm.h - shared definitions for CommDriver v2 (manually mapped)
*   Communication via named shared memory section
*/
#pragma once

// Shared memory section name
// Kernel:   L"\\BaseNamedObjects\\Global\\ArcComm"
// Usermode: "Global\\ArcComm"

// Commands
#define CMD_IDLE           0
#define CMD_FIND_PROCESS   1
#define CMD_READ_MEMORY    2
#define CMD_WRITE_MEMORY   3
#define CMD_GET_PEB        4
#define CMD_BATCH_READ_U64 5    // batch read N u64 values: in=N addrs (N*8B), out=N u64 (N*8B)
#define CMD_PING           0xFF

// Max data buffer (64KB per request)
#define DATA_BUF_SIZE      0x10000

#pragma pack(push, 1)

typedef struct _COMM_SHARED {
    volatile LONG   ready;              // 1 = driver ready
    volatile LONG   command;            // client writes command, driver clears when done
    LONG            status;             // NTSTATUS result

    // Find process params
    CHAR            process_name[260];
    ULONG64         pid;
    ULONG64         cr3;

    // Read/Write memory params
    ULONG64         address;
    ULONG64         size;

    // PEB result
    ULONG64         peb_address;
    ULONG64         image_base;

    // Data buffer (read results / write source)
    UCHAR           data[DATA_BUF_SIZE];
} COMM_SHARED, *PCOMM_SHARED;

#pragma pack(pop)
