/*
*   driver.c - CommDriver v3 (manually mapped, physical memory reads)
*
*   Loaded via kdmapper — no DriverObject, no device, no IOCTL.
*   Communication via named section (shared memory) polled by a system thread.
*
*   Memory reads use CR3 page table walking + MmCopyMemory (physical).
*   This bypasses EAC's protection on MmCopyVirtualMemory.
*
*   IMPORTANT: No __try/__except — SEH does NOT work in manually mapped drivers.
*/
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "../include/comm.h"

/* ── Forward declarations ── */

NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS  SourceProcess,
    PVOID      SourceAddress,
    PEPROCESS  TargetProcess,
    PVOID      TargetAddress,
    SIZE_T     BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T    ReturnSize
);

NTKERNELAPI PUCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);

NTKERNELAPI NTSTATUS NTAPI PsLookupProcessByProcessId(
    HANDLE    ProcessId,
    PEPROCESS *Process
);

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);

/* ── PFN CR3 bypass structures ── */

/*
 * Technique from UC: scan MmPfnDatabase to find the REAL user-mode CR3.
 * This bypasses KVAS completely — we get the page directory that actually
 * maps user pages, not the kernel-only EPROCESS+0x28.
 *
 * Flow: KeCapturePersistentThreadState -> KDDEBUGGER_DATA64 -> MmPfnDatabase + PteBase
 *       Then scan all PFNs to find one whose pte_address matches the process PXE base
 *       and whose flags contain an encrypted EPROCESS matching our target.
 */

#define KDDEBUGGER_DATA_OFFSET 0x2080   /* 64-bit */
#define DUMP_BLOCK_SIZE        0x40000  /* 64-bit */

typedef struct _MMPFN_ENTRY {
    ULONG64 flags;
    ULONG64 pte_address;
    ULONG64 unused1;
    ULONG64 unused2;
    ULONG64 unused3;
    ULONG64 unused4;
} MMPFN_ENTRY;  /* 0x30 bytes per PFN entry */

/* We only need a few fields from KDDEBUGGER_DATA64 */
typedef struct _KD_DEBUGGER_DATA_PARTIAL {
    UCHAR pad[0x78];        /* 0x00-0x77: Header + misc */
    ULONG64 MmPfnDatabase;  /* 0x78 (offset 0xC0 in full struct but we account for list header) */
} KD_DEBUGGER_DATA_PARTIAL;

/* Forward declare KeCapturePersistentThreadState */
NTKERNELAPI VOID NTAPI KeCapturePersistentThreadState(
    PCONTEXT Context,
    PKTHREAD Thread,
    ULONG BugCheckCode,
    ULONG BugCheckParameter1,
    ULONG BugCheckParameter2,
    ULONG BugCheckParameter3,
    ULONG BugCheckParameter4,
    PVOID DumpHeader
);

/* ── Globals ── */

static PCOMM_SHARED   g_shared = NULL;
static HANDLE         g_section = NULL;
static HANDLE         g_thread_handle = NULL;
static volatile LONG  g_stop = 0;
static ULONG64        g_target_pid = 0;
static ULONG64        g_target_cr3 = 0;
static PEPROCESS      g_target_process = NULL;  /* Referenced PEPROCESS for fallback reads */
static volatile LONG  g_cr3_works = 0;          /* 1 = CR3 page walk validated, 0 = use fallback */

/* PFN scan globals */
static volatile ULONG64 g_MmPfnDatabase = 0;
static volatile ULONG64 g_PXE_BASE = 0;
static volatile ULONG64 g_pte_idx = 0;
static volatile LONG     g_pfn_initialized = 0;

/* Pre-allocated kernel buffer */
static PVOID          g_temp_buf = NULL;
#define TEMP_BUF_SIZE DATA_BUF_SIZE

/* ── Physical memory read via MmCopyMemory ── */

static NTSTATUS
read_physical(ULONG64 phys_addr, PVOID buffer, SIZE_T size)
{
    MM_COPY_ADDRESS addr;
    SIZE_T copied = 0;

    addr.PhysicalAddress.QuadPart = (LONGLONG)phys_addr;
    return MmCopyMemory(buffer, addr, size, MM_COPY_MEMORY_PHYSICAL, &copied);
}

/* ── PFN-based CR3 discovery ── */

/*
 * Initialize PFN database globals using KeCapturePersistentThreadState.
 * This gives us MmPfnDatabase and PteBase from the kernel debugger data block.
 */
static void
init_pfn_cr3(void)
{
    CONTEXT ctx;
    PVOID dump_header;
    ULONG64 pte_base, pde_base, ppe_base, pxe_base;

    if (InterlockedCompareExchange(&g_pfn_initialized, 1, 0) != 0)
        return;  /* Already initialized */

    ctx.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&ctx);

    dump_header = ExAllocatePoolWithTag(NonPagedPool, DUMP_BLOCK_SIZE, 'crPF');
    if (!dump_header)
    {
        DbgPrintEx(0, 0, "[comm] PFN init: failed to allocate dump header\n");
        InterlockedExchange(&g_pfn_initialized, 0);
        return;
    }

    KeCapturePersistentThreadState(&ctx, NULL, 0, 0, 0, 0, 0, dump_header);

    /*
     * KDDEBUGGER_DATA64 is at offset KDDEBUGGER_DATA_OFFSET in the dump header.
     * Field offsets in KDDEBUGGER_DATA64 (from wdbgexts.h):
     *   +0xC0  (192) = MmPfnDatabase (ULONG64 — pointer to the database)
     *   +0x360 (864) = PteBase (ULONG64)
     */
    PUCHAR kd_data = (PUCHAR)dump_header + KDDEBUGGER_DATA_OFFSET;

    /* MmPfnDatabase: value at offset 0xC0 is a POINTER — dereference it */
    ULONG64 pfn_ptr = *(PULONG64)(kd_data + 0xC0);
    /* PteBase: value at offset 0x360 */
    pte_base = *(PULONG64)(kd_data + 0x360);

    ExFreePoolWithTag(dump_header, 'crPF');

    if (pfn_ptr == 0 || pte_base == 0)
    {
        DbgPrintEx(0, 0, "[comm] PFN init: MmPfnDatabase=0x%llx PteBase=0x%llx — INVALID\n",
            pfn_ptr, pte_base);
        InterlockedExchange(&g_pfn_initialized, 0);
        return;
    }

    /* MmPfnDatabase is a pointer to the actual database address */
    if (MmIsAddressValid((PVOID)pfn_ptr))
        g_MmPfnDatabase = *(PULONG64)pfn_ptr;
    else
        g_MmPfnDatabase = pfn_ptr;  /* Already the address */

    /* Calculate PXE base from PTE base (4-level page table hierarchy) */
    pde_base = pte_base + ((pte_base & 0xFFFFFFFFFFFFULL) >> 9);
    ppe_base = pte_base + ((pde_base & 0xFFFFFFFFFFFFULL) >> 9);
    pxe_base = pte_base + ((ppe_base & 0xFFFFFFFFFFFFULL) >> 9);

    g_PXE_BASE = pxe_base;
    g_pte_idx = (pte_base >> 39) - 0x1FFFE00ULL;

    DbgPrintEx(0, 0, "[comm] PFN init OK: MmPfnDatabase=0x%llx PteBase=0x%llx PXE_BASE=0x%llx idx=0x%llx\n",
        g_MmPfnDatabase, pte_base, g_PXE_BASE, g_pte_idx);
}

/*
 * Scan PFN database to find the user-mode CR3 for a given process.
 * This bypasses KVAS by finding the actual page directory used for user pages.
 */
static ULONG64
get_cr3_from_pfn(ULONG pid, const char *target_name)
{
    PHYSICAL_MEMORY_RANGE *mem_ranges;
    ULONG64 dir_base = 0;
    ULONG64 cr3_pte_base;
    ULONG64 start_pfn, end_pfn, pfn;
    int i;

    if (g_MmPfnDatabase == 0 || g_PXE_BASE == 0)
    {
        init_pfn_cr3();
        if (g_MmPfnDatabase == 0 || g_PXE_BASE == 0)
        {
            DbgPrintEx(0, 0, "[comm] PFN scan: not initialized\n");
            return 0;
        }
    }

    mem_ranges = MmGetPhysicalMemoryRanges();
    if (!mem_ranges)
    {
        DbgPrintEx(0, 0, "[comm] PFN scan: MmGetPhysicalMemoryRanges failed\n");
        return 0;
    }

    cr3_pte_base = g_pte_idx * 8 + g_PXE_BASE;
    DbgPrintEx(0, 0, "[comm] PFN scan: target='%s' cr3_pte_base=0x%llx\n",
        target_name, cr3_pte_base);

    for (i = 0; mem_ranges[i].BaseAddress.QuadPart != 0 || mem_ranges[i].NumberOfBytes.QuadPart != 0; i++)
    {
        start_pfn = mem_ranges[i].BaseAddress.QuadPart >> 12;
        end_pfn = start_pfn + (mem_ranges[i].NumberOfBytes.QuadPart >> 12);

        for (pfn = start_pfn; pfn < end_pfn; pfn++)
        {
            MMPFN_ENTRY *entry = (MMPFN_ENTRY *)(g_MmPfnDatabase + 0x30 * pfn);

            /* Safety check — is the MMPFN entry accessible? */
            if (!MmIsAddressValid(entry))
                continue;

            if (entry->flags == 0 || entry->flags == 1)
                continue;
            if (entry->pte_address != cr3_pte_base)
                continue;

            /* Decrypt EPROCESS from flags field */
            ULONG64 eproc_addr = ((entry->flags | 0xF000000000000000ULL) >> 0xd) | 0xFFFF000000000000ULL;

            if (!MmIsAddressValid((PVOID)eproc_addr))
                continue;

            /* Check process name */
            PUCHAR proc_name = PsGetProcessImageFileName((PEPROCESS)eproc_addr);
            if (proc_name && _stricmp((const char *)proc_name, target_name) == 0)
            {
                dir_base = pfn << 12;
                DbgPrintEx(0, 0, "[comm] PFN scan: FOUND CR3=0x%llx for '%s' (PFN=0x%llx EPROCESS=0x%llx)\n",
                    dir_base, target_name, pfn, eproc_addr);
                goto done;
            }
        }
    }

    DbgPrintEx(0, 0, "[comm] PFN scan: no matching CR3 found for '%s'\n", target_name);

done:
    ExFreePool(mem_ranges);
    return dir_base;
}

/* ── CR3 page table walk: virtual → physical ── */

static ULONG64
virt_to_phys(ULONG64 cr3, ULONG64 virt_addr)
{
    ULONG64 entry;
    NTSTATUS status;

    /* PML4 */
    ULONG64 pml4_idx = (virt_addr >> 39) & 0x1FF;
    status = read_physical((cr3 & ~0xFFFULL) + pml4_idx * 8, &entry, sizeof(entry));
    if (!NT_SUCCESS(status) || !(entry & 1))
        return 0;

    /* PDPT */
    ULONG64 pdpt_idx = (virt_addr >> 30) & 0x1FF;
    status = read_physical((entry & 0x000FFFFFFFFFF000ULL) + pdpt_idx * 8, &entry, sizeof(entry));
    if (!NT_SUCCESS(status) || !(entry & 1))
        return 0;
    if (entry & 0x80) /* 1GB page */
        return (entry & 0x000FFFFFC0000000ULL) | (virt_addr & 0x3FFFFFFFULL);

    /* PD */
    ULONG64 pd_idx = (virt_addr >> 21) & 0x1FF;
    status = read_physical((entry & 0x000FFFFFFFFFF000ULL) + pd_idx * 8, &entry, sizeof(entry));
    if (!NT_SUCCESS(status) || !(entry & 1))
        return 0;
    if (entry & 0x80) /* 2MB page */
        return (entry & 0x000FFFFFFFE00000ULL) | (virt_addr & 0x1FFFFFULL);

    /* PT */
    ULONG64 pt_idx = (virt_addr >> 12) & 0x1FF;
    status = read_physical((entry & 0x000FFFFFFFFFF000ULL) + pt_idx * 8, &entry, sizeof(entry));
    if (!NT_SUCCESS(status) || !(entry & 1))
        return 0;

    return (entry & 0x000FFFFFFFFFF000ULL) | (virt_addr & 0xFFFULL);
}

/* ── Forward declarations ── */
static NTSTATUS read_process_memory(ULONG64 cr3, ULONG64 address, PVOID buffer, ULONG64 size);

/* ── Process helpers ── */

/*
 * Find the correct CR3 for user-mode page table by scanning EPROCESS
 * and validating with a known address (ImageBase should have MZ header).
 */
static ULONG64
find_user_cr3(PEPROCESS process, ULONG64 known_base)
{
    /*
     * Windows 11 24H2 (26200+) EPROCESS layout:
     *   0x28  = DirectoryTableBase (kernel CR3 when KVAS active)
     *   0x280 = UserDirectoryTableBase (Win10/11 pre-24H2)
     *   0x388 = UserDirectoryTableBase (some Win11 builds)
     *
     * With KVAS (Kernel Virtual Address Shadow), EPROCESS+0x28 is the
     * KERNEL page table. The USER page table is at a different offset
     * and typically has bit 1 cleared. We need the user CR3.
     *
     * Strategy: try known offsets, then try KVAS variants (toggle bit 1),
     * then brute force EPROCESS up to 0xB00.
     */
    ULONG offsets_to_try[] = { 0x280, 0x388, 0x28, 0x3B8, 0x580 };
    ULONG i;
    USHORT sig;
    ULONG64 cr3, test_cr3, phys;
    NTSTATUS status;

    DbgPrintEx(0, 0, "[comm] find_user_cr3: known_base=0x%llx\n", known_base);

    /* Try common known offsets first */
    for (i = 0; i < 5; i++)
    {
        cr3 = *(PULONG64)((PUCHAR)process + offsets_to_try[i]);

        /* Accept page-aligned OR with KVAS bits (low 3 bits may be set) */
        if (cr3 < 0x1000 || cr3 > 0x20000000000ULL)
            continue;

        /* Mask off low 12 bits for page table walking */
        ULONG64 clean_cr3 = cr3 & ~0xFFFULL;
        if (clean_cr3 < 0x1000)
            continue;

        DbgPrintEx(0, 0, "[comm]   EPROCESS+0x%x = 0x%llx (clean=0x%llx)\n",
            offsets_to_try[i], cr3, clean_cr3);

        /* Try clean CR3 */
        phys = virt_to_phys(clean_cr3, known_base);
        if (phys != 0)
        {
            sig = 0;
            status = read_physical(phys, &sig, sizeof(sig));
            DbgPrintEx(0, 0, "[comm]     clean -> phys=0x%llx sig=0x%x\n", phys, sig);
            if (NT_SUCCESS(status) && sig == 0x5A4D)
            {
                DbgPrintEx(0, 0, "[comm] User CR3 at EPROCESS+0x%x = 0x%llx\n",
                    offsets_to_try[i], clean_cr3);
                return clean_cr3;
            }
        }
        else
        {
            DbgPrintEx(0, 0, "[comm]     clean -> virt_to_phys failed\n");
        }

        /* KVAS: try with bit 1 toggled (user/kernel page table switch) */
        test_cr3 = clean_cr3 ^ 0x2;
        if (test_cr3 >= 0x1000)
        {
            phys = virt_to_phys(test_cr3, known_base);
            if (phys != 0)
            {
                sig = 0;
                status = read_physical(phys, &sig, sizeof(sig));
                DbgPrintEx(0, 0, "[comm]     kvas(0x%llx) -> phys=0x%llx sig=0x%x\n",
                    test_cr3, phys, sig);
                if (NT_SUCCESS(status) && sig == 0x5A4D)
                {
                    DbgPrintEx(0, 0, "[comm] User CR3 at EPROCESS+0x%x = 0x%llx (KVAS toggled from 0x%llx)\n",
                        offsets_to_try[i], test_cr3, cr3);
                    return test_cr3;
                }
            }
            else
            {
                DbgPrintEx(0, 0, "[comm]     kvas(0x%llx) -> virt_to_phys failed\n", test_cr3);
            }
        }
    }

    /* Brute force: scan EPROCESS for any CR3 that maps the base to MZ */
    DbgPrintEx(0, 0, "[comm] Known offsets failed, brute-forcing EPROCESS (0x20-0xB00)...\n");
    for (i = 0x20; i < 0xB00; i += 8)
    {
        cr3 = *(PULONG64)((PUCHAR)process + i);
        if (cr3 < 0x1000 || cr3 > 0x20000000000ULL)
            continue;
        /* Clean low bits (KVAS flag bits) */
        ULONG64 clean = cr3 & ~0xFFFULL;
        if (clean < 0x1000)
            continue;
        cr3 = clean;

        /* Try as-is */
        phys = virt_to_phys(cr3, known_base);
        if (phys != 0)
        {
            sig = 0;
            status = read_physical(phys, &sig, sizeof(sig));
            if (NT_SUCCESS(status) && sig == 0x5A4D)
            {
                DbgPrintEx(0, 0, "[comm] User CR3 at EPROCESS+0x%x = 0x%llx (brute)\n",
                    i, cr3);
                return cr3;
            }
        }

        /* Try KVAS toggle */
        test_cr3 = cr3 ^ 0x2;
        if (test_cr3 >= 0x1000 && test_cr3 != cr3)
        {
            phys = virt_to_phys(test_cr3, known_base);
            if (phys != 0)
            {
                sig = 0;
                status = read_physical(phys, &sig, sizeof(sig));
                if (NT_SUCCESS(status) && sig == 0x5A4D)
                {
                    DbgPrintEx(0, 0, "[comm] User CR3 at EPROCESS+0x%x = 0x%llx (brute+KVAS from 0x%llx)\n",
                        i, test_cr3, cr3);
                    return test_cr3;
                }
            }
        }
    }

    /* Last resort: just use DirectoryTableBase */
    DbgPrintEx(0, 0, "[comm] No user CR3 found, using DTB (0x28)\n");
    return *(PULONG64)((PUCHAR)process + 0x28);
}

static NTSTATUS
find_process(const CHAR *name, PULONG64 out_pid, PULONG64 out_cr3)
{
    PEPROCESS process = NULL;
    NTSTATUS  status;
    ULONG     pid;

    for (pid = 4; pid < 0x10000; pid += 4)
    {
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status))
            continue;

        PUCHAR image_name = PsGetProcessImageFileName(process);
        if (image_name && _stricmp((const char *)image_name, name) == 0)
        {
            *out_pid = pid;

            /* Get ImageBase to validate CR3 against */
            PVOID section_base = PsGetProcessSectionBaseAddress(process);
            if (section_base && (ULONG64)section_base > 0x10000)
            {
                *out_cr3 = find_user_cr3(process, (ULONG64)section_base);
            }
            else
            {
                *out_cr3 = *(PULONG64)((PUCHAR)process + 0x28);
            }

            /* Test if the CR3 can actually read the PE header */
            USHORT mz_test = 0;
            NTSTATUS test_status = read_process_memory(*out_cr3, (ULONG64)section_base, &mz_test, sizeof(mz_test));
            if (NT_SUCCESS(test_status) && mz_test == 0x5A4D)
            {
                InterlockedExchange(&g_cr3_works, 1);
                DbgPrintEx(0, 0, "[comm] CR3 0x%llx VALIDATED (can read MZ)\n", *out_cr3);
            }
            else
            {
                /* EPROCESS-based CR3 failed — try PFN database scan */
                DbgPrintEx(0, 0, "[comm] CR3 0x%llx FAILED read test, trying PFN scan...\n", *out_cr3);

                ULONG64 pfn_cr3 = get_cr3_from_pfn(pid, (const char *)image_name);
                if (pfn_cr3 != 0)
                {
                    /* Validate PFN-derived CR3 */
                    mz_test = 0;
                    test_status = read_process_memory(pfn_cr3, (ULONG64)section_base, &mz_test, sizeof(mz_test));
                    if (NT_SUCCESS(test_status) && mz_test == 0x5A4D)
                    {
                        *out_cr3 = pfn_cr3;
                        InterlockedExchange(&g_cr3_works, 1);
                        DbgPrintEx(0, 0, "[comm] PFN CR3 0x%llx VALIDATED (can read MZ) !!!\n", pfn_cr3);
                    }
                    else
                    {
                        DbgPrintEx(0, 0, "[comm] PFN CR3 0x%llx also failed MZ test (sig=0x%x)\n",
                            pfn_cr3, mz_test);
                        InterlockedExchange(&g_cr3_works, 0);
                    }
                }
                else
                {
                    InterlockedExchange(&g_cr3_works, 0);
                    DbgPrintEx(0, 0, "[comm] PFN scan found nothing — will use MmCopyVirtualMemory fallback\n");
                }
            }

            /* Keep a referenced PEPROCESS for fallback reads */
            if (g_target_process)
                ObDereferenceObject(g_target_process);
            g_target_process = process;
            ObfReferenceObject(process);  /* extra ref — we keep it */

            DbgPrintEx(0, 0, "[comm] Found %s PID=%u CR3=0x%llx Base=0x%p cr3_works=%d\n",
                name, pid, *out_cr3, section_base, g_cr3_works);
            ObDereferenceObject(process);
            return STATUS_SUCCESS;
        }

        ObDereferenceObject(process);
    }

    return STATUS_NOT_FOUND;
}

/* ── Fallback read via MmCopyVirtualMemory (works when CR3 page walk fails) ── */

static NTSTATUS
read_process_memory_fallback(PEPROCESS target, ULONG64 address, PVOID buffer, ULONG64 size)
{
    SIZE_T bytes_copied = 0;
    NTSTATUS status;

    if (!target)
        return STATUS_INVALID_PARAMETER;

    status = MmCopyVirtualMemory(
        target, (PVOID)address,
        PsGetCurrentProcess(), buffer,
        (SIZE_T)size, KernelMode, &bytes_copied);

    return status;
}

/* ── Memory read/write using physical memory ── */

static NTSTATUS
read_process_memory(ULONG64 cr3, ULONG64 address, PVOID buffer, ULONG64 size)
{
    SIZE_T total = 0;

    if (cr3 == 0 || size > TEMP_BUF_SIZE)
        return STATUS_INVALID_PARAMETER;

    while (total < size)
    {
        ULONG64 phys = virt_to_phys(cr3, address + total);
        if (phys == 0)
            return STATUS_PARTIAL_COPY;

        SIZE_T page_remain = 0x1000 - ((address + total) & 0xFFF);
        SIZE_T chunk = (size - total < page_remain) ? (size - total) : page_remain;

        NTSTATUS status = read_physical(phys, (PUCHAR)buffer + total, chunk);
        if (!NT_SUCCESS(status))
            return status;

        total += chunk;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
write_process_memory(ULONG64 cr3, ULONG64 address, PVOID buffer, ULONG64 size)
{
    SIZE_T total = 0;

    if (cr3 == 0 || size > TEMP_BUF_SIZE)
        return STATUS_INVALID_PARAMETER;

    while (total < size)
    {
        ULONG64 phys = virt_to_phys(cr3, address + total);
        if (phys == 0)
            return STATUS_PARTIAL_COPY;

        SIZE_T page_remain = 0x1000 - ((address + total) & 0xFFF);
        SIZE_T chunk = (size - total < page_remain) ? (size - total) : page_remain;

        /* Map physical page, write, unmap */
        PHYSICAL_ADDRESS pa;
        pa.QuadPart = (LONGLONG)phys;
        PVOID mapped = MmMapIoSpace(pa, chunk, MmNonCached);
        if (!mapped)
            return STATUS_INSUFFICIENT_RESOURCES;

        RtlCopyMemory(mapped, (PUCHAR)buffer + total, chunk);
        MmUnmapIoSpace(mapped, chunk);

        total += chunk;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
get_peb_and_base(ULONG64 pid, ULONG64 cr3, PULONG64 out_peb, PULONG64 out_image_base)
{
    PEPROCESS target = NULL;
    NTSTATUS status;

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)pid, &target);
    if (!NT_SUCCESS(status))
        return status;

    ULONG64 peb = (ULONG64)PsGetProcessPeb(target);
    *out_peb = peb;

    /* Primary method: PsGetProcessSectionBaseAddress (no CR3 needed) */
    PVOID section_base = PsGetProcessSectionBaseAddress(target);
    *out_image_base = (ULONG64)section_base;

    if (*out_image_base > 0x10000)
        DbgPrintEx(0, 0, "[comm] SectionBase = 0x%llx\n", *out_image_base);

    /* Fallback: read PEB.ImageBaseAddress via physical memory */
    if (*out_image_base == 0 && peb > 0x10000 && cr3 != 0)
    {
        ULONG64 image_base = 0;
        status = read_process_memory(cr3, peb + 0x10, &image_base, sizeof(image_base));
        if (NT_SUCCESS(status) && image_base > 0x10000)
        {
            *out_image_base = image_base;
            DbgPrintEx(0, 0, "[comm] PEB base = 0x%llx\n", image_base);
        }
    }

    ObDereferenceObject(target);
    return STATUS_SUCCESS;
}

/* ── System thread: init + poll loop ── */

static NTSTATUS
init_shared_memory(void)
{
    NTSTATUS status;
    SECURITY_DESCRIPTOR sd;
    UNICODE_STRING section_name;
    OBJECT_ATTRIBUTES oa;
    LARGE_INTEGER section_size;
    SIZE_T view_size = 0;
    LARGE_INTEGER retry_delay;
    int retries;

    RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    RtlSetDaclSecurityDescriptor(&sd, TRUE, NULL, FALSE);

    RtlInitUnicodeString(&section_name,
        L"\\BaseNamedObjects\\Global\\ArcComm");

    InitializeObjectAttributes(&oa, &section_name,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sd);

    section_size.QuadPart = sizeof(COMM_SHARED);

    /*
     * When loaded via EFI loader (acpiex.sys hijack), DriverEntry runs
     * before smss.exe creates \BaseNamedObjects. Retry until the
     * namespace is available (typically ~10-30 seconds into boot).
     */
    retry_delay.QuadPart = -10000000LL;  /* 1 second */

    for (retries = 0; retries < 120; retries++)  /* up to ~2 minutes */
    {
        status = ZwCreateSection(
            &g_section, SECTION_ALL_ACCESS, &oa,
            &section_size, PAGE_READWRITE, SEC_COMMIT, NULL);

        if (NT_SUCCESS(status))
            break;

        if (status != STATUS_OBJECT_PATH_NOT_FOUND &&
            status != STATUS_OBJECT_NAME_NOT_FOUND)
        {
            /* Unexpected error — don't retry */
            DbgPrintEx(0, 0, "[comm] ZwCreateSection failed: 0x%08x\n", status);
            return status;
        }

        if (retries == 0)
            DbgPrintEx(0, 0, "[comm] \\BaseNamedObjects not ready yet, waiting...\n");

        KeDelayExecutionThread(KernelMode, FALSE, &retry_delay);
    }

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "[comm] ZwCreateSection failed after %d retries: 0x%08x\n",
            retries, status);
        return status;
    }

    if (retries > 0)
        DbgPrintEx(0, 0, "[comm] ZwCreateSection succeeded after %d retries\n", retries);

    status = ZwMapViewOfSection(
        g_section, NtCurrentProcess(), (PVOID *)&g_shared,
        0, 0, NULL, &view_size,
        ViewShare, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "[comm] ZwMapViewOfSection failed: 0x%08x\n", status);
        ZwClose(g_section);
        return status;
    }

    RtlZeroMemory(g_shared, sizeof(COMM_SHARED));

    /* Pre-allocate kernel pool buffer */
    g_temp_buf = ExAllocatePoolWithTag(NonPagedPool, TEMP_BUF_SIZE, 'crAR');
    if (!g_temp_buf)
    {
        DbgPrintEx(0, 0, "[comm] Failed to allocate temp buffer\n");
        ZwUnmapViewOfSection(NtCurrentProcess(), g_shared);
        ZwClose(g_section);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DbgPrintEx(0, 0, "[comm] Shared memory OK\n");
    return STATUS_SUCCESS;
}

static VOID
comm_worker_thread(PVOID ctx)
{
    NTSTATUS status;
    LARGE_INTEGER delay;

    UNREFERENCED_PARAMETER(ctx);

    DbgPrintEx(0, 0, "[comm] Worker thread started\n");

    status = init_shared_memory();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "[comm] init failed: 0x%08x\n", status);
        PsTerminateSystemThread(status);
        return;
    }

    /* Initialize PFN database for CR3 bypass (non-blocking) */
    init_pfn_cr3();

    InterlockedExchange(&g_shared->ready, 1);
    DbgPrintEx(0, 0, "[comm] CommDriver v3 ready (physical memory + PFN CR3 bypass)\n");

    delay.QuadPart = -10000;  /* 1 ms */

    while (!g_stop)
    {
        LONG cmd = InterlockedCompareExchange(&g_shared->command, CMD_IDLE, CMD_IDLE);

        if (cmd == CMD_IDLE)
        {
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            continue;
        }

        status = STATUS_SUCCESS;

        switch (cmd)
        {
        case CMD_PING:
            break;

        case CMD_FIND_PROCESS:
            g_shared->process_name[259] = '\0';
            status = find_process(g_shared->process_name,
                                  &g_shared->pid, &g_shared->cr3);
            if (NT_SUCCESS(status))
            {
                g_target_pid = g_shared->pid;
                g_target_cr3 = g_shared->cr3;
                DbgPrintEx(0, 0, "[comm] Found %s PID=%llu CR3=0x%llx\n",
                    g_shared->process_name, g_shared->pid, g_shared->cr3);
            }
            break;

        case CMD_READ_MEMORY:
        {
            ULONG64 cr3 = g_shared->cr3 ? g_shared->cr3 : g_target_cr3;
            ULONG64 sz  = g_shared->size;

            if (sz == 0 || sz > DATA_BUF_SIZE)
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (g_cr3_works && cr3 != 0)
            {
                /* Primary: CR3 page table walk (stealthier) */
                status = read_process_memory(cr3, g_shared->address,
                                             g_temp_buf, sz);
            }
            else
            {
                status = STATUS_UNSUCCESSFUL;
            }

            /* Fallback: MmCopyVirtualMemory if CR3 failed */
            if (!NT_SUCCESS(status) && g_target_process)
            {
                status = read_process_memory_fallback(
                    g_target_process, g_shared->address,
                    g_temp_buf, sz);
            }

            if (NT_SUCCESS(status))
                RtlCopyMemory(g_shared->data, g_temp_buf, (SIZE_T)sz);
            break;
        }

        case CMD_WRITE_MEMORY:
        {
            ULONG64 cr3 = g_shared->cr3 ? g_shared->cr3 : g_target_cr3;
            ULONG64 sz  = g_shared->size;

            if (cr3 == 0 || sz == 0 || sz > DATA_BUF_SIZE)
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            status = write_process_memory(cr3, g_shared->address,
                                          g_shared->data, sz);
            break;
        }

        case CMD_GET_PEB:
        {
            ULONG64 pid = g_shared->pid ? g_shared->pid : g_target_pid;
            ULONG64 cr3 = g_shared->cr3 ? g_shared->cr3 : g_target_cr3;
            if (pid == 0)
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            status = get_peb_and_base(pid, cr3,
                                      &g_shared->peb_address,
                                      &g_shared->image_base);
            break;
        }

        default:
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        g_shared->status = (LONG)status;
        MemoryBarrier();
        InterlockedExchange(&g_shared->command, CMD_IDLE);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* ── Entry point ── */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  driver_obj,
    _In_ PUNICODE_STRING registry_path)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(driver_obj);
    UNREFERENCED_PARAMETER(registry_path);

    DbgPrintEx(0, 0, "[comm] CommDriver v3 — spawning worker thread...\n");

    status = PsCreateSystemThread(
        &g_thread_handle, THREAD_ALL_ACCESS, NULL,
        NULL, NULL, comm_worker_thread, NULL);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "[comm] PsCreateSystemThread failed: 0x%08x\n", status);
        return status;
    }

    DbgPrintEx(0, 0, "[comm] Worker thread created OK\n");
    return STATUS_SUCCESS;
}
