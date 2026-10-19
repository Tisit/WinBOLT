/*
 * WinBolt runtime unwind test (DesignDoc Stage 6, step 1 "Open").
 *
 * Neither zopfli nor speedtest1 ever unwinds, so a rewrite with wrong exception data for
 * moved functions would pass their runtime checks. This target makes the OS unwinder walk
 * through a chain of ordinary functions, which WinBolt moves or rebuilds, in two ways:
 *   1. the innermost function walks its own stack with RtlLookupFunctionEntry and
 *      RtlVirtualUnwind up to main and counts the frames;
 *   2. it then raises an SEH exception that main catches with __except, so RtlUnwindEx must
 *      unwind every frame in between and restore main's nonvolatile registers.
 * main's __try and Guarded's __finally use SEH scope tables, so they move with rebased tables:
 * the exception must reach main's __except (through its filter function) and run Guarded's
 * termination handler on the way. The walk finds main's frame by its stack address, not by
 * comparing function entries with &main, which names the original (a moved main runs a copy).
 * The output depends only on the program's logic: identical output from the original and a
 * rewritten image means every walk succeeded.
 */
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <string.h>

#define DEPTH 24

static volatile int sink;
static volatile int raiseInLeaf;
static volatile int finallyRan;

/* Where main's return address is: unwinding main's own frame leaves RSP just above it. */
static DWORD64 mainReturnSlot;

int main(int argc, char **argv);

/* Walks from the caller's frame up to main; returns the number of frames, or -1. */
static __declspec(noinline) int WalkToMain(void)
{
    CONTEXT context;
    RtlCaptureContext(&context);
    int frames = 0;
    for (int i = 0; i < 256; i++)
    {
        DWORD64 imageBase;
        PRUNTIME_FUNCTION entry = RtlLookupFunctionEntry(context.Rip, &imageBase, NULL);
        if (entry == NULL)
        {
            return -1; /* a frame without unwind data: the walk cannot continue */
        }

        PVOID handlerData;
        DWORD64 establisher;
        DWORD64 previousRsp = context.Rsp;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, context.Rip, entry, &context, &handlerData, &establisher, NULL);
        if (context.Rsp <= previousRsp)
        {
            return -2; /* the stack must grow toward main */
        }

        if (context.Rsp == mainReturnSlot + 8)
        {
            return frames; /* that frame was main's */
        }

        frames++;
    }

    return -3;
}

/* Many values live across calls: forces callee-saved registers into the prologue. */
static __declspec(noinline) unsigned Busy(int depth, unsigned seed);

static __declspec(noinline) unsigned Big(int depth, unsigned seed)
{
    /* A frame over a page: the prologue calls __chkstk. */
    volatile unsigned char buffer[9000];
    memset((void *)buffer, (int)(seed & 0xFF), sizeof buffer);
    unsigned sum = buffer[seed % sizeof buffer] + buffer[(seed * 7) % sizeof buffer];
    return sum + Busy(depth - 1, seed * 1103515245u + 12345u);
}

static __declspec(noinline) unsigned Leaf(unsigned seed)
{
    int frames = WalkToMain();
    printf("walk: %d frames to main\n", frames);
    if (raiseInLeaf)
    {
        RaiseException(0xE0000001, 0, 0, NULL);
    }

    return seed ^ (unsigned)frames;
}

static __declspec(noinline) unsigned Busy(int depth, unsigned seed)
{
    if (depth <= 0)
    {
        return Leaf(seed);
    }

    /* Early exit before any real work: encourages a shrink-wrapped (chained) prologue. */
    if (seed == 0xFFFFFFFFu)
    {
        return 0;
    }

    unsigned a = seed, b = seed * 3, c = seed ^ 0x5A5A5A5A, d = seed + 17, e = seed * 5, f = seed >> 3;
    unsigned inner = (depth % 3 == 0) ? Big(depth, seed + a) : Busy(depth - 1, seed + b);
    sink = (int)(a + b + c + d + e + f);
    return inner + a * b + c * d + e * f;
}

/* A __finally: its termination handler runs when the exception unwinds through this frame. */
static __declspec(noinline) unsigned Guarded(int depth, unsigned seed)
{
    unsigned result = 0;
    __try
    {
        result = Busy(depth, seed);
    }
    __finally
    {
        finallyRan++;
    }

    return result;
}

static __declspec(noinline) int Filter(DWORD code)
{
    return code == 0xE0000001 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char **argv)
{
    mainReturnSlot = (DWORD64)_AddressOfReturnAddress();
    (void)argc;
    (void)argv;
    unsigned kept1 = 0x11111111, kept2 = 0x22222222, kept3 = 0x33333333;

    /* First run: returns normally after the walk. */
    unsigned result = Guarded(DEPTH, 0x1234);
    printf("normal return: %08X, finally ran %d\n", result, finallyRan);

    /* Second run: the exception unwinds every frame between Leaf and main. */
    raiseInLeaf = 1;
    __try
    {
        result = Guarded(DEPTH, 0x1235);
        printf("not reached: %08X\n", result);
    }
    __except (Filter(GetExceptionCode()))
    {
        printf("caught %08X, finally ran %d\n", (unsigned)GetExceptionCode(), finallyRan);
    }

    kept1 += sink & 0;
    printf("kept: %08X %08X %08X\n", kept1, kept2, kept3);
    return 0;
}
