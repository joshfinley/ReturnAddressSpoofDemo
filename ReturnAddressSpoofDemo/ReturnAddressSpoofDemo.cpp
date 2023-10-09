#include <iostream>
#include <vector>
#include <cstdint>
#include <windows.h>
#include <intrin.h>

/*
        GADGET FINDING
*/

PIMAGE_SECTION_HEADER GetTextSectionHeader(HMODULE hModule) {
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)(hModule);
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(
        reinterpret_cast<PBYTE>(hModule) + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
    for (WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i, ++Section) {
        if (memcmp(Section->Name, ".text", 5) == 0) {
            return Section;
        }
    }

    return NULL;
}

PVOID FindByteSequence(PBYTE Start, SIZE_T Length, PBYTE Sequence, SIZE_T SequenceLength) {
    if (Sequence == NULL || SequenceLength == 0) {
        return NULL;
    }

    for (SIZE_T i = 0; i <= Length - SequenceLength; ++i) {
        bool Match = true;
        for (SIZE_T j = 0; j < SequenceLength; ++j) {
            if (Start[i + j] != Sequence[j]) {
                Match = false;
                break;
            }
        }
        if (Match) {
            return Start + i;
        }
    }

    return NULL;
}

PVOID FindGadget(std::string InModuleName, PBYTE Gadget, SIZE_T GadgetLength) {
    HMODULE ModBase = GetModuleHandleA(InModuleName.c_str());
    PIMAGE_SECTION_HEADER CodeHeader = GetTextSectionHeader(ModBase);

    PBYTE ImageBase = (PBYTE)ModBase;
    PBYTE TextSectionAddr = ImageBase + CodeHeader->VirtualAddress;

    return FindByteSequence(TextSectionAddr, CodeHeader->SizeOfRawData, Gadget, 2);
}

/*
        RETURN ADDRESS SPOOF CALL
*/

typedef struct {
    PVOID JopGadget;            // always JMP RBX
    PVOID Function;             // Target Function
    PVOID Rbx;                  // Placeholder
} PRM, * PPRM;

extern "C" PVOID SpoofStub(PVOID, PVOID, PVOID, PVOID, PPRM, PVOID, PVOID, PVOID, PVOID, PVOID);

PVOID SpoofRetAddr(PVOID Function, PVOID A, PVOID B, PVOID C, PVOID D, PVOID E, PVOID F, PVOID G, PVOID H)
{
    if (Function != NULL)
    {
        PVOID JmpTrampoline; // Address where the code is `jmp rbx`
        BYTE JopGadget[2] = { 0xff, 0x23 };

        JmpTrampoline = FindGadget("kernel32", JopGadget, 2);
        if (JmpTrampoline != NULL)
        {
            PRM Param = { JmpTrampoline, Function, NULL };
            return SpoofStub(A, B, C, D, &Param, NULL, E, F, G, H);
        }
    }

    return NULL;
};


/*
        ENTRY POINT
*/

int main()
{
    char Text[14] = "Hello World!";
    char Caption[5] = "Msg";

    SpoofRetAddr(
        GetProcAddress(GetModuleHandleA("user32"), "MessageBoxA"), 
        NULL, Text, Caption, MB_OK, NULL, NULL, NULL, NULL);

    return 0;
}
