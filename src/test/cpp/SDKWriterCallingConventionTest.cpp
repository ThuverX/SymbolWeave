// Generate fixtures with SDKWriterCallingConventionTest; compile with its annotated
// or ignored directory on the include path. Run annotated on x86 and both on x64.
#include <cassert>
#include <type_traits>
// Keep generated method bodies well formed without requiring a project's dispatcher.
#define SDK_STATIC_IMPLEMENTATION(...) return 0
#define SDK_VIRTUAL_IMPLEMENTATION(...) return 0
#include "SdkMetadata.h"
#include "AbiCDECL.h"
#include "AbiSTDCALL.h"
#include "AbiTHISCALL.h"
#include "AbiFASTCALL.h"
#include "Global.h"

#ifdef SDK_TEST_IGNORE_CONVENTIONS
#define TEST_CDECL
#define TEST_STDCALL
#define TEST_THISCALL
#define TEST_FASTCALL
#else
#define TEST_CDECL SDK_CDECL
#define TEST_STDCALL SDK_STDCALL
#define TEST_THISCALL SDK_THISCALL
#define TEST_FASTCALL SDK_FASTCALL
#endif

#define CHECK_CONVENTION(Name, Convention) \
    static_assert(std::is_same_v<Abi##Name::InvokeMetadata::TFunction, \
                                int (Convention *)(Abi##Name*, int)>); \
    static_assert(std::is_same_v<Abi##Name::InvokeMetadata::TReceiver, Abi##Name>); \
    static_assert(std::is_same_v<decltype(&Abi##Name::Invoke), \
                                int (Convention Abi##Name::*)(int)>); \
    static_assert(std::is_same_v<Abi##Name::VariadicMetadata::TFunction, \
                                int (TEST_CDECL *)(Abi##Name*, int, ...)>); \
    static_assert(std::is_same_v<Abi##Name::VariadicMetadata::TReceiver, Abi##Name>); \
    static_assert(std::is_same_v<decltype(&Abi##Name::Variadic), \
                                int (TEST_CDECL Abi##Name::*)(int, ...)>);
CHECK_CONVENTION(CDECL, TEST_CDECL)
CHECK_CONVENTION(STDCALL, TEST_STDCALL)
CHECK_CONVENTION(THISCALL, TEST_THISCALL)
CHECK_CONVENTION(FASTCALL, TEST_FASTCALL)

static_assert(std::is_same_v<AbiTHISCALL::DirectMetadata::TFunction,
                            int (TEST_THISCALL *)(AbiTHISCALL*, int)>);
static_assert(std::is_same_v<decltype(&AbiTHISCALL::Direct),
                            int (TEST_THISCALL AbiTHISCALL::*)(int)>);

#define CHECK_DIRECT(Name, Convention) \
    static int Convention Native##Name(int value) { return value + 19; } \
    static_assert(std::is_same_v<Abi##Name::DirectMetadata::TFunction, decltype(&Native##Name)>); \
    static_assert(std::is_same_v<decltype(&Abi##Name::Direct), decltype(&Native##Name)>); \
    static_assert(std::is_same_v<decltype(&Loose##Name), decltype(&Native##Name)>);
CHECK_DIRECT(CDECL, TEST_CDECL)
CHECK_DIRECT(STDCALL, TEST_STDCALL)
CHECK_DIRECT(FASTCALL, TEST_FASTCALL)

#define CHECK_NATIVE_VIRTUAL(Name, Convention) \
    struct NativeVirtual##Name { \
        int bias = 29; \
        virtual int Convention Invoke(int value) { return value + bias; } \
    }; \
    static void CheckVirtual##Name() { \
        NativeVirtual##Name native; \
        auto table = *reinterpret_cast<void***>(&native); \
        auto call = reinterpret_cast<Abi##Name::InvokeMetadata::TFunction>(table[0]); \
        for (int value = 0; value < 1000; ++value) \
            assert(call(reinterpret_cast<Abi##Name*>(&native), value) == value + 29); \
    }
CHECK_NATIVE_VIRTUAL(CDECL, TEST_CDECL)
CHECK_NATIVE_VIRTUAL(STDCALL, TEST_STDCALL)
CHECK_NATIVE_VIRTUAL(THISCALL, TEST_THISCALL)
CHECK_NATIVE_VIRTUAL(FASTCALL, TEST_FASTCALL)

int main()
{
    AbiCDECL::DirectMetadata::TFunction cdeclCall = &NativeCDECL;
    AbiSTDCALL::DirectMetadata::TFunction stdcallCall = &NativeSTDCALL;
    AbiFASTCALL::DirectMetadata::TFunction fastcallCall = &NativeFASTCALL;
    for (int value = 0; value < 1000; ++value) {
        assert(cdeclCall(value) == value + 19);
        assert(stdcallCall(value) == value + 19);
        assert(fastcallCall(value) == value + 19);
    }
    CheckVirtualCDECL();
    CheckVirtualSTDCALL();
    CheckVirtualTHISCALL();
    CheckVirtualFASTCALL();
}
