// Runtime support copied alongside generated headers.
#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

using undefined1 = std::uint8_t;
using undefined2 = std::uint16_t;
struct undefined3
{
    std::uint8_t data[3];
};
using undefined4 = std::uint32_t;
using undefined8 = std::uint64_t;

static_assert(sizeof(undefined1) == 1);
static_assert(sizeof(undefined2) == 2);
static_assert(sizeof(undefined3) == 3);
static_assert(sizeof(undefined4) == 4);
static_assert(sizeof(undefined8) == 8);

// x86 conventions have no effect on targets with a unified calling convention.
#if defined(_MSC_VER) && defined(_M_IX86)
#define SDK_CDECL __cdecl
#define SDK_STDCALL __stdcall
#define SDK_THISCALL __thiscall
#define SDK_FASTCALL __fastcall
#elif defined(__i386__) && (defined(__GNUC__) || defined(__clang__))
#define SDK_CDECL __attribute__((cdecl))
#define SDK_STDCALL __attribute__((stdcall))
#define SDK_THISCALL __attribute__((thiscall))
#define SDK_FASTCALL __attribute__((fastcall))
#else
#define SDK_CDECL
#define SDK_STDCALL
#define SDK_THISCALL
#define SDK_FASTCALL
#endif

#define SDK_DETAIL_UNPAREN(...) __VA_ARGS__

#ifndef SDK_REBASE_ADDRESS
#define SDK_REBASE_ADDRESS(Address) (Address)
#endif

#define SDK_ADDRESS_MEMBER(Type, Name, Address) \
    static SDK_DETAIL_UNPAREN Type& Name() \
    { \
        return *reinterpret_cast<SDK_DETAIL_UNPAREN Type*>(SDK_REBASE_ADDRESS(Address)); \
    }

namespace SDKDetail
{
    template<typename TFunction>
    struct VirtualFunctionTraits;

    template<typename TReturn, typename TReceiver, typename... TArguments>
    struct VirtualFunctionTraits<TReturn (SDK_CDECL *)(TReceiver*, TArguments...)>
    {
        using TReceiverType = std::remove_cv_t<TReceiver>;
    };

    template<typename TReturn, typename TReceiver, typename... TArguments>
    struct VirtualFunctionTraits<TReturn (SDK_CDECL *)(TReceiver*, TArguments..., ...)>
    {
        using TReceiverType = std::remove_cv_t<TReceiver>;
    };

#if (defined(_MSC_VER) && defined(_M_IX86)) || \
    (defined(__i386__) && (defined(__GNUC__) || defined(__clang__)))
#define SDK_DETAIL_RECEIVER_TRAITS(Convention) \
    template<typename TReturn, typename TReceiver, typename... TArguments> \
    struct VirtualFunctionTraits<TReturn (Convention *)(TReceiver*, TArguments...)> \
    { \
        using TReceiverType = std::remove_cv_t<TReceiver>; \
    };
    SDK_DETAIL_RECEIVER_TRAITS(SDK_STDCALL)
    SDK_DETAIL_RECEIVER_TRAITS(SDK_THISCALL)
    SDK_DETAIL_RECEIVER_TRAITS(SDK_FASTCALL)
#undef SDK_DETAIL_RECEIVER_TRAITS
#endif
}

#define SDK_DIRECT_FUNCTION(MetadataName, Owner, Function, Address, Signature)  \
    struct MetadataName                                                         \
    {                                                                           \
        using TOwner = Owner;                                                   \
        using TFunction = SDK_DETAIL_UNPAREN Signature;                         \
        static constexpr const char* cFunctionName = #Function;                 \
        static constexpr std::uintptr_t cFunctionAddress = Address;             \
    }

#define SDK_VIRTUAL_FUNCTION(MetadataName, Owner, Function, Address, VtableIndex, Signature)    \
    struct MetadataName                                                                         \
    {                                                                                           \
        using TOwner = Owner;                                                                   \
        using TFunction = SDK_DETAIL_UNPAREN Signature;                                         \
        using TReceiver = typename SDKDetail::VirtualFunctionTraits<TFunction>::TReceiverType;  \
        static constexpr const char* cFunctionName = #Function;                                 \
        static constexpr std::size_t cVtableIndex = VtableIndex;                                \
        static constexpr std::uintptr_t cFunctionAddress = Address;                             \
        static constexpr bool cIsSecondaryVtable = !std::is_same_v<TOwner, TReceiver>;          \
    }

#ifndef SDK_STATIC_IMPLEMENTATION
    #define SDK_STATIC_IMPLEMENTATION(meta,...)
#endif

#ifndef SDK_VIRTUAL_IMPLEMENTATION
    #define SDK_VIRTUAL_IMPLEMENTATION(meta,...)
#endif
