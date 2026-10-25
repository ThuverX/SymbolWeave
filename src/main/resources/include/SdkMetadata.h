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
    struct VirtualFunctionTraits<TReturn (*)(TReceiver*, TArguments...)>
    {
        using TReceiverType = std::remove_cv_t<TReceiver>;
    };
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
