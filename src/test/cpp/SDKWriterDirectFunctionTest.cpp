#include <cassert>
#include <cstdint>
#include <type_traits>
#include <utility>

class NativeCallable;
static NativeCallable* lastReceiver;
static std::uint32_t initialValue;
static unsigned constructed;
static unsigned destroyed;

static NativeCallable* Construct(NativeCallable* receiver, std::uint32_t initial)
{
    lastReceiver = receiver;
    initialValue = initial;
    ++constructed;
    return receiver;
}
static NativeCallable* ConstructDefault(NativeCallable* receiver) { return Construct(receiver, 17); }
static void Destruct(NativeCallable* receiver) { lastReceiver = receiver; ++destroyed; }
static std::uint64_t Compute(NativeCallable* receiver, std::uint64_t value)
{
    lastReceiver = receiver;
    return value + initialValue;
}
static bool Ready(NativeCallable* receiver) { lastReceiver = receiver; return initialValue != 0; }
static std::uint64_t GlobalCall(std::uint64_t value) { return value ^ 0x1122334455667788ULL; }

template<class Metadata>
static auto Resolve()
{
    if constexpr (Metadata::cFunctionAddress == 0x10) return &Construct;
    else if constexpr (Metadata::cFunctionAddress == 0x11) return &ConstructDefault;
    else if constexpr (Metadata::cFunctionAddress == 0x20) return &Destruct;
    else if constexpr (Metadata::cFunctionAddress == 0x30) return &Compute;
    else if constexpr (Metadata::cFunctionAddress == 0x40) return &Ready;
    else if constexpr (Metadata::cFunctionAddress == 0x50) return &GlobalCall;
}
template<class Metadata, class... Arguments>
static decltype(auto) Dispatch(Arguments&&... arguments)
{
    static_assert(std::is_same_v<decltype(Resolve<Metadata>()), typename Metadata::TFunction>);
    return Resolve<Metadata>()(std::forward<Arguments>(arguments)...);
}

#define SDK_STATIC_IMPLEMENTATION(Metadata, ...) return Dispatch<Metadata>(__VA_ARGS__)
#include "NativeCallable.h"

int main()
{
    {
        NativeCallable object(23);
        assert(lastReceiver == &object && initialValue == 23 && constructed == 1);
        assert(object.Compute(0x100000000ULL) == 0x100000017ULL);
        assert(lastReceiver == &object && object.Ready());
        assert(object.GlobalCall(0xFFEEDDCCBBAA0099ULL) ==
               (0xFFEEDDCCBBAA0099ULL ^ 0x1122334455667788ULL));
    }
    assert(destroyed == 1);
    {
        NativeCallable object;
        assert(lastReceiver == &object && initialValue == 17 && constructed == 2);
    }
    assert(destroyed == 2);
}
