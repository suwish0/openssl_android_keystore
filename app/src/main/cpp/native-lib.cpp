#include <jni.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <vector>
#include <string>
#include<sys/prctl.h>
#include <stddef.h>
#include <stdint.h>
#include <algorithm>
#include <iosfwd>
#include <limits>
#include <string>
#include <string_view>
#include <type_traits>
#include "chromium/base/template_util.h"
#include "chromium/base/memory/scoped_ptr.h"
#include "chromium/crypto/scoped_openssl_types.h"
#include <openssl/bn.h>

typedef uint8_t uint8;

#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
  TypeName(const TypeName&);               \
  void operator=(const TypeName&)
JavaVM* g_jvm = nullptr;
JNIEnv* AttachCurrentThread() {
    JNIEnv* env = nullptr;
    jint ret = g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_2);
    if (ret == JNI_EDETACHED || !env) {
        JavaVMAttachArgs args;
        args.version = JNI_VERSION_1_2;
        args.group = nullptr;
        // 16 is the maximum size for thread names on Android.
        char thread_name[16];
        int err = prctl(PR_GET_NAME, thread_name);
        if (err < 0) {
            args.name = nullptr;
        } else {
            args.name = thread_name;
        }
        ret = g_jvm->AttachCurrentThread(&env, &args);
    }
    return env;
}


template<typename T> class JavaRef;
template<>
class JavaRef<jobject> {
public:
    virtual jobject obj() const { return obj_; }
    bool is_null() const { return obj_ == nullptr; }
protected:
    // Initializes a NULL reference.
    JavaRef();
    // Takes ownership of the |obj| reference passed; requires it to be a local
    // reference type.
    JavaRef(JNIEnv* env, jobject obj) {
        env = AttachCurrentThread();
        if (obj)
            obj = env->NewLocalRef(obj);
        if (obj_)
            env->DeleteLocalRef(obj_);
        obj_ = obj;
    }
    ~JavaRef() {}
    // The following are implementation detail convenience methods, for
    // use by the sub-classes.
    JNIEnv* SetNewLocalRef(JNIEnv* env, jobject obj) {
        env = AttachCurrentThread();
        if (obj)
            obj = env->NewLocalRef(obj);
        if (obj_)
            env->DeleteLocalRef(obj_);
        obj_ = obj;
        return env;
    }
    void SetNewGlobalRef(JNIEnv* env, jobject obj) {
        env = AttachCurrentThread();
        if (obj)
            obj = env->NewGlobalRef(obj);
        if (obj_)
            env->DeleteGlobalRef(obj_);
        obj_ = obj;
    }
    void ResetLocalRef(JNIEnv* env) {
        if (obj_) {
            env->DeleteLocalRef(obj_);
            obj_ = nullptr;
        }
    }
    void ResetGlobalRef() {
        if (obj_) {
            AttachCurrentThread()->DeleteGlobalRef(obj_);
            obj_ = nullptr;
        }
    }
    jobject ReleaseInternal() {
        jobject obj = obj_;
        obj_ = nullptr;
        return obj;
    }
private:
    jobject obj_;
    DISALLOW_COPY_AND_ASSIGN(JavaRef);
};
template<typename T>
class JavaRef : public JavaRef<jobject> {
public:
    T obj() const { return static_cast<T>(JavaRef<jobject>::obj()); }
protected:
    JavaRef() = default;
    ~JavaRef() = default;
    JavaRef(JNIEnv* env, T obj) : JavaRef<jobject>(env, obj) {}
private:
    DISALLOW_COPY_AND_ASSIGN(JavaRef);
};
template<typename T>
class ScopedJavaLocalRef : public JavaRef<T> {
public:
    ScopedJavaLocalRef() : env_(nullptr) {}
    // Non-explicit copy constructor, to allow ScopedJavaLocalRef to be returned
    // by value as this is the normal usage pattern.
    ScopedJavaLocalRef(const ScopedJavaLocalRef<T>& other)
            : env_(other.env_) {
        this->SetNewLocalRef(env_, other.obj());
    }
    template<typename U>
    explicit ScopedJavaLocalRef(const U& other)
            : env_(nullptr) {
        this->Reset(other);
    }
    // Assumes that |obj| is a local reference to a Java object and takes
    // ownership  of this local reference.
    ScopedJavaLocalRef(JNIEnv* env, T obj) : JavaRef<T>(env, obj), env_(env) {}
    ~ScopedJavaLocalRef() {
        this->Reset();
    }
    // Overloaded assignment operator defined for consistency with the implicit
    // copy constructor.
    void operator=(const ScopedJavaLocalRef<T>& other) {
        this->Reset(other);
    }
    void Reset() {
        this->ResetLocalRef(env_);
    }
    template<typename U>
    void Reset(const ScopedJavaLocalRef<U>& other) {
        // We can copy over env_ here as |other| instance must be from the same
        // thread as |this| local ref. (See class comment for multi-threading
        // limitations, and alternatives).
        this->Reset(other.env_, other.obj());
    }
    template<typename U>
    void Reset(const U& other) {
        // If |env_| was not yet set (is still NULL) it will be attached to the
        // current thread in SetNewLocalRef().
        this->Reset(env_, other.obj());
    }
    template<typename U>
    void Reset(JNIEnv* env, U obj) {
        implicit_cast<T>(obj);  // Ensure U is assignable to T
        env_ = this->SetNewLocalRef(env, obj);
    }
    // Releases the local reference to the caller. The caller *must* delete the
    // local reference when it is done with it.
    T Release() {
        return static_cast<T>(this->ReleaseInternal());
    }
private:
    // This class is only good for use on the thread it was created on so
    // it's safe to cache the non-threadsafe JNIEnv* inside this object.
    JNIEnv* env_;
};
template<typename T>
class ScopedJavaGlobalRef : public JavaRef<T> {
public:
    ScopedJavaGlobalRef() = default;
    explicit ScopedJavaGlobalRef(const ScopedJavaGlobalRef<T>& other) {
        this->Reset(other);
    }
    template<typename U>
    explicit ScopedJavaGlobalRef(const U& other) {
        this->Reset(other);
    }
    ~ScopedJavaGlobalRef() {
        this->Reset();
    }
    void Reset() {
        this->ResetGlobalRef();
    }
    template<typename U>
    void Reset(const U& other) {
        this->Reset(NULL, other.obj());
    }
    template<typename U>
    void Reset(JNIEnv* env, U obj) {
        implicit_cast<T>(obj);  // Ensure U is assignable to T
        this->SetNewGlobalRef(env, obj);
    }
    // Releases the global reference to the caller. The caller *must* delete the
    // global reference when it is done with it.
    T Release() {
        return static_cast<T>(this->ReleaseInternal());
    }
};

template <typename JavaArrayType>
size_t SafeGetArrayLength(JNIEnv* env,
const JavaRef<JavaArrayType>& jarray) {
jsize length = env->GetArrayLength(jarray.obj());
return static_cast<size_t>(std::max(0, length));
}

void AppendJavaByteArrayToByteVector(JNIEnv* env,
                                     const JavaRef<jbyteArray>& byte_array,
                                     std::vector<uint8_t>* out) {
    size_t len = SafeGetArrayLength(env, byte_array);
    if (!len)
        return;
    size_t back = out->size();
    out->resize(back + len);
    env->GetByteArrayRegion(byte_array.obj(), 0, static_cast<jsize>(len),
                            reinterpret_cast<int8_t*>(out->data() + back));
}
void JavaByteArrayToByteVector(JNIEnv* env,
                               const JavaRef<jbyteArray>& byte_array,
                               std::vector<uint8_t>* out) {
    out->clear();
    AppendJavaByteArrayToByteVector(env, byte_array, out);
}

#define PR_GET_NAME    16		/* Get process name */

// This is called by the VM when the shared library is first loaded.
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_jvm = vm;
}

namespace base {
    template <typename CharT, typename Traits = std::char_traits<CharT>>
    class BasicStringPiece;
    using StringPiece = BasicStringPiece<char>;
    using StringPiece16 = BasicStringPiece<char16_t>;
    using WStringPiece = BasicStringPiece<wchar_t>;
}  // namespace base

namespace base {
// internal --------------------------------------------------------------------
// Many of the StringPiece functions use different implementations for the
// 8-bit and 16-bit versions, and we don't want lots of template expansions in
// this (very common) header that will slow down compilation.
//
// So here we define overloaded functions called by the StringPiece template.
// For those that share an implementation, the two versions will expand to a
// template internal to the .cc file.
    namespace internal {
        size_t find(StringPiece self, StringPiece s, size_t pos);
        size_t find(StringPiece16 self, StringPiece16 s, size_t pos);
        size_t rfind(StringPiece self, StringPiece s, size_t pos);
        size_t rfind(StringPiece16 self, StringPiece16 s, size_t pos);
        size_t find_first_of(StringPiece self, StringPiece s, size_t pos);
        size_t find_first_of(StringPiece16 self,
        StringPiece16 s,
                size_t pos);
        size_t find_first_not_of(StringPiece self,
        StringPiece s,
                size_t pos);
        size_t find_first_not_of(StringPiece16 self,
        StringPiece16 s,
                size_t pos);
        size_t find_last_of(StringPiece self, StringPiece s, size_t pos);
        size_t find_last_of(StringPiece16 self,
        StringPiece16 s,
                size_t pos);
        size_t find_last_not_of(StringPiece self,
        StringPiece s,
                size_t pos);
        size_t find_last_not_of(StringPiece16 self,
        StringPiece16 s,
                size_t pos);
        size_t find(WStringPiece self, WStringPiece s, size_t pos);
        size_t rfind(WStringPiece self, WStringPiece s, size_t pos);
        size_t find_first_of(WStringPiece self, WStringPiece s, size_t pos);
        size_t find_first_not_of(WStringPiece self,
        WStringPiece s,
                size_t pos);
        size_t find_last_of(WStringPiece self, WStringPiece s, size_t pos);
        size_t find_last_not_of(WStringPiece self,
        WStringPiece s,
                size_t pos);
    }  // namespace internal
    constexpr bool is_constant_evaluated() noexcept {
        return __builtin_is_constant_evaluated();
    }

// BasicStringPiece ------------------------------------------------------------
// Mirrors the C++17 version of std::basic_string_view<> as closely as possible,
// except where noted below.
    template <typename CharT, typename Traits>
    class BasicStringPiece {
            public:
            using traits_type = Traits;
            using value_type = CharT;
            using pointer = CharT*;
            using const_pointer = const CharT*;
            using reference = CharT&;
            using const_reference = const CharT&;
            using const_iterator = const CharT*;
            using iterator = const_iterator;
            using const_reverse_iterator = std::reverse_iterator<const_iterator>;
            using reverse_iterator = const_reverse_iterator;
            using size_type = size_t;
            using difference_type = ptrdiff_t;
            constexpr BasicStringPiece() noexcept : ptr_(nullptr), length_(0) {}
            constexpr BasicStringPiece(const BasicStringPiece& other) noexcept = default;
            constexpr BasicStringPiece& operator=(const BasicStringPiece& view) noexcept =
            default;
            constexpr BasicStringPiece(const CharT* s, size_t count)
            : ptr_(s), length_(count) {
                // Intentional STL deviation: Check the string length fits in
                // `difference_type`. No valid buffer can exceed this type, otherwise
                // pointer arithmetic would not be defined. This helps avoid bugs where
                // `count` was computed from an underflow or negative sentinel value.
            }
            // NOLINTNEXTLINE(google-explicit-constructor)
            constexpr BasicStringPiece(const CharT* s)
            : ptr_(s), length_(s ? traits_type::length(s) : 0) {
                // Intentional STL deviation: Null-check instead of UB.
                CHECK(s);
            }
            // Explicitly disallow construction from nullptr. Note that this does not
            // catch construction from runtime strings that might be null.
            // Note: The following is just a more elaborate way of spelling
            // `BasicStringPiece(nullptr_t) = delete`, but unfortunately the terse form is
            // not supported by the PNaCl toolchain.
            template <class T, class = std::enable_if_t<std::is_null_pointer<T>::value>>
            // NOLINTNEXTLINE(google-explicit-constructor)
            BasicStringPiece(T) {
                static_assert(sizeof(T) == 0,  // Always false.
                              "StringPiece does not support construction from nullptr, use "
                              "the default constructor instead.");
            }
            // These are necessary because std::basic_string provides construction from
            // (an object convertible to) a std::basic_string_view, as well as an explicit
            // cast operator to a std::basic_string_view, but (obviously) not from/to a
            // BasicStringPiece.
            // NOLINTNEXTLINE(google-explicit-constructor)
            BasicStringPiece(const std::basic_string<CharT>& str)
            : ptr_(str.data()), length_(str.size()) {}
            explicit operator std::basic_string<CharT>() const {
                return std::basic_string<CharT>(data(), size());
            }
            // Provide implicit conversions from/to the STL version, for interoperability
            // with non-Chromium code.
            // TODO(crbug.com/691162): These will be moot when BasicStringPiece is
            // replaced with std::basic_string_view.
            // NOLINTNEXTLINE(google-explicit-constructor)
            constexpr BasicStringPiece(std::basic_string_view<CharT> str)
            : ptr_(str.data()), length_(str.size()) {}
            // NOLINTNEXTLINE(google-explicit-constructor)
            constexpr operator std::basic_string_view<CharT>() const {
                return std::basic_string_view<CharT>(data(), size());
            }
            constexpr const_iterator begin() const noexcept { return ptr_; }
            constexpr const_iterator cbegin() const noexcept { return ptr_; }
            constexpr const_iterator end() const noexcept { return ptr_ + length_; }
            constexpr const_iterator cend() const noexcept { return ptr_ + length_; }
            constexpr const_reverse_iterator rbegin() const noexcept {
                return const_reverse_iterator(ptr_ + length_);
            }
            constexpr const_reverse_iterator crbegin() const noexcept {
                return const_reverse_iterator(ptr_ + length_);
            }
            constexpr const_reverse_iterator rend() const noexcept {
                return const_reverse_iterator(ptr_);
            }
            constexpr const_reverse_iterator crend() const noexcept {
                return const_reverse_iterator(ptr_);
            }
            constexpr const_reference operator[](size_type pos) const {
                // Intentional STL deviation: Bounds-check instead of UB.
                return at(pos);
            }
            constexpr const_reference at(size_type pos) const {
                CHECK_LT(pos, size());
                return data()[pos];
            }
            constexpr const_reference front() const { return operator[](0); }
            constexpr const_reference back() const { return operator[](size() - 1); }
            constexpr const_pointer data() const noexcept { return ptr_; }
            constexpr size_type size() const noexcept { return length_; }
            constexpr size_type length() const noexcept { return length_; }
            constexpr size_type max_size() const {
                return std::numeric_limits<size_type>::max() / sizeof(CharT);
            }
            [[nodiscard]] constexpr bool empty() const noexcept { return size() == 0; }
            constexpr void remove_prefix(size_type n) {
                // Intentional STL deviation: Bounds-check instead of UB.
                CHECK_LE(n, size());
                ptr_ += n;
                length_ -= n;
            }
            constexpr void remove_suffix(size_type n) {
                // Intentional STL deviation: Bounds-check instead of UB.
                CHECK_LE(n, size());
                length_ -= n;
            }
            constexpr void swap(BasicStringPiece& v) noexcept {
                // Note: Cannot use std::swap() since it is not constexpr until C++20.
                const const_pointer ptr = ptr_;
                ptr_ = v.ptr_;
                v.ptr_ = ptr;
                const size_type length = length_;
                length_ = v.length_;
                v.length_ = length;
            }
            constexpr size_type copy(CharT* dest,
            size_type count,
            size_type pos = 0) const {
                CHECK_LE(pos, size());
                const size_type rcount = std::min(count, size() - pos);
                traits_type::copy(dest, data() + pos, rcount);
                return rcount;
            }
            constexpr BasicStringPiece substr(size_type pos = 0,
            size_type count = npos) const {
                CHECK_LE(pos, size());
                const size_type rcount = std::min(count, size() - pos);
                return {data() + pos, rcount};
            }
            constexpr int compare(BasicStringPiece v) const noexcept {
                const size_type rlen = std::min(size(), v.size());
                const int result = traits_type::compare(data(), v.data(), rlen);
                if (result != 0)
                    return result;
                if (size() == v.size())
                    return 0;
                return size() < v.size() ? -1 : 1;
            }
            constexpr int compare(size_type pos1,
            size_type count1,
            BasicStringPiece v) const {
                return substr(pos1, count1).compare(v);
            }
            constexpr int compare(size_type pos1,
            size_type count1,
            BasicStringPiece v,
            size_type pos2,
            size_type count2) const {
                return substr(pos1, count1).compare(v.substr(pos2, count2));
            }
            constexpr int compare(const CharT* s) const {
                return compare(BasicStringPiece(s));
            }
            constexpr int compare(size_type pos1,
            size_type count1,
            const CharT* s) const {
                return substr(pos1, count1).compare(BasicStringPiece(s));
            }
            constexpr int compare(size_type pos1,
            size_type count1,
            const CharT* s,
            size_type count2) const {
                return substr(pos1, count1).compare(BasicStringPiece(s, count2));
            }
            constexpr size_type find(BasicStringPiece v,
            size_type pos = 0) const noexcept {
                if (is_constant_evaluated()) {
                    if (v.size() > size())
                        return npos;
                    for (size_type p = pos; p <= size() - v.size(); ++p) {
                        if (!compare(p, v.size(), v))
                            return p;
                    }
                    return npos;
                }
                return internal::find(*this, v, pos);
            }
            constexpr size_type find(CharT ch, size_type pos = 0) const noexcept {
                if (pos >= size())
                    return npos;
                const const_pointer result =
                        traits_type::find(data() + pos, size() - pos, ch);
                return result ? static_cast<size_type>(result - data()) : npos;
            }
            constexpr size_type find(const CharT* s,
            size_type pos,
            size_type count) const {
                return find(BasicStringPiece(s, count), pos);
            }
            constexpr size_type find(const CharT* s, size_type pos = 0) const {
                return find(BasicStringPiece(s), pos);
            }
            constexpr size_type rfind(BasicStringPiece v,
            size_type pos = npos) const noexcept {
                if (is_constant_evaluated()) {
                    if (v.size() > size())
                        return npos;
                    for (size_type p = std::min(size() - v.size(), pos);; --p) {
                        if (!compare(p, v.size(), v))
                            return p;
                        if (!p)
                            break;
                    }
                    return npos;
                }
                return internal::rfind(*this, v, pos);
            }
            constexpr size_type rfind(CharT c, size_type pos = npos) const noexcept {
                if (empty())
                    return npos;
                for (size_t i = std::min(pos, size() - 1);; --i) {
                    if (data()[i] == c)
                        return i;
                    if (i == 0)
                        break;
                }
                return npos;
            }
            constexpr size_type rfind(const CharT* s,
            size_type pos,
            size_type count) const {
                return rfind(BasicStringPiece(s, count), pos);
            }
            constexpr size_type rfind(const CharT* s, size_type pos = npos) const {
                return rfind(BasicStringPiece(s), pos);
            }
            constexpr size_type find_first_of(BasicStringPiece v,
            size_type pos = 0) const noexcept {
                if (is_constant_evaluated()) {
                    if (empty() || v.empty())
                        return npos;
                    for (size_type p = pos; p < size(); ++p) {
                        if (v.find(data()[p]) != npos)
                            return p;
                    }
                    return npos;
                }
                return internal::find_first_of(*this, v, pos);
            }
            constexpr size_type find_first_of(CharT c, size_type pos = 0) const noexcept {
                return find(c, pos);
            }
            constexpr size_type find_first_of(const CharT* s,
            size_type pos,
            size_type count) const {
                return find_first_of(BasicStringPiece(s, count), pos);
            }
            constexpr size_type find_first_of(const CharT* s, size_type pos = 0) const {
                return find_first_of(BasicStringPiece(s), pos);
            }
            constexpr size_type find_last_of(BasicStringPiece v,
            size_type pos = npos) const noexcept {
                if (is_constant_evaluated()) {
                    if (empty() || v.empty())
                        return npos;
                    for (size_type p = std::min(pos, size() - 1);; --p) {
                        if (v.find(data()[p]) != npos)
                            return p;
                        if (!p)
                            break;
                    }
                    return npos;
                }
                return internal::find_last_of(*this, v, pos);
            }
            constexpr size_type find_last_of(CharT c,
            size_type pos = npos) const noexcept {
                return rfind(c, pos);
            }
            constexpr size_type find_last_of(const CharT* s,
            size_type pos,
            size_type count) const {
                return find_last_of(BasicStringPiece(s, count), pos);
            }
            constexpr size_type find_last_of(const CharT* s, size_type pos = npos) const {
                return find_last_of(BasicStringPiece(s), pos);
            }
            constexpr size_type find_first_not_of(BasicStringPiece v,
            size_type pos = 0) const noexcept {
                if (is_constant_evaluated()) {
                    if (empty())
                        return npos;
                    for (size_type p = pos; p < size(); ++p) {
                        if (v.find(data()[p]) == npos)
                            return p;
                    }
                    return npos;
                }
                return internal::find_first_not_of(*this, v, pos);
            }
            constexpr size_type find_first_not_of(CharT c,
            size_type pos = 0) const noexcept {
                if (empty())
                    return npos;
                for (; pos < size(); ++pos) {
                    if (data()[pos] != c)
                        return pos;
                }
                return npos;
            }
            constexpr size_type find_first_not_of(const CharT* s,
            size_type pos,
            size_type count) const {
                return find_first_not_of(BasicStringPiece(s, count), pos);
            }
            constexpr size_type find_first_not_of(const CharT* s,
            size_type pos = 0) const {
                return find_first_not_of(BasicStringPiece(s), pos);
            }
            constexpr size_type find_last_not_of(BasicStringPiece v,
            size_type pos = npos) const noexcept {
                if (is_constant_evaluated()) {
                    if (empty())
                        return npos;
                    for (size_type p = std::min(pos, size() - 1);; --p) {
                        if (v.find(data()[p]) == npos)
                            return p;
                        if (!p)
                            break;
                    }
                    return npos;
                }
                return internal::find_last_not_of(*this, v, pos);
            }
            constexpr size_type find_last_not_of(CharT c,
            size_type pos = npos) const noexcept {
                if (empty())
                    return npos;
                for (size_t i = std::min(pos, size() - 1);; --i) {
                    if (data()[i] != c)
                        return i;
                    if (i == 0)
                        break;
                }
                return npos;
            }
            constexpr size_type find_last_not_of(const CharT* s,
            size_type pos,
            size_type count) const {
                return find_last_not_of(BasicStringPiece(s, count), pos);
            }
            constexpr size_type find_last_not_of(const CharT* s,
            size_type pos = npos) const {
                return find_last_not_of(BasicStringPiece(s), pos);
            }
            static constexpr size_type npos = size_type(-1);
            protected:
            const_pointer ptr_;
            size_type length_;
    };
// static
    template <typename CharT, typename Traits>
    const typename BasicStringPiece<CharT, Traits>::size_type
            BasicStringPiece<CharT, Traits>::npos;
// MSVC doesn't like complex extern templates and DLLs.
#if !defined(COMPILER_MSVC)
    extern template class BasicStringPiece<char>;
    extern template class BasicStringPiece<char16_t>;
#endif
    template <typename CharT, typename Traits>
    constexpr bool operator==(BasicStringPiece<CharT, Traits> lhs,
                              BasicStringPiece<CharT, Traits> rhs) noexcept {
        return lhs.size() == rhs.size() && lhs.compare(rhs) == 0;
    }
// Here and below we make use of std::common_type_t to emulate
// std::type_identity (part of C++20). This creates a non-deduced context, so
// that we can compare StringPieces with types that implicitly convert to
// StringPieces. See https://wg21.link/n3766 for details.
// Furthermore, we require dummy template parameters for these overloads to work
// around a name mangling issue on Windows.
    template <typename CharT, typename Traits, int = 1>
    constexpr bool operator==(
            BasicStringPiece<CharT, Traits> lhs,
            std::common_type_t<BasicStringPiece<CharT, Traits>> rhs) noexcept {
        return lhs.size() == rhs.size() && lhs.compare(rhs) == 0;
    }
    template <typename CharT, typename Traits, int = 2>
    constexpr bool operator==(
            std::common_type_t<BasicStringPiece<CharT, Traits>> lhs,
            BasicStringPiece<CharT, Traits> rhs) noexcept {
        return lhs.size() == rhs.size() && lhs.compare(rhs) == 0;
    }
    template <typename CharT, typename Traits>
    constexpr bool operator!=(BasicStringPiece<CharT, Traits> lhs,
                              BasicStringPiece<CharT, Traits> rhs) noexcept {
        return !(lhs == rhs);
    }
    template <typename CharT, typename Traits, int = 1>
    constexpr bool operator!=(
            BasicStringPiece<CharT, Traits> lhs,
            std::common_type_t<BasicStringPiece<CharT, Traits>> rhs) noexcept {
        return !(lhs == rhs);
    }
    template <typename CharT, typename Traits, int = 2>
    constexpr bool operator!=(
            std::common_type_t<BasicStringPiece<CharT, Traits>> lhs,
            BasicStringPiece<CharT, Traits> rhs) noexcept {
        return !(lhs == rhs);
    }
    template <typename CharT, typename Traits>
    constexpr bool operator<(BasicStringPiece<CharT, Traits> lhs,
                             BasicStringPiece<CharT, Traits> rhs) noexcept {
        return lhs.compare(rhs) < 0;
    }
    template <typename CharT, typename Traits, int = 1>
    constexpr bool operator<(
            BasicStringPiece<CharT, Traits> lhs,
            std::common_type_t<BasicStringPiece<CharT, Traits>> rhs) noexcept {
        return lhs.compare(rhs) < 0;
    }
    template <typename CharT, typename Traits, int = 2>
    constexpr bool operator<(
            std::common_type_t<BasicStringPiece<CharT, Traits>> lhs,
            BasicStringPiece<CharT, Traits> rhs) noexcept {
        return lhs.compare(rhs) < 0;
    }
    template <typename CharT, typename Traits>
    constexpr bool operator>(BasicStringPiece<CharT, Traits> lhs,
                             BasicStringPiece<CharT, Traits> rhs) noexcept {
        return rhs < lhs;
    }
    template <typename CharT, typename Traits, int = 1>
    constexpr bool operator>(
            BasicStringPiece<CharT, Traits> lhs,
            std::common_type_t<BasicStringPiece<CharT, Traits>> rhs) noexcept {
        return rhs < lhs;
    }
    template <typename CharT, typename Traits, int = 2>
    constexpr bool operator>(
            std::common_type_t<BasicStringPiece<CharT, Traits>> lhs,
            BasicStringPiece<CharT, Traits> rhs) noexcept {
        return rhs < lhs;
    }
    template <typename CharT, typename Traits>
    constexpr bool operator<=(BasicStringPiece<CharT, Traits> lhs,
                              BasicStringPiece<CharT, Traits> rhs) noexcept {
        return !(rhs < lhs);
    }
    template <typename CharT, typename Traits, int = 1>
    constexpr bool operator<=(
            BasicStringPiece<CharT, Traits> lhs,
            std::common_type_t<BasicStringPiece<CharT, Traits>> rhs) noexcept {
        return !(rhs < lhs);
    }
    template <typename CharT, typename Traits, int = 2>
    constexpr bool operator<=(
            std::common_type_t<BasicStringPiece<CharT, Traits>> lhs,
            BasicStringPiece<CharT, Traits> rhs) noexcept {
        return !(rhs < lhs);
    }
    template <typename CharT, typename Traits>
    constexpr bool operator>=(BasicStringPiece<CharT, Traits> lhs,
                              BasicStringPiece<CharT, Traits> rhs) noexcept {
        return !(lhs < rhs);
    }
    template <typename CharT, typename Traits, int = 1>
    constexpr bool operator>=(
            BasicStringPiece<CharT, Traits> lhs,
            std::common_type_t<BasicStringPiece<CharT, Traits>> rhs) noexcept {
        return !(lhs < rhs);
    }
    template <typename CharT, typename Traits, int = 2>
    constexpr bool operator>=(
            std::common_type_t<BasicStringPiece<CharT, Traits>> lhs,
            BasicStringPiece<CharT, Traits> rhs) noexcept {
        return !(lhs < rhs);
    }
    std::ostream& operator<<(std::ostream& o, StringPiece piece);
// Not in the STL: convenience functions to output non-UTF-8 strings to an
// 8-bit-width stream.
    std::ostream& operator<<(std::ostream& o, StringPiece16 piece);
    std::ostream& operator<<(std::ostream& o, WStringPiece piece);
// Intentionally omitted (since Chromium does not use character literals):
// operator""sv.
// Stand-ins for the STL's std::hash<> specializations.
    template <typename StringPieceType>
    struct StringPieceHashImpl {
        using is_transparent = void;  // to allow for heterogenous lookup
        // This is a custom hash function. We don't use the ones already defined for
        // string and std::u16string directly because it would require the string
        // constructors to be called, which we don't want.
        size_t operator()(StringPieceType sp) const {
            size_t result = 0;
            for (auto c : sp)
                result = (result * 131) + static_cast<size_t>(c);
            return result;
        }
    };
    using StringPieceHash = StringPieceHashImpl<StringPiece>;
    using StringPiece16Hash = StringPieceHashImpl<StringPiece16>;
    using WStringPieceHash = StringPieceHashImpl<WStringPiece>;
}  // namespace base


ScopedJavaLocalRef<jbyteArray> ToJavaByteArray(JNIEnv* env,
                                               const uint8_t* bytes,
                                               size_t len) {
    const jsize len_jsize = static_cast<jsize>(len);
    jbyteArray byte_array = env->NewByteArray(len_jsize);
    env->SetByteArrayRegion(byte_array, 0, len_jsize,
                            reinterpret_cast<const jbyte*>(bytes));
    return ScopedJavaLocalRef<jbyteArray>(env, byte_array);
}


bool RawSignDigestWithPrivateKey(const JavaRef<jobject>& private_key_ref,
                                 const base::StringPiece& digest,
                                 std::vector<uint8_t>* signature) {
//    JNIEnv* env = AttachCurrentThread();
//    // Convert message to byte[] array.
//    ScopedJavaLocalRef<jbyteArray> digest_ref = ToJavaByteArray(
//            env, reinterpret_cast<const uint8_t*>(digest.data()), digest.length());
//
//
//    jclass clazz = (*env).FindClass("com/example/nanotestapp/MainActivity");
//    jmethodID mid = (*env).GetStaticMethodID(clazz, "rawSignDigestWithPrivateKey","(Ljava/security/PrivateKey;[B)[B");
//
//
//    // Invoke platform API
//    ScopedJavaLocalRef<jbyteArray> signature_ref =
//            ScopedJavaLocalRef<jbyteArray>(env,
//                                static_cast<jbyteArray>(
//                                        env->CallStaticObjectMethod(clazz,
//                                                                    mid,
//                                                                    private_key_ref.obj(),
//                                                                    digest_ref.obj())));
//    if (signature_ref.is_null())
//        return false;
//    // Write signature to string.
//    JavaByteArrayToByteVector(env, signature_ref, signature);
    return true;
}



//AndroidEVP_PKEY* GetOpenSSLSystemHandleForPrivateKey(
//        const JavaRef<jobject>& private_key_ref) {
//    JNIEnv* env = AttachCurrentThread();
//    // Note: the pointer is passed as a jint here because that's how it
//    // is stored in the Java object. Java doesn't have a primitive type
//    // like intptr_t that matches the size of pointers on the host
//    // machine, and Android only runs on 32-bit CPUs.
//    //
//    // Given that this routine shall only be called on Android < 4.2,
//    // this won't be a problem in the far future (e.g. when Android gets
//    // ported to 64-bit environments, if ever).
//    long pkey =
//            Java_AndroidKeyStore_getOpenSSLHandleForPrivateKey(env, private_key_ref);
//    return reinterpret_cast<AndroidEVP_PKEY*>(pkey);
//}
//ScopedJavaLocalRef<jobject> GetOpenSSLEngineForPrivateKey(
//        const JavaRef<jobject>& private_key_ref) {
//    JNIEnv* env = AttachCurrentThread();
//    ScopedJavaLocalRef<jobject> engine =
//            Java_AndroidKeyStore_getOpenSSLEngineForPrivateKey(env, private_key_ref);
//    return engine;
//}

// KeyExData contains the data that is contained in the EX_DATA of the RSA, DSA
// and ECDSA objects that are created to wrap Android system keys.
struct KeyExData {
    // private_key contains a reference to a Java, private-key object.
    jobject private_key;
    // cached_size contains the "size" of the key. This is the size of the
    // modulus (in bytes) for RSA, or the group order size for (EC)DSA. This
    // avoids calling into Java to calculate the size.
    size_t cached_size;
};

// ExDataDup is called when one of the RSA, DSA or EC_KEY objects is
// duplicated. We don't support this and it should never happen.
int ExDataDup(CRYPTO_EX_DATA* to,
              const CRYPTO_EX_DATA* from,
              void** from_d,
              int index,
              long argl,
              void* argp) {
    // CHECK(false);
    return 0;
}
// ExDataFree is called when one of the RSA, DSA or EC_KEY object is freed.
void ExDataFree(void* parent,
                void* ptr,
                CRYPTO_EX_DATA* ad,
                int index,
                long argl,
                void* argp) {
    // Ensure the global JNI reference created with this wrapper is
    // properly destroyed with it.
    KeyExData *ex_data = reinterpret_cast<KeyExData*>(ptr);
    if (ex_data != NULL) {
//        ReleaseKey(ex_data->private_key);
        delete ex_data;
    }
}

ECDSA_SIG* EcdsaMethodDoSign(const unsigned char* dgst,
                             int dgst_len,
                             const BIGNUM* inv,
                             const BIGNUM* rp,
                             EC_KEY* eckey) {
    // Retrieve private key JNI reference.
    jobject private_key = reinterpret_cast<jobject>(
            ECDSA_get_ex_data(eckey, EcdsaGetExDataIndex()));
    if (!private_key) {
        return NULL;
    }
    // Sign message with it through JNI.
    std::vector<uint8> signature;
    base::StringPiece digest(
            reinterpret_cast<const char*>(dgst),
            static_cast<size_t>(dgst_len));
    if (!RawSignDigestWithPrivateKey(
            JavaRef<>(private_key), digest, &signature)) {
        return NULL;
    }

    // Note: With ECDSA, the actual signature may be smaller than
    // ECDSA_size().
    size_t max_expected_size = static_cast<size_t>(ECDSA_size(eckey));
    if (signature.size() > max_expected_size) {
        return NULL;
    }

    // Convert signature to ECDSA_SIG object
    const unsigned char* sigbuf =
            reinterpret_cast<const unsigned char*>(&signature[0]);
    long siglen = static_cast<long>(signature.size());
    return d2i_ECDSA_SIG(NULL, &sigbuf, siglen);
}

int EcdsaMethodSignSetup(EC_KEY* eckey,
                         BN_CTX* ctx,
                         BIGNUM** kinv,
                         BIGNUM** r) {
    return -1;
}

int EcdsaMethodDoVerify(const unsigned char* dgst,
                        int dgst_len,
                        const ECDSA_SIG* sig,
                        EC_KEY* eckey) {
    return -1;
}

const EC_KEY_METHOD android_ecdsa_method = {
        /* .name = */ "Android signing-only ECDSA method",
        /* .ecdsa_do_sign = */ EcdsaMethodDoSign,
        /* .ecdsa_sign_setup = */ EcdsaMethodSignSetup,
        /* .ecdsa_do_verify = */ EcdsaMethodDoVerify,
        /* .flags = */ 0,
        /* .app_data = */ NULL,
};
// BoringSSLEngine is a BoringSSL ENGINE that implements RSA, DSA and ECDSA by
// forwarding the requested operations to the Java libraries.
class BoringSSLEngine {
public:
    BoringSSLEngine()
            : ec_key_index_(EC_KEY_get_ex_new_index(0 /* argl */,
                                                    NULL /* argp */,
                                                    NULL /* new_func */,
                                                    reinterpret_cast<int (*)(CRYPTO_EX_DATA *,
                                                                             const CRYPTO_EX_DATA *,
                                                                             void *, int, long,
                                                                             void *)>(ExDataDup),
                                                    ExDataFree)),
              engine_(ENGINE_new()) {
        ENGINE_set_EC(
                engine_, &android_ecdsa_method, sizeof(android_ecdsa_method));
    }
    int ec_key_ex_index() const { return ec_key_index_; }
    const ENGINE* engine() const { return engine_; }
private:
    const int ec_key_index_;
    ENGINE* const engine_;
};

bool GetEcdsaPkeyWrapper(jobject private_key, EVP_PKEY* pkey) {
    crypto::ScopedEC_KEY ec_key(
            EC_KEY_new_method(global_boringssl_engine.Get().engine()));
//    ScopedJavaGlobalRef<jobject> global_key;
//    global_key.Reset(NULL, private_key);
//    if (global_key.is_null()) {
//        return false;
//    }
//    std::vector<uint8> order;
//    if (!GetECKeyOrder(private_key, &order)) {
//        return false;
//    }
//    KeyExData* ex_data = new KeyExData;
//    ex_data->private_key = global_key.Release();
//    ex_data->legacy_rsa = NULL;
//    ex_data->cached_size = VectorBignumSize(order);
//    EC_KEY_set_ex_data(
//            ec_key.get(), global_boringssl_engine.Get().ec_key_ex_index(), ex_data);
//    EVP_PKEY_assign_EC_KEY(pkey, ec_key.release());
    return true;
}


extern "C" JNIEXPORT jstring JNICALL
Java_com_example_nanotestapp_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */,
        jobject key) {



    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}