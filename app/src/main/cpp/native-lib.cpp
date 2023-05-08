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
#include <cstddef>
#include <cstdint>
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
#include "chromium/base/android/scoped_java_ref.h"
#include "chromium/base/atomicops.h"

typedef uint8_t uint8;

#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
  TypeName(const TypeName&);               \
  void operator=(const TypeName&)
JavaVM* g_jvm = nullptr;
JNIEnv* g_jenv = nullptr;
JNIEnv* AttachCurrentThread() {
//    JNIEnv* env = nullptr;
//    jint ret = g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_2);
//    if (ret == JNI_EDETACHED || !env) {
//        JavaVMAttachArgs args;
//        args.version = JNI_VERSION_1_2;
//        args.group = nullptr;
//        // 16 is the maximum size for thread names on Android.
//        char thread_name[16];
//        int err = prctl(PR_GET_NAME, thread_name);
//        if (err < 0) {
//            args.name = nullptr;
//        } else {
//            args.name = thread_name;
//        }
//        ret = g_jvm->AttachCurrentThread(&env, &args);
//    }
//    return env;
    return g_jenv;
}

template <typename JavaArrayType>
size_t SafeGetArrayLength(JNIEnv* env,
const base::android::JavaRef<JavaArrayType>& jarray) {
jsize length = env->GetArrayLength(jarray.obj());
return static_cast<size_t>(std::max(0, length));
}

void AppendJavaByteArrayToByteVector(JNIEnv* env,
                                     const base::android::JavaRef<jbyteArray>& byte_array,
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
                               const base::android::JavaRef<jbyteArray>& byte_array,
                               std::vector<uint8_t>* out) {
    out->clear();
    AppendJavaByteArrayToByteVector(env, byte_array, out);
}

#define PR_GET_NAME    16		/* Get process name */

// This is called by the VM when the shared library is first loaded.
// todo: this leads to a crash when app lauch
//JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
//    if (g_jvm == nullptr) {
//        g_jvm = vm;
//    }
//}


base::android::ScopedJavaLocalRef<jbyteArray> ToJavaByteArray(JNIEnv* env,
                                               const uint8_t* bytes,
                                               size_t len) {
    const jsize len_jsize = static_cast<jsize>(len);
    jbyteArray byte_array = env->NewByteArray(len_jsize);
    env->SetByteArrayRegion(byte_array, 0, len_jsize,
                            reinterpret_cast<const jbyte*>(bytes));
    return base::android::ScopedJavaLocalRef<jbyteArray>(env, byte_array);
}


bool RawSignDigestWithPrivateKey(
        jobject private_key_ref,
        const unsigned char* dgst,
        int dgst_len,
        std::vector<uint8>* signature) {
    JNIEnv* env = AttachCurrentThread();
    // Convert message to byte[] array.
    base::android::ScopedJavaLocalRef<jbyteArray> digest_ref =
            ToJavaByteArray(env,
                            reinterpret_cast<const uint8*>(dgst),
                            dgst_len);
    jclass cls = (*env).FindClass("com/example/nanotestapp/MainActivity");
    jmethodID methodid = (*env).GetStaticMethodID(cls, "rawSignDigestWithPrivateKey",
                                            "(Lcom/example/nanotestapp/AndroidPrivateKey;[B)[B");
    auto sig = (jbyteArray) (*env).CallStaticObjectMethod(cls, methodid, private_key_ref, digest_ref.obj());
    base::android::ScopedJavaLocalRef<jbyteArray> signature_ref = base::android::ScopedJavaLocalRef<jbyteArray>(env, sig);
//    ScopedJavaLocalRef<jbyteArray> signature_ref =
//            Java_AndroidKeyStore_rawSignDigestWithPrivateKey(
//                    env, private_key_ref, digest_ref.obj());
    if (/*HasException(env) || */signature_ref.is_null())
        return false;
    // Write signature to string.
    JavaByteArrayToByteVector(env, signature_ref, signature);
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
    // This callback shall never be called with the current OpenSSL
    // implementation (the library only ever duplicates EX_DATA items
    // for SSL and BIO objects). But provide this to catch regressions
    // in the future.
    // CHECK(false) << "ExDataDup was called for ECDSA custom key !?";
    // Return value is currently ignored by OpenSSL.
    return 0;
}
void ExDataFree(void* parent,
                void* ptr,
                CRYPTO_EX_DATA* ad,
                int idx,
                long argl,
                void* argp) {
    auto private_key = reinterpret_cast<jobject>(ptr);
    if (private_key == nullptr)
        return;
    CRYPTO_set_ex_data(ad, idx, nullptr);
    JNIEnv* env = AttachCurrentThread();
    // todo: this leads to a crash, https://stackoverflow.com/questions/63219070/making-an-object-reference-null-from-jni-code
    // env->DeleteGlobalRef(private_key);
}

class EcdsaExDataIndex {
public:
    int ex_data_index() { return ex_data_index_; }
    EcdsaExDataIndex() {
        ex_data_index_ = EC_KEY_get_ex_new_index(0,           // argl
                                                NULL,        // argp
                                                NULL,        // new_func
                                                 reinterpret_cast<int (*)(CRYPTO_EX_DATA *,
                                                                          const CRYPTO_EX_DATA *,
                                                                          void *, int, long,
                                                                          void *)>(ExDataDup),   // dup_func
                                                ExDataFree); // free_func
    }
private:
    int ex_data_index_;
};

EcdsaExDataIndex g_ecdsa_ex_data_index = EcdsaExDataIndex();

// Returns the index of the custom EX_DATA used to store the JNI reference.
int EcdsaGetExDataIndex() {
    return g_ecdsa_ex_data_index.ex_data_index();
}

EC_KEY_METHOD* android_ecdsa_method = EC_KEY_METHOD_new(nullptr);

// BoringSSLEngine is a BoringSSL ENGINE that implements RSA, DSA and ECDSA by
// forwarding the requested operations to the Java libraries.
class BoringSSLEngine {
public:
    BoringSSLEngine()
            : ec_key_index_(EC_KEY_get_ex_new_index(0 /* argl */,
                                                    nullptr /* argp */,
                                                    nullptr /* new_func */,
                                                    reinterpret_cast<int (*)(CRYPTO_EX_DATA *,
                                                                             const CRYPTO_EX_DATA *,
                                                                             void *, int, long,
                                                                             void *)>(ExDataDup),
                                                    ExDataFree)),
              engine_(ENGINE_new()) {

        ENGINE_set_EC(
                engine_, android_ecdsa_method);
    }
    int ec_key_ex_index() const { return ec_key_index_; }
    ENGINE* engine() const { return engine_; }
private:
    const int ec_key_index_;
    ENGINE* const engine_;
};

const BoringSSLEngine global_boringssl_engine = BoringSSLEngine();


jobject EcKeyGetKey(const EC_KEY* ec_key) {
    auto* ex_data = reinterpret_cast<KeyExData*>(EC_KEY_get_ex_data(
            ec_key, global_boringssl_engine.ec_key_ex_index()));
    return ex_data->private_key;
}

ECDSA_SIG* EcdsaMethodDoSign(const unsigned char* dgst,
                             int dgst_len,
                             const BIGNUM* inv,
                             const BIGNUM* rp,
                             EC_KEY* eckey) {
    // Retrieve private key JNI reference.
    auto private_key = EcKeyGetKey(eckey);
    if (!private_key) {
//        LOG(WARNING) << "Null JNI reference passed to EcdsaMethodDoSign!";
        return nullptr;
    }
    // Sign message with it through JNI.
    std::vector<uint8> signature;
    if (!RawSignDigestWithPrivateKey(
            private_key, dgst, dgst_len, &signature)) {
//        LOG(WARNING) << "Could not sign message in EcdsaMethodDoSign!";
        return nullptr;
    }
    // Note: With ECDSA, the actual signature may be smaller than
    // ECDSA_size().
    auto max_expected_size = static_cast<size_t>(ECDSA_size(eckey));
    if (signature.size() > max_expected_size) {
//        LOG(ERROR) << "ECDSA Signature size mismatch, actual: "
//                   <<  signature.size() << ", expected <= "
//                   << max_expected_size;
        return nullptr;
    }
    // Convert signature to ECDSA_SIG object
    const auto* sigbuf =
            reinterpret_cast<const unsigned char*>(&signature[0]);
    long siglen = static_cast<long>(signature.size());
    return d2i_ECDSA_SIG(nullptr, &sigbuf, siglen);
}


//int EcdsaMethodSign(const uint8_t* digest,
//                    size_t digest_len,
//                    uint8_t* sig,
//                    unsigned int* sig_len,
//                    EC_KEY* ec_key) {
//    // Retrieve private key JNI reference.
//    jobject private_key = EcKeyGetKey(ec_key);
//    if (!private_key) {
////        LOG(WARNING) << "Null JNI reference passed to EcdsaMethodSign!";
//        return 0;
//    }
//    // Sign message with it through JNI.
//    std::vector<uint8> signature;
//    base::StringPiece digest_sp(reinterpret_cast<const char*>(digest),
//                                digest_len);
//    if (!RawSignDigestWithPrivateKey(private_key, digest_sp, &signature)) {
////        LOG(WARNING) << "Could not sign message in EcdsaMethodSign!";
//        return 0;
//    }
//    // Note: With ECDSA, the actual signature may be smaller than
//    // ECDSA_size().
//    size_t max_expected_size = ECDSA_size(ec_key);
//    if (signature.size() > max_expected_size) {
////        LOG(ERROR) << "ECDSA Signature size mismatch, actual: "
////                   <<  signature.size() << ", expected <= "
////                   << max_expected_size;
//        return 0;
//    }
//    memcpy(sig, &signature[0], signature.size());
//    *sig_len = signature.size();
//    return 1;


bool GetECKeyOrder(jobject private_key_ref,
                   std::vector<uint8>* result) {
    JNIEnv* env = AttachCurrentThread();
    jclass cls = (*env).FindClass("com/example/nanotestapp/MainActivity");
    jmethodID methodId = (*env).GetStaticMethodID(cls, "getECKeyOrder",
                                                  "(Lcom/example/nanotestapp/AndroidPrivateKey;)[B");
    auto order = (jbyteArray) (*env).CallStaticObjectMethod(cls, methodId, private_key_ref);
    base::android::ScopedJavaLocalRef<jbyteArray> order_ref = base::android::ScopedJavaLocalRef<jbyteArray>(env, order);
//    ScopedJavaLocalRef<jbyteArray> order_ref =
//            Java_AndroidKeyStore_getECKeyOrder(env, private_key_ref);
    if (order_ref.is_null())
        return false;
    JavaByteArrayToByteVector(env, order_ref, result);
    return true;
}

// VectorBignumSize returns the number of bytes needed to represent the bignum
// given in |v|, i.e. the length of |v| less any leading zero bytes.
size_t VectorBignumSize(const std::vector<uint8>& v) {
    size_t size = v.size();
    // Ignore any leading zero bytes.
    for (size_t i = 0; i < v.size() && v[i] == 0; i++) {
        size--;
    }
    return size;
}

bool GetEcdsaPkeyWrapper(jobject private_key, EVP_PKEY* pkey) {
    crypto::ScopedEC_KEY ec_key(
            EC_KEY_new_method(global_boringssl_engine.engine()));
    base::android::ScopedJavaGlobalRef<jobject> global_key;
    global_key.Reset(AttachCurrentThread(), private_key);
    if (global_key.is_null()) {
//        LOG(ERROR) << "Can't create global JNI reference";
        return false;
    }
    std::vector<uint8> order;
    if (!GetECKeyOrder(private_key, &order)) {
//        LOG(ERROR) << "Can't extract order parameter from EC private key";
        return false;
    }
    auto* ex_data = new KeyExData;
    ex_data->private_key = global_key.Release();
    ex_data->cached_size = VectorBignumSize(order);
    EC_KEY_set_ex_data(
            ec_key.get(), global_boringssl_engine.ec_key_ex_index(), ex_data);
    EVP_PKEY_assign_EC_KEY(pkey, ec_key.release());
    return true;
}


extern "C"
JNIEXPORT jstring
JNICALL
Java_com_example_nanotestapp_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */,
        jobject key) {

    if (g_jenv == nullptr) {
        g_jenv = env;
    }

    // Create new empty EVP_PKEY instance.
    crypto::ScopedEVP_PKEY pkey(EVP_PKEY_new());

    if (!GetEcdsaPkeyWrapper(key, pkey.get())) {
        std::string hello = "Can't create EVP_PKEY from EC private key";
        return env->NewStringUTF(hello.c_str());
    } else {
        std::string hello = std::to_string(EVP_PKEY_id(pkey.get())).append("(EVP_PKEY_ID)");
        return env->NewStringUTF(hello.c_str());
    }
}