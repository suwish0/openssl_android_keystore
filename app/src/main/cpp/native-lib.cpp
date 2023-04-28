#include <jni.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <vector>
#include <string>

typedef uint8_t uint8;

//const RSA_METHOD android_rsa_method = {
//        {
//                0 /* references */,
//                1 /* is_static */
//        } /* common */,
//        NULL /* app_data */,
//        NULL /* init */,
//        NULL /* finish */,
//        RsaMethodSize,
//        NULL /* sign */,
//        NULL /* verify */,
//        RsaMethodEncrypt,
//        RsaMethodSignRaw,
//        RsaMethodDecrypt,
//        RsaMethodVerifyRaw,
//        NULL /* mod_exp */,
//        NULL /* bn_mod_exp */,
//        RSA_FLAG_OPAQUE,
//        NULL /* keygen */,
//};
//
//size_t RsaMethodSize(const RSA *rsa) {
//    const KeyExData *ex_data = RsaGetExData(rsa);
//    return ex_data->cached_size;
//}

// KeyExData contains the data that is contained in the EX_DATA of the RSA, DSA
// and ECDSA objects that are created to wrap Android system keys.
struct KeyExData {
    // private_key contains a reference to a Java, private-key object.
    jobject private_key;
    // legacy_rsa, if not NULL, points to an RSA* in the system's OpenSSL (which
    // might not be ABI compatible with Chromium).
//    AndroidRSA* legacy_rsa;
    // cached_size contains the "size" of the key. This is the size of the
    // modulus (in bytes) for RSA, or the group order size for (EC)DSA. This
    // avoids calling into Java to calculate the size.
    size_t cached_size;
};

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_nanotestapp_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */,
        jobject key) {

//    crypto::ScopedRSA rsa(RSA_new());
//    RSA_set_method(RSA_new(), &android_rsa_method);
    // HACK: RSA_size() doesn't work with custom RSA_METHODs. To ensure that
    // it will return the right value, set the 'n' field of the RSA object
    // to match the private key's modulus.
    std::vector<uint8> modulus;
//    if (!GetRSAKeyModulus(key, &modulus)) {
//        LOG(ERROR) << "Failed to get private key modulus";
//    }
//    if (!SwapBigNumPtrFromBytes(modulus, &rsa.get()->n)) {
//        LOG(ERROR) << "Failed to decode private key modulus";
//    }

//    EVP_PKEY

    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}