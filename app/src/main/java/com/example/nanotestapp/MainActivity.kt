package com.example.nanotestapp

import android.annotation.SuppressLint
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import com.example.nanotestapp.DefaultAndroidKeyStore.DefaultAndroidPrivateKey
import com.example.nanotestapp.databinding.ActivityMainBinding
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStore.PrivateKeyEntry
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.DSAPrivateKey
import java.security.interfaces.ECKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.util.Calendar
import java.util.GregorianCalendar
import javax.security.auth.x500.X500Principal


public class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var keyStore: KeyStore
    private var defaultKeyStore = DefaultAndroidKeyStore()

    @SuppressLint("SetTextI18n")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
        } catch (e: Exception) {
            e.printStackTrace()
            binding.sampleText.text = e.message
            return
        }

        binding.btnGenerateKey.setOnClickListener(View.OnClickListener {
            if (!keyStore.containsAlias(TEST_KEY_ALIAS)) {
                val end: Calendar = GregorianCalendar(2024, 3, 24)
                val spec = KeyGenParameterSpec.Builder(TEST_KEY_ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY /*or KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT*/)
                    .setDigests(KeyProperties.DIGEST_SHA384)
                    .setKeySize(384)
                    .setCertificateSerialNumber(BigInteger(128, SecureRandom()))
                    .setCertificateSubject(X500Principal("CN=$TEST_KEY_ALIAS"))
                    .setCertificateNotAfter(end.time)
                    .setKeyValidityEnd(end.time)
                val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                kpg.initialize(spec.build())
                kpg.genKeyPair()
            }
            binding.sampleText.text = "Key Generated!\n Alias: $TEST_KEY_ALIAS"
        })

        binding.btnGetKey.setOnClickListener(View.OnClickListener {
            if (!keyStore.containsAlias(TEST_KEY_ALIAS)) {
                binding.sampleText.text = "Key not found."
                return@OnClickListener
            }
            val keyEntry: PrivateKeyEntry = keyStore.getEntry(TEST_KEY_ALIAS, null) as PrivateKeyEntry
            val androidKey = defaultKeyStore.createKey(keyEntry.privateKey)
            val pointerKey = defaultKeyStore.getOpenSSLHandleForPrivateKey(androidKey)
            binding.sampleText.text = "$pointerKey"
        })

        binding.btnGetKeyNative.setOnClickListener(View.OnClickListener {
            if (!keyStore.containsAlias(TEST_KEY_ALIAS)) {
                binding.sampleText.text = "Key not found."
                return@OnClickListener
            }

            val keyEntry: PrivateKeyEntry = keyStore.getEntry(TEST_KEY_ALIAS, null) as PrivateKeyEntry
            val androidKey = defaultKeyStore.createKey(keyEntry.privateKey)
            binding.sampleText.text = stringFromJNI(androidKey)
        })
    }

    fun getPrivateKeyEncodedBytes(key: AndroidPrivateKey): ByteArray {
        val javaKey: PrivateKey = (key as DefaultAndroidPrivateKey).javaKey
        return javaKey.encoded
    }


    /**
     * A native method that is implemented by the 'nanotestapp' native library,
     * which is packaged with this application.
     */
    external fun stringFromJNI(key: AndroidPrivateKey): String

    companion object {
        // Used to load the 'nanotestapp' library on application startup.
        init {
            System.loadLibrary("nanotestapp")
        }

        @JvmStatic
        fun getECKeyOrder(key: AndroidPrivateKey): ByteArray? {
            val javaKey = (key as DefaultAndroidPrivateKey).javaKey
            if (javaKey is ECKey) {
                val params = (javaKey as ECKey).params
                return params.order.toByteArray()
            }
            Log.w(TAG, "Not an ECKey instance!")
            return null
        }

        @JvmStatic
        fun rawSignDigestWithPrivateKey(
            key: AndroidPrivateKey,
            message: ByteArray?
        ): ByteArray? {
            val javaKey = (key as DefaultAndroidPrivateKey).javaKey
            // Get the Signature for this key.
            var signature: Signature? = null
            // Hint: Algorithm names come from:
            // http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
            try {
                if (javaKey is RSAPrivateKey) {
                    // IMPORTANT: Due to a platform bug, this will throw NoSuchAlgorithmException
                    // on Android 4.0.x and 4.1.x. Fixed in 4.2 and higher.
                    // See https://android-review.googlesource.com/#/c/40352/
                    signature = Signature.getInstance("NONEwithRSA")
                } else if (javaKey is DSAPrivateKey) {
                    signature = Signature.getInstance("NONEwithDSA")
                } else if (javaKey is ECPrivateKey) {
                    signature = Signature.getInstance("NONEwithECDSA")
                }
            } catch (e: NoSuchAlgorithmException) {
            }
            if (signature == null) {
                Log.e(TAG, "Unsupported private key algorithm: " + javaKey.algorithm)
                return null
            }
            // Sign the message.
            return try {
                signature.initSign(javaKey)
                signature.update(message)
                signature.sign()
            } catch (e: java.lang.Exception) {
                Log.e(
                    TAG, "Exception while signing message with " + javaKey.algorithm +
                            " private key: " + e
                )
                null
            }
        }

        private val TAG = "Android_JNI0"

        private val TEST_KEY_ALIAS = "NanoTestKeyAliasECDSA"
    }
}