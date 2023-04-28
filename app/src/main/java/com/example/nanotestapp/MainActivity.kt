package com.example.nanotestapp

import android.annotation.SuppressLint
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.view.View
import com.example.nanotestapp.DefaultAndroidKeyStore.DefaultAndroidPrivateKey
import com.example.nanotestapp.databinding.ActivityMainBinding
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStore.PrivateKeyEntry
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.interfaces.RSAPrivateKey
import java.util.Calendar
import java.util.GregorianCalendar
import javax.security.auth.x500.X500Principal

class MainActivity : AppCompatActivity() {

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
                val spec = KeyGenParameterSpec.Builder(TEST_KEY_ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setDigests(KeyProperties.DIGEST_SHA384)
                    .setKeySize(2048)
                    .setCertificateSerialNumber(BigInteger(128, SecureRandom()))
                    .setCertificateSubject(X500Principal("CN=$TEST_KEY_ALIAS"))
                    .setCertificateNotAfter(end.time)
                    .setKeyValidityEnd(end.time)
                val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
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
            binding.sampleText.text = stringFromJNI(keyEntry.privateKey)
        })
    }

    /**
     * A native method that is implemented by the 'nanotestapp' native library,
     * which is packaged with this application.
     */
    external fun stringFromJNI(key: PrivateKey): String

    companion object {
        // Used to load the 'nanotestapp' library on application startup.
        init {
            System.loadLibrary("nanotestapp")
        }

        fun getPrivateKeyEncodedBytes(key: AndroidPrivateKey): ByteArray {
            val javaKey: PrivateKey = (key as DefaultAndroidPrivateKey).javaKey
            return javaKey.encoded
        }

        private val TEST_KEY_ALIAS = "NanoTestKeyAliasRsa"
    }
}