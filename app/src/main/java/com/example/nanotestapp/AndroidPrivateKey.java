package com.example.nanotestapp;

/**
 * Abstract private key that bundles the PrivateKey and AndroidKeyStore that it belongs to.
 */
public interface AndroidPrivateKey {
    /** @return AndroidKeyStore that handles this key. */
    AndroidKeyStore getKeyStore();
}