package io.ktor.sessions

import io.ktor.sessions.*
import io.ktor.sessions.SessionTransportTransformerEncrypt
import io.ktor.util.*
import org.slf4j.*
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*

class SessionTransportTransformerEncrypt(
        val encryptionKeySpec: SecretKeySpec,
        val signKeySpec: SecretKeySpec,
        ivGenerator: ((size: Int) -> ByteArray)? = null,
        val encryptAlgorithm: String = encryptionKeySpec.algorithm,
        val signAlgorithm: String = signKeySpec.algorithm
) : SessionTransportTransformer {
    companion object {
        private val log = LoggerFactory.getLogger(SessionTransportTransformerEncrypt::class.qualifiedName)
    }

    private val random by lazy { SecureRandom.getInstance("SHA1PRNG").apply { generateSeed(16) } }
    private fun defaultIvGenerator(size: Int): ByteArray = ByteArray(size).also { random.nextBytes(it) }

    val ivGenerator = ivGenerator ?: { defaultIvGenerator(it) }
    private val charset = Charsets.UTF_8

    /**
     * Encryption key size in bytes
     */
    val encryptionKeySize: Int get() = encryptionKeySpec.encoded.size

    // Check that input keys are right
    init {
        encrypt(ivGenerator(encryptionKeySize), byteArrayOf())
        mac(byteArrayOf())
    }

    constructor(
            encryptionKey: ByteArray,
            signKey: ByteArray,
            ivGenerator: ((size: Int) -> ByteArray)? = null,
            encryptAlgorithm: String = "AES",
            signAlgorithm: String = "HmacSHA256"
    ) : this(
            SecretKeySpec(encryptionKey, encryptAlgorithm),
            SecretKeySpec(signKey, signAlgorithm),
            ivGenerator
    )

    override fun transformRead(transportValue: String): String? {
        try {
            val encrypedMac = transportValue.substringAfterLast('/', "")
            val iv = hex(transportValue.substringBeforeLast('/'))
            val encrypted = hex(encrypedMac.substringBeforeLast(':'))
            val macHex = encrypedMac.substringAfterLast(':', "")
            val decrypted = decrypt(iv, encrypted)

            if (hex(mac(decrypted)) != macHex) {
                return null
            }

            return decrypted.toString(charset)
        } catch (e: Throwable) {
            e.printStackTrace()
            // NumberFormatException // Invalid hex
            // InvalidAlgorithmParameterException // Invalid data
            if (log.isDebugEnabled) {
                log.debug(e.toString())
            }
            return null
        }
    }

    override fun transformWrite(transportValue: String): String {
        val iv = ivGenerator(encryptionKeySize)
        val decrypted = transportValue.toByteArray(charset)
        val encrypted = encrypt(iv, decrypted)
        val mac = mac(decrypted)
        return "${hex(iv)}/${hex(encrypted)}:${hex(mac)}"
    }

    private fun encrypt(initVector: ByteArray, decrypted: ByteArray): ByteArray {
        return encryptDecrypt(Cipher.ENCRYPT_MODE, initVector, decrypted)
    }

    private fun decrypt(initVector: ByteArray, encrypted: ByteArray): ByteArray {
        return encryptDecrypt(Cipher.DECRYPT_MODE, initVector, encrypted)
    }

    private fun encryptDecrypt(mode: Int, initVector: ByteArray, input: ByteArray): ByteArray {
        val iv = IvParameterSpec(initVector)
        val cipher = Cipher.getInstance("$encryptAlgorithm/CBC/PKCS5PADDING")
        cipher.init(mode, encryptionKeySpec, iv)
        return cipher.doFinal(input)
    }

    private fun mac(value: ByteArray): ByteArray = Mac.getInstance(signAlgorithm).run {
        init(signKeySpec)
        doFinal(value)
    }
}
