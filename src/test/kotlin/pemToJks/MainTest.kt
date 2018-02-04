package pemToJks

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Before
import org.junit.Test
import java.io.File
import java.security.KeyStore
import java.security.cert.X509Certificate
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class MainTest {

    private val alias = "alias"
    private val aliasPass = "aliasPass".toCharArray()

    private lateinit var ksFile: File
    private val ksPass = "ksPass".toCharArray()

    private val certFile = File("src/test/resources/cert.pem")
    private val keyFile = File("src/test/resources/key.pem")

    @Before
    fun setUp() {
        ksFile = createTempFile()
    }

    @After
    fun tearDown() {
        ksFile.delete()
    }

    @Test
    fun shouldParseCertificateChain() {
        val certs = readCertChain(certFile)
        assertEquals(2, certs.size)
        var cert = certs[0] as X509Certificate
        assertEquals("CN=pemToJks.service-a.internal.example.com", cert.subjectDN.name)
        cert = certs[1] as X509Certificate
        assertEquals("CN=pki-intermediate-01", cert.subjectDN.name)
    }

    @Test
    fun shouldHandleFileWithoutCerts() {
        val certs = readCertChain(keyFile)
        assertEquals(0, certs.size)
    }

    @Test
    fun shouldParsePrivateKey() {
        val keys = readPrivateKeys(keyFile)
        assertEquals(1, keys.size)
    }

    @Test
    fun shouldHandleFileWithoutKeys() {
        val keys = readPrivateKeys(certFile)
        assertEquals(0, keys.size)
    }

    @Test
    fun shouldVerifyThatCertAndKeyMatch() {
        val certs = readCertChain(certFile)
        val keys = readPrivateKeys(keyFile)

        verifyCertAndKey(certs[0], keys[0])

        assertFailsWith(Exception::class) {
            verifyCertAndKey(certs[1], keys[0])
        }
    }

    @Test
    fun shouldWriteFirstCertToKeyStore() {
        val certs = readCertChain(certFile)

        addToKeyStore(ksFile, ksPass, alias, aliasPass, certs.toTypedArray(), null)

        val ks = KeyStore.getInstance("JKS")
        ksFile.inputStream().use { ks.load(it, ksPass) }

        assertEquals(certs[0], ks.getCertificate(alias))
    }

    @Test
    fun shouldWriteCertsAndKeyToKeyStore() {
        val certs = readCertChain(certFile)
        val keys = readPrivateKeys(keyFile)

        addToKeyStore(ksFile, ksPass, alias, aliasPass, certs.toTypedArray(), keys[0])

        val ks = KeyStore.getInstance("JKS")
        ksFile.inputStream().use { ks.load(it, ksPass) }

        assertEquals(keys[0], ks.getKey(alias, aliasPass))
        assertArrayEquals(certs.toTypedArray(), ks.getCertificateChain(alias))
    }
}
