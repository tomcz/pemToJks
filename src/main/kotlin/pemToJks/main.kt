package pemToJks

import org.apache.commons.cli.CommandLine
import org.apache.commons.cli.DefaultParser
import org.apache.commons.cli.HelpFormatter
import org.apache.commons.cli.Option
import org.apache.commons.cli.Options
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import java.io.File
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.UUID
import javax.crypto.Cipher
import kotlin.system.exitProcess

val provider = BouncyCastleProvider()

fun main(args: Array<String>) {
    val options = Options()
    options.addOption(Option("h", "help", false, "Print this message and exit"))
    options.addOption("cert", true, "Path to PEM certificate file")
    options.addOption("key", true, "Path to PEM key file")
    options.addOption("store", true, "Path to java keystore file")
    options.addOption("storepw", true, "Java keystore password")
    options.addOption("alias", true, "Java keystore alias for certificate/key")
    options.addOption("aliaspw", true, "Java keystore key alias password")

    val cmd = parseArgs(args, options)

    val certFile = File(cmd.getOptionValue("cert"))
    val keyFile = cmd.getOptionValue("key")?.let { File(it) }

    val ksFile = File(cmd.getOptionValue("store"))
    val ksPass = (cmd.getOptionValue("storepw") ?: "").toCharArray()

    val alias = cmd.getOptionValue("alias") ?: "item"
    val aliasPass = (cmd.getOptionValue("aliaspw") ?: "").toCharArray()

    val certs = readCertChain(certFile)
    val keys = keyFile?.let { readPrivateKeys(it) }

    if (certs.isEmpty()) {
        throw RuntimeException("No certificates found!")
    }
    if (keyFile != null && (keys == null || keys.isEmpty())) {
        throw RuntimeException("No keys found!")
    }

    val chain = certs.toTypedArray()
    val key = keys?.get(0)

    key?.let { verifyCertAndKey(chain[0], it) }
    addToKeyStore(ksFile, ksPass, alias, aliasPass, chain, key)

    println("Done")
}

fun parseArgs(args: Array<String>, options: Options): CommandLine {
    val parser = DefaultParser()
    val cmd = parser.parse(options, args)
    if (cmd.hasOption("help")) {
        printUsageAndExit(options)
    }
    if (!cmd.hasOption("cert")) {
        println("Please provide the path to a PEM certificate file")
        printUsageAndExit(options)
    }
    if (!cmd.hasOption("store")) {
        println("Please provide the path to a java keystore file")
        printUsageAndExit(options)
    }
    return cmd
}

fun printUsageAndExit(options: Options) {
    val formatter = HelpFormatter()
    formatter.printHelp("pemToJks", options)
    exitProcess(1)
}

fun readCertChain(certFile: File): List<Certificate> {
    println("Reading certificate file")
    return readFile(certFile)
            .filter { it.type == "CERTIFICATE" }
            .map { createCertificate(it) }
}

fun readPrivateKeys(keyFile: File): List<PrivateKey> {
    println("Reading key file")
    return readFile(keyFile)
            .filter { it.type == "RSA PRIVATE KEY" || it.type == "PRIVATE KEY" }
            .map { createPrivateKey(it) }
}

fun readFile(file: File): List<PemObject> {
    val objects = mutableListOf<PemObject>()
    PemReader(file.reader()).use {
        while (true) {
            val obj = it.readPemObject() ?: break
            objects.add(obj)
        }
    }
    return objects
}

fun createCertificate(obj: PemObject): Certificate {
    val cf = CertificateFactory.getInstance("X.509", provider)
    return cf.generateCertificate(obj.content.inputStream())
}

fun createPrivateKey(obj: PemObject): PrivateKey {
    val spec = PKCS8EncodedKeySpec(obj.content)
    val kf = KeyFactory.getInstance("RSA", provider)
    return kf.generatePrivate(spec)
}

fun verifyCertAndKey(cert: Certificate, key: PrivateKey) {
    println("Verifying certificate against key")
    val expected = UUID.randomUUID().toString()

    val encCipher = Cipher.getInstance("RSA", provider)
    encCipher.init(Cipher.ENCRYPT_MODE, cert.publicKey)
    val cipherText = encCipher.doFinal(expected.toByteArray(Charsets.UTF_8))

    val decCipher = Cipher.getInstance("RSA", provider)
    decCipher.init(Cipher.DECRYPT_MODE, key)
    val actual = String(decCipher.doFinal(cipherText), Charsets.UTF_8)

    if (actual != expected) {
        throw RuntimeException("Verification failed!")
    }
}

fun addToKeyStore(ksFile: File, ksPass: CharArray, alias: String, aliasPass: CharArray,
                  chain: Array<Certificate>, key: PrivateKey?) {

    println("Loading keystore")
    val ks = KeyStore.getInstance("JKS")

    if (ksFile.exists() && ksFile.length() > 0) {
        ksFile.inputStream().use { ks.load(it, ksPass) }
    } else {
        ks.load(null, ksPass)
    }

    if (key != null) {
        println("Adding key & cert chain entry to keystore")
        ks.setKeyEntry(alias, key, aliasPass, chain)
    } else {
        println("Adding certificate entry to keystore")
        ks.setCertificateEntry(alias, chain[0])
    }

    println("Saving keystore")
    ksFile.outputStream().use { ks.store(it, ksPass) }
}
