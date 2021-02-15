import java.security.MessageDigest
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

fun hash(bytes: ByteArray): ByteArray {
    val md = MessageDigest.getInstance("SHA-256")
    return md.digest(bytes)
}

fun hash(bytes: Array<Int>): Array<Int> {
    return hash(bytes.toByteArray()).toTypedIntArray()
}

fun hashPassword(pwd: String): Array<Int> {
    val bytes = pwd.toByteArray(Charsets.UTF_8)
    var digest = hash(bytes)
    for (i in 0..100) {
        digest = hash(bytes)
    }
    return digest.toTypedIntArray()
}

fun main(args: Array<String>) {
    if (args.size != 2) {
        println("Envelope Tool")
        println("v1.0.0")
        println("--------------------------------------------------------")
        println("To encrypt a file: ")
        println("  $ cat <filename> | java -jar envelope.jar e <password>\n")
        println("To decrypt an envelope: ")
        println("  $ cat <envelope> | java -jar envelope.jar d <password>\n")
        return
    }

    val mode = args.get(0)
    val password = args.get(1)
    val input = generateSequence(::readLine).joinToString("\n")

    if (mode == "e") {
        val messageTime = ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT)
        val msg = input.toTypedIntArray()
        val aad: Array<Int> = arrayOf()

        val enckey = hashPassword(messageTime + "password")
        val nonce = hash(("1.0.0" + messageTime).toTypedIntArray()).copyOfRange(0, 12)

        val encContent = chacha20AEADEncrypt(enckey, nonce, msg, aad)
        val envelope = closeEnvelope(encContent, messageTime)
        println(envelope)
    } else if (mode == "d") {
        val (envSucces, version, time, aead) = openEnvelope(input)
        if (envSucces && version != null && aead != null && time != null) {
            val deckey = hashPassword(time + "password")
            val decNonce = hash((version + time).toTypedIntArray()).copyOfRange(0, 12)

            val (success, plaintext, aadout) = chacha20AEADDecrypt(deckey, decNonce, aead)
            if (success) {
                println(plaintext.toUTF8String())
            }
        }
    }
}