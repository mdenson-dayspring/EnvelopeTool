import java.util.*

data class EnvelopeContents(
    val success: Boolean,
    val version: String? = null,
    val messageTime: String? = null,
    val aead: AEADEncrypted? = null
)

/**
 * Close Envelope
 * ==============
 *
 * Wrap the give AEAD Construction and tag into a sofe MIME "envelope" for including in email or other text transport
 */
fun closeEnvelope(content: AEADEncrypted, messageTime: String): String {
    val buff = StringBuffer()

    val allContent = content.cyphertext.toMutableList()
    allContent.addAll(content.tag)

    buff.append("------------------------------------------------------------------------\n")
    buff.append(" Envelope Tool 1.0.0\n")
    buff.append(" Time: $messageTime\n\n")
    buff.append(" ")
    buff.append(
        Base64.getMimeEncoder(71, "\n ".toByteArray())
            .encodeToString(allContent.toTypedArray().map { i -> i.toByte() }.toByteArray())
    )
    buff.append("\n")
    buff.append("------------------------------------------------------------------------\n")

    return buff.toString()
}

/**
 * Open Envelope
 * =============
 *
 * Unwrap the MIME encoded "envelope" and return the AEAD constructed message and tag.
 */
fun openEnvelope(content: String): EnvelopeContents {
    val lines = content.reader().readLines()
    if (!lines.get(1).trim().startsWith("Envelope Tool") ||
        !lines.get(2).trim().startsWith("Time:")
    ) {
        return EnvelopeContents(false)
    } else {
        // get version
        val version = lines.get(1).substring(14).trim()
        // get timestamp
        val timestamp = lines.get(2).substring(6).trim()
        // get content
        val buff = StringBuffer()
        var line = 4
        while (!lines.get(line).startsWith("--")) {
            buff.append(lines.get(line))
            line++
        }
        val bytes = Base64.getMimeDecoder().decode(buff.toString()).toTypedIntArray()
        val aead = AEADEncrypted(bytes.copyOfRange(0, bytes.size - 16), bytes.copyOfRange(bytes.size - 16, bytes.size))
        return EnvelopeContents(true, version, timestamp, aead)
    }
}
