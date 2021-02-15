import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

class MainKtTest {
    @Test
    fun envelopeRoundTrip() {
        val messageTime = "2021-02-12T01:54:30.832413Z"
        val quote =
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        val expectedEnv = "------------------------------------------------------------------------\n" +
                " Envelope Tool 1.0.0\n" +
                " Time: 2021-02-12T01:54:30.832413Z\n" +
                "\n" +
                " lhZPByJXAs2m/IyxMC3qE4j2HY7MPSOPUHEeQ/kz+vfO8hmVE9rMGr77UgRvRPcrfzY/\n" +
                " knUXeChY52oyLLphuH3zflDN3OkGl3xciQYEgDC5G5ugv+R0BHGa58m4E7d9QcHCtAp/\n" +
                " h2uzrRf0l5MxNZrJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHIAAAAAAAAAHCeKUP08kL07\n" +
                " budJsIISqA==\n" +
                "------------------------------------------------------------------------\n"

        val msg = quote.toTypedIntArray()
        val aad: Array<Int> = arrayOf()

        val enckey = hashPassword(messageTime + "password")
        val nonce = hash(("1.0.0" + messageTime).toTypedIntArray()).copyOfRange(0, 12)

        val encContent = chacha20AEADEncrypt(enckey, nonce, msg, aad)
        val envelope = closeEnvelope(encContent, messageTime)

        assertEquals(expectedEnv, envelope, "envelope")

        // -- Now decrypt

        val (envSuccess, version, time, aead) = openEnvelope(envelope)
        assertTrue(envSuccess, "Envelope not unpacked")
        if (envSuccess && version != null && aead != null && time != null) {
            val deckey = hashPassword(time + "password")
            val decNonce = hash((version + time).toTypedIntArray()).copyOfRange(0, 12)

            val (success, plaintext, aadout) = chacha20AEADDecrypt(deckey, decNonce, aead)

            assertTrue(success, "MAC did not match")

            assertEquals(quote, plaintext.toUTF8String(), "Decryption failed")
        } else {
            fail("Data from Envelope unpack is null")
        }
    }
}