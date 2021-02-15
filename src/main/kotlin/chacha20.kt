import java.math.BigInteger
import java.lang.Math.ceil

data class AEADEncrypted(var cyphertext: Array<Int>, var tag: Array<Int>)
data class AEADMessage(val success: Boolean, val plaintext: Array<Int>, val aad: Array<Int>)

/**
 * The ChaCha20 Block Function
 * ===========================
 *
 * The ChaCha block function transforms a ChaCha state by running multiple quarter rounds.
 *
 * The inputs to ChaCha20 are:
 *
 * - A 256-bit key, treated as a concatenation of eight 32-bit little-endian integers.
 * - A 32-bit block count parameter, treated as a 32-bit little-endian integer.
 * - A 96-bit nonce, treated as a concatenation of three 32-bit little-endian integers.
 *
 * The output is 64 random-looking bytes.
 *
 * See Section 2.3 in [RFC 7539](https://datatracker.ietf.org/doc/rfc7539/?include_text=1)
 *
 */
fun chacha20Block(key: Array<Int>, counter: Int, nonce: Array<Int>): Array<Int> {
    fun toByteArray(uints: Array<Long>): Array<Int> {
        val ret = Array(uints.size * 4) { 0 }
        var index = 0;
        for (uint in uints) {
            for (j in 0..3) {
                ret.set(index, ((uint shr (j * 8)) and 0xff).toInt())
                index++
            }
        }
        return ret
    }

    var block_in: Array<Long> = Array(16) { 0 }
    var state: Array<Long> = Array(16) { 0 }

    fun ROTL(a: Long, b: Int): Long {
        return ((a shl b) or (a shr (32 - b))) and 0xffffffff;
    }

    fun qr(ia: Int, ib: Int, ic: Int, id: Int) {
        var a = state.get(ia);
        var b = state.get(ib);
        var c = state.get(ic);
        var d = state.get(id)

        a = (a + b) and 0xffffffff; d = d xor a; d = ROTL(d, 16)
        c = (c + d) and 0xffffffff; b = b xor c; b = ROTL(b, 12)
        a = (a + b) and 0xffffffff; d = d xor a; d = ROTL(d, 8)
        c = (c + d) and 0xffffffff; b = b xor c; b = ROTL(b, 7)

        state.set(ia, a); state.set(ib, b); state.set(ic, c); state.set(id, d)
    }

    fun chachaInitBlock(key: Array<Int>, counter: Int, nonce: Array<Int>) {
        block_in = arrayOf(
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
        )

        var i = 0;
        var work: Long = 0
        for (b in key) {
            work = work or (b.toLong() shl ((i % 4) * 8)) and 0xffffffff
            i++
            if ((i % 4) == 0) {
                block_in.set(3 + (i / 4), work)
                work = 0
            }
        }

        block_in.set(12, counter.toLong())

        i = 0;
        work = 0
        for (b in nonce) {
            work = work or (b.toLong() shl ((i % 4) * 8))
            i++
            if ((i % 4) == 0) {
                block_in.set(12 + (i / 4), work and 0xffffffff)
                work = 0
            }
        }

        state = block_in.copyOf()
    }

    chachaInitBlock(key, counter, nonce)

    for (i in 0..9) {
        qr(0, 4, 8, 12)
        qr(1, 5, 9, 13)
        qr(2, 6, 10, 14)
        qr(3, 7, 11, 15)

        qr(0, 5, 10, 15)
        qr(1, 6, 11, 12)
        qr(2, 7, 8, 13)
        qr(3, 4, 9, 14)
    }

    return toByteArray(Array(16) { i ->
        (state.get(i) + block_in.get(i)) and 0xffffffff
    })
}

/**
 * The ChaCha20 Encryption Algorithm
 * =================================
 *
 * ChaCha20 is a stream cipher designed by D. J. Bernstein.  It is a
 * refinement of the Salsa20 algorithm, and it uses a 256-bit key.
 *
 * ChaCha20 successively calls the ChaCha20 block function, with the
 * same key and nonce, and with successively increasing block counter
 * parameters.  ChaCha20 then serializes the resulting state by writing
 * the numbers in little-endian order, creating a keystream block.
 *
 * The inputs to ChaCha20 are:
 *
 * - A 256-bit key
 * - A 32-bit initial counter.  This can be set to any number, but will
 * usually be zero or one.  It makes sense to use one if we use the
 * zero block for something else, such as generating a one-time
 * authenticator key as part of an AEAD algorithm.
 * - A 96-bit nonce.  In some protocols, this is known as the Initialization Vector.
 * - An arbitrary-length plaintext
 *
 * The output is an encrypted message, or "ciphertext", of the same length.
 *
 * See Section 2.4 in [RFC 7539](https://datatracker.ietf.org/doc/rfc7539/?include_text=1)
 *
 */
fun chacha20Encrypt(key: Array<Int>, counter: Int, nonce: Array<Int>, plaintext: Array<Int>): Array<Int> {
    val numFullBlocks = plaintext.size / 64
    val hasPartialBlock = (plaintext.size % 64) != 0
    val cyphertext = Array(plaintext.size) { 0 }

    for (j in 0..(numFullBlocks - 1)) {
        val keyString = chacha20Block(key, counter + j, nonce)
        for (k in 0..63) {
            cyphertext.set((j * 64) + k, (plaintext.get((j * 64) + k) xor keyString.get(k)))
        }
    }
    if (hasPartialBlock) {
        val j = numFullBlocks
        val keyString = chacha20Block(key, counter + j, nonce)
        for (k in 0..(plaintext.size % 64) - 1) {
            cyphertext.set((j * 64) + k, (plaintext.get((j * 64) + k) xor keyString.get(k)))
        }
    }

    return cyphertext
}

/**
 * Generating the Poly1305 Key Using ChaCha20
 * ==========================================
 *
 * Pseudorandomly generate a one-time key based on a Session key and IV.
 *
 * The inputs to ChaCha20 are:
 *
 * - A 256-bit key
 * - A 96-bit nonce.  In some protocols, this is known as the Initialization Vector.
 *
 * The output is a 128-bit one-time key
 *
 * See Section 2.6 in [RFC 7539](https://datatracker.ietf.org/doc/rfc7539/?include_text=1)
 *
 */
fun poly1305KeyGen(key: Array<Int>, nonce: Array<Int>): Array<Int> {
    val block = chacha20Block(key, 0, nonce)
    return block.copyOfRange(0, 32)
}

/**
 * The Poly1305 Algorithm
 * ======================
 *
 * Poly1305 is a one-time authenticator designed by D. J. Bernstein.
 * Poly1305 takes a 32-byte one-time key and a message and produces a
 * 16-byte tag.  This tag is used to authenticate the message.
 *
 * The inputs to Poly1305 are:
 *
 * - A 256-bit one-time key
 * - An arbitrary length message
 *
 * The output is a 128-bit tag.
 *
 * See Section 2.5 in [RFC 7539](https://datatracker.ietf.org/doc/rfc7539/?include_text=1)
 *
 */
fun poly1305MAC(key: Array<Int>, msg: Array<Int>): Array<Int> {
    fun toBigInt(inputArray: Array<Int>): BigInteger {
        var ret = BigInteger.ZERO

        var count = 0
        for (b in inputArray) {
            ret = ret.add(BigInteger.valueOf(b.toLong()).shiftLeft(count))
            count = count + 8
        }
        return ret
    }

    fun toTag(inputNum: BigInteger): Array<Int> {
        return Array(16) { i ->
            inputNum.shiftRight(i * 8).and(BigInteger("255")).toInt()
        }
    }

    fun prepR(key: Array<Int>): BigInteger {
        val r = key.copyOfRange(0, 16)

        r.set(3, (r.get(3) and 15))
        r.set(7, (r.get(7) and 15))
        r.set(11, (r.get(11) and 15))
        r.set(15, (r.get(15) and 15))

        r.set(4, (r.get(4) and 252))
        r.set(8, (r.get(8) and 252))
        r.set(12, (r.get(12) and 252))

        return toBigInt(r)
    }

    val p = BigInteger.ONE.shiftLeft(130).subtract(BigInteger("5"))
    val r = prepR(key)
    val s = toBigInt(key.copyOfRange(16, 32))
    var a = BigInteger.ZERO

    val blocks = ceil(msg.size.toDouble() / 16.0).toInt()
    var count = 16
    for (i in 0..blocks - 1) {
        if (i == blocks - 1) {
            count = msg.size - (i * 16)
        }
        var n = toBigInt(msg.copyOfRange(i * 16, (i * 16) + count))
        n = n.add(BigInteger.ONE.shiftLeft(count * 8))

        a = a.add(n)
        a = a.times(r).mod(p)
    }
    a = a.plus(s)
    return toTag(a)
}

/**
 * AEAD Construction
 * =================
 *
 * The ChaCha20 and Poly1305 primitives are combined into an AEAD that
 * takes a 256-bit key and 96-bit nonce as follows:
 *
 * The inputs to AEAD Construction are:
 *
 * - A 256-bit key
 * - A 96-bit nonce -- different for each invocation with the same key
 * - An arbitrary length plaintext
 * - Arbitrary length additional authenticated data (AAD)
 *
 * The output from the AEAD is twofold:
 *
 * - The constructed message including AAD and encrypted plaintext.
 * - A 128-bit tag, which is the output of the Poly1305 function run against the constructed message.
 *
 * See Section 2.8 in [RFC 7539](https://datatracker.ietf.org/doc/rfc7539/?include_text=1)
 *
 */
fun chacha20AEADEncrypt(key: Array<Int>, nonce: Array<Int>, msg: Array<Int>, aad: Array<Int>): AEADEncrypted {
    fun toEightByteArray(length: Int): Array<Int> {
        val ret = Array(8) { 0 }
        for (i in 0..3) {
            ret.set(i, ((length shr (i * 8)) and 0xff).toInt())
        }
        return ret
    }

    val onetimekey = poly1305KeyGen(key, nonce)
    val ciphertext = chacha20Encrypt(key, 1, nonce, msg)

    val macData: MutableList<Int> = aad.toMutableList()
    if ((aad.size % 16) != 0) {
        macData.addAll(Array(16 - (aad.size % 16)) { 0 })
    }
    macData.addAll(ciphertext)
    if ((ciphertext.size % 16) != 0) {
        macData.addAll(Array(16 - (ciphertext.size % 16)) { 0 })
    }
    macData.addAll(toEightByteArray(aad.size))
    macData.addAll(toEightByteArray(ciphertext.size))

    val mac = macData.toTypedArray()
    val tag = poly1305MAC(onetimekey, mac)

    return AEADEncrypted(mac, tag)
}

/**
 * Decryption of AEAD Construction
 * ===============================
 *
 * The inputs to AEAD Decryption are:
 *
 * - A 256-bit key
 * - A 96-bit nonce -- different for each invocation with the same key
 * - Constructed AEAD message
 * - Tag of the constructed message
 *
 * The output from the AEAD is threefold:
 *
 * - Flag indicating success or failure of MAC comparison to given tag
 * - The original arbitrary length plaintext.
 * - The Arbitrary length additional authenticated data (AAD) extracted from te construction
 *
 * See Section 2.8 in [RFC 7539](https://datatracker.ietf.org/doc/rfc7539/?include_text=1)
 *
 */
fun chacha20AEADDecrypt(key: Array<Int>, nonce: Array<Int>, msg: AEADEncrypted): AEADMessage {
    fun getValue(value: Array<Int>): Int {
        var i = 0;
        var work: Long = 0
        for (b in value) {
            work = work or (b.toLong() shl ((i % 4) * 8)) and 0x7fffffff
            i++
        }
        return work.toInt()
    }

    val onetimekey = poly1305KeyGen(key, nonce)
    val tag = poly1305MAC(onetimekey, msg.cyphertext)
    if (!(tag contentEquals msg.tag)) {
        return AEADMessage(false, arrayOf(), arrayOf())
    }

    val length = msg.cyphertext.size
    val ctLength = getValue(msg.cyphertext.copyOfRange(length - 8, length - 4))
    val aadLength = getValue(msg.cyphertext.copyOfRange(length - 16, length - 12))
    val beginOfCT = (ceil(aadLength.toDouble() / 16) * 16).toInt()

    val aad = msg.cyphertext.copyOfRange(0, aadLength)
    val ct = msg.cyphertext.copyOfRange(beginOfCT, beginOfCT + ctLength)
    val plaintext = chacha20Encrypt(key, 1, nonce, ct)

    return AEADMessage(true, plaintext, aad)
}
