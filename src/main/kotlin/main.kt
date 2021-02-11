import java.io.BufferedReader
import java.lang.Math.ceil
import java.math.BigInteger
import java.util.*

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

fun printblockhelper(uints: Array<Long>) {
    for (i in 0..15) {
        if (i % 4 == 0) {
            println()
        }
        val index = "00000000" + uints.get(i).toString(16)
        print(index.substring(index.length - 8) + " ")
    }
}
fun fingerprint(bytes: Array<Int>): String {
    val ret = StringBuffer()
    var i = 0
    val length = bytes.size
    for (b in bytes) {
        val v = "00" + (b).toString(16)
        ret.append(v.substring(v.length - 2))
        i++
        if (i != length) {
            ret.append(":")
        }
        if (i % 16 == 0 && i != length) {
            ret.append("\n")
        }
    }
    return ret.toString()
}
fun serialize(bytes: Array<Int>) {
    var ascii = ""
    var i = 0
    for (b in bytes) {
        if (i % 16 == 0) {
            println(ascii)
            ascii = ""
            val index = "000" + i.toString(16)
            print(index.substring(index.length - 3) + " ")
        }
        if (i % 8 == 0) {
            ascii = ascii + " "
            print(" ")
        }

        val v = "00" + (b).toString(16)
        if (31 < b && b < 127) {
            ascii = ascii + b.toChar()
        } else {
            ascii = ascii + "."
        }
        print(v.substring(v.length - 2) + " ")
        i++
    }
    while (i % 16 != 0) {
        print("   ")
        if (i % 8 == 0) {
            print(" ")
        }
        i++
    }
    println(ascii)
}

fun chacha20Encrypt(key: Array<Int>, counter: Int, nonce: Array<Int>, plaintext: Array<Int>): Array<Int> {
    val numFullBlocks = plaintext.size / 64
    val hasPartialBlock = (plaintext.size % 64) != 0
    val cyphertext = Array(plaintext.size) { 0 }

    for (j in 0..(numFullBlocks-1)) {
        val keyString = chacha20Block(key, counter+j, nonce)
        for (k in 0..63) {
            cyphertext.set((j * 64) + k, (plaintext.get((j * 64) + k) xor keyString.get(k)))
        }
    }
    if (hasPartialBlock) {
        val j = numFullBlocks
        val keyString = chacha20Block(key, counter+j, nonce)
        for (k in 0..(plaintext.size % 64)-1) {
            cyphertext.set((j * 64) + k, (plaintext.get((j * 64) + k) xor keyString.get(k)))
        }
    }

    return cyphertext
}

fun poly1305KeyGen(key: Array<Int>, nonce: Array<Int>): Array<Int> {
    val block = chacha20Block(key, 0, nonce)
    return block.copyOfRange(0, 32)
}

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
        return Array (16) { i ->
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
    for (i in 0..blocks-1) {
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

data class AEADEncrypted(var cyphertext: Array<Int>, var tag: Array<Int>)
fun chacha20AEADEncrypt(aad: Array<Int>, key: Array<Int>, nonce: Array<Int>, msg: Array<Int>): AEADEncrypted {
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

data class AEADMessage(val success: Boolean, val plaintext: Array<Int>, val aad: Array<Int>)
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

fun closeEnvelope(content: AEADEncrypted): String {
    val buff = StringBuffer()

    val allContent = content.cyphertext.toMutableList()
    allContent.addAll(content.tag)

    buff.append("------------------------------------------------------------------------\n")
    buff.append(" Envelope Tool 1.0.0\n\n")
    buff.append(" ")
    buff.append(Base64.getMimeEncoder(71, "\n ".toByteArray()).encodeToString(allContent.toTypedArray().map { i -> i.toByte() }.toByteArray()))
    buff.append("\n")
    buff.append("------------------------------------------------------------------------\n")

    return buff.toString()
}

fun openEnvelope(content: String): AEADEncrypted {
    val lines = content.reader().readLines()
    if (lines.get(1).trim() != "Envelope Tool 1.0.0") {
        return AEADEncrypted(arrayOf(), arrayOf())
    } else {
        val buff = StringBuffer()
        var line = 3
        while (lines.get(line) != "------------------------------------------------------------------------") {
            buff.append(lines.get(line))
            line++
        }
        val bytes = Base64.getMimeDecoder().decode(buff.toString()).map { i ->
            if (i >= 0) {
                i.toInt()
            } else {
                i.toInt() + 0x100
            }
        }.toTypedArray()
        return AEADEncrypted(bytes.copyOfRange(0, bytes.size - 16), bytes.copyOfRange(bytes.size - 16, bytes.size))
    }
}

fun main(args: Array<String>) {
    // Test Vector from Section 2.8.2 in https://datatracker.ietf.org/doc/rfc7539/?include_text=1
    val msg =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
            .toByteArray(Charsets.UTF_8).map { b -> b.toInt() }.toTypedArray()
    val aad: Array<Int> = arrayOf()

    val key = Array(32) { it + 0x80 }
    val nonce = arrayOf(
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    )

    val encContent = chacha20AEADEncrypt(aad, key, nonce, msg)
    val envelope = closeEnvelope(encContent)

    println(envelope)
    val decContent = openEnvelope(envelope)

    val (success, plaintext, aadout) = chacha20AEADDecrypt(key, nonce, decContent)
    if (success) {
        serialize(plaintext)
        serialize(aadout)
    }

}