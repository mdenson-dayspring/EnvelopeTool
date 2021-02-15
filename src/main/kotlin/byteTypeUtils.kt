fun ByteArray.toTypedIntArray(): Array<Int> {
    return this.map { i ->
        if (i >= 0) {
            i.toInt()
        } else {
            i.toInt() + 0x100
        }
    }.toTypedArray()
}

fun Array<Int>.toByteArray(): ByteArray {
    return this.map { it.toByte() }.toByteArray()
}

fun String.toTypedIntArray(): Array<Int> {
    return this.toByteArray(Charsets.UTF_8).toTypedIntArray()
}

fun Array<Int>.toUTF8String(): String {
    return this.toByteArray().toString(Charsets.UTF_8)
}

/**
 * Serialize byte array to stdout
 *
 * Example output:
 *
 *    000  4c 61 64 69 65 73 20 61  6e 64 20 47 65 6e 74 6c  Ladies a nd Gentl
 *    010  65 6d 65 6e 20 6f 66 20  74 68 65 20 63 6c 61 73  emen of  the clas
 *    020  73 20 6f 66 20 27 39 39  3a 20 49 66 20 49 20 63  s of '99 : If I c
 *    030  6f 75 6c 64 20 6f 66 66  65 72 20 79 6f 75 20 6f  ould off er you o
 *    040  6e 6c 79 20 6f 6e 65 20  74 69 70 20 66 6f 72 20  nly one  tip for
 *    050  74 68 65 20 66 75 74 75  72 65 2c 20 73 75 6e 73  the futu re, suns
 *    060  63 72 65 65 6e 20 77 6f  75 6c 64 20 62 65 20 69  creen wo uld be i
 *    070  74 2e                                             t.
 */
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

/**
 * Format byte array in form ff:ff:ff...:ff
 *
 * Inpyt are an arbitrary length byte array
 */
fun Array<Int>.fingerprint(): String {
    val ret = StringBuffer()
    var i = 0
    val length = this.size
    for (b in this) {
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

