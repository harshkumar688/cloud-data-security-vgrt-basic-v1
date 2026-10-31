package com.vgrt.securecloud.crypto;

final class HexFormatSupport {
    private HexFormatSupport() {}
    static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) out.append(Character.forDigit((b >>> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        return out.toString();
    }
}
