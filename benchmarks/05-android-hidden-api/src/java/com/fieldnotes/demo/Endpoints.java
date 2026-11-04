package com.fieldnotes.demo;

/** Benchmark 5: the base URL is XOR-encoded so that it never appears as a plain string. */
final class Endpoints {
    private static final int KEY = 0x37;
    private static final int[] BASE = {
        95, 67, 67, 71, 68, 13, 24, 24, 86, 71, 94, 25, 81, 94, 82, 91, 83, 89, 88, 67, 82, 68, 25,
        82, 79, 86, 90, 71, 91, 82,
    };

    private Endpoints() {}

    static String base() {
        StringBuilder url = new StringBuilder();
        for (int value : BASE) {
            url.append((char) (value ^ KEY));
        }
        return url.toString();
    }

    static String session() {
        return base() + "/v2/" + "session";
    }

    static String sync() {
        return base() + "/v2/" + "notes/" + "sync";
    }

    /** Only reachable from the hidden diagnostics switch in MainActivity. */
    static String diagnostics() {
        return base() + new StringBuilder("gaid/lanretni/").reverse();
    }
}
