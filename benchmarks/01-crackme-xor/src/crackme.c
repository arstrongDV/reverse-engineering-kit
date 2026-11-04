/* Benchmark 1: a serial check made of an XOR with a repeating key and a rotation. */
#include <stdio.h>
#include <string.h>

#define SERIAL_LENGTH 16

static const unsigned char KEY[4] = {0x5a, 0xc3, 0x17, 0x9e};
static const unsigned char EXPECTED[SERIAL_LENGTH] = {
    0x40, 0x44, 0x29, 0x45, 0xbb, 0xdc, 0xc2, 0x66,
    0x6b, 0x77, 0x2a, 0x8e, 0xb0, 0x87, 0xd1, 0xfe,
};

static unsigned char rotate_left(unsigned char value, int bits) {
    return (unsigned char)((value << bits) | (value >> (8 - bits)));
}

int check_serial(const char *serial) {
    if (strlen(serial) != SERIAL_LENGTH) {
        return 0;
    }
    for (int index = 0; index < SERIAL_LENGTH; index++) {
        unsigned char mixed = (unsigned char)serial[index] ^ KEY[index % 4];
        if (rotate_left(mixed, 3) != EXPECTED[index]) {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        puts("usage: crackme <serial>");
        return 2;
    }
    if (check_serial(argv[1])) {
        puts("Correct serial. Well done.");
        return 0;
    }
    puts("Wrong serial.");
    return 1;
}
