package symbolweave;

import java.util.ArrayList;
import java.util.List;

/**
 * Small x86-64 length decoder for signature boundaries. It is deliberately not a disassembler: it
 * only identifies instruction extent and address-dependent fields that should be wildcarded.
 */
final class X64InstructionDecoder {
    record Field(int offset, int length) {}

    record Instruction(int length, List<Field> wildcardFields) {}

    private X64InstructionDecoder() {}

    static Instruction decode(byte[] code, int start, int limit) {
        int end = Math.min(code.length, limit);
        if (start < 0 || start >= end) return new Instruction(0, List.of());
        int cursor = start;
        boolean operand16 = false;
        boolean address32 = false;
        boolean rexW = false;

        while (cursor < end) {
            int value = u8(code[cursor]);
            if (value == 0x66) operand16 = true;
            else if (value == 0x67) address32 = true;
            else if (value >= 0x40 && value <= 0x4F) rexW = (value & 8) != 0;
            else if (value == 0xF0
                    || value == 0xF2
                    || value == 0xF3
                    || value == 0x2E
                    || value == 0x36
                    || value == 0x3E
                    || value == 0x26
                    || value == 0x64
                    || value == 0x65) {
                // Legacy prefix.
            } else break;
            cursor++;
            if (cursor - start >= 15) return fallback(start, end);
        }
        if (cursor >= end) return fallback(start, end);

        int opcode = u8(code[cursor++]);
        int map = 0;
        boolean vex = false;
        if (opcode == 0xC5 && cursor + 1 < end) {
            vex = true;
            cursor++; // two-byte VEX payload
            opcode = u8(code[cursor++]);
            map = 1;
        } else if (opcode == 0xC4 && cursor + 2 < end) {
            vex = true;
            int mapSelect = u8(code[cursor]) & 0x1F;
            map = mapSelect == 2 ? 2 : mapSelect == 3 ? 3 : 1;
            cursor += 2;
            opcode = u8(code[cursor++]);
        } else if (opcode == 0x62 && cursor + 3 < end) {
            vex = true;
            int mapSelect = u8(code[cursor]) & 3;
            map = mapSelect == 2 ? 2 : mapSelect == 3 ? 3 : 1;
            cursor += 3;
            opcode = u8(code[cursor++]);
        } else if (opcode == 0x0F) {
            if (cursor >= end) return fallback(start, end);
            map = 1;
            opcode = u8(code[cursor++]);
            if ((opcode == 0x38 || opcode == 0x3A) && cursor < end) {
                map = opcode == 0x38 ? 2 : 3;
                opcode = u8(code[cursor++]);
            }
        }

        boolean modRm = vex ? vexHasModRm(map, opcode) : hasModRm(map, opcode);
        int modRmValue = -1;
        List<Field> fields = new ArrayList<>();
        if (modRm) {
            if (cursor >= end) return fallback(start, end);
            int modRmOffset = cursor;
            modRmValue = u8(code[cursor++]);
            int mod = modRmValue >>> 6;
            int rm = modRmValue & 7;
            if (mod != 3) {
                if (rm == 4) {
                    if (cursor >= end) return fallback(start, end);
                    int sib = u8(code[cursor++]);
                    int base = sib & 7;
                    if (mod == 0 && base == 5) cursor += 4;
                    else if (mod == 1) cursor += 1;
                    else if (mod == 2) cursor += 4;
                } else if (mod == 0 && rm == 5) {
                    int displacement = cursor;
                    cursor += 4;
                    if (!address32) fields.add(new Field(displacement - start, 4));
                } else if (mod == 1) cursor += 1;
                else if (mod == 2) cursor += 4;
            }
            if (cursor > end) return fallback(start, end);
            if (modRmOffset - start >= 15) return fallback(start, end);
        }

        int immediate = immediateSize(map, opcode, modRmValue, operand16, rexW, address32, vex);
        int immediateOffset = cursor;
        cursor += immediate;
        if (cursor > end || cursor - start > 15) return fallback(start, end);

        if (!vex && isRelative(map, opcode)) {
            fields.add(new Field(immediateOffset - start, immediate));
        }
        return new Instruction(cursor - start, List.copyOf(fields));
    }

    private static boolean hasModRm(int map, int opcode) {
        if (map == 2 || map == 3) return true;
        if (map == 1) {
            if (opcode >= 0x80 && opcode <= 0x8F) return false;
            return switch (opcode) {
                case 0x05,
                        0x06,
                        0x07,
                        0x08,
                        0x09,
                        0x0B,
                        0x0E,
                        0x30,
                        0x31,
                        0x32,
                        0x33,
                        0x34,
                        0x35,
                        0x37,
                        0x77,
                        0xA0,
                        0xA1,
                        0xA2,
                        0xA8,
                        0xA9,
                        0xAA,
                        0xC8,
                        0xC9,
                        0xCA,
                        0xCB,
                        0xCC,
                        0xCD,
                        0xCE,
                        0xCF ->
                        false;
                default -> true;
            };
        }
        if ((opcode >= 0x00 && opcode <= 0x03)
                || (opcode >= 0x08 && opcode <= 0x0B)
                || (opcode >= 0x10 && opcode <= 0x13)
                || (opcode >= 0x18 && opcode <= 0x1B)
                || (opcode >= 0x20 && opcode <= 0x23)
                || (opcode >= 0x28 && opcode <= 0x2B)
                || (opcode >= 0x30 && opcode <= 0x33)
                || (opcode >= 0x38 && opcode <= 0x3B)
                || (opcode >= 0x80 && opcode <= 0x8F)
                || (opcode >= 0xD0 && opcode <= 0xD3)
                || (opcode >= 0xD8 && opcode <= 0xDF)) return true;
        return switch (opcode) {
            case 0x62,
                    0x63,
                    0x69,
                    0x6B,
                    0xC0,
                    0xC1,
                    0xC4,
                    0xC5,
                    0xC6,
                    0xC7,
                    0xF6,
                    0xF7,
                    0xFE,
                    0xFF ->
                    true;
            default -> false;
        };
    }

    private static boolean vexHasModRm(int map, int opcode) {
        if (map == 1 && opcode == 0x77) return false; // VZEROUPPER/VZEROALL
        return true;
    }

    private static int immediateSize(
            int map,
            int opcode,
            int modRm,
            boolean operand16,
            boolean rexW,
            boolean address32,
            boolean vex) {
        if (map == 3) return 1;
        if (map == 2) return 0;
        if (map == 1) {
            if (opcode >= 0x80 && opcode <= 0x8F) return 4;
            return switch (opcode) {
                case 0x70, 0x71, 0x72, 0x73, 0xA4, 0xAC, 0xBA, 0xC2, 0xC4, 0xC5, 0xC6 -> 1;
                default -> 0;
            };
        }
        if (opcode >= 0x70 && opcode <= 0x7F) return 1;
        if (opcode >= 0xB0 && opcode <= 0xB7) return 1;
        if (opcode >= 0xB8 && opcode <= 0xBF) return rexW ? 8 : operand16 ? 2 : 4;
        if (opcode >= 0xE0 && opcode <= 0xE3) return 1;
        return switch (opcode) {
            case 0x04,
                    0x0C,
                    0x14,
                    0x1C,
                    0x24,
                    0x2C,
                    0x34,
                    0x3C,
                    0x6A,
                    0x80,
                    0x82,
                    0x83,
                    0xA8,
                    0xC0,
                    0xC1,
                    0xC6,
                    0xCD,
                    0xD4,
                    0xD5,
                    0xE4,
                    0xE5,
                    0xE6,
                    0xE7,
                    0xEB ->
                    1;
            case 0xC2, 0xCA -> 2;
            case 0xC8 -> 3;
            case 0xE8, 0xE9 -> 4;
            case 0x68, 0x69, 0x81, 0xA9, 0xC7 -> operand16 ? 2 : 4;
            case 0x6B -> 1;
            case 0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D -> operand16 ? 2 : 4;
            case 0xA0, 0xA1, 0xA2, 0xA3 -> address32 ? 4 : 8;
            case 0xF6 -> modRm >= 0 && ((modRm >>> 3) & 7) <= 1 ? 1 : 0;
            case 0xF7 -> modRm >= 0 && ((modRm >>> 3) & 7) <= 1 ? (operand16 ? 2 : 4) : 0;
            default -> 0;
        };
    }

    private static boolean isRelative(int map, int opcode) {
        return (map == 0
                        && (opcode == 0xE8
                                || opcode == 0xE9
                                || opcode == 0xEB
                                || (opcode >= 0x70 && opcode <= 0x7F)
                                || (opcode >= 0xE0 && opcode <= 0xE3)))
                || (map == 1 && opcode >= 0x80 && opcode <= 0x8F);
    }

    private static Instruction fallback(int start, int end) {
        return new Instruction(Math.min(1, end - start), List.of());
    }

    private static int u8(byte value) {
        return Byte.toUnsignedInt(value);
    }
}
