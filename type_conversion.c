#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>

// ==========================================
// 1. UNSAFE CONVERSION DEMONSTRATIONS
// ==========================================
void run_unsafe_conversions(void) {
    printf("=== UNSAFE CONVERSIONS (Vulnerable) ===\n");

    // A. Int to Short (Truncation & Overflow)
    int large_int = 70000;
    short unsafe_short = (short)large_int; // Truncation
    printf("[Int -> Short] Original int: %d | Converted short: %d (Overflow/Truncation)\n", large_int, unsafe_short);

    // B. Signed to Unsigned (Sign Conversion / Misinterpretation)
    signed int negative_signed = -15;
    unsigned int unsafe_unsigned = (signed_int); // Misinterpreted as huge number
    printf("[Signed -> Unsigned] Original: %d | Converted unsigned: %u (Sign bit interpretation error)\n", negative_signed, unsafe_unsigned);

    // C. Float to Int (Precision Loss & Overflow)
    float big_float = 3.4028235E38f; // Exceeds standard integer max
    int unsafe_int_from_float = (int)big_float; // Undefined behavior / overflow
    printf("[Float -> Int] Original float: %e | Converted int: %d (Overflow/Undefined)\n", big_float, unsafe_int_from_float);

    // D. String to Numeric (Unchecked atoi - vulnerable to overflow/invalid input)
    char *bad_input = "999999999999999";
    int unsafe_atoi = atoi(bad_input); // Overflow without error detection
    printf("[String -> Numeric] Input string: \"%s\" | atoi result: %d (Silent overflow)\n\n", bad_input, unsafe_atoi);
}

// ==========================================
// 2. SAFE CONVERSION IMPLEMENTATIONS
// ==========================================

// Safe Int to Short Conversion
int safe_int_to_short(int input, short *result) {
    if (input < SHRT_MIN || input > SHRT_MAX) {
        fprintf(stderr, "[Safe Error] Int %d out of range for short [%d, %d].\n", input, SHRT_MIN, SHRT_MAX);
        return -1;
    }
    *result = (short)input;
    return 0;
}

// Safe Signed to Unsigned Conversion
int safe_signed_to_unsigned(int input, unsigned int *result) {
    if (input < 0) {
        fprintf(stderr, "[Safe Error] Negative value %d cannot be safely cast to unsigned int.\n", input);
        return -1;
    }
    *result = (unsigned int)input;
    return 0;
}

// Safe Float to Int Conversion
int safe_float_to_int(float input, int *result) {
    if (input < (float)INT_MIN || input > (float)INT_MAX) {
        fprintf(stderr, "[Safe Error] Float %e exceeds integer bounds.\n", input);
        return -1;
    }
    *result = (int)input;
    return 0;
}

// Safe String to Numeric Conversion using strtol
int safe_string_to_long(const char *str, long *result) {
    char *endptr;
    errno = 0;
    long val = strtol(str, &endptr, 10);

    if ((errno == ERANGE && (val == LONG_MIN || val == LONG_MAX)) || (errno != 0 && val == 0)) {
        fprintf(stderr, "[Safe Error] String conversion range error.\n");
        return -1;
    }
    if (endptr == str) {
        fprintf(stderr, "[Safe Error] No digits found in input string \"%s\".\n", str);
        return -1;
    }
    if (*endptr != '\0') {
        fprintf(stderr, "[Safe Error] Extra characters found after number: \"%s\".\n", endptr);
        return -1;
    }

    *result = val;
    return 0;
}

void run_safe_conversions(void) {
    printf("=== SAFE CONVERSIONS (Validated) ===\n");

    // Safe Int to Short test
    short s_res;
    if (safe_int_to_short(70000, &s_res) == 0) {
        printf("Int to Short success: %d\n", s_res);
    }
    if (safe_int_to_short(300, &s_res) == 0) {
        printf("Int to Short success: %d\n", s_res);
    }

    // Safe Signed to Unsigned test
    unsigned int u_res;
    if (safe_signed_to_unsigned(-15, &u_res) != 0) {
        printf("Successfully rejected negative signed to unsigned conversion.\n");
    }

    // Safe Float to Int test
    int f_res;
    if (safe_float_to_int(42.85f, &f_res) == 0) {
        printf("Float to Int success: %d (truncated cleanly)\n", f_res);
    }

    // Safe String to Numeric test
    long l_res;
    if (safe_string_to_long("12345", &l_res) == 0) {
        printf("String to Numeric success: %ld\n", l_res);
    }
    if (safe_string_to_long("999999999999999", &l_res) != 0) {
        printf("Successfully caught out-of-range string numeric overflow.\n");
    }
}

int main(void) {
    run_unsafe_conversions();
    printf("----------------------------------------\n");
    run_safe_conversions();
    return 0;
}
