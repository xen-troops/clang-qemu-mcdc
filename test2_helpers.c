#include <stdbool.h>

/* int f(void); */

void corner_cases(void) {
        /* int a, b; */
        /* (a + 3 < b - 5); */
        /* (f() + f() > 2 * f()); */
        /* (a == (a < 5)?(a+5):(a-5)); */
	/* f(); */
}
bool get_true(void) {
        return true;
}

bool get_false(void) {
        return false;
}

bool get_inv(bool a) {
        return !a;
}

bool get_or(bool a, bool b) {
        return a || b;
}

bool get_complex_op(bool a, bool b, bool c) {
        return a || b || c;
}

bool get_xor(bool a, bool b) {
        return a != b;
}

bool test_int_ops(int a, int b, int c) {
        a += b + c;
        c = (a-b) * (a+b);
        return (b == 0) || (a < 15);
}
