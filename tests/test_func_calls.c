/* Test for conditional expressions with function calls */
#include <stdbool.h>

bool get_xor(bool a, bool b) {
        return a != b;
}

bool test_cond_params_2(bool a, bool b, bool c)
{
    bool d = get_xor(a && b, b && c) || get_xor(b, c);

    return d;
}

bool test_cond_params_1(bool a, bool b, bool c)
{
        bool d = get_xor(a && b && c, b == c);
        
        return d;
}

int test_or_call(bool a, bool b, bool c)
{
        bool d = get_xor(a, b) || get_xor(b, c);
        
        return d;
}

int main(int argc, char *argv[])
{
        test_or_call(false, false, true);
        test_or_call(true, false, true);
        test_or_call(false, true, true);

        test_cond_params_1(false, false, false);
        test_cond_params_1(true, false, true);
        test_cond_params_1(true, true, false);

        test_cond_params_2(false, false, false);
        test_cond_params_2(true, false, true);
        test_cond_params_2(true, true, false);

        return 0;
}