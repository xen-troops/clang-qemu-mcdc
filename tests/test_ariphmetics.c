/* Test for conditional expressions with non-booleans */
#include <stdbool.h>


#define TEST_TRUE "TEST_TRUE"
#define TEST_FALSE "TEST_FALSE"

int test_ariphmetic_1(int a)
{
    if (a/12 - 5)
        return 1;

    return 0;
}

bool dummy_func(const char *c)
{
    return c[0] == 'T';
}

int dummy_func2(const char *c)
{
    return c[0] != 'T';
}

bool test_ariphmetic_2(int a)
{
    return dummy_func((a >> 2) & 0x1 ? TEST_TRUE : TEST_FALSE);
}

int test_ariphmetic_3(int a, int b)
{
    if (a >> 14 & 0x1 || b)
        return 0;
    return 1;
}

int test_ariphmetic_4(int a)
{
    if (a - 15)
        return 1;
    return 0;
}

int test_ariphmetic_5(int a, int b)
{
    return ((a >> b) * 2) ? 1 : 2;
}

const char* test_ariphmetic_6(int a, int b)
{
    char* c = ((a ^ b) / 2) ? TEST_TRUE : TEST_FALSE;
    return c;
}

const char* test_ariphmetic_7(int a)
{
    const char* c = (a >> 16 & 0xb) ? TEST_TRUE : TEST_FALSE;

    return c;
}

int test_ariphmetic_8(int a, int b)
{
    int c = ((a ^ b) / 2) ? dummy_func(TEST_TRUE) : dummy_func2(TEST_FALSE);

    return c;
}

int test_ariphmetic_9(int a, int b)
{
    int c = ((a ^ b) / 2) ? 5 : 1;
    return 0;
}

int test_ariphmetic_10(int a, int b)
{
    int c = ((a ^ b) / 2) ? 1 : 5;
    return 0;
}

int test_ariphmetic_11(int a, int b)
{
    int c = ((a ^ b) / 2) ? a - 25 : b - 25;
    return c;
}

int test_ariphmetic_12(int a, int b)
{
    int c = ((a ^ b) / 2) ? 5 : 2;
    return c;
}

int test_var_assign(int a)
{
    bool var = !!(a / 2);

    return var;
}

int main()
{
    test_ariphmetic_1(1);

    test_ariphmetic_2(0x1);
    test_ariphmetic_2(0x4);

    test_ariphmetic_3(0x1, 0);
    test_ariphmetic_3(0x4000, 0);

    test_ariphmetic_4(22);

    test_ariphmetic_5(0xF, 2);

    test_ariphmetic_6(0x1, 0x2);

    test_ariphmetic_7(0xF);

    test_ariphmetic_8(0x1, 0x1);
    test_ariphmetic_8(0x1, 0x2);


    test_ariphmetic_9(0x1, 0x1);
    test_ariphmetic_9(0x1, 0x2);

    test_ariphmetic_10(0x1, 0x1);
    test_ariphmetic_10(0x1, 0x2);


    test_ariphmetic_11(0x1, 0x1);
    test_ariphmetic_11(0x1, 0x2);

    test_ariphmetic_12(0x1, 0x1);
    test_ariphmetic_12(0x1, 0x2);


    test_var_assign(2);
    test_var_assign(3);
}