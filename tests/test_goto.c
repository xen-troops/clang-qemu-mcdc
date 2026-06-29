/* Tests with boolean expressions after goto labels */

#include <stdbool.h>

int test_func1(int a, int b)
{
    if (a != b)
        goto exit1;
    else
        goto exit2;

exit1:
    if (a == 0) goto exit2;

    return 1;

exit2:
    return 0;
}

int main(int argc, char *argv[])
{
    test_func1(5, 2);

    return 0;
}