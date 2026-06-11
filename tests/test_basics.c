/* Test for basic boolean expressions */
#include <stdbool.h>

int global_var = 2;

int test_global_var()
{
        if (global_var == 2)
                return 2;
        return 0;
}

int test_int_cmp(int a)
{
        if (a==1)
                return a;

        if (a==2)
                return a;

        if (a==3)
                return a;

        return 0;
}

int test_or(int a)
{
        if (a < 6 || a > 8)
                return a;

        if (a < 16 || a > 18)
                return a;  

        return 0;
}

int test_and(int a, int b)
{
        if (a < 6 && b > 8)
                return a;

        if (a < 16 && b > 18)
                return a;  

        return 0;
}

bool test_or_same_cond(bool a)
{
        if (a || a)
                return true;

        return false;
}

bool test_mult_cond(bool a, bool b, bool c, bool d)
{
        if ( a ) {
                if (a && b) {
                        if (a && b && c) {
                                if (a && b && c && d) {
                                        return true;
                                }
                        }
                }
        }

        return false;
                
}

bool test_and_or_cond_1(bool a, bool b, bool c, bool d)
{
        if ((a && !b) || (c && d))
                return true;

        return false;
}

bool test_and_or_cond_2(bool a, bool b, bool c, bool d)
{
        if ((a && !b) || (!a && b))
                return true;

        return false;
}

int array[3] = {1, 2, 3};

int* simple_loop()
{
        int i, sum = 0;

	for (i = 0; i < 3; i++)
                array[i] = 0;

        return array;
}

int main(int argc, char *argv[])
{
        test_global_var();

        test_int_cmp(1);
        test_int_cmp(2);
        test_int_cmp(4);

        test_or(5);
        test_or(7);
        test_or(9);
        test_or(17);

        test_and(5, 9);
        test_and(6, 4);
        test_and(18, 18);

        test_or_same_cond(true);

        test_mult_cond(0, 0, 0, 0);
        test_mult_cond(1, 0, 0, 0);
        test_mult_cond(1, 1, 0, 0);

        test_and_or_cond_1(0, 0, 1, 0);
        test_and_or_cond_1(1, 0, 0, 0);
        test_and_or_cond_1(1, 1, 0, 0);

        test_and_or_cond_2(0, 0, 0, 0);
        test_and_or_cond_2(1, 0, 0, 0);
        test_and_or_cond_2(1, 1, 0, 0);

        simple_loop();

        return 0;
}

