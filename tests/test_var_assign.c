/* Test for variables assigning by conditional expressions */
#include <stdbool.h>

#if 0
bool test_complex_assign(int a, int b, int c)
{

        bool d =    (!a && !b &&  c) ||
                    (!a &&  b && !c) ||
                    ( a &&  b &&  c) ||
                    ( a && !b && !c);

        return d;
}
#endif

bool test_var_assign(char* array)
{
    bool a = (array[0] == 'a') || (array[0] == '1') || (array[0] == 'T');
    bool b = (array[1] == 'b') || (array[1] == '1') || (array[1] == 'T');
    bool c = (array[2] == 'c') || (array[2] == '1') || (array[2] == 'T');
    bool d = ((char)array[3] == 'd') || (array[3] == '1') || (array[3] == 'T');

#if 0
    bool res = ((a || b) && (c || d));
#endif

    return false;
}

char array1[] = { 'a', 'b', 'c', 'd'};
char array2[] = { '1', '0', '0', '0' };
char array3[] = { '0', '1', '0', '0' };
char array4[] = { '0', '0', '1', '0' };
char array5[] = { '0', '0', '0', 'T' };

int main(int argc, char *array[])
{
    test_var_assign(array1);
    test_var_assign(array2);
    test_var_assign(array3);
    test_var_assign(array4);
    test_var_assign(array5);
#if 0
    test_complex_assign(false, false, false);
    test_complex_assign(true, false, false);
#endif
    return 0;
}