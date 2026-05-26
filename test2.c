#include <stdio.h>
#include <stdbool.h>

bool get_xor(bool a, bool b);

static int __attribute__((__always_inline__)) my_inlined_func(bool a, bool b)
{
	if (a != b)
		return 42;
	if (a || b)
		return 69;
	return 1337;
}

enum test_enum {
        ENUM_VAL_1,
        ENUM_VAL_2
};

struct test_struct {
	int field;
};

int test_global_variable = 2;

bool test_memberr(void)
{
	struct test_struct tst;
	tst.field = 1;

	tst.field += 2;

	return tst.field == 3;
}

int main (int argc, char *argv[])
{
        bool a, b, c, d;
        int ret;
        int tmp;
	int i;
        enum test_enum test_enum = ENUM_VAL_1;

	if (test_global_variable == 2)
		printf("Wow, we can access global variables!\n");

        printf("argc: %d\n", argc);
        if (argc==1)
                return 1;

        if (argc==2)
                return 2;

        if (argc==3)
                return 3;

        if (argc==4)
                return 4;

        if (argc < 6 || argc > 8)
                printf("argc?\n");

	for (i = 0; i < 3; i++)
		printf("%d th arg is %d\n", i, argv[i+1][0] == '1');
        a = (argv[1][0] == 'a') || (argv[1][0] == '1') || (argv[1][0] == 'T');
        b = (argv[2][0] == 'b') || (argv[2][0] == '1') || (argv[2][0] == 'T');
        c = (argv[3][0] == 'c') || (argv[3][0] == '1') || (argv[3][0] == 'T');
        d = ((char)argv[4][0] == 'd') || (argv[4][0] == '1') || (argv[4][0] == 'T');

        if(printf("%d %d %d %d\n", a || d, b, c, d) > 6)
                printf("Test for printf itself \n");

	if (my_inlined_func(a, b) > 22)
		printf("Test for inlined func\n");

        if ( a && b && c && d)
                printf("ALL IN\n");

        if ((a && !b) || (c && d))
                printf("yep\n");

        if (a || a)
                printf("yep?\n");

        d =     (!a && !b &&  c) ||
                (!a &&  b && !c) ||
                ( a &&  b &&  c) ||
                ( a && !b && !c);

        if (d)
                printf("Dee!\n");

        if ((a && !b) || (!a && b))
                printf("XOR\n");
        else
                printf("!XOR\n");

        d = get_xor(a, b);
        if (d)
                printf("Remote XOR1\n");
        else
                printf("Remote !XOR1\n");

        /* d = get_xor(a, b) || get_xor(b, c); */
        /* if (d) */
        /*         printf("Remote XOR2\n"); */
        /* else */
        /*         printf("Remote !XOR2\n"); */

        /* d = get_xor(a && b && c, b == c); */
        /* if (d) */
        /*         printf("Remote XOR3\n"); */
        /* else */
        /*         printf("Remote !XOR3\n"); */

        /* d = get_xor(a && b, b && c) || get_xor(b, c); */
        /* if (d) */
        /*         printf("Remote XOR4\n"); */
        /* else */
        /*         printf("Remote !XOR4\n"); */

        /* tmp = 1; */
        /* if (++tmp == 2) { */
        /*         if (tmp != 2) */
        /*                 printf("oops ^_^!\n"); */
        /* } else */
        /*         printf("oops ^_^ 2!\n"); */


        /* tmp = 1; */
        /* if (tmp++ == 1) { */
        /*         if (tmp != 2) */
        /*                 printf("oops ^_^ 3!\n"); */
        /* } else */
        /*         printf("oops ^_^ 4!\n"); */


        /* if ((tmp + 1) == 2) */
        /*         printf("huh?\n"); */

        /* if (test_enum == ENUM_VAL_2) */
        /*         printf("enum test failed\n"); */

        return 0;
}

