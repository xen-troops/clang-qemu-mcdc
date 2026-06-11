
/* Test for inlined func */
#include <stdbool.h>

static int __attribute__((__always_inline__)) inlined_func(bool a, bool b)
{
	if (a != b)
		return 42;
	if (a || b)
		return 69;
	return 1337;
}

static int __attribute__((__always_inline__)) second_inlined_func(int arg)
{
	if (arg)
		return 1;
	if (!arg)
		return 2;
	return 3;
}

static int __attribute__((__always_inline__)) deeply_inlined_func(void)
{
	if (second_inlined_func(1) == 0)
		return 1;
	return inlined_func(true, false) || second_inlined_func(1);
}

int test_non_inline(int a, int b)
{
    int test1 = false, test2 = false;

	if (inlined_func(a, b) > 22)
		test1 = true;

	if (a || (deeply_inlined_func() == 0))
		test2 = true;

    return test1 && test2;
}

int main()
{
	test_non_inline(5, 5);

    return 0;
}