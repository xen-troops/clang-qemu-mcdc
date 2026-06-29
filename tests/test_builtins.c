/* Test for __builtin_stuff */
#include <stdbool.h>

#define likely(x)     __builtin_expect(!!(x),1)
#define unlikely(x)   __builtin_expect(!!(x),0)

int test_likely(void)
{
	int x = 3;

	if (likely(x == 3))
		return 1;

	if (unlikely(x == 1))
		return 2;

	return 0;
}

int main(int argc, char *argv[])
{
	test_likely();

	return 0;
}
