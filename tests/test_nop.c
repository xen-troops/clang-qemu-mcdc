/* Test for expressions that does not provide a result */
#include <stdbool.h>

/* This one is from Xen */
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
/* SAF-3-safe MISRA C Rule 20.4: Giving the keyword it's C23 meaning. */
#define auto __auto_type
#endif
/*
 * min()/max() macros that also do strict type-checking..
 */
#define min(x, y)                               \
    ({                                          \
        const auto _x = (x);                    \
        const auto _y = (y);                    \
        (void)(&_x == &_y); /* typecheck */     \
        _x < _y ? _x : _y;                      \
    })

int test_simple_nops(void)
{
	int x = 3;
	int y = 0;

	{(void)(x==1);};

	y = ({x==1, x==2, x==3;});

	return 0;
}

int test_min_func(void)
{
	int x = 3;
	int y = 2;
	int z = 1;

	z = min(x, y);

	if (min(x, y) > 4)
		return 0;

	if (min(x, 3))
		return 0;

	if (min(1, 3))
		return 0;

	if (min(x, y))
		return 0;
}

int main(int argc, char *argv[])
{
	test_simple_nops();

	test_min_func();

	return 0;
}
