#include <stdbool.h>

static inline __attribute__((__always_inline__)) int inline_func(int x)
{
	if (x==1)
		return 2;
	if (x==2)
		return 4;
	if (x==3)
		return 6;
	if (x==4)
		return 8;
	if (x==5)
		return 10;
	if (x==6)
		return 12;
	if (x==7)
		return 14;
	return -1;
}

#define complex_macro(y)				\
	({						\
	union { typeof((y)) val; long yy; } x_;		\
        x_.yy = y;					\
	x_.val = inline_func(x_.yy);			\
	x_.val;						\
	})


int test_func()
{
	if (complex_macro(4) == 8)
		return 1;
	return 0;
}

int main(void)
{
	test_func();

	return 0;
}
