/* Test for const expressions */
#include <stdbool.h>

bool is_pv_domain(void)
{
	return false;
}

bool function_that_accepts_bool(bool x)
{
	return !x;
}

void test_simple_const(void)
{
	if (1)
		return;
	if (0)
		test_simple_const();

	do
	{
		return;
	} while (0);

	for (; 1 ; )
		return;

	while (true)
		return;

	function_that_accepts_bool(false);
}

void test_const_expressions(void)
{
	if (2 < 3)
		return;

	if (!false)
		return;

	if (false || true)
		return;

	if (sizeof(int) == 2)
		return;

	while (sizeof(char) == 1)
		return;

	while (!(sizeof(char) != sizeof(int)))
		return;

	while ( (1 << sizeof(char)) > 8)
		return;

	function_that_accepts_bool (2 > 3);
}

void test_half_const_expressions(void)
{
	int x = 0;
	int y = 5;

	if (0 && y < x)
		return;

	if (false && y > x)
		return;

	if (1 || y < x)
		return;

	if (true || y < x)
		return;

	if (is_pv_domain() && y < x)
		return;
}

int main(int argc, char *argv[])
{

	test_simple_const();
	test_const_expressions();

        return 0;
}

