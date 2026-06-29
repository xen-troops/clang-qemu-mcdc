/* Test for comparison with enum values */
#include <stdbool.h>

enum test_enum
{
	ENUM_VALUE1 = 0,
	ENUM_VALUE2,
	ENUM_VALUE3,
};

int main(int argc, char *argv[])
{
	enum test_enum var;

	var = ENUM_VALUE1;

	if (var > ENUM_VALUE1)
		return 1;
	if (var == ENUM_VALUE3)
		return 3;

	if (var >= ENUM_VALUE2)
		return 2;
	return 0;
}
