#include <stdbool.h>

struct dt_device_match {
    const char *path;
    const char *type;
    const char *compatible;
    const bool not_available;
    /*
     * Property name to search for. We only search for the property's
     * existence.
     */
    const char *prop;
    const void *data;
} g_matches;



int main(void)
{
	const struct dt_device_match *matches = &g_matches;

	while ( matches->path || matches->type ||
		matches->compatible || matches->not_available || matches->prop )
		return 1;

	return 0;
}
