#include <libdecomp/libdecomp.h>

int DC_Version(int *major, int *minor)
{
    if (major != NULL) *major = LIBDECOMP_VERSION_MAJOR;
    if (minor != NULL) *minor = LIBDECOMP_VERSION_MINOR;

    return DC_MAKE_VERSION(LIBDECOMP_VERSION_MAJOR, LIBDECOMP_VERSION_MINOR);
}
