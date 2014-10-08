#include <version.h>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#ifdef VERSION_MINOR
#define VERSION_MINOR_STR "." TOSTRING(VERSION_MINOR)
#else
#define VERSION_MINOR_STR ""
#endif

#ifdef VERSION_MAJOR
#define VERSION_STR "Version: " TOSTRING(VERSION_MAJOR) VERSION_MINOR_STR ", "
#else
#define VERSION_STR ""
#endif

#ifdef BUILDID
#define BUILDID_STR "Build: " TOSTRING(BUILDID) ", "
#else
#define BUILDID_STR ""
#endif

char lk_version[] = VERSION_STR BUILDID_STR "Built: " __TIME__ " " __DATE__;
