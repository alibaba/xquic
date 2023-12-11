/*
 * Portions Copyright (c) 1987, 1993, 1994
 * The Regents of the University of California.  All rights reserved.
 */
#ifndef GETOPT_H
#define GETOPT_H

/* rely on the system's getopt.h if present */
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

/*
 * If we have <getopt.h>, assume it declares these variables, else do that
 * ourselves.  (We used to just declare them unconditionally, but Cygwin
 * doesn't like that.)
 */
#ifndef HAVE_GETOPT_H
extern char *optarg;
extern int   optind;
extern int   opterr;
extern int   optopt;
#endif   /* HAVE_GETOPT_H */

#ifndef HAVE_STRUCT_OPTION
struct option
{
    const char *name;
    int         has_arg;
    int        *flag;
    int         val;
};
#define no_argument 0
#define required_argument 1
#define optional_argument 2
#endif /* HAVE_STRUCT_OPTION */

#ifndef HAVE_GETOPT
extern int getopt(int nargc, char *const * nargv, const char *ostr);
#endif

#ifndef HAVE_GETOPT_LONG
extern int getopt_long(int argc, char *const argv[],
                       const char *optstring,
                       const struct option * longopts, int *longindex);
#endif
#endif

