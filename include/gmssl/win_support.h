#ifndef GMSSL_WIN_SUPPORT
#define GMSSL_WIN_SUPPORT

#ifdef _MSC_VER

#include <windows.h>
#include <stdio.h>

#include  <ctype.h>
#include  <string.h>
#include  <time.h>

#define EXPORT  __declspec( dllimport )

#define RTLD_LAZY -1
#define dlopen(path,opt) LoadLibrary(path)
#define dlerror GetLastError
#define dlsym GetProcAddress

#define timegm _mkgmtime
#define gmtime_r(a,b)  gmtime_s((b),(a))

#ifndef _SSIZE_T_DEFINED
#ifdef  _WIN64
typedef unsigned __int64    ssize_t;
#else
typedef _W64 unsigned int   ssize_t;
#endif
#define _SSIZE_T_DEFINED
#endif

#define  ALT_E          0x01
#define  ALT_O          0x02
//#define LEGAL_ALT(x)       { if (alt_format & ~(x)) return (0); }
#define  LEGAL_ALT(x)       { ; }
#define  TM_YEAR_BASE   (1970)

static    int conv_num(const char**, int*, int, int);
static  int strncasecmp(char* s1, char* s2, size_t n);
char* strptime(const char* buf, const char* fmt, struct tm* tm);

static  const char* day[7] = {
     "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday",
     "Friday", "Saturday"
};
static  const char* abday[7] = {
     "Sun","Mon","Tue","Wed","Thu","Fri","Sat"
};
static  const char* mon[12] = {
     "January", "February", "March", "April", "May", "June", "July",
     "August", "September", "October", "November", "December"
};
static  const char* abmon[12] = {
     "Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};
static  const char* am_pm[2] = {
     "AM", "PM"
};
#else
#define EXPORT 
#endif
#endif