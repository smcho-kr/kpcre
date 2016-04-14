#ifndef _KERNEL_LIBC_H
#define _KERNEL_LIBC_H

#include <linux/types.h>


#if defined(__GNUC__)
#define __WORDSIZE __SIZEOF_POINTER__
#endif

/* We don't have #include_next.
   Define ANSI <limits.h> for standard 32-bit words.  */

/* These assume 8-bit `char's, 16-bit `short int's,
   and 32-bit `int's and `long int's.  */

/* Number of bits in a `char'.  */
#ifndef CHAR_BIT
#  define CHAR_BIT  8
#endif

/* Minimum and maximum values a `signed char' can hold.  */
#ifndef SCHAR_MIN
#  define SCHAR_MIN (-128)
#endif
#ifndef SCHAR_MAX
#  define SCHAR_MAX 127
#endif

/* Maximum value an `unsigned char' can hold.  (Minimum is 0.)  */
#ifndef UCHAR_MAX
#  define UCHAR_MAX 255
#endif

/* Minimum and maximum values a `char' can hold.  */
#  ifdef __CHAR_UNSIGNED__
#   define CHAR_MIN 0
#   define CHAR_MAX UCHAR_MAX
#  else
#   define CHAR_MIN SCHAR_MIN
#   define CHAR_MAX SCHAR_MAX
#  endif

#ifndef INT8_MIN
/** The smallest value an 8 bit signed integer can hold @stable ICU 2.0 */
#   define INT8_MIN        ((int8_t)(-128))
#endif
#ifndef INT16_MIN
/** The smallest value a 16 bit signed integer can hold @stable ICU 2.0 */
#   define INT16_MIN       ((int16_t)(-32767-1))
#endif
#ifndef INT32_MIN
/** The smallest value a 32 bit signed integer can hold @stable ICU 2.0 */
#   define INT32_MIN       ((int32_t)(-2147483647-1))
#endif

#ifndef INT8_MAX
/** The largest value an 8 bit signed integer can hold @stable ICU 2.0 */
#   define INT8_MAX        ((int8_t)(127))
#endif
#ifndef INT16_MAX
/** The largest value a 16 bit signed integer can hold @stable ICU 2.0 */
#   define INT16_MAX       ((int16_t)(32767))
#endif
#ifndef INT32_MAX
/** The largest value a 32 bit signed integer can hold @stable ICU 2.0 */
#   define INT32_MAX       ((int32_t)(2147483647))
#endif

#ifndef UINT8_MAX
/** The largest value an 8 bit unsigned integer can hold @stable ICU 2.0 */
#   define UINT8_MAX       ((uint8_t)(255U))
#endif
#ifndef UINT16_MAX
/** The largest value a 16 bit unsigned integer can hold @stable ICU 2.0 */
#   define UINT16_MAX      ((uint16_t)(65535U))
#endif
#ifndef UINT32_MAX
/** The largest value a 32 bit unsigned integer can hold @stable ICU 2.0 */
#   define UINT32_MAX      ((uint32_t)(4294967295U))
#endif


extern void *malloc(size_t size);
extern void *realloc(void *ptr, size_t size);
extern void *calloc(size_t nmemb, size_t size);
extern void free(void *ptr);
extern int snprintf(char *buf, size_t size, const char *fmt, ...);

#endif /* _KERNEL_LIBC_H */
