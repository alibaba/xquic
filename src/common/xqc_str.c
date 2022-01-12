/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/common/xqc_str.h"

unsigned char *
xqc_hex_dump(unsigned char *dst, const unsigned char *src, size_t len)
{
    static const unsigned char hex[] = "0123456789abcdef";

    while (len--) {
        *dst++ = hex[*src >> 4];
        *dst++ = hex[*src++ & 0xf];
    }

    return dst;
}

unsigned char *
xqc_vsprintf(unsigned char *buf, unsigned char *last, const char *fmt, va_list args)
{
    unsigned char  *p;
    unsigned char   zero;
    int             d;
    double          f;
    size_t          len, slen;
    int64_t         i64;
    uint64_t        ui64, frac;
    uint64_t        width, sign, hex, max_width, frac_width, scale, n;
    xqc_str_t      *v;

    while (*fmt && buf < last) {

        if (*fmt == '%') {
            i64 = 0;
            ui64 = 0;

            zero = (unsigned char) ((*++fmt == '0') ? '0' : ' ');
            width = 0;
            sign = 1;
            hex = 0;
            max_width = 0;
            frac_width = 0;
            slen = (size_t) -1;

            while (*fmt >= '0' && *fmt <= '9') {
                width = width * 10 + *fmt++ - '0';
            }

            for ( ;; ) {
                switch (*fmt) {
                case 'u':
                    sign = 0;
                    fmt++;
                    continue;

                case 'm':
                    max_width = 1;
                    fmt++;
                    continue;

                case 'X':
                    hex = 2;
                    sign = 0;
                    fmt++;
                    continue;

                case 'x':
                    hex = 1;
                    sign = 0;
                    fmt++;
                    continue;

                case '.':
                    fmt++;
                    while (*fmt >= '0' && *fmt <= '9') {
                        frac_width = frac_width * 10 + *fmt++ - '0';
                    }
                    break;

                case '*':
                    slen = va_arg(args, size_t);
                    fmt++;
                    continue;

                default:
                    break;
                }

                break;
            }


            switch (*fmt) {

            case 'V':
                v = va_arg(args, xqc_str_t *);
                len = xqc_min(((size_t) (last - buf)), v->len);
                buf = xqc_cpymem(buf, v->data, len);
                fmt++;
                continue;

            case 's':
                p = va_arg(args, unsigned char *);
                if (slen == (size_t) -1) {
                    while (*p && buf < last) {
                        *buf++ = *p++;
                    }
                } else {
                    len = xqc_min(((size_t) (last - buf)), slen);
                    buf = xqc_cpymem(buf, p, len);
                }
                fmt++;
                continue;

            case 'O':
                i64 = (int64_t) va_arg(args, off_t);
                sign = 1;
                break;

            case 'P':
                i64 = (int64_t) va_arg(args, int64_t);
                sign = 1;
                break;

            case 'T':
                i64 = (int64_t) va_arg(args, time_t);
                sign = 1;
                break;

            case 'z':
                if (sign) {
                    i64 = (int64_t) va_arg(args, ssize_t);
                } else {
                    ui64 = (uint64_t) va_arg(args, size_t);
                }
                break;

            case 'i':
                if (sign) {
                    i64 = (int64_t) va_arg(args, int64_t);
                } else {
                    ui64 = (uint64_t) va_arg(args, uint64_t);
                }

                if (max_width) {
                    width = XQC_INT_T_LEN;
                }
                break;

            case 'd':
                if (sign) {
                    i64 = (int64_t) va_arg(args, int);
                } else {
                    ui64 = (uint64_t) va_arg(args, unsigned int);
                }
                break;

            case 'l':
                if (sign) {
                    i64 = (int64_t) va_arg(args, long);
                } else {
                    ui64 = (uint64_t) va_arg(args, unsigned long);
                }
                break;

            case 'D':
                if (sign) {
                    i64 = (int64_t) va_arg(args, int32_t);
                } else {
                    ui64 = (uint64_t) va_arg(args, uint32_t);
                }
                break;

            case 'L':
                if (sign) {
                    i64 = va_arg(args, int64_t);
                } else {
                    ui64 = va_arg(args, uint64_t);
                }
                break;

            case 'f':
                f = va_arg(args, double);

                if (f < 0) {
                    *buf++ = '-';
                    f = -f;
                }

                ui64 = (int64_t) f;
                frac = 0;

                if (frac_width) {
                    scale = 1;
                    for (n = frac_width; n; n--) {
                        scale *= 10;
                    }

                    frac = (uint64_t) ((f - (double) ui64) * scale + 0.5);

                    if (frac == scale) {
                        ui64++;
                        frac = 0;
                    }
                }

                buf = xqc_sprintf_num(buf, last, ui64, zero, 0, width);

                if (frac_width) {
                    if (buf < last) {
                        *buf++ = '.';
                    }
                    buf = xqc_sprintf_num(buf, last, frac, '0', 0, frac_width);
                }

                fmt++;

                continue;
#ifndef WIN32
            case 'r':
                i64 = (int64_t) va_arg(args, rlim_t);
                sign = 1;
                break;
#endif
            case 'p':
                ui64 = (uintptr_t) va_arg(args, void *);
                hex = 2;
                sign = 0;
                zero = '0';
                width = XQC_PTR_SIZE * 2;
                break;

            case 'c':
                d = va_arg(args, int);
                *buf++ = (unsigned char) (d & 0xff);
                fmt++;
                continue;

            case 'Z':
                *buf++ = '\0';
                fmt++;
                continue;

            case 'N':
                *buf++ = LF;
                fmt++;
                continue;

            case '%':
                *buf++ = '%';
                fmt++;
                continue;

            default:
                *buf++ = *fmt++;
                continue;
            }

            if (sign) {
                if (i64 < 0) {
                    *buf++ = '-';
                    ui64 = (uint64_t) -i64;

                } else {
                    ui64 = (uint64_t) i64;
                }
            }
            buf = xqc_sprintf_num(buf, last, ui64, zero, hex, width);
            fmt++;

        } else {
            *buf++ = *fmt++;
        }
    }

    return buf;
}

unsigned char *
xqc_sprintf_num(unsigned char *buf, unsigned char *last, uint64_t ui64, unsigned char zero, uintptr_t hexadecimal, uintptr_t width)
{
    unsigned char         *p, temp[XQC_INT64_LEN + 1];
    /*
     * we need temp[NGX_INT64_LEN] only,
     * but icc issues the warning
     */
    size_t          len;
    uint32_t        ui32;
    static unsigned char   hex[] = "0123456789abcdef";
    static unsigned char   HEX[] = "0123456789ABCDEF";

    p = temp + XQC_INT64_LEN;

    if (hexadecimal == 0) {
        if (ui64 <= (uint64_t) XQC_MAX_UINT32_VALUE) {
            ui32 = (uint32_t) ui64;

            do {
                *--p = (unsigned char) (ui32 % 10 + '0');
            } while (ui32 /= 10);
        } else {
            do {
                *--p = (unsigned char) (ui64 % 10 + '0');
            } while (ui64 /= 10);
        }

    } else if (hexadecimal == 1) {
        do {
            *--p = hex[(uint32_t) (ui64 & 0xf)];
        } while (ui64 >>= 4);

    } else { /* hexadecimal == 2 */

        do {
            *--p = HEX[(uint32_t) (ui64 & 0xf)];

        } while (ui64 >>= 4);
    }

    /* zero or space padding */

    len = (temp + XQC_INT64_LEN) - p;

    while (len++ < width && buf < last) {
        *buf++ = zero;
    }

    /* number safe copy */

    len = (temp + XQC_INT64_LEN) - p;

    if (buf + len > last) {
        len = last - buf;
    }

    return xqc_cpymem(buf, p, len);
}
