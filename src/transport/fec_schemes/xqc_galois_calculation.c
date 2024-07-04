
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/fec_schemes/xqc_galois_calculation.h"
#include "src/transport/xqc_conn.h"
#include <stdio.h>


unsigned char
xqc_galois_multiply(unsigned char a, unsigned char b)
{
    if (a == 0 || b == 0) {
        return 0;
    }

    unsigned char log_a = xqc_rs_log_table[a];
    unsigned char log_b = xqc_rs_log_table[b];

    return xqc_rs_exp_table[log_a + log_b];
}

unsigned char
xqc_galois_exp(unsigned char a, unsigned char n)
{
    unsigned char log_a, log_r;
    if (n == 0) {
        return 1;
    }

    if (a == 0) {
        return 0;
    }

    log_a = xqc_rs_log_table[a];
    log_r = (log_a * n) % 255;
    
    return xqc_rs_exp_table[log_r];
}

xqc_int_t
xqc_galois_divide(unsigned char a, unsigned char b, unsigned char *res)
{
    if (a == 0) {
        *res = 0;
        return XQC_OK;
    }

    if (b == 0) {
        return -XQC_EPARAM;
    }

    unsigned char log_a = xqc_rs_log_table[a];
    unsigned char log_b = xqc_rs_log_table[b];
    unsigned char log_r = 0;

    if (log_a < log_b) {
        log_r += 255;
    }

    log_r += log_a - log_b;
    *res = xqc_rs_exp_table[log_r];
    
    return XQC_OK;
}

unsigned char
xqc_galois_inversion(unsigned char a)
{
    uint16_t i = 0;
    if (a == 0) {
        return 0;
    }
    for (i = 1; i < 256; i++) {
        if (xqc_galois_multiply(a, i) == 1) {
            return i;
        }
    }
    return 0;
}


void
xqc_submatrix(uint16_t row_min, uint16_t row_max,
    uint16_t col_min, uint16_t col_max,
    uint16_t col_max_sub, uint16_t col_max_matrix,
    unsigned char *submatrix, unsigned char *matrix)
{
    xqc_memset(submatrix, 0, col_max_sub * row_max);
    for (uint16_t row_i = row_min; row_i < row_max; row_i++) {
        for (uint16_t col_i = col_min; col_i < col_max; col_i++) {
            *(submatrix + (row_i - row_min) * col_max_sub + col_i - col_min) = *(matrix + row_i * col_max_matrix + col_i);
        }
    }
}

void
xqc_build_vandermonde_matrix(unsigned char rows, unsigned char cols,
    unsigned char (*Vandermonde)[XQC_MAX_MT_ROW])
{
    for (unsigned char i = 0; i < rows; i++) {
        for (unsigned char j = 0; j < cols; j++) {
            Vandermonde[i][j] = (unsigned char)xqc_galois_exp(i, j);
        }
    }
}



/* Generate a identity matrix with given size */
xqc_int_t
xqc_identity_matrix(unsigned char size, unsigned char (*output)[XQC_MAX_MT_ROW])
{
    for (unsigned char i = 0; i < size; i++) {
        xqc_memset(output[i], 0, XQC_MAX_MT_ROW);
        output[i][i] = 1;
    }
    return XQC_OK;
}

/* concatenate 2 matrices horizontally */
xqc_int_t
xqc_concatenate_matrix(unsigned char (*left)[XQC_MAX_MT_ROW], unsigned char (*right)[XQC_MAX_MT_ROW],
    unsigned char left_rows, unsigned char right_rows,
    unsigned char left_cols, unsigned char right_cols,
    unsigned char (*output)[2*XQC_MAX_MT_ROW])
{
    if (left_rows != right_rows) {
        return -XQC_EPARAM;
    }

    for (unsigned char row_i = 0; row_i < left_rows; row_i++) {
        for (unsigned char col_i = 0; col_i < left_cols; col_i++) {
            output[row_i][col_i] = left[row_i][col_i];
        }
        for (unsigned char col_i = 0; col_i < right_cols; col_i++) {
            output[row_i][left_cols + col_i] = right[row_i][col_i];
        }
    }
    return XQC_OK;
}


xqc_int_t
xqc_gaussian_elimination(unsigned char rows, unsigned char cols,
    unsigned char (*output)[2*XQC_MAX_MT_ROW])
{
    uint16_t row_i, col_i, max_row, i, tmp, inv, row_above;
    unsigned char ratio = 0;
    for (row_i = 0; row_i < rows; row_i++) {
        max_row = row_i;
        for (i = row_i + 1; i < rows; i++) {
            if (output[i][row_i] > output[max_row][row_i]) {
                max_row = i;
            }
        }

        for (col_i = row_i; col_i < cols; col_i++) {
            tmp = output[max_row][col_i];
            output[max_row][col_i] = output[row_i][col_i];
            output[row_i][col_i] = tmp;
        }

        if (output[row_i][row_i] == 0) {
            return -XQC_EFEC_SCHEME_ERROR;
        }

        inv = xqc_galois_inversion(output[row_i][row_i]);
        for (col_i = row_i; col_i < cols; col_i++) {
            output[row_i][col_i] = xqc_galois_multiply(output[row_i][col_i], inv);
        }

        for (i = row_i + 1; i < rows; i++) {
            tmp = output[i][row_i];
            for (col_i = row_i; col_i < cols; col_i++) {
                output[i][col_i] ^= xqc_galois_multiply(tmp, output[row_i][col_i]);
            }
        }
    }

    for (row_i = 0; row_i < rows; row_i++) {
        for (row_above = 0; row_above < row_i; row_above++) {
            if (output[row_above][row_i] != 0) {
                ratio = output[row_above][row_i];
                for (col_i = 0; col_i < cols; col_i++) {
                    output[row_above][col_i] ^= xqc_galois_multiply(ratio, output[row_i][col_i]);
                }
            }
        }
    }
    return XQC_OK;
}

xqc_int_t
xqc_invert_matrix(unsigned char rows, unsigned char cols, unsigned char (*output)[XQC_MAX_MT_ROW])
{
    xqc_int_t ret;
    if (rows != cols) {
        return -XQC_EPARAM;
    }
    unsigned char identity_matrix[XQC_MAX_MT_ROW][XQC_MAX_MT_ROW], tmp_matrix[XQC_MAX_MT_ROW][2 * XQC_MAX_MT_ROW];
    if (xqc_identity_matrix(rows, identity_matrix) != XQC_OK) {
        return -XQC_EPARAM;
    }

    if (xqc_concatenate_matrix(output, identity_matrix, rows, rows, cols, rows, tmp_matrix) != XQC_OK) {
        return -XQC_EPARAM;
    }

    ret = xqc_gaussian_elimination(rows, rows + cols, tmp_matrix);
    if (ret != XQC_OK) {
        return ret;
    }

    xqc_submatrix(0, rows, cols, 2 * cols, 256, 512, &output[0][0], &tmp_matrix[0][0]);
    
    return XQC_OK;
}

xqc_int_t
xqc_matrix_time(unsigned char left_row, unsigned char left_col,
    unsigned char (*left)[XQC_MAX_MT_ROW],
    unsigned char right_row, unsigned char right_col,
    unsigned char (*right)[XQC_MAX_MT_ROW],
    unsigned char output_row, unsigned char output_col,
    unsigned char (*output)[XQC_MAX_MT_ROW])
{
    unsigned char value = 0;
    if (left_col != right_row
        || left_row > output_row
        || right_col > output_col)
    {
        /* invalid matrix multiplication. */
        return -XQC_EPARAM;
    }
    for (unsigned char row_i = 0; row_i < left_row; row_i++) {
        for(unsigned char col_i = 0; col_i < right_col; col_i++) {
            value = 0;
            for (unsigned char i = 0; i < left_col; i++) {
                value ^= xqc_galois_multiply(left[row_i][i], right[i][col_i]);
            }
            output[row_i][col_i] = value;
        }
    }
    return XQC_OK;
}

