/* A 17.14 fixed-point number */
typedef signed int fp32;

fp32 fp_f32_to_int (int n);

int fp_fp32_to_int_rnd_zero (fp32 x);
int fp_fp32_to_int_rnd_nearest (fp32 x);

fp32 fp_fp32_plus_fp32 (fp32 x, fp32 y);
fp32 fp_fp32_sub_fp32 (fp32 x, fp32 y);
fp32 fp_fp32_plus_int (fp32 x, int n);
fp32 fp_fp32_sub_int (fp32 x, int n);
fp32 fp_fp32_mult_fp32 (fp32 x, fp32 y);
fp32 fp_fp32_mult_int (fp32 x, int n);
fp32 fp_fp32_div_fp32 (fp32 x, fp32 y);
fp32 fp_fp32_div_int (fp32 x, int n);
