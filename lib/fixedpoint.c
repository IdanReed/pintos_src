#include "fixedpoint.h"
#include "stdint.h"

/* fp32 uses 17.14 */
#define P32 17
#define Q32 14

int32_t f32 = 1 << Q32;

fp32
fp_f32_to_int (int n)
{
  return n * f32;
}

int
fp_fp32_to_int_rzero (fp32 x)
{
  return x / f32;
}

int
fp_fp32_to_int_nearest (fp32 x)
{
  if (x >= 0)
  {
    return (x + (f32/2)) / f32;
  }
  else
  {
    return (x - (f32/2)) / f32; 
  }
}

fp32
fp_fp32_plus_fp32 (fp32 x, fp32 y)
{
  return x + y;
}

fp32
fp_fp32_sub_fp32 (fp32 x, fp32 y)
{
  return x - y;
}

fp32
fp_fp32_plus_int (fp32 x, int n)
{
  return x + (n * f32);
}

fp32
fp_fp32_sub_int (fp32 x, int n)
{
  return x - (n * f32);
}

fp32
fp_fp32_mult_fp32 (fp32 x, fp32 y)
{
  return ((int64_t) x) * y / f32;
}

fp32
fp_fp32_mult_int (fp32 x, int n)
{
  return x * n;
}

fp32
fp_fp32_div_fp32 (fp32 x, fp32 y)
{
  return ((int64_t) x) * f32 / y;
}

fp32
fp_fp32_div_int (fp32 x, int n)
{
  return x / n;
}


