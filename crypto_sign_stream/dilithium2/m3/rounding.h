#ifndef ROUNDING_H
#define ROUNDING_H

#include <stdint.h>
#include "params.h"

#define decompose DILITHIUM_NAMESPACE(_decompose)
int32_t decompose(int32_t *a0, int32_t a);

#define use_hint DILITHIUM_NAMESPACE(_use_hint)
int32_t use_hint(int32_t a, unsigned int hint);

#endif
