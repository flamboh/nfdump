/*
 * Atlantis Flow Stream v1 output.
 */

#ifndef _OUTPUT_ATLANTIS_H
#define _OUTPUT_ATLANTIS_H 1

#include "output.h"

void atlantis_prolog(outputParams_t *outputParam);

void atlantis_epilog(outputParams_t *outputParam);

void atlantis_record(FILE *stream, recordHandle_t *recordHandle, outputParams_t *outputParam);

#endif  // _OUTPUT_ATLANTIS_H
