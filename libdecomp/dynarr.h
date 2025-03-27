#ifndef DYNARR_H
#define DYNARR_H 

#include <stddef.h>

void *dynarr_alloc(void **root, size_t size);
void dynarr_free_element(void **root, void *data);
void dynarr_free(void **root);

#endif /* DYNARR_H */
