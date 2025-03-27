#include "dynarr.h"
#include <stdlib.h>

void *dynarr_alloc(void **root, size_t size)
{
    if (*root == NULL) {
        *root = calloc(1, size);
        return *root;
    }

    void *next;
    for (next = *root; *(void**)(next); next = *(void**)(next));
    *(void**)(next) = calloc(1, size);

    return *(void**)(next);
}

void dynarr_free_element(void **root, void *data)
{
    void *prev = NULL;

    for (void *elem = *root; elem;) {
        void *next = *(void**)(elem);

        if (elem == data) {
            if (prev == NULL)
                *root = next;
            else
                *(void**)(prev) = next;

            free(elem);
        }
        else
            prev = elem;

        elem = next;
    }
}

void dynarr_free(void **root)
{
    /* 
     * recursively call up until the last element 
     * (elements need to be freed in reverse order) 
     */
    if (*(void**)(root)) {
        dynarr_free(*(void**)(root));
        free(*root);
    }
}
