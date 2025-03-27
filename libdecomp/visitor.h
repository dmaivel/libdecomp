#ifndef VISITOR_H
#define VISITOR_H 

#include <stddef.h>
#include <inttypes.h>
#include <stdbool.h>

typedef struct DCVisitor {
    size_t capacity;
    size_t count;
    uint64_t values[1];
} DCVisitor;

DCVisitor *dc_visitor_create(int max_capacity);
bool dc_visitor_add(DCVisitor *visitor, uint64_t value);
uint64_t *dc_visitor_get_compressed(DCVisitor *visitor);

#endif /* VISITOR_H */
