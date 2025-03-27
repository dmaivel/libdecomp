#include "visitor.h"

#include <stdlib.h>
#include <string.h>

/*
 * thank you: https://stackoverflow.com/a/12996028 
 */
static inline uint64_t hash(uint64_t x) 
{
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    x = x ^ (x >> 31);
    return x;
}

static inline uint64_t unhash(uint64_t x) 
{
    x = (x ^ (x >> 31) ^ (x >> 62)) * UINT64_C(0x319642b2d24d8ec3);
    x = (x ^ (x >> 27) ^ (x >> 54)) * UINT64_C(0x96de1b173f119089);
    x = x ^ (x >> 30) ^ (x >> 60);
    return x;
}

DCVisitor *dc_visitor_create(int max_capacity)
{
    DCVisitor *visitor = calloc(1, sizeof(DCVisitor) + (max_capacity * sizeof(uint64_t)));
    memset(visitor->values, 0xff, max_capacity * sizeof(uint64_t));
    visitor->capacity = max_capacity;
    return visitor;
}

bool dc_visitor_add(DCVisitor *visitor, uint64_t value)
{
    if (visitor->capacity == visitor->count)
        return false;

    uint64_t index = hash(value) % visitor->capacity;

    if (visitor->values[index] == value) return false;
    else if (visitor->values[index] == UINT64_C(-1)) goto add; /* SORRY !! */
    
    do {
        index = (index + 1) % visitor->capacity;
        if (visitor->values[index] == value)
            return false;
    } while (visitor->values[index] != UINT64_C(-1)); 

add:
    visitor->values[index] = value;
    visitor->count++;
    return true;
}

uint64_t *dc_visitor_get_compressed(DCVisitor *visitor)
{
    uint64_t *result = calloc(visitor->count, sizeof(uint64_t));
    
    for (int i = 0, j = 0; i < visitor->capacity; i++)
        if (visitor->values[i] != UINT64_C(-1))
            result[j++] = visitor->values[i];

    return result;
}
