#ifndef __KERN_UTILS_H__
#define __KERN_UTILS_H__

#define __must_check
#define __force

/* --- FROM include/linux/err.h --- */
#define MAX_ERRNO	4095
#define IS_ERR_VALUE(x) ((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static inline void * __must_check ERR_PTR(long error)
{
	return (void *) error;
}

static inline long __must_check PTR_ERR(__force const void *ptr)
{
	return (long) ptr;
}

static inline bool __must_check IS_ERR(__force const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool __must_check IS_ERR_OR_NULL(__force const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

#endif // __KERN_UTILS_H__
