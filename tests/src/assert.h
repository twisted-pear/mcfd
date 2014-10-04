#ifdef NDEBUG

#undef assert
#define assert(expression) \
	(do {} while (0); )

#else /* NDEBUG */

extern void mock_assert(const int result, const char* const expression,
		const char * const file, const int line);

#undef assert
#define assert(expression) \
	(mock_assert((int)(expression), #expression, __FILE__, __LINE__))

#endif /* NDEBUG */
