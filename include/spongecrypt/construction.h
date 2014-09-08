#ifndef __CONSTRUCTION_H__
#define __CONSTRUCTION_H__

typedef enum {
	CONSTR_SUCCESS = 0,
	CONSTR_FAILURE,	/* operation failed, safe to try again */
	CONSTR_FATAL	/* operation failed, construction and permutation must not be used
			 * anymore */
} constr_result;

#endif /* __CONSTRUCTION_H__ */
