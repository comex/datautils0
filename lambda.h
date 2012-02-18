#pragma once

/*  Example:
    
    int multiplier = 5;
    DECL_LAMBDA(l, int, (int a), {
        return a * multiplier;
    })
    assert(l.func(l.arg, 4) == 20);

    The point of this is to work on both iOS, where GCC inline
    functions don't work, and Linux, where Apple blocks generally
    aren't available.
*/

#ifdef __BLOCKS__
struct _blk {
    void *isa;
    int flags;
    int reserved;
    void *invoke;
};
#define LAMBDA_BODY(typ, ret, args, body) \
    ({ union { \
           ret (^blk) args; \
           struct _blk *_blk; \
        } u = { ^ret args body }; \
       (typ) {u._blk->invoke, u._blk}; \
       })
#else
#define LAMBDA_BODY_(typ, ret, args, body) \
    ({ ret func args body; \
       (typ) {&func, 0}; \
       })
#define LAMBDA_BODY(typ, ret, args, body) \
    LAMBDA_BODY_(typ, ret, LAMBDA_UNPAREN args, body)
#endif

// based on http://lefteris.realintelligence.net/?p=593
#define LAMBDA_YUP() LAMBDA_NOPE
#define LAMBDA_CHECK_LAMBDA_YUP_() ,
#define LAMBDA_CHECK_LAMBDA_NOPE_()
#define LAMBDA_CHECK_LAMBDA_YUP LAMBDA_CHECK_LAMBDA_YUP_,
#define LAMBDA_CHECK_LAMBDA_NOPE LAMBDA_CHECK_LAMBDA_NOPE_,
#define LAMBDA_APPLY_FIRST_ARG(a, ...) a()
#define LAMBDA_COMMA_IF_NONEMPTY___(a...) LAMBDA_APPLY_FIRST_ARG(a)
#define LAMBDA_COMMA_IF_NONEMPTY__(a) LAMBDA_COMMA_IF_NONEMPTY___(LAMBDA_CHECK_##a)
#define LAMBDA_COMMA_IF_NONEMPTY_(a) LAMBDA_COMMA_IF_NONEMPTY__(a)
#define LAMBDA_COMMA_IF_NONEMPTY(a, ...) LAMBDA_COMMA_IF_NONEMPTY_(LAMBDA_YUP a ())
#define LAMBDA_UNPAREN(args...) (void *_lambda_ignored LAMBDA_COMMA_IF_NONEMPTY(args) args)
#define DECL_LAMBDA(name, ret, args, body) \
    struct __lambda_##name { \
        ret (*func) LAMBDA_UNPAREN args; \
        void *arg; \
    } name = LAMBDA_BODY(struct __lambda_##name, ret, args, body);
