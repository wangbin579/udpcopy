bin_PROGRAMS=udpcopy

udpcopy_SOURCES=\
                udpcopy.h\
                send.c send.h\
                manager.c manager.h\
                session.c session.h\
                main.c
udpcopy_LDADD=\
               ../core/libcore.a\
               ../log/liblog.a\
               ../util/libutil.a\
               ../event/libevent.a\
			   -lm
