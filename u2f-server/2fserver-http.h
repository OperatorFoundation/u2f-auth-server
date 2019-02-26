#ifndef TWOFSERVER_HTTP_H
#define TWOFSERVER_HTTP_H 1

/* PORTING: see section 1.5 of the libmicrohttpd manual, "Including the
   microhttpd.h header", if porting to non-GNU/Linux systems */
#include <microhttpd.h>

void twofserver_start_http(unsigned port);

#endif /* !TWOFSERVER_HTTP_H */
