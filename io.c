#include <sys/queue.h>

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/x509.h>

#include "extern.h"

void
socket_blocking(int fd, int verb)
{
	int	 fl;

	if ((fl = fcntl(fd, F_GETFL, 0)) == -1)
		err(EXIT_FAILURE, "fcntl");
	if (fcntl(fd, F_SETFL, fl & ~O_NONBLOCK) == -1)
		err(EXIT_FAILURE, "fcntl");
}

void
socket_nonblocking(int fd, int verb)
{
	int	 fl;

	if ((fl = fcntl(fd, F_GETFL, 0)) == -1)
		err(EXIT_FAILURE, "fcntl");
	if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1)
		err(EXIT_FAILURE, "fcntl");
}

/*
 * Blocking write of a binary buffer.
 * Buffers of length zero are simply ignored.
 */
void
simple_write(int fd, const void *res, size_t sz)
{
	ssize_t	 ssz;

	if (sz == 0)
		return;
	if ((ssz = write(fd, res, sz)) < 0)
		err(EXIT_FAILURE, "write");
	else if ((size_t)ssz != sz)
		errx(EXIT_FAILURE, "write: short write");
}

/*
 * Like simple_write() but into a buffer.
 */
void
simple_buffer(char **b, size_t *bsz,
	size_t *bmax, const void *res, size_t sz)
{

	if (*bsz + sz > *bmax) {
		if ((*b = realloc(*b, *bsz + sz)) == NULL)
			err(EXIT_FAILURE, NULL);
		*bmax = *bsz + sz;
	}

	memcpy(*b + *bsz, res, sz);
	*bsz += sz;
}

/*
 * Like buf_write() but into a buffer.
 */
void
buf_buffer(char **b, size_t *bsz, size_t *bmax,
	int verb, const void *p, size_t sz)
{

	simple_buffer(b, bsz, bmax, &sz, sizeof(size_t));
	if (sz > 0)
		simple_buffer(b, bsz, bmax, p, sz);
}

/*
 * Write a binary buffer of the given size, which may be zero.
 */
void
buf_write(int fd, int verb, const void *p, size_t sz)
{

	simple_write(fd, &sz, sizeof(size_t));
	simple_write(fd, p, sz);
}

/*
 * Like str_write() but into a buffer.
 */
void
str_buffer(char **b, size_t *bsz, size_t *bmax, int verb, const char *p)
{
	size_t	 sz = (p == NULL) ? 0 : strlen(p);

	buf_buffer(b, bsz, bmax, verb, p, sz);
}

/*
 * Write a NUL-terminated string, which may be zero-length.
 */
void
str_write(int fd, int verb, const char *p)
{
	size_t	 sz = (p == NULL) ? 0 : strlen(p);

	buf_write(fd, verb, p, sz);
}

/*
 * Read of a binary buffer that must be on a blocking descriptor.
 * Does nothing if "sz" is zero.
 * This will fail and exit on EOF or short reads.
 */
void
simple_read(int fd, void *res, size_t sz)
{
	ssize_t	 ssz;

	if (sz == 0)
		return;

	if ((ssz = read(fd, res, sz)) < 0)
		err(EXIT_FAILURE, "read");
	else if (ssz == 0)
		errx(EXIT_FAILURE, "read: unexpected end of file");
	else if ((size_t)ssz < sz)
		errx(EXIT_FAILURE, "read: short read");
}

/*
 * Read a binary buffer, allocating space for it.
 * If the buffer is zero-sized, this won't allocate "res", but
 * will still initialise it to NULL.
 */
void
buf_read_alloc(int fd, void **res, size_t *sz)
{

	*res = NULL;
	simple_read(fd, sz, sizeof(size_t));
	if (*sz == 0)
		return;
	if ((*res = malloc(*sz)) == NULL)
		err(EXIT_FAILURE, NULL);
	simple_read(fd, *res, *sz);
}

/*
 * Read a string (which may just be \0 and zero-length), allocating
 * space for it.
 */
void
str_read(int fd, char **res)
{
	size_t	 sz;

	simple_read(fd, &sz, sizeof(size_t));
	if ((*res = calloc(sz + 1, 1)) == NULL)
		err(EXIT_FAILURE, NULL);
	simple_read(fd, *res, sz);
}
