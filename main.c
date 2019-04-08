/*	$Id$ */
/*
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <fts.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "extern.h"

/*
 * Base directory for where we'll look for all media.
 */
#define	BASE_DIR "/var/cache/rpki-client"

/*
 * Statistics collected during run-time.
 */
struct	stats {
	size_t	 tals; /* total number of locators */
	size_t	 mfts; /* total number of manifests */
	size_t	 mfts_stale; /* stale manifests */
	size_t	 certs; /* certificates */
	size_t	 roas; /* route announcements */
	size_t	 roas_invalid; /* invalid routes */
	size_t	 repos; /* repositories */
	size_t	 crls; /* revocation lists */
};

/*
 * An rsync repository.
 */
struct	repo {
	char	*host; /* hostname */
	char	*module; /* module name */
	int	 loaded; /* whether loaded or not */
	size_t	 id; /* identifier (array index) */
};

/*
 * A running rsync process.
 * We can have multiple of these simultaneously and need to keep track
 * of which process maps to which request.
 */
struct	rsyncproc {
	size_t	 id; /* identity of request */
	pid_t	 pid; /* pid of process or 0 if unassociated */
};

/*
 * Table of all known repositories.
 */
struct	repotab {
	struct repo	*repos; /* repositories */
	size_t		 reposz; /* number of repos */
};

/*
 * An entry (MFT, ROA, certificate, etc.) that needs to be downloaded
 * and parsed.
 */
struct	entry {
	size_t		 id; /* unique identifier */
	enum rtype	 type; /* type of entry (not RTYPE_EOF) */
	char		*uri; /* file or rsync:// URI */
	int		 has_dgst; /* whether dgst is specified */
	unsigned char	 dgst[SHA256_DIGEST_LENGTH]; /* optional */
	ssize_t		 repo; /* repo index or <0 if w/o repo */
	int		 has_pkey; /* whether pkey/sz is specified */
	unsigned char	*pkey; /* public key (optional) */
	size_t		 pkeysz; /* public key length (optional) */
	TAILQ_ENTRY(entry) entries;
};

TAILQ_HEAD(entryq, entry);

/*
 * Mark that our subprocesses will never return.
 */
static void	 proc_parser(int, int, int)
			__attribute__((noreturn));
static void	 proc_rsync(const char *, int, int)
			__attribute__((noreturn));
static void	 logx(const char *fmt, ...) 
			__attribute__((format(printf, 1, 2)));

static int	 verbose;

/*
 * Log a message to stderr if and only if "verbose" is non-zero.
 * This uses the err(3) functionality.
 */
static void
logx(const char *fmt, ...)
{
	va_list	 ap;

	if (verbose && fmt != NULL) {
		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}
}

/*
 * Resolve the media type of a resource by looking at its suffice.
 * Returns the type of RTYPE_EOF if not found.
 */
static enum rtype
rtype_resolve(const char *uri)
{
	enum rtype	 rp;

	(void)rsync_uri_parse(NULL, NULL, 
		NULL, NULL, NULL, NULL, &rp, uri);
	return rp;
}

static void
entry_free(struct entry *ent)
{

	if (ent == NULL)
		return;

	free(ent->pkey);
	free(ent->uri);
	free(ent);
}

/*
 * Read a queue entry from the descriptor.
 * Matched by entry_buffer_req().
 * The pointer must be passed entry_free().
 */
static void
entry_read_req(int fd, struct entry *ent)
{

	io_simple_read(fd, &ent->id, sizeof(size_t));
	io_simple_read(fd, &ent->type, sizeof(enum rtype));
	io_str_read(fd, &ent->uri);
	io_simple_read(fd, &ent->has_dgst, sizeof(int));
	if (ent->has_dgst)
		io_simple_read(fd, ent->dgst, sizeof(ent->dgst));
	io_simple_read(fd, &ent->has_pkey, sizeof(int));
	if (ent->has_pkey)
		io_buf_read_alloc(fd, (void **)&ent->pkey, &ent->pkeysz);
}

/*
 * Look up a repository, queueing it for discovery if not found.
 */
static const struct repo *
repo_lookup(int fd, struct repotab *rt, const char *uri)
{
	const char	*host, *mod;
	size_t		 hostsz, modsz, i;
	struct repo	*rp;

	if (!rsync_uri_parse(&host, &hostsz,
	    &mod, &modsz, NULL, NULL, NULL, uri))
		errx(EXIT_FAILURE, "%s: malformed", uri);

	/* Look up in repository table. */

	for (i = 0; i < rt->reposz; i++) {
		if (strlen(rt->repos[i].host) != hostsz)
			continue;
		if (strlen(rt->repos[i].module) != modsz)
			continue;
		if (strncasecmp(rt->repos[i].host, host, hostsz))
			continue;
		if (strncasecmp(rt->repos[i].module, mod, modsz))
			continue;
		return &rt->repos[i];
	}
	
	rt->repos = reallocarray(rt->repos,
		rt->reposz + 1, sizeof(struct repo));
	if (rt->repos == NULL)
		err(EXIT_FAILURE, NULL);

	rp = &rt->repos[rt->reposz++];
	memset(rp, 0, sizeof(struct repo));
	rp->id = rt->reposz - 1;

	if ((rp->host = strndup(host, hostsz)) == NULL ||
	    (rp->module = strndup(mod, modsz)) == NULL)
		err(EXIT_FAILURE, NULL);

	i = rt->reposz - 1;

	logx("%s/%s: loading", rp->host, rp->module);
	io_simple_write(fd, &i, sizeof(size_t));
	io_str_write(fd, rp->host);
	io_str_write(fd, rp->module);
	return rp;
}

/*
 * Read the next entry from the parser process, removing it from the
 * queue of pending requests in the process.
 * This always returns a valid entry.
 */
static struct entry *
entryq_next(int fd, struct entryq *q)
{
	size_t		 id;
	struct entry	*entp;

	io_simple_read(fd, &id, sizeof(size_t));

	TAILQ_FOREACH(entp, q, entries)
		if (entp->id == id)
			break;

	assert(entp != NULL);
	TAILQ_REMOVE(q, entp, entries);
	return entp;
}

static void
entry_buffer_resp(char **b, size_t *bsz,
	size_t *bmax, const struct entry *ent)
{

	io_simple_buffer(b, bsz, bmax, &ent->id, sizeof(size_t));
}

/*
 * Like entry_write_req() but into a buffer.
 * Matched by entry_read_req().
 */
static void
entry_buffer_req(char **b, size_t *bsz,
	size_t *bmax, const struct entry *ent)
{

	io_simple_buffer(b, bsz, bmax, &ent->id, sizeof(size_t));
	io_simple_buffer(b, bsz, bmax, &ent->type, sizeof(enum rtype));
	io_str_buffer(b, bsz, bmax, ent->uri);
	io_simple_buffer(b, bsz, bmax, &ent->has_dgst, sizeof(int));
	if (ent->has_dgst)
		io_simple_buffer(b, bsz, bmax, ent->dgst, sizeof(ent->dgst));
	io_simple_buffer(b, bsz, bmax, &ent->has_pkey, sizeof(int));
	if (ent->has_pkey)
		io_buf_buffer(b, bsz, bmax, ent->pkey, ent->pkeysz);
}

/*
 * Write the queue entry.
 * Simply a wrapper around entry_buffer_req().
 */
static void
entry_write_req(int fd, const struct entry *ent)
{
	char	*b = NULL;
	size_t	 bsz = 0, bmax = 0;

	entry_buffer_req(&b, &bsz, &bmax, ent);
	io_simple_write(fd, b, bsz);
	free(b);
}

/*
 * Scan through all queued requests and see which ones are in the given
 * repo, then flush those into the parser process.
 */
static void
entryq_flush(int fd, struct entryq *q, const struct repo *repo)
{
	struct entry	*p;

	TAILQ_FOREACH(p, q, entries) {
		if (p->repo < 0 || repo->id != (size_t)p->repo)
			continue;
		entry_write_req(fd, p);
	}
}

/*
 * Add the heap-allocated file to the queue for processing.
 */
static void
entryq_add(int fd, struct entryq *q, char *file, enum rtype type, 
	const struct repo *rp, const unsigned char *dgst, 
	const unsigned char *pkey, size_t pkeysz, size_t *eid)
{
	struct entry	*p;

	if ((p = calloc(1, sizeof(struct entry))) == NULL)
		err(EXIT_FAILURE, NULL);

	p->id = (*eid)++;
	p->type = type;
	p->uri = file;
	p->repo = (NULL != rp) ? rp->id : -1;
	p->has_dgst = dgst != NULL;
	p->has_pkey = pkey != NULL;
	if (p->has_dgst)
		memcpy(p->dgst, dgst, sizeof(p->dgst));
	if (p->has_pkey) {
		p->pkeysz = pkeysz;
		if ((p->pkey = malloc(pkeysz)) == NULL)
			err(EXIT_FAILURE, NULL);
		memcpy(p->pkey, pkey, pkeysz);
	}
	TAILQ_INSERT_TAIL(q, p, entries);

	/* 
	 * Write to the queue if there's no repo or the repo has already
	 * been loaded.
	 */

	if (NULL == rp || rp->loaded)
		entry_write_req(fd, p);
}

/*
 * Add a file (CER, ROA, CRL) from an MFT file, RFC 6486.
 * These are always relative to the directory in which "mft" sits.
 */
static void
queue_add_from_mft(int fd, struct entryq *q,
	const char *mft, const struct mftfile *file, size_t *eid)
{
	size_t	 	 sz = strlen(file->file);
	char		*cp, *nfile;
	enum rtype	 type = RTYPE_EOF;

	assert(strncmp(mft, BASE_DIR, strlen(BASE_DIR)) == 0);
	assert(sz > 4);

	/* Determine the file type, ignoring revocation lists. */

	if (strcasecmp(file->file + sz - 4, ".cer") == 0)
		type = RTYPE_CER;
	else if (strcasecmp(file->file + sz - 4, ".roa") == 0)
		type = RTYPE_ROA;
	else if (strcasecmp(file->file + sz - 4, ".crl") == 0)
		type = RTYPE_CRL;

	assert(type != RTYPE_EOF);

	/* Construct local path from filename. */

	sz = strlen(file->file) + strlen(mft);
	if ((nfile = calloc(sz + 1, 1)) == NULL)
		err(EXIT_FAILURE, NULL);

	/* We know this is BASE_DIR/host/module/... */

	strlcpy(nfile, mft, sz + 1);
	cp = strrchr(nfile, '/');
	assert(cp != NULL);
	cp++;
	*cp = '\0';
	strlcat(nfile, file->file, sz + 1);

	/*
	 * Since we're from the same directory as the MFT file, we know
	 * that the repository has already been loaded.
	 */

	entryq_add(fd, q, nfile, type,
		NULL, file->hash, NULL, 0, eid);
}

/*
 * Loops over queue_add_from_mft() for all files.
 */
static void
queue_add_from_mft_set(int fd, struct entryq *q,
	const struct mft *mft, size_t *eid)
{
	size_t	 i;

	for (i = 0; i < mft->filesz; i++)
		queue_add_from_mft(fd, q,
			mft->file, &mft->files[i], eid);
}

/*
 * Add a local TAL file (RFC 7730) to the queue of files to fetch.
 */
static void
queue_add_tal(int fd, struct entryq *q, const char *file, size_t *eid)
{
	char		*nfile;

	if ((nfile = strdup(file)) == NULL)
		err(EXIT_FAILURE, NULL);

	/* Not in a repository, so directly add to queue. */

	entryq_add(fd, q, nfile, RTYPE_TAL, 
		NULL, NULL, NULL, 0, eid);
}

/*
 * Add rsync URIs (CER) from a TAL file, RFC 7730.
 * Only use the first URI of the set.
 */
static void
queue_add_from_tal(int proc, int rsync, struct entryq *q,
	const struct tal *tal, struct repotab *rt, size_t *eid)
{
	char		  *nfile;
	const struct repo *repo;
	const char 	  *uri = tal->uri[0];

	assert(tal->urisz);
	uri = tal->uri[0];

	/* Look up the repository. */

	assert(rtype_resolve(uri) == RTYPE_CER);
	repo = repo_lookup(rsync, rt, uri);
	uri += 8 + strlen(repo->host) + 1 + strlen(repo->module) + 1;

	if (asprintf(&nfile, "%s/%s/%s/%s",
	    BASE_DIR, repo->host, repo->module, uri) < 0)
		err(EXIT_FAILURE, NULL);

	entryq_add(proc, q, nfile, RTYPE_CER,
		repo, NULL, tal->pkey, tal->pkeysz, eid);
}

/*
 * Add a manifest (MFT) or CRL found in an X509 certificate, RFC 6487.
 */
static void
queue_add_from_cert(int proc, int rsync, struct entryq *q,
	const char *uri, struct repotab *rt, size_t *eid)
{
	char		  *nfile;
	enum rtype	   type;
	const struct repo *repo;

	if ((type = rtype_resolve(uri)) == RTYPE_EOF)
		errx(EXIT_FAILURE, "%s: unknown file type", uri);
	if (type != RTYPE_MFT && type != RTYPE_CRL)
		errx(EXIT_FAILURE, "%s: invalid file type", uri);

	/* Look up the repository. */

	repo = repo_lookup(rsync, rt, uri);
	uri += 8 + strlen(repo->host) + 1 + strlen(repo->module) + 1;

	if (asprintf(&nfile, "%s/%s/%s/%s",
	    BASE_DIR, repo->host, repo->module, uri) < 0)
		err(EXIT_FAILURE, NULL);

	entryq_add(proc, q, nfile, type, repo, NULL, NULL, 0, eid);
}

static void
proc_child(int signal)
{

	/* Nothing: just discard. */
}

/*
 * Process used for synchronising repositories.
 * This simply waits to be told which repository to synchronise, then
 * does so.
 * It then responds with the identifier of the repo that it updated.
 * It only exits cleanly when fd is closed.
 * FIXME: this should use buffered output to prevent deadlocks, but it's
 * very unlikely that we're going to fill our buffer, so whatever.
 * FIXME: limit the number of simultaneous process.
 * Currently, an attacker can trivially specify thousands of different
 * repositories and saturate our system.
 */
static void
proc_rsync(const char *prog, int fd, int noop)
{
	size_t		  id, i, idsz = 0;
	ssize_t		  ssz;
	char		 *host = NULL, *mod = NULL, *uri = NULL, *dst = NULL;
	pid_t		  pid;
	char		 *args[32];
	int		  st, rc = 0;
	struct pollfd	  pfd;
	sigset_t	  mask, oldmask;
	struct rsyncproc *ids = NULL;

	pfd.fd = fd;
	pfd.events = POLLIN;

	if (sigemptyset(&mask) == -1)
		err(EXIT_FAILURE, NULL);
	if (signal(SIGCHLD, proc_child) == SIG_ERR)
		err(EXIT_FAILURE, NULL);
	if (sigaddset(&mask, SIGCHLD) == -1)
		err(EXIT_FAILURE, NULL);
	if (sigprocmask(SIG_BLOCK, &mask, &oldmask) == -1)
		err(EXIT_FAILURE, NULL);

	for (;;) {
		if (ppoll(&pfd, 1, NULL, &oldmask) == -1) {
			if (errno != EINTR)
				err(EXIT_FAILURE, "ppoll");

			/*
			 * If we've received an EINTR, it means that one
			 * of our children has exited and we can reap it
			 * and look up its identifier.
			 * Then we respond to the parent.
			 */

			if ((pid = waitpid(WAIT_ANY, &st, 0)) == -1)
				err(EXIT_FAILURE, "waitpid");

			if (!WIFEXITED(st)) {
				warnx("rsync did not exit");
				goto out;
			} else if (WEXITSTATUS(st) != EXIT_SUCCESS) {
				warnx("rsync failed");
				goto out;
			}

			for (i = 0; i < idsz; i++)
				if (ids[i].pid == pid)
					break;

			assert(i < idsz);
			io_simple_write(fd, &ids[i].id, sizeof(size_t));
			ids[i].pid = 0;
			ids[i].id = 0;
			continue;
		}

		/* 
		 * Read til the parent exits.
		 * That will mean that we can safely exit.
		 */

		if ((ssz = read(fd, &id, sizeof(size_t))) < 0)
			err(EXIT_FAILURE, "read");
		if (ssz == 0)
			break;

		/* Read host and module. */

		io_str_read(fd, &host);
		io_str_read(fd, &mod);

		if (noop) {
			io_simple_write(fd, &id, sizeof(size_t));
			free(host);
			free(mod);
			continue;
		}

		/* Create source and destination locations. */

		if (asprintf(&dst, "%s/%s/%s", BASE_DIR, host, mod) < 0)
			err(EXIT_FAILURE, NULL);
		if (asprintf(&uri, "rsync://%s/%s", host, mod) < 0)
			err(EXIT_FAILURE, NULL);

		/* Run process itself, wait for exit, check error. */

		if ((pid = fork()) == -1)
			err(EXIT_FAILURE, "fork");

		if (pid == 0) {
			i = 0;
			args[i++] = (char *)prog;
			args[i++] = "-r";
			args[i++] = "-l";
			args[i++] = "-t";
			args[i++] = "--delete";
			args[i++] = uri;
			args[i++] = dst;
			args[i] = NULL;
			execvp(args[0], args);
			err(EXIT_FAILURE, "%s: execvp", prog);
		}

		/* Augment the list of running processes. */

		for (i = 0; i < idsz; i++) 
			if (ids[i].pid == 0) {
				ids[i].id = id;
				ids[i].pid = pid;
				break;
			}

		if (i == idsz) {
			ids = reallocarray(ids, idsz + 1, 
				sizeof(struct rsyncproc));
			if (ids == NULL)
				err(EXIT_FAILURE, NULL);
			ids[idsz].id = id;
			ids[idsz].pid = pid;
			idsz++;
		}

		/* Clean up temporary values. */

		free(mod);
		free(dst);
		free(host);
		free(uri);
	}
	rc = 1;
out:

	/* No need for these to be hanging around. */

	for (i = 0; i < idsz; i++)
		if (ids[i].pid > 0)
			kill(ids[i].pid, SIGTERM);

	free(ids);
	exit(rc ? EXIT_SUCCESS : EXIT_FAILURE);
	/* NOTREACHED */
}

/*
 * Process responsible for parsing and validating content.
 * All this process does is wait to be told about a file to parse, then
 * it parses it and makes sure that the data being returned is fully
 * validated and verified.
 * The process will exit cleanly only when fd is closed.
 */
static void
proc_parser(int fd, int force, int norev)
{
	struct tal	*tal;
	struct cert	*cert;
	struct mft	*mft;
	struct roa	*roa;
	struct crl	*crl;
	struct entry	*entp;
	struct entryq	 q;
	int		 rc = 0, c;
	struct pollfd	 pfd;
	char		*b = NULL;
	size_t		 i, bsz = 0, bmax = 0, bpos = 0, authsz = 0;
	ssize_t		 ssz;
	X509		*x509;
	struct auth	*auths = NULL;

	TAILQ_INIT(&q);

	pfd.fd = fd;
	pfd.events = POLLIN;

	io_socket_nonblocking(pfd.fd);

	for (;;) {
		if (poll(&pfd, 1, INFTIM) < 0)
			err(EXIT_FAILURE, "poll");
		if ((pfd.revents & (POLLERR|POLLNVAL)))
			errx(EXIT_FAILURE, "poll: bad descriptor");
		
		/* If the parent closes, return immediately. */

		if ((pfd.revents & POLLHUP))
			break;

		/*
		 * Start with read events.
		 * This means that the parent process is sending us
		 * something we need to parse.
		 * We don't actually parse it til we have space in our
		 * outgoing buffer for responding, though.
		 */

		if ((pfd.revents & POLLIN)) {
			io_socket_blocking(fd);
			entp = calloc(1, sizeof(struct entry));
			if (entp == NULL)
				err(EXIT_FAILURE, NULL);
			entry_read_req(fd, entp);
			TAILQ_INSERT_TAIL(&q, entp, entries);
			pfd.events |= POLLOUT;
			io_socket_nonblocking(fd);
		}

		if (!(pfd.revents & POLLOUT))
			continue;

		/*
		 * If we have a write buffer, then continue trying to
		 * push it all out.
		 * When it's all pushed out, reset it and get ready to
		 * continue sucking down more data.
		 */

		if (bsz) {
			assert(bpos < bmax);
			if ((ssz = write(fd, b + bpos, bsz)) < 0)
				err(EXIT_FAILURE, "write");
			bpos += ssz;
			bsz -= ssz;
			if (bsz)
				continue;
			bpos = bsz = 0;
		}

		/*
		 * If there's nothing to parse, then stop waiting for
		 * the write signal.
		 */

		if (TAILQ_EMPTY(&q)) {
			pfd.events &= ~POLLOUT;
			continue;
		}

		entp = TAILQ_FIRST(&q);
		assert(entp != NULL);

		entry_buffer_resp(&b, &bsz, &bmax, entp);

		switch (entp->type) {
		case RTYPE_TAL:
			assert(!entp->has_dgst);
			if ((tal = tal_parse(entp->uri)) == NULL)
				goto out;
			tal_buffer(&b, &bsz, &bmax, tal);
			tal_free(tal);
			break;
		case RTYPE_CER:
			/* 
			 * Certificates are from manifests or TALs.
			 * In the former case, the certificates have
			 * digests and infer the signer from the SKI
			 * record of the certificate.
			 * In the latter case, we're given the public
			 * key from the TAL itself.
			 */

			assert(entp->has_dgst || entp->has_pkey);
			x509 = NULL;
			cert = cert_parse(&x509, entp->uri,
				entp->has_dgst ? entp->dgst : NULL);
			if (cert == NULL)
				goto out;
			assert(x509 != NULL);
			c = entp->has_pkey ?
				x509_auth_selfsigned_cert(x509, 
					entp->uri, &auths, &authsz,
					entp->pkey, entp->pkeysz, cert) :
				x509_auth_signed_cert(x509,
					entp->uri, &auths, &authsz, cert);
			X509_free(x509);
			if (!c) {
				cert_free(cert);
				goto out;
			}
			cert_buffer(&b, &bsz, &bmax, cert);
			/*
			 * Don't free the certificate here because we're
			 * going to cache it in the "auths" array.
			 */
			break;
		case RTYPE_MFT:
			assert(!entp->has_dgst);
			if ((mft = mft_parse(&x509, entp->uri, force)) == NULL)
				goto out;
			c = x509_auth_signed_mft
				(x509, entp->uri, &auths, &authsz, mft);
			X509_free(x509);
			if (!c) {
				mft_free(mft);
				goto out;
			}
			mft_buffer(&b, &bsz, &bmax, mft);
			mft_free(mft);
			break;
		case RTYPE_CRL:
			if (norev)
				break;
			crl = crl_parse(entp->uri, 
				entp->has_dgst ? entp->dgst : NULL);
			if (crl == NULL)
				goto out;
			crl_buffer(&b, &bsz, &bmax, crl);
			crl_free(crl);
			break;
		case RTYPE_ROA:
			assert(entp->has_dgst);
			roa = roa_parse(&x509, entp->uri, entp->dgst);
			if (roa == NULL)
				goto out;
			
			/*
			 * If the ROA isn't valid, we accept it anyway
			 * and depend upon the code around roa_read() to
			 * check the "invalid" field itself.
			 */

			x509_auth_signed_roa(x509, 
				entp->uri, &auths, &authsz, roa);
			X509_free(x509);
			roa_buffer(&b, &bsz, &bmax, roa);
			roa_free(roa);
			break;
		default:
			abort();
		}

		TAILQ_REMOVE(&q, entp, entries);
		entry_free(entp);
	}

	rc = 1;
out:
	while ((entp = TAILQ_FIRST(&q)) != NULL) {
		TAILQ_REMOVE(&q, entp, entries);
		entry_free(entp);
	}

	for (i = 0; i < authsz; i++) {
		free(auths[i].fn);
		free(auths[i].ski);
		EVP_PKEY_free(auths[i].pkey);
		cert_free(auths[i].cert);
	}

	free(auths);
	exit(rc ? EXIT_SUCCESS : EXIT_FAILURE);
}

/*
 * Process parsed content.
 * For non-ROAs, we grok for more data.
 * For ROAs, we want to extract the valid/invalid info.
 */
static void
entry_process(int norev, int proc, int rsync, struct stats *st,
	struct entryq *q, const struct entry *ent, struct repotab *rt,
	size_t *eid)
{
	struct tal	*tal = NULL;
	struct cert	*cert = NULL;
	struct mft	*mft = NULL;
	struct roa	*roa = NULL;
	struct crl	*crl = NULL;
	char		 buf[64];
	size_t		 i;

	switch (ent->type) {
	case RTYPE_TAL:
		st->tals++;
		tal = tal_read(proc);
		queue_add_from_tal(proc, rsync, q, tal, rt, eid);
		break;
	case RTYPE_CER:
		st->certs++;
		cert = cert_read(proc);
		if (cert->mft != NULL)
			queue_add_from_cert(proc, rsync, 
				q, cert->mft, rt, eid);
		if (cert->crl != NULL)
			queue_add_from_cert(proc, rsync, 
				q, cert->crl, rt, eid);
		break;
	case RTYPE_MFT:
		st->mfts++;
		mft = mft_read(proc);
		if (mft->stale)
			st->mfts_stale++;
		queue_add_from_mft_set(proc, q, mft, eid);
		break;
	case RTYPE_CRL:
		if (norev)
			break;
		st->crls++;
		crl = crl_read(proc);
		break;
	case RTYPE_ROA:
		st->roas++;
		roa = roa_read(proc);
		if (roa->invalid) {
			st->roas_invalid++;
			break;
		}
		for (i = 0; i < roa->ipsz; i++) {
			ip_addr_print(&roa->ips[i].addr, 
				roa->ips[i].afi, buf, sizeof(buf));
			printf("%s ", buf);
			if (roa->ips[i].maxlength)
				printf("maxlength %zu ", roa->ips[i].maxlength);
			printf("source-as %" PRIu32 "\n", roa->asid);
		}
		break;
	default:
		abort();
	}

	tal_free(tal);
	mft_free(mft);
	roa_free(roa);
	cert_free(cert);
	crl_free(crl);
}

int
main(int argc, char *argv[])
{
	int		 rc = 0, c, proc, st, rsync,
			 fl = SOCK_STREAM | SOCK_CLOEXEC, noop = 0,
			 force = 0, norev = 0;
	size_t		 i, j, eid = 1;
	pid_t		 procpid, rsyncpid;
	int		 fd[2];
	struct entryq	 q;
	struct entry	*ent;
	struct pollfd	 pfd[2];
	struct repotab	 rt;
	struct stats	 stats;
	const char	*rsync_prog = "openrsync";

	/* Main pledge. */

	if (pledge("stdio rpath proc exec", NULL) == -1)
		err(EXIT_FAILURE, "pledge");

	while ((c = getopt(argc, argv, "e:fnrv")) != -1) 
		switch (c) {
		case 'e':
			rsync_prog = optarg;
			break;
		case 'f':
			force = 1;
			break;
		case 'n':
			noop = 1;
			break;
		case 'r':
			norev = 1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			goto usage;
		}

	argv += optind;
	if ((argc -= optind) == 0)
		goto usage;

	/* Initialise SSL, errors, and our structures. */

	SSL_library_init();
	SSL_load_error_strings();

	memset(&rt, 0, sizeof(struct repotab));
	memset(&stats, 0, sizeof(struct stats));
	TAILQ_INIT(&q);

	/* 
	 * Create the file reader as a jailed child process.
	 * It will be responsible for reading all of the files (ROAs,
	 * manifests, certificates, etc.) and returning contents.
	 */

	if (socketpair(AF_UNIX, fl, 0, fd) == -1)
		err(EXIT_FAILURE, "socketpair");
	if ((procpid = fork()) == -1)
		err(EXIT_FAILURE, "fork");

	if (procpid == 0) {
		close(fd[1]);
		if (pledge("stdio rpath", NULL) == -1)
			err(EXIT_FAILURE, "pledge");
		proc_parser(fd[0], force, norev);
		/* NOTREACHED */
	} 

	close(fd[0]);
	proc = fd[1];

	/*
	 * Create a process that will do the rsync'ing.
	 * This process is responsible for making sure that all the
	 * repositories referenced by a certificate manifest (or the
	 * TAL) exists and has been downloaded.
	 */

	if (socketpair(AF_UNIX, fl, 0, fd) == -1) 
		err(EXIT_FAILURE, "socketpair");
	if ((rsyncpid = fork()) == -1) 
		err(EXIT_FAILURE, "fork");

	if (rsyncpid == 0) {
		close(fd[1]);
		if (pledge("stdio proc exec", NULL) == -1)
			err(EXIT_FAILURE, "pledge");

		/* If -n, we don't exec. */

		if (noop && pledge("stdio", NULL) == -1)
			err(EXIT_FAILURE, "pledge");
		proc_rsync(rsync_prog, fd[0], noop);
		/* NOTREACHED */
	}

	close(fd[0]);
	rsync = fd[1];

	assert(rsync != proc);

	/*
	 * The main process drives the top-down scan to leaf ROAs using
	 * data downloaded by the rsync process and parsed by the
	 * parsing process.
	 */

	if (pledge("stdio", NULL) == -1)
		err(EXIT_FAILURE, "pledge");

	/*
	 * Prime the process with our TAL file.
	 * This will contain (hopefully) links to our manifest and we
	 * can get the ball rolling.
	 */

	for (i = 0; i < (size_t)argc; i++)
		queue_add_tal(proc, &q, argv[i], &eid);

	pfd[0].fd = rsync;
	pfd[1].fd = proc;
	pfd[0].events = pfd[1].events = POLLIN;

	while (!TAILQ_EMPTY(&q)) {
		/*
		 * We want to be nonblocking while we wait for the
		 * ability to read or write, but blocking when we
		 * actually talk to the subprocesses.
		 */

		io_socket_nonblocking(pfd[0].fd);
		io_socket_nonblocking(pfd[1].fd);

		if ((c = poll(pfd, 2, 10000)) < 0)
			err(EXIT_FAILURE, "poll");
		
		/* Debugging: print some statistics if we stall. */

		if (c == 0) {
			for (i = j = 0; i < rt.reposz; i++)
				if (!rt.repos[i].loaded)
					j++;
			logx("timeout: %zu pending repos", j);
			j = 0;
			TAILQ_FOREACH(ent, &q, entries)
				j++;
			logx("timeout: %zu pending entries", j);
			continue;
		}

		if ((pfd[0].revents & (POLLERR|POLLNVAL)) ||
		    (pfd[1].revents & (POLLERR|POLLNVAL)))
			errx(EXIT_FAILURE, "poll: bad fd");
		if ((pfd[0].revents & POLLHUP) ||
		    (pfd[1].revents & POLLHUP))
			errx(EXIT_FAILURE, "poll: hangup");

		/* Reenable blocking. */

		io_socket_blocking(pfd[0].fd);
		io_socket_blocking(pfd[1].fd);

		/* 
		 * Check the rsync process.
		 * This means that one of our modules has completed
		 * downloading and we can flush the module requests into
		 * the parser process.
		 */

		if ((pfd[0].revents & POLLIN)) {
			io_simple_read(rsync, &i, sizeof(size_t));
			assert(i < rt.reposz);
			assert(!rt.repos[i].loaded);
			rt.repos[i].loaded = 1;
			logx("%s/%s/%s: loaded", BASE_DIR,
				rt.repos[i].host, rt.repos[i].module);
			stats.repos++;
			entryq_flush(proc, &q, &rt.repos[i]);
		}

		/* 
		 * The parser has finished something for us.
		 * Dequeue these one by one.
		 */

		if ((pfd[1].revents & POLLIN)) {
			ent = entryq_next(proc, &q);
			entry_process(norev, proc, rsync,
				&stats, &q, ent, &rt, &eid);
			if (verbose > 1)
				fprintf(stderr, "%s\n", ent->uri);
			entry_free(ent);
		}
	}

	assert(TAILQ_EMPTY(&q));
	logx("all files parsed: exiting");
	rc = 1;

	/*
	 * For clean-up, close the input for the parser and rsync
	 * process.
	 * This will cause them to exit, then we reap them.
	 */

	close(proc);
	close(rsync);

	if (waitpid(procpid, &st, 0) == -1)
		err(EXIT_FAILURE, "waitpid");
	if (!WIFEXITED(st) || WEXITSTATUS(st) != EXIT_SUCCESS) {
		warnx("parser process exited abnormally");
		rc = 0;
	}
	if (waitpid(rsyncpid, &st, 0) == -1)
		err(EXIT_FAILURE, "waitpid");
	if (!WIFEXITED(st) || WEXITSTATUS(st) != EXIT_SUCCESS) {
		warnx("rsync process exited abnormally");
		rc = 0;
	}

	logx("Routes: %zu (%zu invalid)", stats.roas, stats.roas_invalid);
	logx("Certificates: %zu", stats.certs);
	logx("Trust anchor locators: %zu", stats.tals);
	logx("Manifests: %zu (%zu stale)", stats.mfts, stats.mfts_stale);
	logx("Certificate revocation lists: %zu", stats.crls);
	logx("Repositories: %zu", stats.repos);

	/* Memory cleanup. */

	for (i = 0; i < rt.reposz; i++) {
		free(rt.repos[i].host);
		free(rt.repos[i].module);
	}
	free(rt.repos);
	ERR_free_strings();
	return rc ? EXIT_SUCCESS : EXIT_FAILURE;

usage:
	fprintf(stderr, "usage: %s [-fnrv] "
		"[-e rsync_prog] tal ...\n", getprogname());
	return EXIT_FAILURE;
}
