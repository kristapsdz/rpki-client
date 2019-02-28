#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <fts.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "extern.h"

/*
 * Base directory for where we'll look for all media.
 */
#define	BASE_DIR "/tmp/rpki-client"

struct	repo {
	char	*host;
	char	*module;
	int	 loaded;
	size_t	 id;
};

struct	repotab {
	struct repo	*repos;
	size_t		 reposz;
};

/*
 * An entry (MFT, ROA, certificate, etc.) that needs to be downloaded
 * and parsed.
 */
struct	entry {
	enum rtype	   type; /* type of entry (not RTYPE_EOF/CRL) */
	char		  *uri; /* file or rsync:// URI */
	ssize_t		   repo; /* repo index or <0 if w/o repo */
	TAILQ_ENTRY(entry) entries;
};

TAILQ_HEAD(entryq, entry);

/*
 * Mark that our subprocesses will never return.
 */
static void	 proc_parser(int, int) __attribute__((noreturn));
static void	 proc_rsync(int, int) __attribute__((noreturn));

/*
 * Resolve the media type of a resource by looking at its suffice.
 * Returns the type of RTYPE_EOF if not found.
 */
static enum rtype
rtype_resolve(int verb, const char *uri)
{
	enum rtype	 rp;

	(void)rsync_uri_parse(verb, NULL,
		NULL, NULL, NULL, NULL, NULL, &rp, uri);

	return rp;
}

/*
 * Read into a queue entry.
 * Returns >0 on success, <0 on failure, 0 on eof.
 * On success, the entry's memory must be freed.
 */
static int
queue_read(int fd, int verb, struct entry *ent)
{
	ssize_t	 ssz;

	memset(ent, 0, sizeof(struct entry));

	/* Use read() to catch if we're EOF. */

	if ((ssz = read(fd, &ent->type, sizeof(enum rtype))) < 0) {
		WARN("read");
		return -1;
	} else if (ssz == 0)
		return 0;

	if (!str_read(fd, verb, &ent->uri))
		WARNX1(verb, "str_read");
	else
		return 1;
	return 0;
}

/*
 * Look up a repository, queueing it for discovery if not found.
 * Returns zero on failure, non-zero otherwise.
 * On success, "repo" is filled in.
 */
static int
repo_lookup(int fd, int verb, struct repotab *rt,
	const char *uri, const struct repo **repo)
{
	const char	*host, *mod;
	size_t		 hostsz, modsz, i;
	struct repo	*rp;
	void		*pp;

	if (!rsync_uri_parse(verb, &host, &hostsz,
	    &mod, &modsz, NULL, NULL, NULL, uri)) {
		WARNX1(verb, "rsync_uri_parse");
		return 0;
	}

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
		*repo = &rt->repos[i];
		return 1;
	}
	
	pp = reallocarray(rt->repos, rt->reposz + 1, sizeof(struct repo));
	if (pp == NULL) {
		WARN("reallocarray");
		return 0;
	}
	rt->repos = pp;
	rp = &rt->repos[rt->reposz++];
	memset(rp, 0, sizeof(struct repo));
	rp->id = rt->reposz - 1;

	if ((rp->host = strndup(host, hostsz)) == NULL) {
		WARN("strndup");
		return 0;
	} else if ((rp->module = strndup(mod, modsz)) == NULL) {
		WARN("strndup");
		return 0;
	}

	i = rt->reposz - 1;

	if (!simple_write(fd, &i, sizeof(size_t))) {
		WARNX1(verb, "simple_write");
		return 0;
	} else if (!str_write(fd, verb, rp->host)) {
		WARNX1(verb, "buf_write");
		return 0;
	} else if (!str_write(fd, verb, rp->module)) {
		WARNX1(verb, "buf_write");
		return 0;
	}

	*repo = rp;
	return 1;
}

static struct entry *
queue_dequeue(int fd, int verb, struct entryq *q)
{
	struct entry	 ent;
	struct entry	*entp;
	int		 c;

	if ((c = queue_read(fd, verb, &ent)) < 0) {
		WARNX1(verb, "queue_read");
		return NULL;
	} else if (c == 0) {
		WARNX1(verb, "queue_read: unexpected end of file");
		return NULL;
	}

	TAILQ_FOREACH(entp, q, entries)
		if (entp->type == ent.type &&
	 	    0 == strcmp(entp->uri, ent.uri)) {
			TAILQ_REMOVE(q, entp, entries);
			break;
		}

	assert(entp != NULL);
	free(ent.uri);
	return entp;
}

/*
 * Like queue_write() but into a buffer.
 */
static int
queue_buffer(char **b, size_t *bsz, size_t *bmax,
	int verb, const struct entry *ent)
{

	if (!simple_buffer(b, bsz, bmax, &ent->type, sizeof(enum rtype)))
		WARNX1(verb, "simple_buffer");
	else if (!str_buffer(b, bsz, bmax, verb, ent->uri))
		WARNX1(verb, "str_buffer");
	else
		return 1;

	return 0;
}

/*
 * Write the queue entry.
 * Returns zero on failure, non-zero on success.
 */
static int
queue_write(int fd, int verb, const struct entry *ent)
{

	if (!simple_write(fd, &ent->type, sizeof(enum rtype)))
		WARNX1(verb, "simple_write");
	else if (!str_write(fd, verb, ent->uri))
		WARNX1(verb, "str_write");
	else
		return 1;

	return 0;
}

/*
 * Scan through all queued requests and see which ones are in the given
 * repo, then flush those into the parser process.
 * Returns zero on failure, non-zero on success.
 */
static int
queue_flush(int fd, int verb,
	struct entryq *q, const struct repo *repo)
{
	struct entry	*p;

	TAILQ_FOREACH(p, q, entries) {
		if (p->repo < 0 || repo->id != (size_t)p->repo)
			continue;
		LOG(verb, "%s: flushing after repository load", p->uri);
		if (!queue_write(fd, verb, p)) {
			WARNX1(verb, "queue_write");
			return 0;
		}
	}
	return 1;
}

/*
 * Add the heap-allocated file to the queue for processing.
 * Returns zero on failure, non-zero on success.
 */
static int
queue_add(int fd, int verb, struct entryq *q,
	char *file, enum rtype type, const struct repo *rp)
{
	struct entry	*p;

	if ((p = calloc(1, sizeof(struct entry))) == NULL) {
		ERR("calloc");
		return 0;
	}
	p->type = type;
	p->uri = file;
	p->repo = NULL != rp ? rp->id : -1;
	TAILQ_INSERT_TAIL(q, p, entries);

	if (NULL != rp && 0 == rp->loaded)
		LOG(verb, "%s: delaying til queue flush", p->uri);

	/* 
	 * Write to the queue if there's no repo or the repo has already
	 * been loaded.
	 */

	if ((NULL == rp || rp->loaded) && !queue_write(fd, verb, p)) {
		WARNX1(verb, "queue_write");
		return 0;
	}
	return 1;
}

/*
 * Add a file (CER, ROA, or CRL) from an MFT file, RFC 6486.
 * These are always relative to the directory in which "mft" sits.
 * Return zero on failure, non-zero on success.
 */
static int
queue_add_from_mft(int fd, int verb, struct entryq *q,
	const char *mft, const char *file)
{
	size_t	 	 sz = strlen(file);
	char		*cp, *nfile;
	enum rtype	 type = RTYPE_EOF;

	assert(strncmp(mft, BASE_DIR, strlen(BASE_DIR)) == 0);
	assert(sz > 4);

	/* Determine the file type, ignoring revocation lists. */

	if (strcasecmp(file + sz - 4, ".crl") == 0)
		type = RTYPE_CRL;
	else if (strcasecmp(file + sz - 4, ".cer") == 0)
		type = RTYPE_CER;
	else if (strcasecmp(file + sz - 4, ".roa") == 0)
		type = RTYPE_ROA;

	assert(type != RTYPE_EOF);
	if (type == RTYPE_CRL)
		return 1;

	/* Construct local path from filename. */

	sz = strlen(file) + strlen(mft);
	if ((nfile = calloc(sz + 1, 1)) == NULL) {
		WARN("calloc");
		return 0;
	}

	/* We know this is BASE_DIR/host/module/... */

	strlcpy(nfile, mft, sz + 1);
	cp = strrchr(nfile, '/');
	assert(cp != NULL);
	cp++;
	*cp = '\0';
	strlcat(nfile, file, sz + 1);

	/*
	 * Since we're from the same directory as the MFT file, we know
	 * that the repository has already been loaded.
	 */

	if (!queue_add(fd, verb, q, nfile, type, NULL)) {
		WARNX1(verb, "queue_add");
		free(nfile);
		return 0;
	}
	LOG(verb, "%s: added: %s", file, nfile);
	return 1;
}

/*
 * Loops over queue_add_from_mft() for all files.
 */
static int
queue_add_from_mft_set(int fd, int verb,
	struct entryq *q, const struct mft *mft)
{
	size_t	 i;

	for (i = 0; i < mft->filesz; i++)
		if (!queue_add_from_mft(fd, verb,
		    q, mft->file, mft->files[i])) {
			WARNX1(verb, "queue_add_from_mft");
			return 0;
		}

	return 1;
}

/*
 * Add a local TAL file (RFC 7730) to the queue of files to fetch.
 * The "file" path has not been sanitised at all.
 * Returns zero on failure, non-zero on success.
 */
static int
queue_add_tal(int fd, int verb, struct entryq *q, const char *file)
{
	char		*nfile;
	size_t		 sz = strlen(file);

	if (sz <= 4 || strcasecmp(file + sz - 4, ".tal")) {
		WARNX(verb, "%s: invalid file type", file);
		return 0;
	} else if ((nfile = strdup(file)) == NULL) {
		ERR("strdup");
		return 0;
	}

	/* Not in a repository, so directly add to queue. */

	if (!queue_add(fd, verb, q, nfile, RTYPE_TAL, NULL)) {
		WARNX1(verb, "queue_add");
		free(nfile);
		return 0;
	}
	LOG(verb, "%s: added", file);
	return 1;
}

/*
 * Add rsync URIs (CER) from a TAL file, RFC 7730.
 * Returns zero on failure, non-zero on success.
 */
static int
queue_add_from_tal(int proc, int rsync, int verb,
	struct entryq *q, const char *uri, struct repotab *rt)
{
	char		  *nfile;
	const struct repo *repo;

	/* Look up the repository. */

	assert(rtype_resolve(verb, uri) == RTYPE_CER);

	if (!repo_lookup(rsync, verb, rt, uri, &repo)) {
		WARNX1(verb, "repo_lookup");
		return 0;
	} 

	uri += 8 + strlen(repo->host) + 1 + strlen(repo->module) + 1;

	if (asprintf(&nfile, "%s/%s/%s/%s",
	    BASE_DIR, repo->host, repo->module, uri) < 0) {
		WARN("asprintf");
		return 0;
	} else if (!queue_add(proc, verb, q, nfile, RTYPE_CER, repo)) {
		WARNX1(verb, "queue_add");
		free(nfile);
		return 0;
	}
	LOG(verb, "%s: added: %s", uri, nfile);
	return 1;
}

/*
 * Loops over queue_add_from_tal() for all files.
 */
static int
queue_add_from_tal_set(int proc, int rsync, int verb,
	struct entryq *q, const struct tal *tal, struct repotab *rt)
{
	size_t	 i;

	for (i = 0; i < tal->urisz; i++)
		if (!queue_add_from_tal(proc, rsync,
		    verb, q, tal->uri[i], rt)) {
			WARNX1(verb, "queue_add_from_tal");
			return 0;
		}

	return 1;
}

/*
 * Add a manifest (MFT) found in an X509 certificate, RFC 6487.
 * Returns zero on failure, non-zero on success.
 */
static int
queue_add_from_cert(int proc, int rsync, int verb,
	struct entryq *q, const char *uri, struct repotab *rt)
{
	char		  *nfile;
	enum rtype	   type;
	const struct repo *repo;

	/* FIXME: assert as cert_parse() should guarantee. */

	if ((type = rtype_resolve(verb, uri)) == RTYPE_EOF) {
		WARNX(verb, "%s: unknown file type", uri);
		return 0;
	} else if (type != RTYPE_MFT) {
		WARNX(verb, "%s: invalid file type", uri);
		return 0;
	}

	/* Look up the repository. */

	if (!repo_lookup(rsync, verb, rt, uri, &repo)) {
		WARNX1(verb, "repo_lookup");
		return 0;
	} 
	
	uri += 8 + strlen(repo->host) + 1 + strlen(repo->module) + 1;

	if (asprintf(&nfile, "%s/%s/%s/%s",
	    BASE_DIR, repo->host, repo->module, uri) < 0) {
		WARN("asprintf");
		return 0;
	} else if (!queue_add(proc, verb, q, nfile, type, repo)) {
		WARNX1(verb, "queue_add");
		free(nfile);
		return 0;
	}
	LOG(verb, "%s: added: %s", uri, nfile);
	return 1;
}

/*
 * Process used for synchronising repositories.
 * This simply waits to be told which repository to synchronise, then
 * does so.
 * It then responds with the identifier of the repo that it updated.
 * It only exits cleanly when fd is closed.
 * FIXME: this should use buffered output to prevent deadlocks.
 */
static void
proc_rsync(int fd, int verb)
{
	size_t	 id, i;
	ssize_t	 ssz;
	char	*host = NULL, *mod = NULL, *uri = NULL, *dst = NULL;
	pid_t	 pid;
	char	*args[32];
	int	 st, rc = 0, c;

	LOG(verb, "rsync process starting");

	for (;;) {
		/* 
		 * Read til the parent exits.
		 * That will mean that we can safely exit.
		 */

		if ((ssz = read(fd, &id, sizeof(size_t))) < 0) {
			WARN("read");
			goto out;
		} else if (ssz == 0) {
			LOG(verb, "rsync process exiting");
			break;
		}

		/* Read host and module. */

		if (!str_read(fd, verb, &host)) {
			WARNX1(verb, "str_read");
			goto out;
		} else if (!str_read(fd, verb, &mod)) {
			WARNX1(verb, "str_read");
			goto out;
		}

		/* Create source and destination locations. */

		if (asprintf(&dst, "%s/%s/%s", BASE_DIR, host, mod) < 0) {
			WARN("asprintf");
			dst = NULL;
			goto out;
		} else if (asprintf(&uri, "rsync://%s/%s", host, mod) < 0) {
			WARN("asprintf");
			uri = NULL;
			goto out;
		}

		/* Run process itself, wait for exit, check error. */

		if ((pid = fork()) == -1) {
			WARN("fork");
			goto out;
		} else if (pid == 0) {
			i = 0;
			args[i++] = "openrsync";
			args[i++] = "-r";
			args[i++] = "-l";
			args[i++] = "-t";
			args[i++] = "-v";
			args[i++] = "--delete";
			args[i++] = uri;
			args[i++] = dst;
			args[i] = NULL;
			execvp(args[0], args);
			ERR("openrsync: execvp");
		}

		if (waitpid(pid, &st, 0) == -1) {
			WARN("waitpid");
			goto out;
		} else if (!WIFEXITED(st)) {
			WARNX(verb, "openrsync did not exit");
			goto out;
		} else if ((c = WEXITSTATUS(st)) != EXIT_SUCCESS) {
			WARNX(verb, "openrsync failed (%d)", c);
			goto out;
		}

		free(mod);
		free(dst);
		free(host);
		free(uri);
		mod = dst = host = uri = NULL;
		if (!simple_write(fd, &id, sizeof(size_t))) {
			WARNX1(verb, "simple_write");
			goto out;
		}
	}

	rc = 1;
out:
	free(host);
	free(mod);
	free(uri);
	free(dst);
	exit(rc ? EXIT_SUCCESS : EXIT_FAILURE);
}

/*
 * Process responsible for parsing content.
 * All this process does is wait to be told about a file to parse, then
 * it parses it.
 * The process will exit cleanly only when fd is closed.
 */
static void
proc_parser(int fd, int verb)
{
	struct tal	*tal;
	struct cert	*x;
	struct mft	*mft;
	struct roa	*roa;
	struct entry	 ent;
	struct entry	*entp;
	struct entryq	 q;
	int		 c, rc = 0, vverb = 0;
	struct pollfd	 pfd;
	char		*b = NULL;
	size_t		 bsz = 0, bmax = 0, bpos = 0;
	ssize_t		 ssz;

	TAILQ_INIT(&q);

	pfd.fd = fd;
	pfd.events = POLLIN;
	LOG(verb, "parser process starting");

	if (!socket_nonblocking(pfd.fd, verb)) {
		WARNX1(verb, "socket_nonblocking");
		goto out;
	}

	for (;;) {
		if (poll(&pfd, 1, INFTIM) < 0) {
			WARN("poll");
			goto out;
		} else if ((pfd.revents & (POLLERR|POLLNVAL))) {
			WARNX(verb, "poll: bad fd");
			goto out;
		} 
		
		/* If the parent closes, return immediately. */

		if ((pfd.revents & POLLHUP)) {
			LOG(verb, "parser process exiting");
			break;
		}

		/*
		 * Start with read events.
		 * This means that the parent process is sending us
		 * something we need to parse.
		 * We don't actually parse it til we have space in our
		 * outgoing buffer for responding, though.
		 */

		if ((pfd.revents & POLLIN)) {
			if (!socket_blocking(fd, verb)) {
				WARNX1(verb, "socket_blocking");
				goto out;
			}
			if ((c = queue_read(fd, verb, &ent)) < 0) {
				WARNX1(verb, "queue_read");
				goto out;
			} else if (c == 0) {
				WARNX(verb, "queue_read: "
					"unexpected end of file");
				goto out;
			}

			entp = calloc(1, sizeof(struct entry));
			if (entp == NULL) {
				WARN("calloc");
				goto out;
			}
			*entp = ent;
			TAILQ_INSERT_TAIL(&q, entp, entries);
			pfd.events |= POLLOUT;
			if (!socket_nonblocking(fd, verb)) {
				WARNX1(verb, "socket_nonblocking");
				goto out;
			}
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
			if ((ssz = write(fd, b + bpos, bsz)) < 0) {
				WARN("write");
				goto out;
			}
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

		if (!queue_buffer(&b, &bsz, &bmax, verb, entp)) {
			WARNX1(verb, "queue_buffer");
			goto out;
		}

		switch (entp->type) {
		case RTYPE_TAL:
			tal = tal_parse(vverb, entp->uri);
			if (tal == NULL) {
				WARNX1(verb, "tal_parse");
				goto out;
			}
			if (!tal_buffer(&b, &bsz, &bmax, verb, tal)) {
				WARNX1(verb, "tal_buffer");
				goto out;
			}
			tal_free(tal);
			break;
		case RTYPE_CER:
			x = cert_parse(vverb, NULL, entp->uri);
			if (x == NULL) {
				WARNX1(verb, "cert_parse");
				goto out;
			}
			if (!cert_buffer(&b, &bsz, &bmax, verb, x)) {
				WARNX1(verb, "cert_buffer");
				goto out;
			}
			cert_free(x);
			break;
		case RTYPE_MFT:
			mft = mft_parse(vverb, NULL, entp->uri);
			if (mft == NULL) {
				WARNX1(verb, "mft_parse");
				goto out;
			}
			if (!mft_buffer(&b, &bsz, &bmax, verb, mft)) {
				WARNX1(verb, "mft_buffer");
				goto out;
			}
			mft_free(mft);
			break;
		case RTYPE_ROA:
			roa = roa_parse(vverb, NULL, entp->uri);
			if (roa == NULL) {
				WARNX1(verb, "roa_parse");
				goto out;
			}
			if (!roa_buffer(&b, &bsz, &bmax, verb, roa)) {
				WARNX1(verb, "roa_buffer");
				goto out;
			}
			roa_free(roa);
			break;
		default:
			abort();
		}

		TAILQ_REMOVE(&q, entp, entries);
		free(entp->uri);
		free(entp);
	}

	rc = 1;
out:
	while ((entp = TAILQ_FIRST(&q)) != NULL) {
		TAILQ_REMOVE(&q, entp, entries);
		free(entp->uri);
		free(entp);
	}
	exit(rc ? EXIT_SUCCESS : EXIT_FAILURE);
}

/*
 * Process parsed content.
 * For non-ROAs, we grok for more data.
 * For ROAs, we want to extract the valid/invalid info.
 */
static int
queue_process(int proc, int rsync, int verb,
	struct entryq *q, const struct entry *ent, struct repotab *rt)
{
	struct tal	*tal = NULL;
	struct cert	*cert = NULL;
	struct mft	*mft = NULL;
	struct roa	*roa = NULL;
	int		 rc = 0;

	switch (ent->type) {
	case RTYPE_TAL:
		LOG(verb, "%s: handling tal file", ent->uri);
		if ((tal = tal_read(proc, verb)) == NULL) {
			WARNX1(verb, "tal_read");
			break;
		}
		if (!queue_add_from_tal_set(proc, rsync, verb, q, tal, rt)) {
			WARNX1(verb, "queue_add_from_tal_set");
			break;
		}
		rc = 1;
		break;
	case RTYPE_CER:
		LOG(verb, "%s: handling certificate file", ent->uri);
		if ((cert = cert_read(proc, verb)) == NULL) {
			WARNX1(verb, "cert_read");
			break;
		}
		if (cert->mft != NULL &&
		    !queue_add_from_cert(proc, rsync, verb, q, cert->mft, rt)) {
			WARNX1(verb, "queue_add_from_cert");
			break;
		}
		rc = 1;
		break;
	case RTYPE_MFT:
		LOG(verb, "%s: handling mft file", ent->uri);
		if ((mft = mft_read(proc, verb)) == NULL) {
			WARNX1(verb, "mft_read");
			break;
		}
		if (!queue_add_from_mft_set(proc, verb, q, mft)) {
			WARNX1(verb, "queue_add_from_mft_set");
			break;
		}
		rc = 1;
		break;
	case RTYPE_ROA:
		LOG(verb, "%s: handling roa file", ent->uri);
		if ((roa = roa_read(proc, verb)) == NULL) {
			WARNX1(verb, "roa_read");
			break;
		}
		rc = 1;
		break;
	default:
		abort();
	}

	tal_free(tal);
	mft_free(mft);
	roa_free(roa);
	cert_free(cert);
	return 1;
}

int
main(int argc, char *argv[])
{
	int		  rc = 0, c, verb = 0, proc, st, rsync,
			  fl = SOCK_STREAM | SOCK_CLOEXEC;
	size_t		  i;
	pid_t		  procpid, rsyncpid;
	int		  fd[2];
	struct entryq	  q;
	struct entry	 *ent;
	struct pollfd	  pfd[2];
	struct repotab	  rt;

	while ((c = getopt(argc, argv, "v")) != -1) 
		switch (c) {
		case 'v':
			verb++;
			break;
		default:
			goto usage;
		}

	argv += optind;
	if ((argc -= optind) != 1)
		goto usage;

	/* Initialise SSL, errors, and our structures. */

	SSL_library_init();
	rpki_log_open();

	memset(&rt, 0, sizeof(struct repotab));
	TAILQ_INIT(&q);

	/* 
	 * Create the file reader as a jailed child process.
	 * It will be responsible for reading all of the files (ROAs,
	 * manifests, certificates, etc.) and returning contents.
	 */

	if (socketpair(AF_UNIX, fl, 0, fd) == -1)
		ERR("socketpair");
	if ((procpid = fork()) == -1)
		ERR("fork");

	if (procpid == 0) {
		close(fd[1]);
		if (pledge("stdio rpath", NULL) == -1)
			ERR("pledge");
		proc_parser(fd[0], verb);
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
		ERR("socketpair");
	if ((rsyncpid = fork()) == -1) 
		ERR("fork");

	if (rsyncpid == 0) {
		close(fd[1]);
		if (pledge("stdio proc exec", NULL) == -1)
			ERR("pledge");
		proc_rsync(fd[0], verb);
		/* NOTREACHED */
	}

	close(fd[0]);
	rsync = fd[1];

	/*
	 * The main process drives the top-down scan to leaf ROAs using
	 * data downloaded by the rsync process and parsed by the
	 * parsing process.
	 */

	if (pledge("stdio", NULL) == -1)
		ERR("pledge");

	/*
	 * Prime the process with our TAL file.
	 * This will contain (hopefully) links to our manifest and we
	 * can get the ball rolling.
	 */

	if (!queue_add_tal(proc, verb, &q, argv[0])) {
		WARNX1(verb, "queue_add_tal");
		goto out;
	}

	pfd[0].fd = rsync;
	pfd[1].fd = proc;
	pfd[0].events = pfd[1].events = POLLIN;

	while (!TAILQ_EMPTY(&q)) {
		/*
		 * We want to be nonblocking while we wait for the
		 * ability to read or write, but blocking when we
		 * actually talk to the subprocesses.
		 */

		if (!socket_nonblocking(pfd[0].fd, verb)) {
			WARNX1(verb, "socket_nonblocking");
			goto out;
		} else if (!socket_nonblocking(pfd[1].fd, verb)) {
			WARNX1(verb, "socket_nonblocking");
			goto out;
		}

		if ((c = poll(pfd, 2, 10000)) < 0) {
			WARN("poll");
			goto out;
		} else if (c == 0) {
			LOG(verb, "stats: dumping...");
			for (i = 0; i < rt.reposz; i++) {
				if (rt.repos[i].loaded)
					continue;
				LOG(verb, "stats: %s/%s",
					rt.repos[i].host,
					rt.repos[i].module);
			}
			TAILQ_FOREACH(ent, &q, entries)
				LOG(verb, "stats: %s", ent->uri);
			continue;
		}

		if ((pfd[0].revents & (POLLERR|POLLNVAL)) ||
		    (pfd[1].revents & (POLLERR|POLLNVAL))) {
			WARNX(verb, "poll: bad fd");
			goto out;
		}
		if ((pfd[0].revents & POLLHUP) ||
		    (pfd[1].revents & POLLHUP)) {
			WARNX(verb, "poll: hangup");
			goto out;
		}

		/* Reenable blocking. */

		if (!socket_blocking(pfd[0].fd, verb)) {
			WARNX1(verb, "socket_blocking");
			goto out;
		} else if (!socket_blocking(pfd[1].fd, verb)) {
			WARNX1(verb, "socket_blocking");
			goto out;
		}

		/* 
		 * Check the rsync process.
		 * This means that one of our modules has completed
		 * downloading and we can flush the module requests into
		 * the parser process.
		 */

		if ((pfd[0].revents & POLLIN)) {
			if (!simple_read(rsync, verb, &i, sizeof(size_t))) {
				WARNX1(verb, "simple_read");
				goto out;
			} else if (i >= rt.reposz) {
				WARNX(verb, "repo identifier out of range");
				goto out;
			} 
			assert(!rt.repos[i].loaded);
			rt.repos[i].loaded = 1;
			LOG(verb, "%s/%s/%s: loaded", BASE_DIR,
				rt.repos[i].host, rt.repos[i].module);
			if (!queue_flush(proc, verb, &q, &rt.repos[i])) {
				WARNX1(verb, "queue_flush");
				goto out;
			}
		}

		/* 
		 * The parser has finished something for us.
		 * Dequeue these one by one.
		 */

		if ((pfd[1].revents & POLLIN)) {
			if ((ent = queue_dequeue(proc, verb, &q)) == NULL) {
				WARNX1(verb, "queue_dequeue");
				goto out;
			}
			if (!queue_process(proc, rsync, verb, &q, ent, &rt)) {
				WARNX1(verb, "queue_process");
				goto out;
			}
			fprintf(stderr, "%s\n", ent->uri);
			free(ent->uri);
			free(ent);
		}
	}

	assert(TAILQ_EMPTY(&q));
	LOG(verb, "all files parsed: exiting");
	rc = 1;
out:
	/*
	 * For clean-up, close the input for the parser and rsync
	 * process.
	 * This will cause them to exit, then we reap them.
	 */

	close(proc);
	close(rsync);

	if (waitpid(procpid, &st, 0) == -1)
		ERR("waitpid");
	if (!WIFEXITED(st) || WEXITSTATUS(st) != EXIT_SUCCESS) {
		WARNX(verb, "parser process exited abnormally");
		rc = 0;
	}
	if (waitpid(rsyncpid, &st, 0) == -1)
		ERR("waitpid");
	if (!WIFEXITED(st) || WEXITSTATUS(st) != EXIT_SUCCESS) {
		WARNX(verb, "rsync process exited abnormally");
		rc = 0;
	}

	/* Memory cleanup. */

	for (i = 0; i < rt.reposz; i++) {
		free(rt.repos[i].host);
		free(rt.repos[i].module);
	}
	free(rt.repos);

	rpki_log_close();
	return rc ? EXIT_SUCCESS : EXIT_FAILURE;

usage:
	fprintf(stderr, "usage: %s [-v] tal\n", getprogname());
	return EXIT_FAILURE;
}
