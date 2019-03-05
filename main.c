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

struct	stats {
	size_t	 tals;
	size_t	 mfts;
	size_t	 mfts_stale;
	size_t	 certs;
	size_t	 roas;
};

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
	int		   has_dgst; /* whether dgst is specified */
	unsigned char	   dgst[SHA256_DIGEST_LENGTH]; /* optional */
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
 * Read a queue entry from the descriptor.
 * The entry's contents must be freed.
 */
static void
entry_read(int fd, int verb, struct entry *ent)
{

	memset(ent, 0, sizeof(struct entry));
	simple_read(fd, verb, &ent->type, sizeof(enum rtype));
	str_read(fd, verb, &ent->uri);
	simple_read(fd, verb, &ent->has_dgst, sizeof(int));
	simple_read(fd, verb, ent->dgst, sizeof(ent->dgst));
}

/*
 * Look up a repository, queueing it for discovery if not found.
 */
static const struct repo *
repo_lookup(int fd, int verb, struct repotab *rt, const char *uri)
{
	const char	*host, *mod;
	size_t		 hostsz, modsz, i;
	struct repo	*rp;

	if (!rsync_uri_parse(verb, &host, &hostsz,
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

	simple_write(fd, &i, sizeof(size_t));
	str_write(fd, verb, rp->host);
	str_write(fd, verb, rp->module);
	return rp;
}

/*
 * Read the next entry from the parser process, removing it from the
 * queue of pending requests in the process.
 * This always returns a valid entry.
 */
static struct entry *
entryq_next(int fd, int verb, struct entryq *q)
{
	struct entry	 ent;
	struct entry	*entp;

	entry_read(fd, verb, &ent);

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
 * Like entry_write() but into a buffer.
 */
static void
entry_buffer(char **b, size_t *bsz, size_t *bmax,
	int verb, const struct entry *ent)
{

	simple_buffer(b, bsz, bmax, &ent->type, sizeof(enum rtype));
	str_buffer(b, bsz, bmax, verb, ent->uri);
	simple_buffer(b, bsz, bmax, &ent->has_dgst, sizeof(int));
	simple_buffer(b, bsz, bmax, ent->dgst, sizeof(ent->dgst));
}

/*
 * Write the queue entry.
 */
static void
entry_write(int fd, int verb, const struct entry *ent)
{

	simple_write(fd, &ent->type, sizeof(enum rtype));
	str_write(fd, verb, ent->uri);
	simple_write(fd, &ent->has_dgst, sizeof(int));
	simple_write(fd, ent->dgst, sizeof(ent->dgst));
}

/*
 * Scan through all queued requests and see which ones are in the given
 * repo, then flush those into the parser process.
 */
static void
entryq_flush(int fd, int verb,
	struct entryq *q, const struct repo *repo)
{
	struct entry	*p;

	TAILQ_FOREACH(p, q, entries) {
		if (p->repo < 0 || repo->id != (size_t)p->repo)
			continue;
		LOG(verb, "%s: flushing after repository load", p->uri);
		entry_write(fd, verb, p);
	}
}

/*
 * Add the heap-allocated file to the queue for processing.
 */
static void
entryq_add(int fd, int verb, struct entryq *q,
	char *file, enum rtype type, const struct repo *rp,
	const unsigned char *dgst)
{
	struct entry	*p;

	if ((p = calloc(1, sizeof(struct entry))) == NULL)
		err(EXIT_FAILURE, NULL);

	p->type = type;
	p->uri = file;
	p->repo = NULL != rp ? rp->id : -1;
	p->has_dgst = dgst != NULL;
	if (p->has_dgst)
		memcpy(p->dgst, dgst, sizeof(p->dgst));
	TAILQ_INSERT_TAIL(q, p, entries);

	if (NULL != rp && 0 == rp->loaded)
		LOG(verb, "%s: delaying til queue flush", p->uri);

	/* 
	 * Write to the queue if there's no repo or the repo has already
	 * been loaded.
	 */

	if (NULL == rp || rp->loaded)
		entry_write(fd, verb, p);
}

/*
 * Add a file (CER, ROA, or CRL) from an MFT file, RFC 6486.
 * These are always relative to the directory in which "mft" sits.
 */
static void
queue_add_from_mft(int fd, int verb, struct entryq *q,
	const char *mft, const struct mftfile *file)
{
	size_t	 	 sz = strlen(file->file);
	char		*cp, *nfile;
	enum rtype	 type = RTYPE_EOF;

	assert(strncmp(mft, BASE_DIR, strlen(BASE_DIR)) == 0);
	assert(sz > 4);

	/* Determine the file type, ignoring revocation lists. */

	if (strcasecmp(file->file + sz - 4, ".crl") == 0)
		type = RTYPE_CRL;
	else if (strcasecmp(file->file + sz - 4, ".cer") == 0)
		type = RTYPE_CER;
	else if (strcasecmp(file->file + sz - 4, ".roa") == 0)
		type = RTYPE_ROA;

	assert(type != RTYPE_EOF);
	if (type == RTYPE_CRL)
		return;

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

	entryq_add(fd, verb, q, nfile, type, NULL, file->hash);
	LOG(verb, "%s: added: %s", file->file, nfile);
}

/*
 * Loops over queue_add_from_mft() for all files.
 */
static void
queue_add_from_mft_set(int fd, int verb,
	struct entryq *q, const struct mft *mft)
{
	size_t	 i;

	for (i = 0; i < mft->filesz; i++)
		queue_add_from_mft(fd, verb, q, mft->file, &mft->files[i]);
}

/*
 * Add a local TAL file (RFC 7730) to the queue of files to fetch.
 */
static void
queue_add_tal(int fd, int verb, struct entryq *q, const char *file)
{
	char		*nfile;

	if ((nfile = strdup(file)) == NULL)
		err(EXIT_FAILURE, NULL);

	/* Not in a repository, so directly add to queue. */

	entryq_add(fd, verb, q, nfile, RTYPE_TAL, NULL, NULL);
	LOG(verb, "%s: added", file);
}

/*
 * Add rsync URIs (CER) from a TAL file, RFC 7730.
 */
static void
queue_add_from_tal(int proc, int rsync, int verb,
	struct entryq *q, const char *uri, struct repotab *rt)
{
	char		  *nfile;
	const struct repo *repo;

	/* Look up the repository. */

	assert(rtype_resolve(verb, uri) == RTYPE_CER);

	repo = repo_lookup(rsync, verb, rt, uri);
	uri += 8 + strlen(repo->host) + 1 + strlen(repo->module) + 1;

	if (asprintf(&nfile, "%s/%s/%s/%s",
	    BASE_DIR, repo->host, repo->module, uri) < 0)
		err(EXIT_FAILURE, NULL);

	entryq_add(proc, verb, q, nfile, RTYPE_CER, repo, NULL);
	LOG(verb, "%s: added: %s", uri, nfile);
}

/*
 * Loops over queue_add_from_tal() for all files.
 */
static void
queue_add_from_tal_set(int proc, int rsync, int verb,
	struct entryq *q, const struct tal *tal, struct repotab *rt)
{
	size_t	 i;

	for (i = 0; i < tal->urisz; i++)
		queue_add_from_tal(proc, rsync, verb, q, tal->uri[i], rt);
}

/*
 * Add a manifest (MFT) found in an X509 certificate, RFC 6487.
 */
static void
queue_add_from_cert(int proc, int rsync, int verb,
	struct entryq *q, const char *uri, struct repotab *rt)
{
	char		  *nfile;
	enum rtype	   type;
	const struct repo *repo;

	if ((type = rtype_resolve(verb, uri)) == RTYPE_EOF)
		errx(EXIT_FAILURE, "%s: unknown file type", uri);
	if (type != RTYPE_MFT)
		errx(EXIT_FAILURE, "%s: invalid file type", uri);

	/* Look up the repository. */

	repo = repo_lookup(rsync, verb, rt, uri);
	uri += 8 + strlen(repo->host) + 1 + strlen(repo->module) + 1;

	if (asprintf(&nfile, "%s/%s/%s/%s",
	    BASE_DIR, repo->host, repo->module, uri) < 0)
		err(EXIT_FAILURE, NULL);

	entryq_add(proc, verb, q, nfile, type, repo, NULL);
	LOG(verb, "%s: added: %s", uri, nfile);
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

		str_read(fd, verb, &host);
		str_read(fd, verb, &mod);

		/* Create source and destination locations. */

		if (asprintf(&dst, "%s/%s/%s", BASE_DIR, host, mod) < 0)
			err(EXIT_FAILURE, NULL);
		if (asprintf(&uri, "rsync://%s/%s", host, mod) < 0)
			err(EXIT_FAILURE, NULL);

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
		simple_write(fd, &id, sizeof(size_t));
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
	int		 rc = 0, vverb = 0;
	struct pollfd	 pfd;
	char		*b = NULL;
	size_t		 bsz = 0, bmax = 0, bpos = 0;
	ssize_t		 ssz;

	TAILQ_INIT(&q);

	pfd.fd = fd;
	pfd.events = POLLIN;
	LOG(verb, "parser process starting");

	socket_nonblocking(pfd.fd, verb);

	for (;;) {
		if (poll(&pfd, 1, INFTIM) < 0)
			err(EXIT_FAILURE, "poll");
		if ((pfd.revents & (POLLERR|POLLNVAL)))
			errx(EXIT_FAILURE, "poll: bad descriptor");
		
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
			socket_blocking(fd, verb);
			entry_read(fd, verb, &ent);
			entp = calloc(1, sizeof(struct entry));
			if (entp == NULL)
				err(EXIT_FAILURE, NULL);
			*entp = ent;
			TAILQ_INSERT_TAIL(&q, entp, entries);
			pfd.events |= POLLOUT;
			socket_nonblocking(fd, verb);
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

		entry_buffer(&b, &bsz, &bmax, verb, entp);

		switch (entp->type) {
		case RTYPE_TAL:
			assert(!entp->has_dgst);
			tal = tal_parse(vverb, entp->uri);
			if (tal == NULL) {
				WARNX1(verb, "tal_parse");
				goto out;
			}
			tal_buffer(&b, &bsz, &bmax, verb, tal);
			tal_free(tal);
			break;
		case RTYPE_CER:
			x = cert_parse(vverb, NULL, entp->uri,
				entp->has_dgst ? entp->dgst : NULL);
			if (x == NULL) {
				WARNX1(verb, "cert_parse");
				goto out;
			}
			cert_buffer(&b, &bsz, &bmax, verb, x);
			cert_free(x);
			break;
		case RTYPE_MFT:
			assert(!entp->has_dgst);
			mft = mft_parse(vverb, NULL, entp->uri);
			if (mft == NULL) {
				WARNX1(verb, "mft_parse");
				goto out;
			}
			mft_buffer(&b, &bsz, &bmax, verb, mft);
			mft_free(mft);
			break;
		case RTYPE_ROA:
			assert(entp->has_dgst);
			roa = roa_parse(NULL, entp->uri, entp->dgst);
			if (roa == NULL) {
				WARNX1(verb, "roa_parse");
				goto out;
			}
			roa_buffer(&b, &bsz, &bmax, roa);
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
entry_process(int proc, int rsync, int verb, struct stats *st,
	struct entryq *q, const struct entry *ent, struct repotab *rt)
{
	struct tal	*tal = NULL;
	struct cert	*cert = NULL;
	struct mft	*mft = NULL;
	struct roa	*roa = NULL;
	int		 rc = 0;

	switch (ent->type) {
	case RTYPE_TAL:
		st->tals++;
		LOG(verb, "%s: handling tal file", ent->uri);
		tal = tal_read(proc, verb);
		queue_add_from_tal_set(proc, rsync, verb, q, tal, rt);
		rc = 1;
		break;
	case RTYPE_CER:
		st->certs++;
		LOG(verb, "%s: handling certificate file", ent->uri);
		cert = cert_read(proc, verb);
		if (cert->mft != NULL)
			queue_add_from_cert(proc, rsync, verb, q, cert->mft, rt);
		rc = 1;
		break;
	case RTYPE_MFT:
		st->mfts++;
		LOG(verb, "%s: handling mft file", ent->uri);
		mft = mft_read(proc, verb);
		if (mft->stale)
			st->mfts_stale++;
		queue_add_from_mft_set(proc, verb, q, mft);
		rc = 1;
		break;
	case RTYPE_ROA:
		st->roas++;
		LOG(verb, "%s: handling roa file", ent->uri);
		roa = roa_read(proc);
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
	struct stats	  stats;

	while ((c = getopt(argc, argv, "v")) != -1) 
		switch (c) {
		case 'v':
			verb++;
			break;
		default:
			goto usage;
		}

	argv += optind;
	if ((argc -= optind) == 0)
		goto usage;

	/* Initialise SSL, errors, and our structures. */

	SSL_library_init();
	rpki_log_open();

	memset(&rt, 0, sizeof(struct repotab));
	memset(&stats, 0, sizeof(struct stats));
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

	for (i = 0; i < (size_t)argc; i++)
		queue_add_tal(proc, verb, &q, argv[i]);

	pfd[0].fd = rsync;
	pfd[1].fd = proc;
	pfd[0].events = pfd[1].events = POLLIN;

	while (!TAILQ_EMPTY(&q)) {
		/*
		 * We want to be nonblocking while we wait for the
		 * ability to read or write, but blocking when we
		 * actually talk to the subprocesses.
		 */

		socket_nonblocking(pfd[0].fd, verb);
		socket_nonblocking(pfd[1].fd, verb);

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

		socket_blocking(pfd[0].fd, verb);
		socket_blocking(pfd[1].fd, verb);

		/* 
		 * Check the rsync process.
		 * This means that one of our modules has completed
		 * downloading and we can flush the module requests into
		 * the parser process.
		 */

		if ((pfd[0].revents & POLLIN)) {
			simple_read(rsync, verb, &i, sizeof(size_t));
			if (i >= rt.reposz) {
				WARNX(verb, "repo identifier out of range");
				goto out;
			} 
			assert(!rt.repos[i].loaded);
			rt.repos[i].loaded = 1;
			LOG(verb, "%s/%s/%s: loaded", BASE_DIR,
				rt.repos[i].host, rt.repos[i].module);
			entryq_flush(proc, verb, &q, &rt.repos[i]);
		}

		/* 
		 * The parser has finished something for us.
		 * Dequeue these one by one.
		 */

		if ((pfd[1].revents & POLLIN)) {
			ent = entryq_next(proc, verb, &q);
			if (!entry_process(proc, rsync, 
			    verb, &stats, &q, ent, &rt)) {
				WARNX1(verb, "entry_process");
				goto out;
			}
			if (verb)
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
	
	fprintf(stderr, 
		"Route announcements: %zu\n"
		"Certificates: %zu\n"
		"Trust anchor locators: %zu\n"
		"Manifests: %zu (%zu stale)\n",
		stats.roas, stats.certs, stats.tals, stats.mfts,
		stats.mfts_stale);
	return rc ? EXIT_SUCCESS : EXIT_FAILURE;

usage:
	fprintf(stderr, "usage: %s [-v] tal ...\n", getprogname());
	return EXIT_FAILURE;
}
