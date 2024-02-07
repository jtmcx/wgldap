#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <net/if_wg.h>
#include <resolv.h>
#include "aldap.h"

#define WG_BASE64_KEY_LEN 44

struct config {
	struct aldap_url *url;
};

static char*
strip_comment(char *s)
{
	char *p;
	if ((p = strchr(s, '#')) != NULL)
		*p = '\0';
	return s;
}

static void
parse_config_line(struct config *cfg, char *line)
{
	const char *p;
	p = strtok(line, " \t\n");
	if (p == NULL) {
		return;
	} else if (strcmp(p, "host") == 0) {
		if ((p = strtok(NULL, " \t\n")) == NULL)
			;
	} else {
		errx(1, "config: parse error at key '%s'", p);
	}
}

void
parse_config(struct config *cfg, const char *path)
{
	FILE *f;
	ssize_t len;
	size_t buflen = 0;
	char *buf = NULL;

	if ((f = fopen(path, "r")) == NULL)
		err(1, "open %s", path);
	while ((len = getline(&buf, &buflen, f)) != -1) {
		printf("%s", strip_comment(buf));		
	}
}

int
parse_aip(struct wg_aip_io *aip, const char *str)
{
	int cidr;

	cidr = inet_net_pton(AF_INET, str, &aip->a_ipv4, sizeof(aip->a_ipv4));
	if (cidr != -1) {
		aip->a_af = AF_INET;
		goto out;
	}
	cidr = inet_net_pton(AF_INET6, str, &aip->a_ipv6, sizeof(aip->a_ipv6));
	if (cidr != -1) {
		aip->a_af = AF_INET6;
		goto out;
	}
	warnx("bad address: %s", str);
	return -1;
out:
	aip->a_cidr = cidr;
	return 0;
}

int
parse_key(uint8_t *dst, const char *src)
{
	int r;
	uint8_t tmp[WG_KEY_LEN];

	if (strlen(src) != WG_BASE64_KEY_LEN) {
		warn("key: invalid length\n");
		return -1;
	}
	if (b64_pton(src, tmp, sizeof(tmp)) != sizeof(tmp)) {
		warn("key: invalid base64\n");
		return -1;
	}
	memcpy(dst, tmp, WG_KEY_LEN);
	return 0;
}

static int
connect_tcp(struct aldap_url *url)
{
	struct addrinfo ai, *res, *res0;
	char port[6];
	int rc, fd;

	assert(url);
	memset(&ai, 0, sizeof(ai));
	ai.ai_family = AF_UNSPEC;
	ai.ai_socktype = SOCK_STREAM;
	ai.ai_protocol = IPPROTO_TCP;
	snprintf(port, sizeof(port), "%u", url->port);
	if ((rc = getaddrinfo(url->host, port, &ai, &res0)) != 0) {
		warnx("getaddrinfo: %s", gai_strerror(rc));
		return -1;
	}
	for (res = res0; res; res = res->ai_next, fd = -1) {
		if ((fd = socket(res->ai_family, res->ai_socktype,
				res->ai_protocol)) == -1)
			continue;
		if (connect(fd, res->ai_addr, res->ai_addrlen) >= 0)
			break;
		close(fd);
	}
	freeaddrinfo(res0);
	return fd;	/* will be -1 on error */
}

static int
connect_unix(struct aldap_url *url)
{
	int fd;
	struct sockaddr_un un;

	assert(url);
	assert(url->protocol == LDAPI);
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	if (strlcpy(un.sun_path, url->host, sizeof(un.sun_path))
			>= sizeof(un.sun_path)) {
		warnx("socket path too long");
		return -1;
	}
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		warn("socket");
		return -1;
	}
	if (connect(fd, (struct sockaddr *)&un, sizeof(un)) == -1) {
		warn("connect %s", url->host);
		return -1;
	}
	return fd;
}

static int
do_tls(struct aldap *aldap, struct aldap_url *url, const char *capath)
{
	struct aldap_message *m;
	struct tls_config *tls_config;
	const char *errstr;
	int code;

	switch (url->protocol) {
	case LDAPTLS:
		if (aldap_req_starttls(aldap) == -1) {
			warnx("STARTTLS failed");
			return -1;
		}
		if ((m = aldap_parse(aldap)) == NULL) {
			warnx("failed to parse STARTTLS response");
			return -1;
		}
		if (aldap->msgid != m->msgid ||
			(code = aldap_get_resultcode(m)) != LDAP_SUCCESS)
		{
			warnx("STARTTLS failed %d", code);	
			aldap_freemsg(m);
			return -1;
		}
		aldap_freemsg(m);
		/* fallthrough */
	case LDAPS:
		if ((tls_config = tls_config_new()) == NULL) {
			warnx("TLS config failed");
			return -1;
		}
		if (capath == NULL)
			capath = tls_default_ca_cert_file();
		if (tls_config_set_ca_file(tls_config, capath) == -1) {
			warnx("unable to set CA %s", capath);
			return -1;
		}
		if (aldap_tls(aldap, tls_config, url->host) < 0) {
			aldap_get_errno(aldap, &errstr);
			warnx("TLS failed: %s", errstr);
			tls_config_free(tls_config);
			return -1;
		}
		break;
	}
	return 0;
}

static int
do_bind(struct aldap *aldap, char *binddn, char *secret)
{
	struct aldap_message *m;
	const char *errstr;
	int code;

	if (aldap_bind(aldap, binddn, secret) == -1) {
		warnx("LDAP bind failed");
		return -1;
	}
	if ((m = aldap_parse(aldap)) == NULL) {
		warnx("failed to parse bind response");
		return -1;
	}
	if (aldap->msgid != m->msgid ||
		(code = aldap_get_resultcode(m)) != LDAP_SUCCESS)
	{
		warnx("bind failed %d", code);	
		aldap_freemsg(m);
		return -1;
	}
	aldap_freemsg(m);
	return 0;
}

static struct aldap*
ldapc_connect(struct aldap_url *url, const char *capath)
{
	struct aldap *aldap;
	int fd = -1;

	switch (url->protocol) {
	case LDAP:
	case LDAPTLS:
	case LDAPS:
		fd = connect_tcp(url);
		break;
	case LDAPI:
		fd = connect_unix(url);
		break;
	}	
	if (fd == -1) {
		warnx("failed to connect to LDAP host");
		return NULL;
	}
	if ((aldap = aldap_init(fd)) == NULL) {
		warnx("failed to initialize LDAP client");
		return NULL;
	}	
	if (do_tls(aldap, url, capath) == -1) {
		warnx("failed to start LDAP TLS");
		aldap_close(aldap);
		return NULL;
	}
	return aldap;
}


int
main(int argc, char *argv[])
{
	struct aldap *aldap;
	struct aldap_url url;

	memset(&url, 0, sizeof(url));	/* needed for `filter' */
	if (aldap_parse_url(argv[1], &url) == -1)
		errx(1, "ldap: bad url");

	if (url.protocol == -1)
		url.protocol = LDAP;
	if (url.port == 0) {
		switch (url.protocol) {
		case LDAP:
		case LDAPTLS:
			url.port = LDAP_PORT;
			break;
		case LDAPS:
			url.port = LDAPS_PORT;
			break;
		}
	}

	printf("proto:\t%d\n", url.protocol);
	printf("host:\t%s\n", url.host);
	printf("port:\t%d\n", url.port);
	printf("dn:\t%s\n", url.dn);
	printf("scope:\t%d\n", url.scope);
	printf("filter:\t%s\n", url.filter);
	printf("buffer:\t%s\n", url.buffer);

	/* TODO: capath */
	if ((aldap = ldapc_connect(&url, NULL)) == NULL)
		errx(1, "wow");

	const char *errstr;
	struct aldap_page_control *pg = NULL;
	int rc = aldap_search(aldap, url.dn, url.scope, url.filter,
			NULL, 0, 0, 0, pg);
	if (rc == -1) {
		aldap_get_errno(aldap, &errstr);
		warnx("LDAP search failed: %s", errstr);
		return 1;  /* TODO */
	}

	return 0;
}

	/*
	size_t last_size;
	const char *ifname = "wg0";

	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	struct wg_data_io wgdata;

	strlcpy(wgdata.wgd_name, ifname, sizeof(wgdata.wgd_name));
	wgdata.wgd_size = 0;
	wgdata.wgd_interface = NULL;
	for (last_size = wgdata.wgd_size;; last_size = wgdata.wgd_size) {
		if (ioctl(sock, SIOCGWG, (caddr_t)&wgdata) < 0)
			err(1, "SIOCGWG %s", ifname);
		if (last_size >= wgdata.wgd_size)
			break;
		wgdata.wgd_interface = realloc(wgdata.wgd_interface,
			wgdata.wgd_size);
		if (wgdata.wgd_interface == NULL)
			err(1, "realloc");
	}
	*/
