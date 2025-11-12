#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_link.h> /* XDP_FLAGS_* */

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

/* Names must match maps in dns_lb_kern.c */
#define MAP_BACKENDS     "backends"
#define MAP_BACKEND_CNT  "backend_count"
#define MAP_VIP          "vip_map"

struct backend_val {
	__u32 ip_be;
	__u16 port_be;
	__u16 pad;
};

struct backend_cfg {
	__u32 ip_be;
	__u16 port_be;
};

static int parse_config(const char *path, char *vip_str, size_t vip_sz,
			struct backend_cfg *backs, int max_backs, int *out_cnt)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "Failed to open config file %s: %s\n", path, strerror(errno));
		return -1;
	}
	char line[512];
	int in_backend = 0;
	int found_vip = 0;
	int count = 0;
	char ipbuf[128] = {0};
	int port = 53;

	while (fgets(line, sizeof(line), f)) {
		/* trim leading spaces */
		char *s = line;
		while (*s == ' ' || *s == '\t') s++;
		/* skip comments/empty */
		if (*s == '#' || *s == '/' || *s == '\n' || *s == '\0')
			continue;
		if (strstr(s, "global:") || strstr(s, "[global]")) {
			in_backend = 0;
			continue;
		}
		if (strstr(s, "backend:") || strstr(s, "[backend]")) {
			in_backend = 1;
			ipbuf[0] = 0;
			port = 53;
			continue;
		}
		if (strstr(s, "listen_address:")) {
			/* VIP: use listen_address as VIP */
			char *c = strchr(s, ':');
			if (c) {
				c++;
				while (*c == ' ' || *c == '\t' || *c == '"') c++;
				char *e = c;
				while (*e && *e != '"' && *e != '\r' && *e != '\n') e++;
				size_t n = (size_t)(e - c);
				if (n > 0 && n < vip_sz) {
					memcpy(vip_str, c, n);
					vip_str[n] = 0;
					found_vip = 1;
				}
			}
			continue;
		}

		if (in_backend) {
			if (strstr(s, "ip:")) {
				char *c = strchr(s, ':');
				if (c) {
					c++;
					while (*c == ' ' || *c == '\t' || *c == '"') c++;
					char *e = c;
					while (*e && *e != '"' && *e != '\r' && *e != '\n') e++;
					size_t n = (size_t)(e - c);
					if (n > 0 && n < sizeof(ipbuf)) {
						memcpy(ipbuf, c, n);
						ipbuf[n] = 0;
					}
				}
			} else if (strstr(s, "port:")) {
				char *c = strchr(s, ':');
				if (c) {
					port = atoi(c + 1);
					if (port <= 0 || port > 65535) port = 53;
				}
			}

			/* finalize backend when we have IP and see line end or next section soon. We accept loose parsing;
			 * push when both IP present and either EOF or next backend seen; for simplicity, push
			 * immediately when ip: is parsed (one-backend-per-block in provided config). */
			if (ipbuf[0] && count < max_backs) {
				struct backend_cfg *b = &backs[count++];
				struct in_addr ina;
				if (inet_pton(AF_INET, ipbuf, &ina) != 1) {
					fprintf(stderr, "Invalid backend IP: %s\n", ipbuf);
					count--;
				} else {
					b->ip_be = ina.s_addr;
					b->port_be = (__u16)htons((uint16_t)port);
				}
				ipbuf[0] = 0; /* avoid double-add */
			}
		}
	}
	fclose(f);
	*out_cnt = count;
	return found_vip ? 0 : -1;
}

static void usage(const char *p)
{
	fprintf(stderr,
		"Usage: %s --iface IFACE [--config ../config.txt] [--vip A.B.C.D]\n"
		"       Attaches XDP (generic/SKB mode) DNS LB program and populates maps.\n",
		p);
}

int main(int argc, char **argv)
{
	const char *iface = NULL;
	const char *config = "../config.txt";
	char vip_str[128] = {0};
	struct in_addr vip_addr = {0};
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--iface") && i + 1 < argc) {
			iface = argv[++i];
		} else if (!strcmp(argv[i], "--config") && i + 1 < argc) {
			config = argv[++i];
		} else if (!strcmp(argv[i], "--vip") && i + 1 < argc) {
			snprintf(vip_str, sizeof(vip_str), "%s", argv[++i]);
		} else {
			usage(argv[0]);
			return 1;
		}
	}
	if (!iface) {
		usage(argv[0]);
		return 1;
	}

	struct backend_cfg backs[64];
	int back_cnt = 0;
	if (vip_str[0] == 0) {
		if (parse_config(config, vip_str, sizeof(vip_str), backs, 64, &back_cnt) != 0) {
			fprintf(stderr, "Failed to parse VIP from %s; specify via --vip\n", config);
			return 1;
		}
	} else {
		/* still parse backends from config */
		if (parse_config(config, (char[1]){0}, 1, backs, 64, &back_cnt) != 0) {
			/* ignore error here if VIP provided; continue with backends we parsed (maybe zero) */
		}
	}
	if (inet_pton(AF_INET, vip_str, &vip_addr) != 1) {
		fprintf(stderr, "Invalid VIP: %s\n", vip_str);
		return 1;
	}

	int ifindex = if_nametoindex(iface);
	if (!ifindex) {
		fprintf(stderr, "Invalid iface %s: %s\n", iface, strerror(errno));
		return 1;
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Optional: silence libbpf logs unless error */
	libbpf_set_print(NULL);

	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	int prog_fd = -1;

	/* Try to open object from CWD; if that fails, try alongside executable */
	const char *obj_path = "dns_lb_kern.o";
	obj = bpf_object__open_file(obj_path, NULL);
	int err = libbpf_get_error(obj);
	if (err) {
		/* build path next to executable */
		char exe_path[512];
		ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
		if (n > 0) {
			exe_path[n] = 0;
			/* strip filename */
			char *slash = strrchr(exe_path, '/');
			if (slash) *slash = 0;
			char alt[1024];
			snprintf(alt, sizeof(alt), "%s/dns_lb_kern.o", exe_path);
			obj = bpf_object__open_file(alt, NULL);
			err = libbpf_get_error(obj);
		}
	}
	if (err) {
		fprintf(stderr, "Failed to open BPF object: %s\n", strerror(-err));
		return 1;
	}
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
		bpf_object__close(obj);
		return 1;
	}
	/* find XDP program (first one or by name) */
	prog = bpf_object__find_program_by_name(obj, "xdp_dns_lb");
	if (!prog) {
		fprintf(stderr, "Failed to find program xdp_dns_lb\n");
		bpf_object__close(obj);
		return 1;
	}
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "Failed to get program FD\n");
		bpf_object__close(obj);
		return 1;
	}

	/* Attach in generic (SKB) mode to avoid NIC offload dependency */
#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_UPDATE_IF_NOEXIST (1U << 0)
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif
	__u32 xdp_flags = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
	err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
	if (err) {
		fprintf(stderr, "bpf_xdp_attach failed on %s: %s\n", iface, strerror(-err));
		bpf_object__close(obj);
		return 1;
	}
	printf("Attached XDP (generic) to %s\n", iface);

	/* Populate maps */
	int map_fd_backends = bpf_object__find_map_fd_by_name(obj, MAP_BACKENDS);
	int map_fd_cnt = bpf_object__find_map_fd_by_name(obj, MAP_BACKEND_CNT);
	int map_fd_vip = bpf_object__find_map_fd_by_name(obj, MAP_VIP);
	if (map_fd_backends < 0 || map_fd_cnt < 0 || map_fd_vip < 0) {
		fprintf(stderr, "Failed to find required maps in object\n");
		goto err_detach;
	}

	__u32 zero = 0;
	__u32 cnt = back_cnt > 0 ? (unsigned)back_cnt : 0;
	if (bpf_map_update_elem(map_fd_cnt, &zero, &cnt, BPF_ANY) != 0) {
		fprintf(stderr, "Failed to set backend_count: %s\n", strerror(errno));
		goto err_detach;
	}

	if (bpf_map_update_elem(map_fd_vip, &zero, &vip_addr.s_addr, BPF_ANY) != 0) {
		fprintf(stderr, "Failed to set VIP map: %s\n", strerror(errno));
		goto err_detach;
	}

	for (int j = 0; j < back_cnt && j < 64; j++) {
		struct backend_val v = {
			.ip_be = backs[j].ip_be,
			.port_be = backs[j].port_be ? backs[j].port_be : htons(53),
			.pad = 0,
		};
		__u32 key = (unsigned)j;
		if (bpf_map_update_elem(map_fd_backends, &key, &v, BPF_ANY) != 0) {
			fprintf(stderr, "Failed to set backend %d: %s\n", j, strerror(errno));
			goto err_detach;
		}
	}

	printf("Configured VIP=%s with %d backend(s) from %s\n", vip_str, back_cnt, config);
	printf("Done.\n");
	return 0;

err_detach:
	bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
	bpf_object__close(obj);
	return 1;
}


