"""

General help:

to run from the commandline:

  python -m pyfooware.ddns godaddy

run with -h for a list of options


GoDaddy help:

to update GoDaddy DNS, first create the file $HOME/.godaddyrc with the
following three properties:

    username=myuser
    password=mypass
    domains=domain1.com,domain2.org

the following updates GoDaddy and logs output to syslog (good for cron)

  python -m pyfooware.ddns godaddy -L

"""

import network
import os.path
import sys
import syslog

class DDNSError(Exception):
    
    def __init__(self, message, error=None):
        self.message = message
        self.error = error

    def __repr__(self):
        return self.message

    def __str__(self):
        return self.message

class DNSProvider(object):

    def __init__(self, syslog_ident):
        if syslog_ident:
            self.syslogging_on = True
            syslog.openlog(syslog_ident, facility=syslog.LOG_USER)
        else:
            self.syslogging_on = False

    def update(self):
        pass

    def log(self, message):
        print message
        if self.syslogging_on:
            syslog.syslog(syslog.LOG_ALERT, message)

    def error(self, message):
        if self.logging_on:
            print >> sys.stderr, message
        if self.syslogging_on:
            syslog.syslog(syslog.LOG_ALERT, message)


class GoDaddy(DNSProvider):
    """
    sample ~/.godaddyrc

    username=myuser
    password=mypass
    hosts=@.domain1.com,www.domain2.org,...
    """

    def __init__(self, config_path=None, syslog_ident=None):
        DNSProvider.__init__(self, syslog_ident)
        self.config_path = config_path
        if not self.config_path:
            self.config_path = os.path.expanduser("~/.godaddyrc")
        self._init_from_config()

    def _init_from_config(self):
        props = {}
        lnbr = 0
        try:
            for line in open(self.config_path):
                lnbr += 1
                line = line.strip()
                i = line.find("#")
                if i >= 0:
                    line = line[:i]
                if not line:
                    continue
                name, value = line.split("=")
                props[name] = value
        except ValueError as e:
            msg = "invalid config value [line %s]: %s" % (lnbr, line)
            self.error(msg)
            raise DDNSError(msg)
        except Exception as e:
            msg =  "error reading %s (%s)" % (self.config_path, `e`)
            self.error(msg)
            raise DDNSError(msg, e)
        self.username = props.get("username", None)
        if not self.username:
            msg = "no godaddy username configured"
            self.error(msg)
            raise DDNSError(msg)
        self.password = props.get("password", None)
        if not self.password:
            msg = "no godaddy password configured"
            self.error(msg)
            raise DDNSError(msg)
        self.hosts = filter(lambda d: d != '', props.get("hosts", "").split(","))
        if not self.hosts:
            msg = "no godaddy hosts configured"
            self.error(msg)
            raise DDNSError(msg)

    def update(self):
        try:
            wan_ip = network.Network().get_wan_ip()
        except Exception as e:
            raise DDNSError('error getting WAN IP', e)
        self.log("router wan ip is " + wan_ip)
        godaddy = pygodaddy.GoDaddyClient()
        if not godaddy.login(self.username, self.password):
            msg = "godaddy login failure for " + self.username
            self.error(msg)
            raise DDNSError(msg)
        for host in self.hosts:
            name, domain = host.split(".", 1)
            recs = godaddy.find_dns_records(domain)
            if recs:
                for rec in recs:
                    if rec.hostname != name:
                        continue
                    if rec.value == wan_ip:
                        self.log("%s already set to %s, skipping" % (host, wan_ip))
                    else:
                        self.log("updating %s from %s to %s" %
                                (host, rec.value, wan_ip))
                        dns_entry = domain if name == "@" else host
                        if not godaddy.update_dns_record(dns_entry, wan_ip):
                            self.log("failed to update %s dns record" % dns_entry)
                    break
                else:
                    self.log("no record found for %s" % host)
            else:
                self.log("no records for %s" % host)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("provider",
            metavar="provider",
            help="dns provider name")
    parser.add_argument("-l", "--log",
            dest="logging",
            action="store_true",
            help="log to syslog")
    parser.add_argument("-i", "--ident",
            metavar="name",
            dest="syslog_ident",
            nargs="?",
            help="syslog identifier (default: ddns_<provider>)")
    args = parser.parse_args(sys.argv[1:])
    try:
        if args.provider == "godaddy":
            try:
                import pygodaddy
            except ImportError as e:
                msg = "pygodaddy module not found: " + \
                        "https://pygodaddy.readthedocs.org/"
                print >> sys.stderr, msg
                raise DDNSError(msg)
            if args.logging:
                ident = args.syslog_ident
                if not args.syslog_ident:
                    ident = "ddns_" + args.provider
            else:
                ident=None
            provider = GoDaddy(syslog_ident=ident)
        else:
            msg = "unknown dns provider: " + args.provider
            print >> sys.stderr, msg
            raise DDNSError(msg)
        provider.update()
    except DDNSError as e:
        print "fatal error:", e
        sys.exit(1)
