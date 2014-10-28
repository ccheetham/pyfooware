import urllib2

class Network(object):

    def get_wan_ip(self):
        page = urllib2.urlopen("http://checkip.dyndns.org/").read()
        marker = "IP Address: "
        start = page.find(marker) + len(marker)
        end = page.find("<", start)
        return page[start:end]


if __name__ == "__main__":
    net = Network()
    print "wan ip:", net.get_wan_ip()
