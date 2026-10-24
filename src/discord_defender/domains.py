"""Domain helpers shared by the link analyser and the blocklist.

We avoid pulling in the full Public Suffix List: we only need to know where the
"registrable" part of a hostname starts, so lookalike checks look at
``discord-nitro`` in ``discord-nitro.vercel.app`` instead of at ``vercel``.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

# Suffixes under which anyone can register their own name. Two groups:
# country second-level domains, and free hosting platforms that phishing kits
# love (every one of these shows up hundreds of times in the public scam feeds).
# fmt: off
MULTI_LABEL_SUFFIXES = frozenset(
    {
        # country second-level domains
        "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk",
        "com.au", "edu.au", "gov.au", "id.au", "net.au", "org.au",
        "ac.nz", "co.nz", "govt.nz", "org.nz",
        "ac.jp", "co.jp", "go.jp", "ne.jp", "or.jp",
        "ac.kr", "co.kr", "or.kr",
        "com.br", "edu.br", "gov.br", "net.br", "org.br",
        "com.cn", "edu.cn", "gov.cn", "net.cn", "org.cn",
        "com.mx", "edu.mx", "gob.mx", "org.mx",
        "ac.in", "co.in", "edu.in", "gov.in", "net.in", "org.in",
        "com.ar", "com.co", "com.de", "com.eg", "com.ge", "com.hk", "com.my", "com.ng",
        "com.ph", "com.pk", "com.pl", "com.sa", "com.sg", "com.tr", "com.tw", "com.ua",
        "com.vn", "co.id", "co.il", "co.za", "my.id",
        "com.ru", "net.ru", "org.ru", "pp.ru", "pp.ua", "ru.com",
        # free hosting and app platforms
        "000webhostapp.com", "appspot.com", "azurewebsites.net", "blogspot.com",
        "carrd.co", "cloudfront.net", "duckdns.org", "firebaseapp.com", "fleek.co",
        "fly.dev", "framer.app", "framer.website", "github.io", "gitlab.io", "glitch.me",
        "godaddysites.com", "herokuapp.com", "js.org", "myshopify.com", "netlify.app",
        "ngrok-free.app", "ngrok.app", "ngrok.io", "onrender.com", "pages.dev", "r2.dev",
        "railway.app", "readthedocs.io", "replit.app", "replit.dev", "repl.co", "rf.gd",
        "square.site", "surge.sh", "vercel.app", "web.app", "webflow.io", "weebly.com",
        "wixsite.com", "wordpress.com", "workers.dev",
    }
)
# fmt: on


def registered_domain(host: str) -> str:
    """Return the registrable domain: ``a.b.evil.co.uk`` -> ``evil.co.uk``."""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def self_and_parents(host: str) -> Iterator[str]:
    """Yield ``a.b.c.com``, ``b.c.com``, ``c.com`` - never a bare TLD."""
    labels = host.split(".")
    for i in range(len(labels) - 1):
        yield ".".join(labels[i:])


def in_domains(host: str, domains: Iterable[str] | frozenset[str]) -> bool:
    """True if ``host`` is one of ``domains`` or a subdomain of one."""
    domain_set = domains if isinstance(domains, (set, frozenset)) else set(domains)
    return any(candidate in domain_set for candidate in self_and_parents(host))


def defang_host(host: str) -> str:
    """Make a hostname unclickable for display: ``evil.com`` -> ``evil[.]com``."""
    return host.replace(".", "[.]")
