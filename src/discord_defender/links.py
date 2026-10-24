"""Link extraction and lookalike-domain detection."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit

from .domains import defang_host, in_domains, registered_domain
from .text import clean, fold

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`]+")
# [shown text](https://real.target) - Discord renders only the shown text.
MASKED_LINK_RE = re.compile(r"\[([^\[\]\n]{1,256})\]\(\s*<?(https?://[^\s<>()]+)>?\s*\)", re.I)
# Domain-looking words in plain text, e.g. "go to dlscord-gift.com". Used only for
# exact blocklist matches, never for the fuzzy lookalike checks.
BARE_HOST_RE = re.compile(r"(?i)(?<![\w@./-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(/[^\s<>\"'`]*)?")
INVITE_RE = re.compile(
    r"(?i)(?:https?://)?(?:www\.|ptb\.|canary\.)?"
    r"(?:discord(?:app)?\.com/invite|discord\s*[.,]\s*gg|dsc\.gg|discord\.me|discord\.io|"
    r"invite\.gg|discord\.li)"
    r"\s*/\s*([a-z0-9-]{2,32})"
)

_TRAILING = ".,;:!?'\"*_~|>"
# fmt: off
EXECUTABLE_EXTENSIONS = frozenset(
    {
        "apk", "bat", "cmd", "cpl", "dll", "exe", "hta", "img", "iso", "jar", "jse",
        "lnk", "msi", "msix", "pif", "ps1", "scr", "vbe", "vbs", "vhd", "vhdx", "wsf",
    }
)
# fmt: on
# Words that turn "uses the Discord name" into "is almost certainly phishing".
# fmt: off
SCAM_HOST_WORDS = (
    "airdrop", "appeal", "auth", "boost", "bonus", "claim", "drop", "event", "free",
    "gift", "giveaway", "login", "nitro", "prize", "promo", "reward", "security",
    "signin", "skin", "staff", "support", "trade", "verif",
)
# fmt: on

# fmt: off
_SKELETON = str.maketrans(
    {"0": "o", "1": "l", "i": "l", "!": "l", "|": "l", "3": "e", "4": "a", "@": "a",
     "5": "s", "$": "s", "7": "t", "-": None, "_": None}
)
# fmt: on


@dataclass(frozen=True)
class Brand:
    """A service scammers impersonate, with its real domains."""

    name: str
    keywords: tuple[str, ...]
    domains: tuple[str, ...]


# fmt: off
DEFAULT_BRANDS = (
    Brand(
        "Discord",
        ("discord", "discordapp"),
        ("discord.com", "discord.gg", "discord.gift", "discord.new", "discord.media",
         "discord.dev", "discord.co", "discordapp.com", "discordapp.net",
         "discordstatus.com", "discordmerch.com", "dis.gd"),
    ),
    Brand(
        "Steam",
        ("steamcommunity", "steampowered"),
        ("steamcommunity.com", "steampowered.com", "steamstatic.com", "steamgames.com",
         "steamusercontent.com", "steamserver.net", "steam-chat.com", "steamdeck.com",
         "valvesoftware.com", "s.team"),
    ),
)
# fmt: on

# fmt: off
DEFAULT_SHORTENERS = (
    "bit.ly", "bitly.com", "bitly.su", "clck.ru", "cutt.ly", "goo.su", "inlnk.ru", "is.gd",
    "ow.ly", "qrco.de", "rb.gy", "rebrand.ly", "s.id", "shorturl.asia", "shorturl.at",
    "t.ly", "tiny.cc", "tinyurl.com", "u.to", "v.gd",
)
# fmt: on


@dataclass(frozen=True)
class LinkFinding:
    kind: str  # signal name, e.g. "lookalike_domain"
    host: str
    detail: str


@dataclass
class LinkReport:
    hosts: list[str] = field(default_factory=list)
    findings: list[LinkFinding] = field(default_factory=list)
    invite_codes: list[str] = field(default_factory=list)


class BlocklistLike(Protocol):
    def match(self, host: str, path: str = "") -> str | None: ...


def _trim_url(url: str) -> str:
    while url:
        last = url[-1]
        if last in _TRAILING:
            url = url[:-1]
        elif last == ")" and url.count("(") < url.count(")"):
            url = url[:-1]
        elif last == "]" and url.count("[") < url.count("]"):
            url = url[:-1]
        else:
            break
    return url


def _find_urls(cleaned: str) -> list[str]:
    # Split "[shown](target)" apart first, otherwise "https://shown](https://target)"
    # reads as a single URL and the real target is never checked.
    unmasked = MASKED_LINK_RE.sub(lambda m: f" {m.group(1)} {m.group(2)} ", cleaned)
    return [_trim_url(m.group(0)) for m in URL_RE.finditer(unmasked)]


def extract_urls(text: str) -> list[str]:
    """All http(s) URLs in ``text``, including masked-link targets."""
    return _find_urls(clean(text))


def extract_invite_codes(text: str) -> list[str]:
    """Discord invite codes (``discord.gg/abc`` and friends), case preserved."""
    seen: dict[str, None] = {}
    for match in INVITE_RE.finditer(clean(text)):
        seen.setdefault(match.group(1), None)
    return list(seen)


def split_url(url: str) -> tuple[str, str] | None:
    """Return ``(ascii_host, path)`` for a URL, resolving tricks like ``user@host``."""
    if not re.match(r"(?i)https?://", url):
        url = "http://" + url
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return host.lower(), parts.path


def unicode_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except UnicodeError:
            return label
    return label


def skeleton(text: str) -> str:
    """Collapse visual tricks: ``d1sc0rd``, ``dіscord`` and ``dlscord`` all match."""
    s = fold(text).translate(_SKELETON)
    return s.replace("rn", "m").replace("vv", "w")


def osa_distance(a: str, b: str, limit: int | None = None) -> int:
    """Edit distance where swapping two neighbouring letters counts as one edit.

    With ``limit``, stops early and returns ``limit + 1`` once the distance is
    certain to exceed it.
    """
    if a == b:
        return 0
    if limit is not None and abs(len(a) - len(b)) > limit:
        return limit + 1
    rows = [list(range(len(b) + 1))]
    for i in range(1, len(a) + 1):
        row = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            row[j] = min(rows[i - 1][j] + 1, row[j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                row[j] = min(row[j], rows[i - 2][j - 2] + 1)
        if limit is not None and min(row) > limit:
            return limit + 1
        rows.append(row)
    return rows[-1][-1]


def _tolerance(keyword: str) -> int:
    """How many typos a lookalike may have. Short names get none (too many real words)."""
    if len(keyword) >= 13:
        return 3
    if len(keyword) >= 10:
        return 2
    if len(keyword) >= 6:
        return 1
    return 0


def _fuzzy_contains(haystack: str, needle: str, tolerance: int) -> bool:
    n = len(needle)
    for size in range(n - tolerance, n + tolerance + 1):
        for start in range(0, len(haystack) - size + 1):
            if osa_distance(haystack[start : start + size], needle, tolerance) <= tolerance:
                return True
    return False


class LinkAnalyzer:
    def __init__(
        self,
        blocklist: BlocklistLike | None = None,
        *,
        brands: Iterable[Brand] = DEFAULT_BRANDS,
        allowlist: Iterable[str] = (),
        shorteners: Iterable[str] = DEFAULT_SHORTENERS,
    ) -> None:
        self.blocklist = blocklist
        self.brands = tuple(brands)
        official = {d.lower() for brand in self.brands for d in brand.domains}
        self.allowlist = frozenset(official | {d.lower().strip() for d in allowlist if d.strip()})
        self.shorteners = frozenset(s.lower() for s in shorteners)
        self._brand_skeletons = [
            (brand, kw, skeleton(kw), _tolerance(kw)) for brand in self.brands for kw in brand.keywords
        ]

    def is_allowed(self, host: str) -> bool:
        return in_domains(host, self.allowlist)

    def analyze(self, text: str) -> LinkReport:
        report = LinkReport(invite_codes=extract_invite_codes(text))
        cleaned = clean(text)
        urls = _find_urls(cleaned)

        seen_hosts: set[str] = set()
        for url in urls:
            parts = split_url(url)
            if parts is None:
                continue
            host, path = parts
            if host not in seen_hosts:
                seen_hosts.add(host)
                report.hosts.append(host)
            report.findings.extend(self._check_url(host, path))

        # Plain-text domains: blocklist only, the fuzzy checks would be too noisy.
        if self.blocklist is not None:
            remainder = URL_RE.sub(" ", fold(cleaned))
            for match in BARE_HOST_RE.finditer(remainder):
                host, path = match.group(1).lower(), match.group(2) or ""
                if host in seen_hosts or self.is_allowed(host):
                    continue
                hit = self.blocklist.match(host, path)
                if hit:
                    seen_hosts.add(host)
                    report.findings.append(
                        LinkFinding("phishing_domain", host, f"Known scam domain {defang_host(hit)}")
                    )

        for shown, target in MASKED_LINK_RE.findall(cleaned):
            finding = self._check_masked(shown, target)
            if finding:
                report.findings.append(finding)
        return report

    def _check_url(self, host: str, path: str) -> list[LinkFinding]:
        findings: list[LinkFinding] = []
        # Checked even for trusted hosts: malware is often served from Discord's own CDN.
        filename = path.rsplit("/", 1)[-1]
        extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if extension in EXECUTABLE_EXTENSIONS:
            findings.append(LinkFinding("executable_link", host, f"Link to a .{extension} program file"))
        if self.is_allowed(host):
            return findings
        shown = defang_host(host)

        if self.blocklist is not None:
            hit = self.blocklist.match(host, path)
            if hit:
                findings.append(LinkFinding("phishing_domain", host, f"Known scam link {defang_host(hit)}"))

        lookalike = self.classify_lookalike(host)
        if lookalike:
            findings.append(lookalike)

        if any(label.startswith("xn--") for label in host.split(".")):
            findings.append(LinkFinding("idn_domain", host, f"Internationalised (punycode) domain {shown}"))
        try:
            ipaddress.ip_address(host)
            findings.append(LinkFinding("ip_link", host, f"Link to a bare IP address {shown}"))
        except ValueError:
            pass
        if in_domains(host, self.shorteners):
            findings.append(LinkFinding("shortener", host, f"URL shortener hides the destination ({shown})"))
        return findings

    def classify_lookalike(self, host: str) -> LinkFinding | None:
        """Detect domains pretending to be one of the protected brands."""
        if self.is_allowed(host):
            return None
        shown = defang_host(host)
        reg = registered_domain(host)
        label = reg.split(".")[0]
        label_skel = skeleton(unicode_label(label))
        subdomains = [skeleton(unicode_label(s)) for s in host[: -len(reg)].split(".") if s]
        scam_words = [w for w in SCAM_HOST_WORDS if w in host]

        for brand in self.brands:
            for official in brand.domains:
                if f"{official}." in host or f"{official}-" in host:
                    return LinkFinding("lookalike_domain", host, f"{shown} pretends to be {defang_host(official)}")

        for brand, keyword, kw_skel, tolerance in self._brand_skeletons:
            if label == keyword:
                kind = "lookalike_domain" if scam_words else "brand_domain"
                return LinkFinding(kind, host, f"{shown} uses the {brand.name} name but is not {brand.name}")
            if label_skel == kw_skel or (tolerance and osa_distance(label_skel, kw_skel, tolerance) <= tolerance):
                return LinkFinding("lookalike_domain", host, f"{shown} is a misspelling of {brand.name}")
            if kw_skel in label_skel:
                kind = "lookalike_domain" if scam_words else "brand_domain"
                return LinkFinding(kind, host, f"{shown} uses the {brand.name} name but is not {brand.name}")
            if tolerance and _fuzzy_contains(label_skel, kw_skel, tolerance):
                return LinkFinding("lookalike_domain", host, f"{shown} contains a misspelling of {brand.name}")
            if any(kw_skel in sub for sub in subdomains):
                # "discord.myclub.org" invite redirects are common and harmless, so
                # a brand in a subdomain only counts as phishing with scam words.
                kind = "lookalike_domain" if scam_words else "brand_domain"
                return LinkFinding(kind, host, f"{shown} uses the {brand.name} name but is not {brand.name}")
        return None

    def _check_masked(self, shown_text: str, target: str) -> LinkFinding | None:
        parts = split_url(_trim_url(target))
        if parts is None:
            return None
        target_host = parts[0]
        shown_hosts = []
        for match in URL_RE.finditer(shown_text):
            p = split_url(_trim_url(match.group(0)))
            if p:
                shown_hosts.append(p[0])
        for match in BARE_HOST_RE.finditer(fold(shown_text)):
            shown_hosts.append(match.group(1).lower())
        target_reg = registered_domain(target_host)
        for shown_host in shown_hosts:
            if registered_domain(shown_host) != target_reg:
                return LinkFinding(
                    "masked_link",
                    target_host,
                    f"Link text says {defang_host(shown_host)} but really opens {defang_host(target_host)}",
                )
        return None
