import pytest

from discord_defender.blocklist import Blocklist
from discord_defender.domains import registered_domain
from discord_defender.links import (
    LinkAnalyzer,
    extract_invite_codes,
    extract_urls,
    osa_distance,
    split_url,
)
from discord_defender.text import defang, fold


def kinds(report):
    return {f.kind for f in report.findings}


@pytest.fixture
def analyzer():
    return LinkAnalyzer(Blocklist(extra=["evil-gift.com", "bit.ly/3scam"]), allowlist=["discord.js.org"])


def test_fold_undoes_lookalike_tricks():
    assert fold("frее nіtro") == "free nitro"  # Cyrillic е and і
    assert fold("ＦＲＥＥ 𝐍𝐈𝐓𝐑𝐎") == "free nitro"  # fullwidth and maths bold
    assert fold("fr​ee") == "free"  # zero-width space


def test_defang_breaks_links_and_code_fences():
    out = defang("see https://evil.com ```")
    assert "https://" not in out and "hxxps://evil.com" in out
    assert "```" not in out


def test_url_extraction_trims_markdown_and_punctuation():
    text = "look: ||https://a.com/x|| and **https://b.com/y**, (https://c.com/z)."
    assert extract_urls(text) == ["https://a.com/x", "https://b.com/y", "https://c.com/z"]


def test_masked_link_target_is_extracted_separately():
    urls = extract_urls("[https://discord.com/gifts](https://evil-gift.com/x)")
    assert "https://evil-gift.com/x" in urls


def test_userinfo_trick_resolves_real_host():
    assert split_url("https://discord.com@evil.ru/login")[0] == "evil.ru"


def test_registered_domain_handles_hosting_platforms():
    assert registered_domain("a.b.evil.co.uk") == "evil.co.uk"
    assert registered_domain("discord-gift.vercel.app") == "discord-gift.vercel.app"
    assert registered_domain("www.google.com") == "google.com"


def test_invite_codes_with_and_without_scheme():
    text = "join https://discord.gg/AbC123 or discord.gg/xyz or discord.com/invite/q-1"
    assert extract_invite_codes(text) == ["AbC123", "xyz", "q-1"]


def test_osa_counts_transposition_as_one():
    assert osa_distance("dicsord", "discord") == 1
    assert osa_distance("discord", "discord") == 0
    assert osa_distance("abcdef", "uvwxyz", limit=2) == 3


@pytest.mark.parametrize(
    "host",
    [
        "dlscord.com",  # l for i
        "d1scord-nitro.gift",  # digit swap
        "dicsord.com",  # transposition
        "discord-gift.vercel.app",  # brand + scam word on free hosting
        "discord.com.verify-account.ru",  # real domain used as a subdomain
        "steamcommunlty.com",
        "steancomnnunity.ru",  # several typos in a long name
        "steamcommunity.com-trade.ru",
        "discord.gifts",  # brand on a scammy TLD
        "xn--dscord-6ve.com",  # Cyrillic і, punycode encoded
    ],
)
def test_lookalikes_are_caught(analyzer, host):
    finding = analyzer.classify_lookalike(host)
    assert finding is not None and finding.kind == "lookalike_domain", host


@pytest.mark.parametrize(
    "host",
    [
        "discord.com",
        "cdn.discordapp.com",
        "discord.gg",
        "support.discord.com",
        "steamcommunity.com",
        "store.steampowered.com",
        "s.team",
        "steamdb.info",
        "steam.com",
        "stream.com",
        "streamable.com",
        "discogs.com",
        "discover.com",
        "google.com",
        "docs.google.com",
        "asce.org",
        "github.com",
        "discord.js.org",
        "steamboat.com",
        "steampunk.com",
        "record.com",
    ],
)
def test_legitimate_domains_are_not_lookalikes(analyzer, host):
    assert analyzer.classify_lookalike(host) is None, host


def test_brand_name_without_scam_words_is_only_a_soft_signal(analyzer):
    assert analyzer.classify_lookalike("discordservers.com").kind == "brand_domain"
    assert analyzer.classify_lookalike("discord.myclub.org").kind == "brand_domain"


def test_blocklisted_url_and_bare_domain(analyzer):
    assert "phishing_domain" in kinds(analyzer.analyze("claim at https://www.evil-gift.com/claim"))
    assert "phishing_domain" in kinds(analyzer.analyze("go to evil-gift.com and log in"))
    assert "phishing_domain" in kinds(analyzer.analyze("https://bit.ly/3scam"))
    assert "phishing_domain" not in kinds(analyzer.analyze("https://bit.ly/3scamX"))


def test_masked_link_mismatch(analyzer):
    report = analyzer.analyze("[steamcommunity.com/gift](https://scam.example/x)")
    assert "masked_link" in kinds(report)
    assert "masked_link" not in kinds(analyzer.analyze("[our form](https://forms.gle/abc)"))
    assert "masked_link" not in kinds(analyzer.analyze("[google.com](https://docs.google.com/x)"))


def test_executable_link_is_flagged_even_on_discord_cdn(analyzer):
    report = analyzer.analyze("try my game https://cdn.discordapp.com/attachments/1/2/Setup.exe")
    assert kinds(report) == {"executable_link"}


def test_ip_shortener_and_punycode(analyzer):
    assert "ip_link" in kinds(analyzer.analyze("http://45.13.2.9/login"))
    assert "shortener" in kinds(analyzer.analyze("https://tinyurl.com/abc"))
    assert "idn_domain" in kinds(analyzer.analyze("https://xn--80ak6aa92e.com/"))


def test_clean_message_has_no_findings(analyzer):
    report = analyzer.analyze("Meeting slides: https://docs.google.com/presentation/d/abc and https://www.asce.org")
    assert report.findings == []
    assert report.hosts == ["docs.google.com", "www.asce.org"]
