import pytest

from discord_defender.heuristics import DEFAULT_RULES, PhraseScanner, build_rules, prepare

scanner = PhraseScanner(DEFAULT_RULES)


def hits(text):
    return {r.name for r in scanner.scan(prepare(text))}


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("FREE discord NITRO for everyone!!", "nitro_scam"),
        ("f||r||ee n**i**tro giveaway", "nitro_scam"),
        ("frее nіtro gift", "nitro_scam"),  # Cyrillic letters
        ("get your $50 steam gift card here", "steam_scam"),
        ("I'm giving away my old PS5, first come first serve", "giveaway_bait"),
        ("selling my macbook pro m2 for $200", "selling_bait"),
        ("selling 4 taylor swift tickets", "selling_bait"),
        ("add me on telegram for details", "dm_lure"),
        ("make $800 per week from home, passive income", "money_promise"),
        ("invest in bitcoin and get guaranteed profits", "crypto_scam"),
        ("use promo code BEAST on this casino to withdraw instantly", "casino_promo"),
        ("Hello, I offer help with assignments, essays, online classes and exams. DM me", "academic_services"),
        ("We can take your online class and exams, affordable and guaranteed A+", "academic_services"),
        ("Sorry, I accidentally reported your account, talk to discord staff to appeal", "account_scam"),
        ("your account will be banned unless you verify", "account_scam"),
        ("hey can you test my new game? need feedback", "game_test_lure"),
        ("only 3 spots left, act fast", "urgency"),
    ],
)
def test_scam_phrases_match(text, rule):
    assert rule in hits(text)


@pytest.mark.parametrize(
    "text",
    [
        "General meeting Thursday 6pm, free pizza!",
        "Does anyone have the steam tables for thermo?",
        "Can anyone help with the statics homework? I'm stuck on problem 4",
        "Anyone have the homework and exam solutions for CE 201? dm me",
        "I can help with the steel bridge project this weekend",
        "We're giving out ASCE shirts at the table",
        "who wants pizza?",
        "The concrete canoe team is looking for new members, message me if interested",
        "Our project report is due friday, the exam is monday",
        "The crypto lecture in CS was interesting",
    ],
)
def test_ordinary_club_chat_scores_low(text):
    matched = scanner.scan(prepare(text))
    assert sum(r.weight for r in matched) < 40, [r.name for r in matched]


def test_prepare_strips_mentions_links_and_markdown():
    assert prepare("<@123> **Free** <#456> https://x.com nitro <:pog:789>") == "free nitro"


def test_build_rules_supports_custom_and_disabled():
    rules = build_rules([{"name": "fee", "pattern": r"processing fee", "weight": 45}], disabled=["urgency"])
    names = {r.name for r in rules}
    assert "fee" in names and "urgency" not in names
    assert any(r.matches("pay the processing fee") for r in rules if r.name == "fee")
