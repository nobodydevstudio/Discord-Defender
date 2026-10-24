import pytest

from discord_defender.config import Config, ConfigError, RuleConfig
from discord_defender.engine import Action, Attachment, Engine, MessageInfo

NOW = 1_800_000_000.0
DAY = 86400
VETERAN = dict(author_joined_at=NOW - 400 * DAY, author_created_at=NOW - 900 * DAY)
NEWCOMER = dict(author_joined_at=NOW - 600, author_created_at=NOW - 2 * DAY)


def make_engine(**tweaks) -> Engine:
    config = Config()
    config.server.honeypot_channel_ids = [999]
    config.server.allowed_invite_codes = ["ourclub"]
    for path, value in tweaks.items():
        section, key = path.split("__")
        setattr(getattr(config, section), key, value)
    engine = Engine(config)
    engine.blocklist.set_feed_entries({"evil-gift.com"})
    return engine


def msg(content="", *, channel=10, author=1, mid=None, at=NOW, who=VETERAN, **kw) -> MessageInfo:
    msg.counter = getattr(msg, "counter", 0) + 1
    return MessageInfo(
        message_id=mid or msg.counter,
        channel_id=channel,
        author_id=author,
        content=content,
        created_at=at,
        **who,
        **kw,
    )


def test_normal_chat_is_left_alone():
    engine = make_engine()
    for text in ["hey all, meeting at 6", "https://docs.google.com/x", "lol", "selling my calculator, dm me"]:
        assert engine.evaluate(msg(text, who=NEWCOMER)).action is Action.NONE


def test_known_scam_link_times_out_even_trusted_members():
    engine = make_engine()
    v = engine.evaluate(msg("https://evil-gift.com/claim", author_trusted=True))
    assert v.action is Action.TIMEOUT and v.has("phishing_domain")


def test_trusted_members_ignore_soft_signals():
    engine = make_engine()
    v = engine.evaluate(msg("@everyone free nitro giveaway, first come first serve", author_trusted=True))
    assert v.action is Action.NONE and v.signals == []


def test_newcomer_bonus_only_sharpens_existing_evidence():
    engine = make_engine()
    assert engine.evaluate(msg("text me if you need a ride", who=NEWCOMER)).score == 15
    veteran = engine.evaluate(msg("join discord.gg/abc123"))
    newcomer = engine.evaluate(msg("join discord.gg/abc123", who=NEWCOMER))
    assert veteran.action is Action.FLAG
    assert newcomer.action is Action.DELETE and newcomer.has("newcomer")


def test_allowed_and_own_invites_are_fine():
    engine = make_engine()
    assert engine.evaluate(msg("discord.gg/OurClub")).action is Action.NONE
    assert engine.evaluate(msg("discord.gg/x1", own_invite_codes=frozenset({"x1"}))).action is Action.NONE


def test_honeypot_times_out_on_first_message():
    engine = make_engine()
    v = engine.evaluate(msg("hello", channel=999))
    assert v.action is Action.TIMEOUT and v.has("honeypot")
    assert engine.evaluate(msg("hi", channel=5, parent_channel_id=999)).has("honeypot")
    assert engine.evaluate(msg("posting the rules", channel=999, author_trusted=True)).action is Action.NONE


def test_hijacked_account_spamming_channels_is_stopped_and_cleaned_up():
    engine = make_engine()
    spam = "Selling my old MacBook Air, barely used, message me"
    first = engine.evaluate(msg(spam, channel=1, author=5, mid=101, at=NOW))
    second = engine.evaluate(msg(spam, channel=2, author=5, mid=102, at=NOW + 2))
    third = engine.evaluate(msg(spam, channel=3, author=5, mid=103, at=NOW + 4))
    assert first.action < Action.DELETE and second.action < Action.DELETE
    assert third.action is Action.TIMEOUT and third.has("duplicate_burst")
    assert set(third.related) == {(1, 101), (2, 102)}


def test_rotating_screenshot_spam_is_caught_by_shape():
    engine = make_engine()
    verdicts = []
    for i, channel in enumerate([1, 2, 3, 4, 5]):
        images = [Attachment(f"IMG_{i}{j}.jpg", 50_000 + 97 * i + j, "image/jpeg") for j in range(4)]
        verdicts.append(engine.evaluate(msg("", channel=channel, author=8, attachments=images, at=NOW + i)))
    assert [v.action for v in verdicts[:2]] == [Action.NONE, Action.NONE]
    assert verdicts[2].action is Action.DELETE and verdicts[2].has("similar_burst")
    assert verdicts[4].action is Action.TIMEOUT
    assert len(verdicts[4].related) == 4


def test_same_message_repeated_in_one_channel():
    engine = make_engine()
    text = "please check out my new channel and subscribe"
    verdicts = [engine.evaluate(msg(text, channel=1, author=3, at=NOW + i)) for i in range(5)]
    assert verdicts[-1].has("repeat_flood") and verdicts[-1].action >= Action.DELETE


def test_edits_are_scored_but_not_counted_as_new_posts():
    engine = make_engine()
    for channel in (1, 2, 3):
        v = engine.evaluate(
            msg("this is a long enough message to fingerprint", channel=channel, author=4, is_edit=True)
        )
    assert not v.has("duplicate_burst")
    assert engine.evaluate(msg("now with https://evil-gift.com", is_edit=True)).action is Action.TIMEOUT


def test_phrases_alone_never_time_out_an_established_member():
    engine = make_engine()
    v = engine.evaluate(
        msg("free nitro giveaway! invest in crypto for guaranteed profits, casino promo code inside, dm me")
    )
    assert v.action is Action.DELETE and v.score == 90


def test_dry_run_style_untracked_evaluation_has_no_side_effects():
    engine = make_engine()
    text = "a message long enough to be fingerprinted"
    for channel in (1, 2, 3):
        v = engine.evaluate(msg(text, channel=channel, author=6), track=False)
    assert v.action is Action.NONE and engine.tracker.recent(6, since=0) == []


def test_executable_attachment():
    engine = make_engine()
    v = engine.evaluate(msg("try my game", who=NEWCOMER, attachments=[Attachment("Game.exe", 1, None)]))
    assert v.has("executable_attachment") and v.action is Action.DELETE


def test_weights_override_and_validation():
    config = Config()
    config.weights = {"server_invite": 0}
    engine = Engine(config)
    assert engine.evaluate(msg("discord.gg/abc", who=NEWCOMER)).action is Action.NONE
    config.weights = {"not_a_signal": 5}
    with pytest.raises(ConfigError):
        Engine(config)


def test_custom_rule_and_bad_regex():
    config = Config()
    config.heuristics.extra_rules = [RuleConfig("fee", "processing fee", 40, "Fee scam")]
    assert Engine(config).evaluate(msg("scholarship! just pay the processing fee")).action is Action.FLAG
    config.heuristics.extra_rules = [RuleConfig("bad", "(unclosed", 40)]
    with pytest.raises(ConfigError):
        Engine(config)
