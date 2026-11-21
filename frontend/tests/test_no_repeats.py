"""The dashboard shows one fact once: no parent + sub-technique pair, no rights list repeated in the story text."""
from frontend.app import _RIGHTS_SENTENCE, _most_specific


def test_parent_technique_is_hidden_when_its_sub_technique_is_shown():
    shown = _most_specific([{"id": "T1110"}, {"id": "T1110.001"}, {"id": "T1078"}, {"id": "T1021.002"}, {"id": "T1021"}])
    assert [t["id"] for t in shown] == ["T1110.001", "T1078", "T1021.002"]       # T1078 has no sub-technique: kept


def test_story_without_the_rights_sentence_keeps_everything_else():
    story = ("It started at 16:04 UTC. The activity moved WS-1 -> DC-02. Rights gained or stolen: 16:09 credential "
             "dumping command; 16:14 pass-the-hash; 16:16 added to a privileged group. Impact: files encrypted (ransomware).")
    assert _RIGHTS_SENTENCE.sub("", story) == ("It started at 16:04 UTC. The activity moved WS-1 -> DC-02. "
                                               "Impact: files encrypted (ransomware).")
