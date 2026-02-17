import json
import itertools
import re
from difflib import SequenceMatcher

QUIZ_PATH = "cyberbase/data/quiz.json"
RUN_SIZE = 10


def _normalize(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _xfnv1a_32(s: str) -> int:
    """32-bit FNV-1a hash (matches the JS xfnv1a implementation used in quiz.html)."""
    h = 2166136261
    for ch in s:
        h ^= ord(ch)
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def _mulberry32(seed: int):
    """Deterministic PRNG (matches the JS mulberry32 implementation used in quiz.html)."""
    a = seed & 0xFFFFFFFF

    def rand() -> float:
        nonlocal a
        a = (a + 0x6D2B79F5) & 0xFFFFFFFF
        t = a
        t ^= (t >> 15)
        t = (t * ((t | 1) & 0xFFFFFFFF)) & 0xFFFFFFFF
        t ^= (t + (((t ^ (t >> 7)) & 0xFFFFFFFF) * ((t | 61) & 0xFFFFFFFF) & 0xFFFFFFFF)) & 0xFFFFFFFF
        t ^= (t >> 14)
        return (t & 0xFFFFFFFF) / 4294967296.0

    return rand


def _seeded_shuffle(items, rand):
    for i in range(len(items) - 1, 0, -1):
        j = int(rand() * (i + 1))
        items[i], items[j] = items[j], items[i]
    return items


def _pick_questions(topic_id: str, questions: list, run_id: str):
    seed = _xfnv1a_32(f"{run_id}|{topic_id}")
    rand = _mulberry32(seed)
    idx = list(range(len(questions)))
    _seeded_shuffle(idx, rand)
    picked = [questions[i] for i in idx[: min(RUN_SIZE, len(questions))]]
    return picked


def _load_quiz():
    with open(QUIZ_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_each_topic_has_30_unique_questions_and_valid_answers():
    quiz = _load_quiz()
    topics = quiz.get("quizzes", [])
    assert topics, "No quiz topics found"

    for t in topics:
        tid = t.get("id")
        qs = t.get("questions", [])
        assert len(qs) == 30, f"{tid} has {len(qs)} questions, expected 30"

        raw = [q.get("q", "") for q in qs]
        assert len(set(raw)) == 30, f"{tid} contains duplicate question text"

        norm = [_normalize(x) for x in raw]
        assert len(set(norm)) == 30, f"{tid} contains duplicate (normalized) question text"

        for (i, a), (j, b) in itertools.combinations(list(enumerate(norm)), 2):
            ratio = SequenceMatcher(None, a, b).ratio()
            assert ratio <= 0.93, f"{tid} contains very similar questions at {i} and {j} (ratio={ratio:.2f})"

        for i, q in enumerate(qs):
            choices = q.get("choices")
            answer = q.get("answer")

            assert isinstance(choices, list) and len(choices) == 4, f"{tid} q{i} must have 4 choices"
            assert isinstance(answer, int), f"{tid} q{i} answer must be an int"
            assert 0 <= answer < 4, f"{tid} q{i} answer out of range"

            # Exactly one correct option is implied by a single index, but validate structure.
            assert len(choices) == len(set(choices)), f"{tid} q{i} contains duplicate choice text"


def test_run_selects_10_unique_questions():
    quiz = _load_quiz()
    topics = quiz.get("quizzes", [])

    for t in topics:
        tid = t["id"]
        qs = t["questions"]
        picked = _pick_questions(tid, qs, run_id="run-1")

        assert len(picked) == 10, f"{tid} run should pick 10 questions"
        picked_texts = [q["q"] for q in picked]
        assert len(set(picked_texts)) == 10, f"{tid} run contains repeated questions"


def test_multiple_runs_often_differ():
    quiz = _load_quiz()
    topics = quiz.get("quizzes", [])

    different = 0
    for t in topics:
        tid = t["id"]
        qs = t["questions"]
        p1 = [q["q"] for q in _pick_questions(tid, qs, run_id="run-1")]
        p2 = [q["q"] for q in _pick_questions(tid, qs, run_id="run-2")]
        if p1 != p2:
            different += 1

    # With a 30 question bank, two different seeds should differ for most topics.
    assert different >= max(1, int(len(topics) * 0.8)), f"Only {different}/{len(topics)} topics differed between runs"
