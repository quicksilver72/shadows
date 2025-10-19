#!/usr/bin/env python3
"""
lib/webster_words.py
Efficient Webster Word Concatenator for passgen.sh
Generates 3 randomized adjective+noun(+verb) combos for secure password base.
"""

import random
import string
from nltk.corpus import wordnet as wn

# === CONFIG ===
MIN_WORD_LEN = 3
MAX_WORD_LEN = 7
MIN_TOTAL_LEN = 11
MAX_TOTAL_LEN = 21
SAMPLE_SIZE = 100


def random_letter():
    return random.choice(string.ascii_lowercase)


def collect_words(pos, letter):
    """Collect up to SAMPLE_SIZE words starting with a given letter."""
    words = []
    for syn in wn.all_synsets(pos=pos):
        for lemma in syn.lemmas():
            w = lemma.name().replace("_", "")
            if (
                w.isalpha()
                and w.lower().startswith(letter)
                and MIN_WORD_LEN <= len(w) <= MAX_WORD_LEN
            ):
                words.append(w.lower())
                if len(words) >= SAMPLE_SIZE:
                    return words
    return words


def get_random_word(pos):
    """Fetch a random valid word of the given POS from a random letter window."""
    for _ in range(10):
        letter = random_letter()
        words = collect_words(pos, letter)
        if words:
            return random.choice(words)
    raise RuntimeError(f"No valid {pos} words found.")


def capitalize(w):
    return w.capitalize()


def generate_name():
    """Generate a single Webster-style concatenated name."""
    adj = get_random_word("a")
    noun = get_random_word("n")
    combo = adj + noun

    # Add verb only if total is too short
    if len(combo) < MIN_TOTAL_LEN:
        verb = get_random_word("v")
        combo = adj + noun + verb
        parts = [adj, noun, verb]
    else:
        parts = [adj, noun]

    # Retry if too long
    if len(combo) > MAX_TOTAL_LEN:
        return generate_name()

    return "".join(capitalize(p) for p in parts)


if __name__ == "__main__":
    for _ in range(3):
        print(generate_name())
