import argparse
import json
import random
from datetime import datetime


def parse_school_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--input",
        type=argparse.FileType("r", encoding="UTF-8"),
        required=True,
        help=(
            "Fichier de voeux des élèves des trois classes "
            "(ex.: /path/to/dghack2021-ecole-repartition.json)"
        ),
        default="./dghack2021-ecole-repartition.json",
    )
    parser.add_argument(
        "-c",
        "--classes",
        type=argparse.FileType("r", encoding="UTF-8"),
        required=True,
        help="Fichier de répartition finale des élèves (à scorer)",
    )

    args = parser.parse_args()

    eleves = json.load(args.input)
    classes = json.load(args.classes)

    return classes, eleves


def score_for_eleve(el, classe):
    score = 0
    for note in range(0, 4):
        if el["friends"][note] in classe:
            score += (4 - note) * 5
    return score


def score_for_classe(classe, eleves):
    score = 0
    for e in classe:
        el = eleves[e - 1]
        score += score_for_eleve(el, classe)
    return score


def score_total(classes, eleves):
    return (
        score_for_classe(classes[0], eleves)
        + score_for_classe(classes[1], eleves)
        + score_for_classe(classes[2], eleves)
    )


def score_total_with_error_notification(classes, eleves):
    for i in range(0, 2):
        if len(classes[i]) > 30:
            raise ValueError(
                "Une classe ne peut pas contenir plus de 30 élèves."
            )
        for e in classes[i]:
            if e in classes[(i + 1) % 3] or e in classes[(i + 2) % 3]:
                raise ValueError(
                    "Un élève ne peut pas être dans deux classes."
                )
            if classes[i].count(e) > 1:
                raise ValueError(
                    "Un élève ne peut pas être deux fois dans une classe."
                )

    return score_total(classes, eleves)


def verify_score(score):
    return score >= 2950


# All code above is from the challenge itself.
# Here are the changes applied to it:
#  - Code formatting in order to be PEP8 compliant
#  - import random

if __name__ == "__main__":
    classes, students_data = parse_school_arguments()

    start_time = datetime.now()

    # Create a corpus of N entries to mutate
    # corpus entry contains the classes and the associated score
    N = 1
    corpus = []
    for _ in range(N):
        n = [
            list(range(0, 30)),
            list(range(30, 60)),
            list(range(60, 90)),
        ]
        corpus.append((n, 0))

    tries = 0
    last_sec = 0
    while "Mutate all the things !":
        tries += 1

        for i, candidate in enumerate(corpus):

            # Create a new entry to mutate
            newc = [
                candidate[0][0].copy(),
                candidate[0][1].copy(),
                candidate[0][2].copy(),
            ]

            K = random.randint(2, 128)

            # Swap 2 students K times
            for _ in range(K):
                c1 = random.randint(0, 2)
                s1 = random.randint(0, 29)

                tmp = newc[c1][s1]

                c2 = random.randint(0, 2)
                s2 = random.randint(0, 29)

                newc[c1][s1] = newc[c2][s2]
                newc[c2][s2] = tmp

            # Do not use score_total_with_error_notification in order to be
            # even faster. Since we're sure our 'fuzzer' is properly
            # implemented this is not an issue
            score = score_total(newc, students_data)

            if score >= 2950:
                print("You win !")
                with open("result.json", "w") as fp:
                    json.dump(newc, fp)
                print("Saved in result.json")
                breakpoint()

            if score > corpus[i][1]:
                print(f"[{i}] New score: {score}")
                # Saving the mutated entry in the corpus
                corpus[i] = (newc.copy(), score)

        elapsed = (datetime.now() - start_time).seconds
        if elapsed != last_sec:
            last_sec = elapsed
            if elapsed:
                print(f"{tries/elapsed:.2f} tries/sec")
                with open("python-stat.txt", "a+") as fd:
                    fd.write(f"{elapsed} {tries/elapsed:.2f}\n")
