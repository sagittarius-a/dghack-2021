yara_candidates = set()
for line in open("yara.candidates.txt").readlines():
    yara_candidates.add(line.strip())

candidates = set()
for line in open("candidates.txt").readlines():
    candidates.add(line.strip())

print(candidates.intersection(yara_candidates))
