## Use yara to find XOR string candidates

```sh
$ yara -r xor.yara samples | awk ' { print $2 }' | sort -u >  yara.candidates.txt
```

## Find candidates for other predicates

```sh
$ python asdf.py
```

## Find good sample

```sh
python finder.py
```

## Flag

`DGA{ca17ba40c5ae2eb3}`
