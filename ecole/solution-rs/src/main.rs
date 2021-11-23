use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
use std::ops::{Index, IndexMut};
use std::time::Instant;

extern crate collect_slice;
use collect_slice::CollectSlice;

#[derive(Debug, Deserialize)]
struct StudentWish {
    idx: usize,
    friends: [usize; 4],
}

#[derive(Debug, Copy, Clone, Serialize)]
struct School {
    class1: Class,
    class2: Class,
    class3: Class,
}

#[derive(Debug, Copy, Clone, Serialize)]
struct Class {
    composition: [usize; 30],
}

impl Index<usize> for School {
    type Output = Class;

    fn index(&self, value: usize) -> &Self::Output {
        match value {
            0 => &self.class1,
            1 => &self.class2,
            2 => &self.class3,
            _ => panic!("Invalid index for School"),
        }
    }
}

impl IndexMut<usize> for School {
    fn index_mut(&mut self, value: usize) -> &mut Self::Output {
        match value {
            0 => &mut self.class1,
            1 => &mut self.class2,
            2 => &mut self.class3,
            _ => panic!("Invalid index for School"),
        }
    }
}

impl Index<usize> for Class {
    type Output = usize;

    fn index(&self, value: usize) -> &Self::Output {
        &self.composition[value]
    }
}

impl IndexMut<usize> for Class {
    fn index_mut(&mut self, value: usize) -> &mut Self::Output {
        &mut self.composition[value]
    }
}

const NB_CORPUS_ENTRIES: usize = 1;

fn main() -> std::io::Result<()> {
    let wishes = load_wishes().unwrap();
    let mut rng = rand::thread_rng();
    let now = Instant::now();

    // Create the corpus containing several School object
    let mut corpus: Vec<(School, usize)> = Vec::new();
    let mut composition = [0usize; 30];

    (0..=29).collect_slice(&mut composition[..]);
    let class1 = Class { composition };
    (30..=59).collect_slice(&mut composition[..]);
    let class2 = Class { composition };
    (60..=89).collect_slice(&mut composition[..]);
    let class3 = Class { composition };

    let s = School {
        class1,
        class2,
        class3,
    };

    // Populate the corpus with freshly created shools
    for _ in 0..NB_CORPUS_ENTRIES {
        corpus.push((s, 0));
    }

    // Benchmarking perfs
    let mut bench = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("./rust-stat.txt")?;

    let mut tries = 0;
    let mut last_sec = 0;

    'bf: loop {
        // Temporary buffer to store mutated entries that got better result
        // than their ancestor
        let mut changes: Vec<(usize, (School, usize))> = Vec::new();

        for (i, (candidate, score)) in corpus.iter_mut().enumerate() {
            tries += 1;

            let mut new_school = candidate.clone();

            // Swap 2 students k times
            for _ in 0..rng.gen_range(2..129) {
                let c1 = rng.gen_range(0..3);
                let s1 = rng.gen_range(0..30);

                let tmp = new_school[c1][s1];

                let c2 = rng.gen_range(0..3);
                let s2 = rng.gen_range(0..30);

                new_school[c1][s1] = new_school[c2][s2];
                new_school[c2][s2] = tmp;
            }

            let new_score = total(new_school, &wishes);

            if new_score >= 2950 {
                println!("You win !");

                let file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open("./solution.json")?;
                println!("Update solution.json before uploading it");
                serde_json::to_writer(
                    &file,
                    &[new_school.class1, new_school.class2, new_school.class3],
                )?;
                break 'bf;
            }

            if new_score > *score {
                println!("[{}] New score: {}", i, new_score);
                changes.push((i, (new_school, new_score)));
            }
        }

        // Apply new schools to corpus
        for (index, (school, score)) in changes {
            corpus[index] = (school, score);
        }

        // Print some fancy statistics
        if tries % 100_000 == 0 {
            let elapsed = now.elapsed().as_secs_f64();
            println!("{:.2} tries/sec", tries as f64 / elapsed);
        }

        // Benchmark
        let elapsed = now.elapsed().as_secs();
        if elapsed != last_sec {
            last_sec = elapsed;
            if let Err(e) = writeln!(
                bench,
                "{} {:.2}",
                elapsed,
                (tries as f64 / now.elapsed().as_secs_f64())
            ) {
                eprintln!("Couldn't write to benchmark file: {}", e);
            }
        }
    }

    println!("Total time elapsed: {:?}", now.elapsed());

    Ok(())
}

fn score_for_student(student_wish: &StudentWish, class: &Class) -> usize {
    let mut score = 0;
    for note in 0..4 {
        if class.composition.contains(&student_wish.friends[note]) {
            score += (4 - note) * 5;
        }
    }
    score
}

fn score_for_class(class: Class, wishes: &Vec<StudentWish>) -> usize {
    let mut score = 0;
    for e in class.composition.iter() {
        // Reproduce negative idnexing in Python
        // Accessing [-1] means accessing the last element of the list
        let index = *e;
        let student;
        if index != 0 {
            student = &wishes[index - 1];
        } else {
            student = &wishes.last().unwrap();
        }
        score += score_for_student(student, &class);
    }
    score
}

fn total(school: School, wishes: &Vec<StudentWish>) -> usize {
    let mut score = 0;
    score += score_for_class(school.class1, wishes);
    score += score_for_class(school.class2, wishes);
    score += score_for_class(school.class3, wishes);
    score
}

fn load_wishes() -> Result<Vec<StudentWish>, io::Error> {
    let wishes;
    // Try to read the wishes file
    match std::fs::File::open("./wishes.json") {
        Ok(f) => {
            wishes = serde_json::from_reader(f).unwrap();
        }
        Err(e) => {
            eprintln!("Error: Cannot open wish file");
            return Err(e);
        }
    };
    Ok(wishes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Test based on Python values in order to validate the Rust version
    fn check_scores() {
        let wishes = load_wishes().unwrap();

        let school = School {
            class1: Class {
                composition: [
                    44, 1, 2, 59, 4, 5, 68, 16, 8, 86, 10, 28, 12, 36, 14, 15, 7, 70, 18, 19, 57,
                    21, 13, 23, 24, 25, 26, 27, 38, 29,
                ],
            },
            class2: Class {
                composition: [
                    49, 31, 32, 33, 34, 35, 46, 37, 69, 0, 40, 41, 42, 43, 39, 71, 22, 52, 79, 30,
                    3, 51, 47, 53, 64, 55, 56, 20, 58, 78,
                ],
            },
            class3: Class {
                composition: [
                    83, 61, 62, 63, 54, 85, 66, 67, 6, 11, 17, 45, 72, 60, 74, 75, 76, 48, 50, 77,
                    80, 81, 82, 73, 84, 65, 9, 87, 88, 89,
                ],
            },
        };

        let class1_score = score_for_class(school.class1, &wishes);
        assert_eq!(class1_score, 425);

        let class2_score = score_for_class(school.class2, &wishes);
        assert_eq!(class2_score, 435);

        let class3_score = score_for_class(school.class3, &wishes);
        assert_eq!(class3_score, 580);

        let total_score = total(school, &wishes);
        assert_eq!(total_score, 1440);
    }
}
