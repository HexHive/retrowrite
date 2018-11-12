import argparse
import os
from collections import defaultdict

import pandas


def results_to_csv(results_dir, out):
    results = defaultdict(lambda: defaultdict(lambda: 0))

    for filename in os.listdir(results_dir):
        if filename.endswith(".asan.log"):
            key = "Source ASAN"
        elif filename.endswith(".binary-asan.log"):
            key = "Binary ASAN"
        else:
            key = "Valgrind Memcheck"

        fullpath = os.path.join(results_dir, filename)
        with open(fullpath, encoding="ISO-8859-1") as fd:
            data = fd.read().split("\n")[-9:]

        keys2 = ["Total", "True Positive", "False Negative",
                 "Total", "True Negative", "False Positive",
                 "Timeout Vuln", "Timeout Safe"]

        for idx, line in enumerate(data):
            if not line:
                continue
            value = int(line.split(": ")[1].strip())
            results[key][keys2[idx]] += value

    df = pandas.DataFrame.from_dict(results)
    df = df.reset_index()
    df['index'] = pandas.Categorical(
        df['index'], ["Total", "True Positive", "True Negative",
                      "False Positive", "False Negative",
                      "Timeout Vuln", "Timeout Safe"])

    df = df.sort_values('index').set_index('index').rename_axis(None)
    print(df)


if __name__ == '__main__':
    argp = argparse.ArgumentParser()

    argp.add_argument(
        "results", type=str, help="Directory with result files")

    argp.add_argument(
        "out", type=str, help="Prefix name for outfile")
    
    args = argp.parse_args()
    results_to_csv(args.results, args.out)
