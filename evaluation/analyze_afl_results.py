import argparse
import os
import glob
from collections import defaultdict
import tarfile
import json

import pandas
import matplotlib.pyplot as plt
import numpy as np


def results_to_json(input, out):
    results = defaultdict(lambda: defaultdict(list))

    for filename in glob.glob(input + "/**/*.tar.gz", recursive=True):
        path = os.path.abspath(filename)
        result_tar = path

        benchmark = os.path.basename(os.path.dirname(path))
        mode = os.path.basename(path).split("-")[0]
        trial = int(os.path.basename(path).split("-")[1].split(".")[0][-1])

        """
        execs_done        : 4426984
        execs_per_sec     : 60.31
        unique_crashes    : 0
        """

        tf = tarfile.open(result_tar, "r:*")
        path_template = "sync_dir/{}-fuzzer0{}/fuzzer_stats"
        for i in range(1, 9):
            tpath = path_template.format(benchmark, i)
            try:
                contents = tf.extractfile(tpath).read().decode('utf-8')
            except KeyError:
                break

            data = dict()
            for line in contents.split("\n"):
                if not line:
                    continue
                line = line.split(":")
                data[line[0].strip()] = line[1].strip()

            data["trial"] = trial
            results[mode][benchmark].append(data)

    with open(out + ".json", "w") as fd:
        json.dump(results, fd, indent=2)


def results_to_csv(input, out):
    jsonf = out + ".json"
    with open(jsonf) as fd:
        data = json.load(fd)

    results = defaultdict(lambda: defaultdict(lambda: [0, 0, 0]))
    execs_per_s = defaultdict(lambda: defaultdict(lambda: [[], [], []]))
    crashes = defaultdict(lambda: defaultdict(lambda: [0, 0, 0]))

    for kind, values in data.items():
        for bench, infos in values.items():
            for info in infos:
                trial = info["trial"] - 1
                results[kind][bench][trial] += int(info["execs_done"])
                crashes[kind][bench][trial] += int(info["unique_crashes"])
                execs_per_s[kind][bench][trial].append(float(info["execs_per_sec"]))

    df = pandas.DataFrame.from_dict(results)
    print(df)

    for kind, values in execs_per_s.items():
        for bench, infos in values.items():
            for idx, exs in enumerate(infos):
                execs_per_s[kind][bench][idx] = sum(exs) / len(exs)
            #print(kind, bench, np.mean(execs_per_s[kind][bench]))


    edf = pandas.DataFrame.from_dict(execs_per_s)
    print(edf)

    cdf = pandas.DataFrame.from_dict(crashes)
    print(cdf)



if __name__ == "__main__":
    argp = argparse.ArgumentParser()

    argp.add_argument(
        "out", type=str, help="Prefix name for outfile")

    argp.add_argument(
        "--inputs", type=str, help="SPEC result files to analyze")

    argp.add_argument(
        "--latex", action='store_true', help="Generate latex tables")

    argp.add_argument(
        "--plot", action='store_true', help="Generate plots")

    argp.add_argument(
        "--pp", action='store_true', help="Pretty print table")

    args = argp.parse_args()

    results_to_json(args.inputs, args.out)
    results_to_csv(args.inputs, args.out)

    #if args.latex:
        #to_latex(args.out)
    #if args.pp:
        #ascii_pp(args.out)
    #if args.plot:
        #plot(args.out)
