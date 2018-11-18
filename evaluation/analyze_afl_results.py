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
                execs_per_s[kind][bench][trial].append(
                    float(info["execs_per_sec"]))
        execs_per_s[kind + "-mean"][bench] = 0.0
        execs_per_s[kind + "-var"][bench] = 0.0
        execs_per_s[kind + "-std"][bench] = 0.0

    df = pandas.DataFrame.from_dict(results)
    print(df)

    for kind, values in execs_per_s.items():
        if kind.endswith("-mean"):
            continue
        if kind.endswith("-var"):
            continue
        if kind.endswith("-std"):
            continue
        for bench, infos in values.items():
            for idx, exs in enumerate(infos):
                execs_per_s[kind][bench][idx] = round(sum(exs) / len(exs), 2)
            execs_per_s[kind + "-mean"][bench] = round(
                np.mean(execs_per_s[kind][bench]), 2)
            execs_per_s[kind + "-var"][bench] = round(
                np.var(execs_per_s[kind][bench]), 2)
            execs_per_s[kind + "-std"][bench] = round(
                np.std(execs_per_s[kind][bench]), 2)

    edf = pandas.DataFrame.from_dict(execs_per_s)
    print(edf)
    print(edf.to_csv())

    cdf = pandas.DataFrame.from_dict(crashes)
    print(cdf)


def analyze_unique_bugs(logd, outf):
    logfiles = os.listdir(logd)
    results = defaultdict(lambda: defaultdict(lambda: [[], [], []]))

    for file in logfiles:
        components = file.split("-")
        bench = components[0]
        kind = components[1]
        trial = int(components[2][-5]) - 1

        path = os.path.abspath(os.path.join(logd, file))
        with open(path) as fd:
            data = fd.read()
        lines = data.split("\n")
        for bug in lines:
            if not bug:
                continue
            results[kind][bench][trial].append(int(bug))

    for kind, values in results.items():
        for bench, infos in values.items():
            for idx, bugs in enumerate(infos):
                if not results[kind][bench][idx]:
                    results[kind][bench][idx] = '-'
                    continue
                results[kind][bench][idx] = ', '.join([
                    str(x) for x in results[kind][bench][idx]])

    bugs = pandas.DataFrame.from_dict(results)
    print(bugs)


if __name__ == "__main__":
    argp = argparse.ArgumentParser()

    argp.add_argument("out", type=str, help="Prefix name for outfile")

    argp.add_argument(
        "--inputs", type=str, help="SPEC result files to analyze")

    argp.add_argument(
        "--unique", type=str, help="Unique bug log files")

    argp.add_argument(
        "--latex", action='store_true', help="Generate latex tables")

    argp.add_argument("--plot", action='store_true', help="Generate plots")

    argp.add_argument("--pp", action='store_true', help="Pretty print table")

    args = argp.parse_args()

    results_to_json(args.inputs, args.out)
    results_to_csv(args.inputs, args.out)

    if args.unique:
        analyze_unique_bugs(args.unique, args.out)

    #if args.latex:
    #to_latex(args.out)
    #if args.pp:
    #ascii_pp(args.out)
    #if args.plot:
    #plot(args.out)
