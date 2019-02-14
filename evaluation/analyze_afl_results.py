import argparse
import os
import glob
from collections import defaultdict
import tarfile
import json

import pandas
import matplotlib.pyplot as plt
import numpy as np
import scipy.stats


def set_box_color(bp, color):
    plt.setp(bp['boxes'], color=color)
    plt.setp(bp['whiskers'], color=color)
    plt.setp(bp['caps'], color=color)
    plt.setp(bp['medians'], color=color)


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

    results = defaultdict(lambda: defaultdict(lambda: [0, 0, 0, 0, 0]))
    execs_per_s = defaultdict(lambda: defaultdict(lambda: [[], [], [], [], []]))
    crashes = defaultdict(lambda: defaultdict(lambda: [0, 0, 0, 0, 0]))

    #box = [[], [], []]
    bidx = dict(src=0, binary=1, qemu=2)

    for kind, values in data.items():
        for bench, infos in values.items():
            for info in infos:
                trial = info["trial"] - 1
                results[kind][bench][trial] += int(info["execs_done"])
                crashes[kind][bench][trial] += int(info["unique_crashes"])
                execs_per_s[kind][bench][trial].append(
                    float(info["execs_per_sec"]))

                #box[bidx[kind]].append(float(info["execs_per_sec"]))

        execs_per_s[kind + "-mean"][bench] = 0.0
        #execs_per_s[kind + "-var"][bench] = 0.0
        execs_per_s[kind + "-std"][bench] = 0.0

    df = pandas.DataFrame.from_dict(results)
    pandas.set_option('display.max_colwidth', -1)
    #print(df)

    for kind, values in execs_per_s.items():
        if kind.endswith("-mean"):
            continue
        if kind.endswith("-std"):
            continue
        for bench, infos in values.items():
            for idx, exs in enumerate(infos):
                execs_per_s[kind][bench][idx] = round(sum(exs) / len(exs), 2)
            execs_per_s[kind + "-mean"][bench] = round(
                np.mean(execs_per_s[kind][bench]), 2)
            execs_per_s[kind + "-std"][bench] = round(
                np.std(execs_per_s[kind][bench]), 2)

    edf = pandas.DataFrame.from_dict(execs_per_s)
    #print(edf)
    with open(out + "-execs-table.tex", "w") as fd:
        fd.write(edf.to_latex())

    cdf = pandas.DataFrame.from_dict(crashes)
    #print(cdf)

    # Make a boxplot
    box = defaultdict(list)
    boxx = list()
    pvalues = {"Binary-AFL v/s Source-AFL": dict(), 
           "Binary-AFL v/s QEMU": dict()}

    for benchname in execs_per_s["binary"]:
        bchar = execs_per_s["binary"][benchname]
        qchar = execs_per_s["qemu"][benchname]
        schar = execs_per_s["src"][benchname]
        pvalues["Binary-AFL v/s QEMU"][benchname] = scipy.stats.mannwhitneyu(bchar, qchar)[1]
        pvalues["Binary-AFL v/s Source-AFL"][benchname] = scipy.stats.mannwhitneyu(bchar, schar)[1]

    manndf = pandas.DataFrame.from_dict(pvalues)
    print(manndf)

    with open(out + '-mann-whitney.tex', 'w') as fd:
        fd.write(manndf.to_latex())

    for kind, benchmarks in execs_per_s.items():
        if kind.endswith("-mean"):
            continue
        if kind.endswith("-std"):
            continue

        for benchname in sorted(benchmarks):
            if benchname not in boxx:
                boxx.append(benchname)
            box[kind].append(benchmarks[benchname])

    print(box)

    fig = plt.figure()
    ax = fig.add_subplot(111)
    src = plt.boxplot(
        box['src'],
        positions=np.array(range(len(box['src'])))*3.0-0.7, sym='',
        widths=0.6)

    binary = plt.boxplot(
        box['binary'],
        positions=np.array(range(len(box['binary'])))*3.0, sym='',
        widths=0.6)

    qemu = plt.boxplot(
        box['qemu'],
        positions=np.array(range(len(box['qemu'])))*3.0+0.7, sym='',
        widths=0.6)

    set_box_color(src, "#e41a1c")
    set_box_color(binary, "#377eb8")
    set_box_color(qemu, "#4daf4a")

    plt.plot([], c="#e41a1c", label="Source-AFL")
    plt.plot([], c="#377eb8", label="Binary-AFL")
    plt.plot([], c="#4daf4a", label="QEMU")
    plt.legend()

    plt.xticks(range(0, len(boxx) * 3, 3), boxx)
    plt.xlim(-2, len(boxx)*3)
    ax.set_ylabel("Executions / s")

    plt.tight_layout()
    plt.savefig(out + "-boxplot.pdf")


def analyze_unique_bugs(logd, outf):
    logfiles = os.listdir(logd)
    results = defaultdict(lambda: defaultdict(lambda: [[], [], [], [], []]))
    counts = defaultdict(lambda: defaultdict(lambda: [0, 0, 0, 0, 0]))

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
            counts[kind][bench][trial] += 1

    for kind, values in results.items():
        for bench, infos in values.items():
            for idx, bugs in enumerate(infos):
                if not results[kind][bench][idx]:
                    results[kind][bench][idx] = '-'
                    continue
                results[kind][bench][idx] = ':'.join([
                    str(x) for x in results[kind][bench][idx]])

    bugs = pandas.DataFrame.from_dict(results)
    cdf = pandas.DataFrame.from_dict(counts)
    print(cdf)

    with open(outf + "-unique-bugs.tex", "w") as fd:
        fd.write(cdf.to_latex())
    #print(bugs)


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
