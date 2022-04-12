import argparse
import os
from collections import defaultdict
import re
import itertools

import pandas

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
import numpy as np
import matplotlib.pyplot as plt


def results_to_csv(results_dir, out):
    results = defaultdict(lambda: defaultdict(lambda: 0))

    for filename in os.listdir(results_dir):
        if filename.endswith(".asan.log"):
            key = "ASan"
        elif filename.endswith(".binary-asan.log"):
            key = "BASan"
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

    csvf = out + ".csv"
    with open(csvf, 'w') as fd:
        fd.write(df.to_csv())


def deep_analyze(results_dir, out):
    #plt.rcParams['font.size'] = 1
    results = defaultdict(set)
    counts = defaultdict(lambda: defaultdict(lambda: 0))

    all_cwes = set()

    for filename in os.listdir(results_dir):
        if filename.endswith(".asan.log"):
            key = "ASan"
        elif filename.endswith(".binary-asan.log"):
            key = "BASan"
        else:
            key = "Valgrind Memcheck"

        fullpath = os.path.join(results_dir, filename)
        with open(fullpath, encoding="ISO-8859-1") as fd:
            data = fd.read().split("\n")

        data = set(data)

        for line in data:
            if not line.startswith("CWE"):
                continue
            if "failed" in line and "bad" in line:
                cwes = tuple(re.findall(r"(CWE[0-9]+)", line))
                results[key].add(cwes)
                counts[key][cwes] += 1
                all_cwes.update(cwes)

    print(all_cwes)

    xlabels = ["CWE121", "CWE122", "CWE124", "CWE126", "CWE127"]
    ylabels = list(sorted(all_cwes.difference(xlabels)))


    all_cwes = list(sorted(all_cwes))
    points = defaultdict(lambda: [[], []])
    annotations = defaultdict(list)

    keyys = {'ASan': +0.1, 'BASan': -0.1, 'Valgrind Memcheck': 0}
    keyxs = {'ASan': -0.1, 'BASan': -0.1, 'Valgrind Memcheck': 0.1}

    for key, failed in results.items():
        for tags in failed:
            if not tags:
                continue
            tag0 = xlabels.index(tags[0])
            if len(tags) > 1:
                tag1 = ylabels.index(tags[1]) + 1
            else:
                tag1 = 0

            x = tag0 + keyxs[key]
            y = tag1 + keyys[key]

            #x = 0.20 * np.random.random() + (tag0)
            #y = 0.20 * np.random.random() + (tag1)

            points[key][0].append(x)
            points[key][1].append(y)
            annotations[key].append(counts[key][tags])

    colors = {
        'ASan': '#1b9e77',
        'BASan': '#d95f02',
        'Valgrind Memcheck': '#7570b3'}

    fig = plt.figure()
    ax = fig.add_subplot(111)

    print(annotations)

    plt.scatter(
        points["ASan"][1],
        points["ASan"][0],
        c=colors["ASan"],
        alpha=1.0,
        marker="+")

    plt.scatter(
        points["BASan"][1],
        points["BASan"][0],
        c=colors["BASan"],
        alpha=1.0,
        marker="x")

    plt.scatter(
        points["Valgrind Memcheck"][1],
        points["Valgrind Memcheck"][0],
        c=colors["Valgrind Memcheck"],
        alpha=1.0,
        marker="^")

    plt.plot([], c=colors["ASan"], marker="+", label="ASan")
    plt.plot([], c=colors["BASan"], marker="x", label="BASan")
    plt.plot([], c=colors["Valgrind Memcheck"], marker="^", label="Valgrind Memcheck")
    plt.legend()
    
    for key, values in points.items():
        for idx in range(len(values[0])):
            tx = values[1][idx] + keyys[key]
            ty = values[0][idx] + keyxs[key]

            if keyys[key] < 0:
                tx -= 0.1
            else:
                tx -= 0.04

            if keyxs[key] < 0:
                ty -= 0.05

            plt.annotate(
                annotations[key][idx], (values[1][idx], values[0][idx]),
                xytext=(tx, ty),
                fontsize=6,
                color=colors[key])

    xlabels = [x[3:] for x in xlabels]
    ylabels = [y[3:] for y in ylabels]
    plt.yticks(range(0, len(xlabels)), xlabels, rotation=0)
    plt.xticks(range(0, len(ylabels) + 1), ['N/A'] + ylabels)
    plt.ylim(-0.5, len(xlabels))
    plt.xlim(-1, len(ylabels) + 1.5)

    ax.set_ylabel("Primary CWE-ID (What/Where)")
    ax.set_xlabel("Secondary CWE-ID (How)")

    plt.tight_layout()
    plt.savefig(out + "-scatter.pdf")

    #for k1, k2 in itertools.combinations(results.keys(), 2):
        #print(
            #"{} & {}".format(k1, k2),
            #results[k1].intersection(results[k2])
            #)



def results_to_latex(out):
    csvf = out + ".csv"
    df = pandas.read_csv(csvf)
    latexf = out + ".tex"

    with open(latexf, 'w') as fd:
        fd.write(df.to_latex())


if __name__ == '__main__':
    argp = argparse.ArgumentParser()

    argp.add_argument(
        "results", type=str, help="Directory with result files")

    argp.add_argument(
        "out", type=str, help="Prefix name for outfile")

    argp.add_argument(
        "--latex", action='store_true', help="Generate latex tables")

    args = argp.parse_args()
    results_to_csv(args.results, args.out)
    deep_analyze(args.results, args.out)

    if args.latex:
        results_to_latex(args.out)
