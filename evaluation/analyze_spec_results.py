import argparse
import os
from collections import defaultdict

import pandas
import matplotlib.pyplot as plt


def results_to_csv(inputs, out):
    results = defaultdict(list)
    keys = list()

    for fname in inputs:
        with open(fname) as fd:
            data = fd.read()

        data = data.split("\n")
        start = False
        key = os.path.basename(fname)
        keys.append(key)

        for line in data:
            if not line:
                continue
            if start:
                line = line.split()
                if line[-1] != "NR":
                    benchmark = line[0].strip()
                    results[benchmark].append(float(line[2].strip()))
            elif line.startswith("-----"):
                start = True

    csvl = list()
    csvl.append(
        "benchmark,{}".format(','.join(keys)))
    csvl.extend(
        ["{},{}".format(
            k, ','.join(map(lambda x: str(x), results[k]))) for k in sorted(results)])

    csvf = out + ".csv"
    with open(csvf, "w") as fd:
        fd.write("\n".join(csvl))


def ascii_pp(csvf):
    csvf = csvf + ".csv"
    df = pandas.read_csv(csvf)
    print(df)


def to_latex(outf):
    csvf = outf + ".csv"
    df = pandas.read_csv(csvf)
    latexf = outf + ".tex"
    with open(latexf, "w") as fd:
        fd.write(df.to_latex())


def plot(outf):
    csvf = outf + ".csv"
    df = pandas.read_csv(csvf)
    df = df.set_index("benchmark")

    ax = df.plot.bar(rot=30, figsize=(8, 6))
    ax.set_xlabel("Benchmark")
    ax.set_ylabel("Runtime (s)")

    plot = outf + ".pdf"

    fig = ax.get_figure()
    fig.savefig(plot)


if __name__ == "__main__":
    argp = argparse.ArgumentParser()

    argp.add_argument(
        "out", type=str, help="Prefix name for outfile")

    argp.add_argument(
        "--inputs", nargs="+", help="SPEC result files to analyze")

    argp.add_argument(
        "--latex", action='store_true', help="Generate latex tables")

    argp.add_argument(
        "--plot", action='store_true', help="Generate plots")

    argp.add_argument(
        "--pp", action='store_true', help="Pretty print table")

    args = argp.parse_args()

    results_to_csv(args.inputs, args.out)
    if args.latex:
        to_latex(args.out)
    if args.pp:
        ascii_pp(args.out)
    if args.plot:
        plot(args.out)
