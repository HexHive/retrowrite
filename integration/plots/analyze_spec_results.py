import argparse
import os
from collections import defaultdict

import pandas
import matplotlib.pyplot as plt
import seaborn as sns


def results_to_csv(inputs, out):
    results = {}
    all_benchs = set()
    keys = list()

    for fname in inputs:
        with open(fname) as fd:
            data = fd.read()

        data = data.split("\n")
        start = False
        key = os.path.basename(fname)
        key = key.split(".")[0].replace("_", " ").replace("asan", "ASan").replace("5", "").replace("symbolization", "ARMWrestling")
        keys.append(key)

        results[key] = defaultdict(lambda: "NaN")

        for line in data:
            if not line:
                continue
            if start:
                if line[0] == " ": 
                    start = False
                    continue
                line = line.split()
                if len(line) < 2: break
                if line[-1] != "NR":
                    benchmark = line[0].strip()
                    benchmark = benchmark.split(".")[1]
                    benchmark = benchmark.replace("_r", "")
                    if any([x in benchmark for x in ["x264", "gcc", "nab", "namd", "imagick", "lbm", "mcf", "xz", "perlbench"]]):
                        benchmark += "(C)"
                        continue
                    # else:
                        # benchmark += "(C++)"
                    # if any([x in benchmark for x in ["x264", "gcc" ]]):
                    # if any([x in benchmark for x in ["x264" ,]]):
                    # if any([x in benchmark for x in ["x264", ]]):
                        # continue
                    all_benchs.add(benchmark)
                    results[key][benchmark] = float(line[2].strip())
            elif line.startswith("======="):
                start = True

    csvl = list()
    csvl.append("benchmark,{}".format(','.join(keys)))
    for bench in sorted(all_benchs, key=lambda x: not any(y in x for y in["gcc", "perlbench", "nab", "lbm", "x264", "xz", "imagick", "namd", "mcf"])):
        csvl.extend(
            ["%s,%s" % (bench, ','.join([str(results[k][bench]) for k in keys]))])

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
    print(df)

    # ugly patching for cuttin off bars too high
    height_limit = 3250
    # height_limit = 12000

    sns.set(style="darkgrid", palette="deep")
    ax = df.plot.bar(rot=30, figsize=(32, 10), ylim=(1,height_limit*1.1))
    ax.set_ylabel("Runtime (seconds)")
    for x in ax.get_xticklabels() + ax.legend().get_texts() + ax.get_yticklabels() + [ax.title, ax.xaxis.label, ax.yaxis.label]:
        x.set_fontsize(14)
    sns.despine()
    # ax.set_title("SPEC CPU 2017 benchmark results\nCompile flags used: -fno-unsafe-math-optimizations -fno-tree-loop-vectorize -O3")

    for p in ax.patches:
        if p.get_height() < height_limit*0.96: continue
        ax.annotate("("+format(p.get_height(), '.0f')+")",
            (p.get_x() + p.get_width() / 2., min(height_limit, p.get_height())), 
            ha = 'center', va = 'center', 
            xytext = (0, 9), 
            textcoords = 'offset points')
    for p in ax.patches:
        if p.get_height() > height_limit:
            p.set_height(height_limit)

    plot = outf + ".pdf"

    fig = ax.get_figure()
    fig.savefig(plot)


def plot_diff(outf):
    csvf = outf + ".csv"
    df = pandas.read_csv(csvf)
    numrows = len(df.index)
    df.loc[numrows, "benchmark"] = "Average"
    for x in range(1, len(df.columns.values)):
        df.iloc[numrows, x] = sum([df.iloc[i, x] for i in range(numrows)])

    base = "baseline"
    sasan = "Source_Asan"
    basan = "ARMore call emulation"
    # if base not in df.columns:
        # print("Baseline not found")
        # exit(0)

    print(df)
    try:
        print("Overhead on baseline")
        for i in range(len(df.iloc[:])):
            for x in range(2, len(df.columns.values)):
                if df.columns[x] == base: continue
                # df.iloc[i, x] /= df.iloc[i][base]
                df.iloc[i, x] = "{:.2f}%".format(df.iloc[i, x] / df.iloc[i][base] * 100 - 100)
        print(df)
    except :
        pass


    df = pandas.read_csv(csvf)
    numrows = len(df.index)
    df.loc[numrows, "benchmark"] = "Average"
    for x in range(1, len(df.columns.values)):
        df.iloc[numrows, x] = sum([df.iloc[i, x] for i in range(numrows)])

    try:
        print("Overhead on source ASAN")
        for i in range(len(df.iloc[:])):
            for x in range(2, len(df.columns.values)):
                if df.columns[x] == sasan: continue
                df.iloc[i, x] /= df.iloc[i][sasan]
        print(df)
    except:
        pass


    # delete from down here

    # df = pandas.read_csv(csvf)
    # numrows = len(df.index)
    # df.loc[numrows, "benchmark"] = "Average"
    # for x in range(1, len(df.columns.values)):
        # df.iloc[numrows, x] = sum([df.iloc[i, x] for i in range(numrows)])

    # print("Overhead on binary ASAN")
    # for i in range(len(df.iloc[:])):
        # for x in range(2, len(df.columns.values)):
            # if df.columns[x] == basan: continue
            # df.iloc[i, x] /= df.iloc[i][basan]

    # print(df)



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
        plot_diff(args.out)
