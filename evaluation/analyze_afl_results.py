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


TARGETS = dict(
    qemu=dict(color="#003f5c", name="gcc", rename="qemu"),
    retrowrite=dict(color="#58508d", name="afl-retrowrite", rename="retrowrite"),
    afl_gcc=dict(color="#bc5090", name="afl-gcc", rename="afl-gcc"),
    afl_dyninst=dict(color="#ff6361", name="afl-dyninst", rename="dyninst"),
    afl_clang_fast=dict(color="#ffa600", name="afl-clang-fast", rename="afl-clang-fast")
)


def set_box_color(bp, color):
    plt.setp(bp['boxes'], color=color)
    plt.setp(bp['whiskers'], color=color)
    plt.setp(bp['caps'], color=color)
    plt.setp(bp['medians'], color=color)


def compute_p_values(execs_per_s):
    pvalues = {"Binary-AFL v/s Source-AFL": dict(), 
           "Binary-AFL v/s QEMU": dict()}

    for benchname in execs_per_s["binary"]:
        bchar = execs_per_s["binary"][benchname]
        qchar = execs_per_s["qemu"][benchname]
        schar = execs_per_s["src"][benchname]
        pvalues["Binary-AFL v/s QEMU"][benchname] = scipy.stats.mannwhitneyu(bchar, qchar)[1]
        pvalues["Binary-AFL v/s Source-AFL"][benchname] = scipy.stats.mannwhitneyu(bchar, schar)[1]

    return pvalues


def results_to_json(input, out):
    results = defaultdict(lambda: defaultdict(list))

    for filename in glob.glob(input + "*.tar.gz", recursive=True):
        path = os.path.abspath(filename)

        basename = os.path.basename(filename)
        benchmark = basename.split("-")[0]
        system = '-'.join(basename.split("trial")[0].split("-")[1:])[:-1]
        trial = int(filename.split("-")[-1][0])
        result_tar = path

        # fuzz/libtiff-afl-gcc/1/fuzz-out/fuzzer5/plot_data
        tf = tarfile.open(result_tar, "r:*")
        path_template = "fuzz/{}/{}/fuzz-out/fuzzer{}/fuzzer_stats"
        for i in range(0, 8):
            tpath = path_template.format(basename.split("-trial")[0], trial, i)
            try:
                contents = tf.extractfile(tpath).read().decode('utf-8')
            except KeyError:
                print("Failed: %s: %s" % (basename, path))
                data = dict()
                data["trial"] = trial
                results[system][benchmark].append(data)
                continue

            data = dict()
            for line in contents.split("\n"):
                if not line:
                    continue
                line = line.split(":")
                data[line[0].strip()] = line[1].strip()

            data["trial"] = trial
            results[system][benchmark].append(data)

    with open(out + ".json", "w") as fd:
        json.dump(results, fd, indent=2)


def results_to_csv(input, out):
    jsonf = out + ".json"
    with open(jsonf) as fd:
        data = json.load(fd)

    systemsn = len(data)

    results = defaultdict(lambda: defaultdict(lambda: [0 for _ in range(0, systemsn)]))
    execs_per_s = defaultdict(lambda: defaultdict(lambda: [[] for _ in range(systemsn)]))
    crashes = defaultdict(lambda: defaultdict(lambda: [0 for _ in range(0, systemsn)]))

    for kind, values in data.items():
        for bench, infos in values.items():
            for info in infos:
                trial = info["trial"] - 1

                if "execs_done" in info:
                    results[kind][bench][trial] += int(info["execs_done"])
                else:
                    results[kind][bench][trial] += 0

                if "unique_crashes" in info:
                    crashes[kind][bench][trial] += int(info["unique_crashes"])
                else:
                    crashes[kind][bench][trial] += 0

                if "execs_per_sec" in info:
                    execs_per_s[kind][bench][trial].append(
                        float(info["execs_per_sec"]))
                else:
                    execs_per_s[kind][bench][trial].append(0.0)
                        
        execs_per_s[kind + "-mean"][bench] = 0.0
        execs_per_s[kind + "-std"][bench] = 0.0

    df = pandas.DataFrame.from_dict(results)
    pandas.set_option('display.max_colwidth', -1)
    #print(df)

    ignore = ['-mean', '-std']
    for kind, values in execs_per_s.items():
        print(kind)
        if any([kind.endswith(x) for x in ignore]):
            continue

        for bench, infos in values.items():
            for idx, exs in enumerate(infos):
                execs_per_s[kind][bench][idx] = round(sum(exs) / len(exs), 2)
            execs_per_s[kind + "-mean"][bench] = round(
                np.mean(execs_per_s[kind][bench]), 2)
            execs_per_s[kind + "-std"][bench] = round(
                np.std(execs_per_s[kind][bench]), 2)

    edf = pandas.DataFrame.from_dict(execs_per_s)
    print(edf)
    with open(out + "-execs-table.tex", "w") as fd:
        fd.write(edf.to_latex())
    with open(out + "-execs-table.csv", "w") as fd:
        fd.write(edf.to_csv())

    cdf = pandas.DataFrame.from_dict(crashes)
    #print(cdf)

    # Calculate p-values.
    # TODO: This may need to be changed. Not sure how to compare against
    # multiple systems to show that the differences may not be statistically
    # significant. This was brought up by some reviewer.
    #pvalues = compute_p_values(execs_per_s)
    #manndf = pandas.DataFrame.from_dict(pvalues)
    #print(manndf)
    #with open(out + '-mann-whitney.tex', 'w') as fd:
    #    fd.write(manndf.to_latex())

    ### BOX PLOT
    # Make a boxplot for the executions per second computation.
    box = defaultdict(list)
    boxx = list()
    for kind, benchmarks in execs_per_s.items():
        if any([kind.endswith(x) for x in ignore]):
            continue
        for benchname in sorted(benchmarks):
            if benchname not in boxx:
                boxx.append(benchname)
            box[kind].append(benchmarks[benchname])

    print(box)
    keys = execs_per_s.keys()

    fig = plt.figure()
    ax = fig.add_subplot(111)

    wd = 0.4
    db = 0.1
    lb = 0.9
    cstep = (len(box) - 1) * (wd + db) + lb
    base = 2 * (wd + db)
    centers = None

    valid_keys = -1

    for key in keys:
        props = None
        for bench, value in TARGETS.items():
            if value['name'] == key:
                props = value
                break

        if not props:
            continue

        valid_keys += 1

    count = 0
    for key in keys:
        props = None
        for bench, value in TARGETS.items():
            if value['name'] == key:
                props = value
                break

        if not props:
            print("[X] Unknown key %s! Skipping." % (key))
            continue

        centers = np.array(np.arange(base, base + cstep * len(box[key]), cstep))
        positions = centers + ((count - ((valid_keys) / 2)) * (db + wd))
        print(centers)
        print(positions)
        print(count , (count - ((valid_keys) / 2)))
        print((count - (((valid_keys) / 2)) * (db + wd)))

        plot = plt.boxplot(
                box[key],
                positions=positions, sym='',
                widths=wd)

        set_box_color(plot, props['color'])
        plt.plot([], c=props['color'], label=props['rename'])
        count += 1

    #src = plt.boxplot(
        #box['src'],
        #positions=np.array(range(len(box['src'])))*3.0-0.7, sym='',
        #widths=0.6)

    #binary = plt.boxplot(
        #box['binary'],
        #positions=np.array(range(len(box['binary'])))*3.0, sym='',
        #widths=0.6)

    #qemu = plt.boxplot(
        #box['qemu'],
        #positions=np.array(range(len(box['qemu'])))*3.0+0.7, sym='',
        #widths=0.6)

    #set_box_color(src, "#e41a1c")
    #set_box_color(binary, "#377eb8")
    #set_box_color(qemu, "#4daf4a")

    #plt.plot([], c="#e41a1c", label="Source-AFL")
    #plt.plot([], c="#377eb8", label="Binary-AFL")
    #plt.plot([], c="#4daf4a", label="QEMU")
    plt.legend()

    plt.xticks(centers, boxx)
    print(centers)
    plt.xlim(-2, centers[-1] + 2 * (db + wd) + wd)
    ax.set_ylabel("Executions / s")

    plt.tight_layout()
    plt.savefig(out + "-boxplot.pdf")


def analyze_unique_bugs(logd, outf):
    logfiles = os.listdir(logd)
    results = defaultdict(lambda: defaultdict(lambda: [[], [], [], [], []]))
    counts = defaultdict(lambda: defaultdict(lambda: [0, 0, 0, 0, 0]))

    for file in logfiles:
        bench, components = file.split("-", 1)
        kind, _, trial = components.rsplit("-", 2)
        trial = int(trial[0]) - 1

        path = os.path.abspath(os.path.join(logd, file))
        with open(path) as fd:
            data = fd.read()

        lines = data.split("\n")

        if not lines[0]:
            results[kind][bench][trial].append(0)
            counts[kind][bench][trial] += 0
            continue

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

    with open(outf + "-unique-bugs.tex", "w") as fd:
        fd.write(cdf.to_latex())
    with open(outf + "-unique-bugs.csv", "w") as fd:
        fd.write(cdf.to_csv())


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

    #results_to_json(args.inputs, args.out)
    #results_to_csv(args.inputs, args.out)

    if args.unique:
        analyze_unique_bugs(args.unique, args.out)

    #if args.latex:
    #to_latex(args.out)
    #if args.pp:
    #ascii_pp(args.out)
    #if args.plot:
    #plot(args.out)
