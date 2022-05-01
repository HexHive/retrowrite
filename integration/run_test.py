#!/usr/bin/env python3
import os
import sys
from subprocess import *
import hashlib

if "BENCHDIR" not in os.environ:
    print("BENCHDIR env variable not found. Quitting.")
    exit(1)

PATH_SPECPU = os.environ["BENCHDIR"]
PATH_TESTS = f"{PATH_SPECPU}/benchspec/CPU"

tests = {
"blender_r"    : "526.blender_r",
"bwaves_r"     : "503.bwaves_r",
"cactusBSSN_r" : "507.cactuBSSN_r",
"cam4_r"       : "527.cam4_r",
"cpugcc_r"     : "502.gcc_r"      ,
"cpuxalan_r"   : "523.xalancbmk_r",
"deepsjeng_r"  : "531.deepsjeng_r",
"diffwrf_521"  : "521.wrf_r",
"exchange2_r"  : "548.exchange2_r",
"fotonik3d_r"  : "549.fotonik3d_r",
"imagick_r"    : "538.imagick_r"  ,
"lbm_r"        : "519.lbm_r"      ,
"ldecod_r"     : "525.x264_r"      ,
"leela_r"      : "541.leela_r",
"mcf_r"        : "505.mcf_r"      ,
"nab_r"        : "544.nab_r"      ,
"namd_r"       : "508.namd_r",
"omnetpp_r"    : "520.omnetpp_r",
"parest_r"     : "510.parest_r",
"perlbench_r"  : "500.perlbench_r",
"povray_r"     : "511.povray_r",
"roms_r"       : "554.roms_r",
"specrand_fr"  : "997.specrand_fr",
"specrand_ir"  : "999.specrand_ir",
"wrf_r"        : "521.wrf_r",
"x264_r"       : "525.x264_r"     ,
"xz_r"         : "557.xz_r"       ,
"xz_s"         : "657.xz_s",
"gcc_s"        : "602.gcc_s"      ,
"lbm_s"        : "619.lbm_s"      ,
"mcf_s"        : "605.mcf_s"      ,
"perlbench_s"  : "600.perlbench_s",
"x264_s"       : "625.x264_s"     ,
}



def quit(msg):
    print(msg)
    exit(1)

def cmd(text):
    try:
        return check_output(text, shell=True, stderr=STDOUT)
    except CalledProcessError as e:
        print(e.output)
        return e.output


def run(command):
    process = Popen(command, stdout=PIPE, shell=True)
    while True:
        line = process.stdout.readline().rstrip()
        if not line:
            break
        yield line


if len(sys.argv) < 2:
    quit("./run_test.py <binaries>")

final_str = ""

for binary_full in sys.argv[1:]:
    binary = os.path.basename(binary_full)
    if not os.path.exists(os.path.expanduser(binary_full)):
        quit(f"{binary} not found")

    if len(binary.split("_")) < 2: 
        quit(f"{binary} wrong format")

    if not any(x in binary for x in ["lbm_r"]):
        continue

    binary_original_name = "_".join(binary.split("_")[:2])

    if binary_original_name not in tests.keys():
        quit(f"{binary_original_name} not found in tests list")

    test_name = tests[binary_original_name]


    md5 = hashlib.md5(open(binary_full, "rb").read()).hexdigest()
    print (f"=== Preparing test {test_name}")
    print (f"=== md5sum {binary} = {md5}")

    cmd(f"rm -rf {PATH_TESTS}/{test_name}/run")
    cmd(f"cp {binary_full} {PATH_TESTS}/{test_name}/exe/{binary_original_name}_base.mytest-64")

    final_str += " " + test_name



# TODO: modify this to write into a file 'benchmark_cmd' and use a Makefile!
print("="*50)
print("Finished. You can now run:")
# print(f"cd {PATH_SPECPU} && source shrc && runcpu --nobuild --iterations 1 --config strace.cfg {final_str}")
# print(f"cd {PATH_SPECPU} && source shrc && runcpu --nobuild --iterations 1 --config final.cfg {final_str}")
# print(f"cd {PATH_SPECPU} && source shrc && runcpu --nobuild --iterations 1 --config final.cfg {final_str}")
print(f"cd {PATH_SPECPU} && source shrc && runcpu --nobuild --iterations 1 --config counter.cfg {final_str}")
# print(f"cd {PATH_SPECPU} && source shrc && runcpu --rebuild --iterations 1 --config final_ASAN.cfg {final_str}")
# print(f"cd {PATH_SPECPU} && source shrc && runcpu --rebuild --iterations 1 --config valgrind.cfg {final_str}")
# --size test --loose --fake 

