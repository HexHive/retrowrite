#!/usr/bin/env python3

import argparse
import base64
import greenstalk
import json
import os


def do_save(args):
    client = greenstalk.Client(host=args.host, port=args.port, use="results",
            watch=["results"])
    client.use("results")

    while True:
        job = client.reserve()
        current = json.loads(job.body)
        name = current['name']
        #data = current['data']

        path = os.path.join(args.o, name)
        print(path)
        #with open(path, 'wb') as fd:
            #fd.write(base64.decode64(data))

        client.delete(job)


if __name__ == '__main__':
    argp = argparse.ArgumentParser()

    argp.add_argument(
        "--host",
        help="Result pipe host")
    argp.add_argument(
        "--port",
        help="Result pipe port")
    argp.add_argument(
        "--pipe",
        help="Result pipe name")
    argp.add_argument(
        "-o",
        help="Output directory")

    args = argp.parse_args()
    do_save(args)
