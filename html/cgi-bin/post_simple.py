#!/usr/bin/env python3

import sys


def header():
    print("Content-Type: text/plain")
    print()


def main():
    post_data = sys.stdin.read()

    print("post data vvvvvvvvvvvvvvv")
    print(post_data)
    print("post data ^^^^^^^^^^^^^^^")


if __name__ == "__main__":
    header()
    main()
