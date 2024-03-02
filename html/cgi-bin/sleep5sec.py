#!/usr/bin/env python3
import time


def header():
    print('Content-Type: text/html')
    print()


def main():
    print('sleep...')
    time.sleep(5)
    print('...fin')


if __name__ == "__main__":
    header()
    main()
