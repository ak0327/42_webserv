#!/usr/bin/env python3
import time


def header():
    print('Content-Type: text/html')
    print()


def main():
    i = 0
    while True:
        time.sleep(0.01)
        print(i)
        i += 1


if __name__ == "__main__":
    header()
    main()
