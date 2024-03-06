#!/usr/bin/env python3


def header():
    print('Content-Type: text/html')
    print()


def main():
    test = [1]
    print(test[100])


if __name__ == "__main__":
    header()
    main()
