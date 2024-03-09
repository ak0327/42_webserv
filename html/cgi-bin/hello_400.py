#!/usr/bin/env python3


def header():
    print('Content-Type: text/html')
    print('Status: 400 Bad Request')
    print()


def main():
    print('hello 400')


if __name__ == "__main__":
    header()
    main()
