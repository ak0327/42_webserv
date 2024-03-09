#!/usr/bin/env python3


def header():
    print('Status: 302 Found')
    print('Content-Type: text/html')
    print('Location: /')
    print()


def main():
    print('redirect to index')


if __name__ == "__main__":
    header()
    main()
