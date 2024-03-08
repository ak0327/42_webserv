#!/usr/bin/env python3
import os
import time


def header():
    print('Content-Type: text/html')
    print()


def main():
    query_string = os.environ.get('QUERY_STRING', '')
    print(f'sleep {query_string} sec')
    time.sleep(float(query_string))
    print('fin')


if __name__ == "__main__":
    header()
    main()
