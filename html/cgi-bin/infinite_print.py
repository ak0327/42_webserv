#!/usr/bin/env python3
import time

print('Content-Type: text/html')
print('')

i = 0
while True:
    time.sleep(0.01)
    print(i)
    i += 1
