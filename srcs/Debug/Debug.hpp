#pragma once

# include <pthread.h>

extern pthread_mutex_t print_mutex;

void DEBUG_SERVER_PRINT(const char *fmt, ...);
void DEBUG_CLIENT_PRINT(const char *fmt, ...);
void DEBUG_PRINT(const char *color, const char *fmt, ...);
