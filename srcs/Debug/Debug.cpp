# include <unistd.h>
# include <stdarg.h>
# include <cstdio>
# include "Color.hpp"
# include "Debug.hpp"

pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

void DEBUG_SERVER_PRINT(const char *fmt, ...) {
#ifdef DEBUG
	pthread_mutex_lock(&print_mutex);
	dprintf(STDERR_FILENO, "%s%s", BLUE, "#DEBUG server: ");
	va_list args;
	va_start(args, fmt);
	vdprintf(STDERR_FILENO, fmt, args);
	va_end(args);
	dprintf(STDERR_FILENO, "%s\n", RESET);
	pthread_mutex_unlock(&print_mutex);
#else
	(void)fmt;
#endif
}

void DEBUG_CLIENT_PRINT(const char *fmt, ...) {
#ifdef DEBUG
	pthread_mutex_lock(&print_mutex);
	dprintf(STDERR_FILENO, "%s%s", MAGENTA, "#DEBUG client: ");
	va_list args;
	va_start(args, fmt);
	vdprintf(STDERR_FILENO, fmt, args);
	va_end(args);
	dprintf(STDERR_FILENO, "%s\n", RESET);
	pthread_mutex_unlock(&print_mutex);
#else
	(void)fmt;
#endif
}

void DEBUG_PRINT(const char *fmt, ...) {
#ifdef DEBUG
	pthread_mutex_lock(&print_mutex);
	dprintf(STDERR_FILENO, "%s", "#DEBUG : ");
	va_list args;
	va_start(args, fmt);
	vdprintf(STDERR_FILENO, fmt, args);
	va_end(args);
	dprintf(STDERR_FILENO, "%s\n", RESET);
	pthread_mutex_unlock(&print_mutex);
#else
	(void)fmt;
#endif
}

void DEBUG_PRINT(const char *color, const char *fmt, ...) {
#ifdef DEBUG
	pthread_mutex_lock(&print_mutex);
	dprintf(STDERR_FILENO, "%s%s", color, "#DEBUG : ");
	va_list args;
	va_start(args, fmt);
	vdprintf(STDERR_FILENO, fmt, args);
	va_end(args);
	dprintf(STDERR_FILENO, "%s\n", RESET);
	pthread_mutex_unlock(&print_mutex);
#else
	(void)fmt;
	(void)color;
#endif
}
