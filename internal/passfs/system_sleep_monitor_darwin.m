//go:build darwin && cgo

#import <AppKit/AppKit.h>
#import <CoreFoundation/CoreFoundation.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct passfs_system_sleep_watcher {
	int read_fd;
	int write_fd;
	pthread_t thread;
	pthread_mutex_t mutex;
	pthread_cond_t ready_condition;
	CFRunLoopRef run_loop;
	bool ready;
	bool stopping;
} passfs_system_sleep_watcher;

@interface PassFSSystemSleepObserver : NSObject {
	int eventFileDescriptor;
}

- (instancetype)initWithFileDescriptor:(int)fileDescriptor;
- (void)systemPowerChanged:(NSNotification *)notification;

@end

@implementation PassFSSystemSleepObserver

- (instancetype)initWithFileDescriptor:(int)fileDescriptor
{
	self = [super init];
	if (self != nil) {
		eventFileDescriptor = fileDescriptor;
	}
	return self;
}

- (void)systemPowerChanged:(NSNotification *)notification
{
	uint8_t event = [notification.name
		isEqualToString:NSWorkspaceWillSleepNotification] ? 1 : 2;
	ssize_t result;
	do {
		result = write(eventFileDescriptor, &event, sizeof(event));
	} while (result < 0 && errno == EINTR);
}

@end

static bool passfs_system_sleep_watcher_is_stopping(
	passfs_system_sleep_watcher *watcher
) {
	pthread_mutex_lock(&watcher->mutex);
	bool stopping = watcher->stopping;
	pthread_mutex_unlock(&watcher->mutex);
	return stopping;
}

static void *passfs_system_sleep_watcher_run(void *context)
{
	passfs_system_sleep_watcher *watcher = context;
	@autoreleasepool {
		PassFSSystemSleepObserver *observer =
			[[PassFSSystemSleepObserver alloc]
				initWithFileDescriptor:watcher->write_fd];
		NSNotificationCenter *notifications =
			[[NSWorkspace sharedWorkspace] notificationCenter];
		[notifications
			addObserver:observer
			selector:@selector(systemPowerChanged:)
			name:NSWorkspaceWillSleepNotification
			object:nil];
		[notifications
			addObserver:observer
			selector:@selector(systemPowerChanged:)
			name:NSWorkspaceDidWakeNotification
			object:nil];

		NSPort *keepAlive = [NSPort port];
		[[NSRunLoop currentRunLoop]
			addPort:keepAlive
			forMode:NSDefaultRunLoopMode];

		pthread_mutex_lock(&watcher->mutex);
		watcher->run_loop = (CFRunLoopRef)CFRetain(CFRunLoopGetCurrent());
		watcher->ready = true;
		pthread_cond_signal(&watcher->ready_condition);
		pthread_mutex_unlock(&watcher->mutex);

		while (!passfs_system_sleep_watcher_is_stopping(watcher)) {
			@autoreleasepool {
				[[NSRunLoop currentRunLoop]
					runMode:NSDefaultRunLoopMode
					beforeDate:[NSDate dateWithTimeIntervalSinceNow:3600]];
			}
		}

		[notifications removeObserver:observer];
		[observer release];

		pthread_mutex_lock(&watcher->mutex);
		CFRunLoopRef runLoop = watcher->run_loop;
		watcher->run_loop = NULL;
		pthread_mutex_unlock(&watcher->mutex);
		if (runLoop != NULL) {
			CFRelease(runLoop);
		}
	}
	return NULL;
}

static void passfs_system_sleep_watcher_set_error(
	char **errorMessage,
	const char *message
) {
	if (errorMessage != NULL) {
		*errorMessage = strdup(message);
	}
}

passfs_system_sleep_watcher *passfs_system_sleep_watcher_create(
	int *readFileDescriptor,
	char **errorMessage
) {
	if (readFileDescriptor == NULL) {
		passfs_system_sleep_watcher_set_error(
			errorMessage,
			"System sleep watcher requires an event destination");
		return NULL;
	}
	*readFileDescriptor = -1;
	passfs_system_sleep_watcher *watcher = calloc(1, sizeof(*watcher));
	if (watcher == NULL) {
		passfs_system_sleep_watcher_set_error(
			errorMessage,
			"Could not allocate the system sleep watcher");
		return NULL;
	}
	watcher->read_fd = -1;
	watcher->write_fd = -1;
	int fileDescriptors[2];
	if (pipe(fileDescriptors) != 0) {
		free(watcher);
		passfs_system_sleep_watcher_set_error(
			errorMessage,
			"Could not create the system sleep event channel");
		return NULL;
	}
	watcher->read_fd = fileDescriptors[0];
	watcher->write_fd = fileDescriptors[1];
	(void)fcntl(watcher->read_fd, F_SETFD, FD_CLOEXEC);
	(void)fcntl(watcher->write_fd, F_SETFD, FD_CLOEXEC);
	int writeFlags = fcntl(watcher->write_fd, F_GETFL, 0);
	if (writeFlags >= 0) {
		(void)fcntl(watcher->write_fd, F_SETFL, writeFlags | O_NONBLOCK);
	}
	if (pthread_mutex_init(&watcher->mutex, NULL) != 0) {
		close(watcher->read_fd);
		close(watcher->write_fd);
		free(watcher);
		passfs_system_sleep_watcher_set_error(
			errorMessage,
			"Could not initialize the system sleep watcher");
		return NULL;
	}
	if (pthread_cond_init(&watcher->ready_condition, NULL) != 0) {
		pthread_mutex_destroy(&watcher->mutex);
		close(watcher->read_fd);
		close(watcher->write_fd);
		free(watcher);
		passfs_system_sleep_watcher_set_error(
			errorMessage,
			"Could not initialize the system sleep watcher");
		return NULL;
	}
	if (pthread_create(
		&watcher->thread,
		NULL,
		passfs_system_sleep_watcher_run,
		watcher) != 0) {
		pthread_cond_destroy(&watcher->ready_condition);
		pthread_mutex_destroy(&watcher->mutex);
		close(watcher->read_fd);
		close(watcher->write_fd);
		free(watcher);
		passfs_system_sleep_watcher_set_error(
			errorMessage,
			"Could not start the system sleep watcher");
		return NULL;
	}

	pthread_mutex_lock(&watcher->mutex);
	while (!watcher->ready) {
		pthread_cond_wait(&watcher->ready_condition, &watcher->mutex);
	}
	pthread_mutex_unlock(&watcher->mutex);
	*readFileDescriptor = watcher->read_fd;
	return watcher;
}

void passfs_system_sleep_watcher_close(
	passfs_system_sleep_watcher *watcher
) {
	if (watcher == NULL) {
		return;
	}
	pthread_mutex_lock(&watcher->mutex);
	watcher->stopping = true;
	CFRunLoopRef runLoop = watcher->run_loop == NULL ? NULL :
		(CFRunLoopRef)CFRetain(watcher->run_loop);
	pthread_mutex_unlock(&watcher->mutex);
	if (runLoop != NULL) {
		CFRunLoopStop(runLoop);
		CFRunLoopWakeUp(runLoop);
		CFRelease(runLoop);
	}
	pthread_join(watcher->thread, NULL);
	close(watcher->write_fd);
	pthread_cond_destroy(&watcher->ready_condition);
	pthread_mutex_destroy(&watcher->mutex);
	free(watcher);
}
